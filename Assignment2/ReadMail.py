import sys
from os import path, remove
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512
from Crypto.Hash import SHA3_512
from Crypto.Signature import PKCS1_v1_5
from base64 import b64encode, b64decode
import Common


def decrypt_email_CONF(cipher_text_file, receiver, encrypt_algo):
    recipient_priv_key = RSA.import_key(
        open(f"keys/{receiver}_priv.PEM", "rb").read())

    with open(cipher_text_file, 'rb') as f:
        enc_session_key, cipher_text = [f.read(x) for x in (
            recipient_priv_key.size_in_bytes(), -1)]

    cipher_rsa = PKCS1_OAEP.new(recipient_priv_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    if encrypt_algo == "aes-256-cbc":
        plain_text = Common.AES_decrypt(cipher_text, session_key)
    elif encrypt_algo == "des-ede3-cbc":
        plain_text = Common.DES3_decrypt(cipher_text, session_key)

    return plain_text


def decrypt_email_AUIN(cipher_text_file, sender, digest_algo):
    with open(cipher_text_file, 'r') as f:
        signature = b64decode(f.readline())
        plain_text = f.read().encode("utf-8")

    senders_pub_key = RSA.import_key(
        open(f"keys/{sender}_pub.PEM", "rb").read())

    if digest_algo == "sha3-512":
        message_digest = Common.sha3_512(plain_text)
    elif digest_algo == "sha512":
        message_digest = Common.sha_512(plain_text)

    signer = PKCS1_v1_5.new(senders_pub_key)

    return [signer.verify(message_digest, signature), plain_text]


def decrypt_email_COAI(cipher_text_file, sender, receiver, digest_algo, encrypt_algo):
    digest_plain_text = decrypt_email_CONF(
        cipher_text_file, receiver, encrypt_algo)

    with open('temp', 'w') as fo:
        fo.write(digest_plain_text)

    return decrypt_email_AUIN("temp", sender, digest_algo)


# ReadMail SecType Sender Receiver SecureInputFile PlainTextOutputFile DigestAlg EncryAlg
number_of_args = len(sys.argv)
if number_of_args != 9:
    print("Usage: ReadMail.py <SecType> <Sender> <Receiver> <SecureInputFile> <PlainTextOutputFile> <DigestAlg> <EncryptAlg> <RSA-KeySize| 2048 | 1024>")
    print("Example: python ReadMail.py COAI user1 user2 cipher_txt plain_text.txt  sha512  aes-256-cbc 1024")
    exit(1)
else:
    sec_type = sys.argv[1]
    sender = sys.argv[2]
    receiver = sys.argv[3]
    cipher_text_file = sys.argv[4]
    plain_text_file = sys.argv[5]
    digest_algo = sys.argv[6]
    encrypt_algo = sys.argv[7]
    rsa_key_size = sys.argv[8]

    if sec_type == "CONF":
        plain_text = decrypt_email_CONF(
            cipher_text_file, receiver, encrypt_algo)
        with open(plain_text_file, 'w') as fo:
            fo.write(plain_text)
        

    elif sec_type == "AUIN":
        a = decrypt_email_AUIN(cipher_text_file, sender, digest_algo)
        with open(plain_text_file, 'w') as fo:
            fo.write(a[1].decode("utf-8"))
        print ("Authentication/Integrity: Pass" if a[0] == True else "Authentication/Integrity: Fail")
 
    elif sec_type == "COAI":
        a = decrypt_email_COAI(cipher_text_file, sender,
                               receiver, digest_algo, encrypt_algo)
        remove("temp")
        with open(plain_text_file, 'w') as fo:
            fo.write(a[1].decode("utf-8"))
        print ("Authentication/Integrity: Pass" if a[0] == True else "Authentication/Integrity: Fail")

    else:
        print("Please Enter a valid sec_type")
        print("Example: python ReadMail.py COAI user1 user2 cipher_txt plain_text.txt  sha512  aes-256-cbc 1024")
        exit(1)
