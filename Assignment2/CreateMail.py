import sys
from os import path, remove
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512
from Crypto.Hash import SHA3_512
from Crypto.Signature import PKCS1_v1_5
from base64 import b64encode, b64decode
from Crypto.Cipher import DES3
import Common


def encrypt_email_COAI(plain_text_file, sender, receiver, digest_algo, encrypt_algo):
    message_digest, _ = encrypt_email_AUIN(
        plain_text_file, sender, digest_algo)

    with open("temp", "w") as fo:
        fo.write(message_digest.decode("utf-8") + "\n" + _.decode("utf-8"))

    enc_session_key, cipher_text = encrypt_email_CONF(
        "temp", receiver, encrypt_algo)
    
    remove("temp")
    return [enc_session_key, cipher_text]


def encrypt_email_AUIN(plain_text_file, sender, digest_algo):
    with open(plain_text_file, 'rb') as f:
        plain_text = f.read()

    senders_priv_key = RSA.import_key(
        open(f"keys/{sender}_priv.PEM", "rb").read())

    if digest_algo == "sha3-512":
        message_digest = Common.sha3_512(plain_text)
    elif digest_algo == "sha512":
        message_digest = Common.sha_512(plain_text)

    signer = PKCS1_v1_5.new(senders_priv_key)
    message_digest = b64encode(signer.sign(message_digest))
    return [message_digest, plain_text]



def encrypt_email_CONF(plain_text_file, receiver, encrypt_algo):
    with open(plain_text_file, 'rb') as f:
        plain_text = f.read()

    if encrypt_algo == "aes-256-cbc":
        session_key = get_random_bytes(32)
        cipher_text = Common.AES_encrypt(plain_text, session_key)
    elif encrypt_algo == "des-ede3-cbc":
        session_key = DES3.adjust_key_parity(get_random_bytes(24))
        cipher_text = Common.DES3_encrypt(plain_text, session_key)

    recipient_pub_key = RSA.import_key(
        open(f"keys/{receiver}_pub.PEM", "rb").read())
    cipher_rsa = PKCS1_OAEP.new(recipient_pub_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    return [enc_session_key, cipher_text]

    # return enc_session_key + cipher_text


number_of_args = len(sys.argv)
if number_of_args != 9:
    print("Usage: CreateKeys.py <SecType> <Sender> <Receiver> <PlainTextFile> <CipherTextFile> <DigestAlg|NA> <EncryptAlg> <RSA-KeySize| 2048 | 1024>")
    print("Example: python CreateMail.py COAI user1 user2 plain.txt cipher sha512  aes-256-cbc 1024")
    exit(1)
else:
    sec_type = sys.argv[1]
    sender = sys.argv[2]
    receiver = sys.argv[3]
    plain_text_file = sys.argv[4]
    cipher_text_file = sys.argv[5]
    digest_algo = sys.argv[6]
    encrypt_algo = sys.argv[7]
    rsa_key_size = sys.argv[8]

    if sec_type == "CONF":
        enc_session_key, cipher_text = encrypt_email_CONF(
            plain_text_file, receiver, encrypt_algo)
        with open(cipher_text_file, 'wb') as fo:
            fo.write(enc_session_key)
            fo.write(cipher_text)

    elif sec_type == "AUIN":
        message_digest, plain_text = encrypt_email_AUIN(
            plain_text_file, sender, digest_algo)
        with open(cipher_text_file, 'w') as fo:
            fo.write(message_digest.decode("utf-8") +
                     "\n"+plain_text.decode("utf-8"))

    elif sec_type == "COAI":
        enc_session_key, cipher_text = encrypt_email_COAI(
            plain_text_file, sender, receiver, digest_algo, encrypt_algo)
        with open(cipher_text_file, 'wb') as fo:
            fo.write(enc_session_key)
            fo.write(cipher_text)
            

    else:
        print("Please Enter a valid sec_type")
        print("Example: python CreateMail.py COAI user1 user2 plain.txt cipher sha512  aes-256-cbc 1024")
        exit(1)

    
