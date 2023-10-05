import sys
from os import path
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512
from Crypto.Hash import SHA3_512
from Crypto.Signature import PKCS1_v1_5
from base64 import b64encode, b64decode
from Crypto.Cipher import DES3

def RSA_encrypt(session_key, receiver):
    recipient_key = RSA.import_key(
        open(f"keys/{receiver}_pub.PEM", "rb").read())
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    return enc_session_key


def RSA_decrypt(enc_session_key, receiver):
    private_key = RSA.import_key(
        open(f"keys/{receiver}_priv.PEM", "rb").read())
    print(private_key.size_in_bytes())

    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    return session_key


def AES_encrypt(plain_text, key):
    plain_text = pad(plain_text)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    cipher_text = cipher.encrypt(plain_text)
    return iv + cipher_text


def AES_decrypt(cipher_text, key):
    iv = cipher_text[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plain_text = cipher.decrypt(cipher_text[AES.block_size:])
    return plain_text.rstrip(b"\0").decode("utf-8")


def DES3_encrypt(plain_text, key):
    iv = get_random_bytes(DES3.block_size)
    cipher = DES3.new(key, DES3.MODE_CFB, iv)
    # plaintext = b'We are no longer the knights who say ni!'
    cipher_text = cipher.iv + cipher.encrypt(plain_text)
    return cipher_text

def DES3_decrypt(cipher_text, key):
    iv = cipher_text[:DES3.block_size]
    cipher = DES3.new(key, DES3.MODE_CFB, iv) 
    plain_text = cipher.decrypt(cipher_text[DES3.block_size:])
    return plain_text.decode("utf-8")

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)


def sha_512(plain_text):
    digest = SHA512.new()
    digest.update(plain_text)
    return digest


def sha3_512(plain_text):
    digest = SHA3_512.new()
    digest.update(plain_text)
    return digest