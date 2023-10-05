from Crypto.Hash import MD5
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def pad(s):
    '''
        plain_text : bytes
        return type : byte
    '''
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)


def get_key (message):
    '''
        plain_text : bytes
        return type : byte
    '''
    hash = MD5.new()
    hash.update(message)
    return hash.digest()

def AES_encrypt(plain_text, key):
    '''
        plain_text : bytes
        key         : bytes
        return type : byte
    '''
    plain_text = pad(plain_text)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    cipher_text = cipher.encrypt(plain_text)
    return iv + cipher_text


def AES_decrypt(cipher_text, key):
    '''
        cipher_text : bytes
        key         : bytes
        return type : byte
    '''
    iv = cipher_text[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plain_text = cipher.decrypt(cipher_text[AES.block_size:])
    return plain_text.rstrip(b"\0")

def AES_decrypt_ASCII(cipher_text, key):
    '''
        cipher_text : bytes
        key         : bytes
        return type : ASCII
    '''
    return AES_decrypt(cipher_text, key).decode('utf-8')