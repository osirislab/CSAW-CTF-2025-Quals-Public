import time
import hmac
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad
import secrets
from random import uniform

def obfuscate_hmac(min_ms=250, max_ms=1000):
    delay_seconds = uniform(min_ms, max_ms) / 1000
    time.sleep(delay_seconds)

def encrypt_cbc(plaintext, key):
    iv = bytes.fromhex(secrets.token_hex(16))
    
    cipher = AES.new(key, AES.MODE_CBC, iv)

    encrypted = iv + cipher.encrypt(pad(plaintext, AES.block_size))

    h = HMAC.new(key, digestmod=SHA256)
    h.update(encrypted)
    mac = h.digest()
    
    return mac + encrypted

def decrypt_cbc(ciphertext, key):
    ciphertext = bytes.fromhex(ciphertext)
    
    ciph_mac = ciphertext[:32]
    ciph_ciph = ciphertext[32:]
    iv = ciph_ciph[:AES.block_size]
    ciph = ciph_ciph[AES.block_size:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        unpadded = unpad(cipher.decrypt(ciph), AES.block_size)
    except Exception as e:
        raise Exception("Incorrect padding.")

    if len(ciphertext) != 96:
        print(len(ciphertext))
        raise Exception("Incorrect length")
    
    obfuscate_hmac()

    h = HMAC.new(key, digestmod=SHA256)
    h.update(ciph_ciph)
    if ciph_mac != h.digest():
        raise Exception("MAC verification failed.")
    else:
        return unpadded
    
