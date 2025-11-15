import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_message(key, plaintext):
    nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce + ciphertext  # Send nonce with ciphertext

def decrypt_message(key, encrypted_data):
    nonce, ciphertext = encrypted_data[:12], encrypted_data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()
