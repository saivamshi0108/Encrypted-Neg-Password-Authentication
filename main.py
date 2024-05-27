import hashlib
import os
from cryptography.hazmat.primitives import padding,hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_key(password, salt=b'salt'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    print(type(key))
    return key

def getpasswords(password):
    salt = os.urandom(16)  # Generate a random salt
    key = generate_key(password, salt)
    hashed_password = hash_password(password)
    #negative_password = generate_negative_password(password)
    negative_password = generate_binary_negative_password(password)
    encrypted_password = encrypt_password(negative_password, key)
    decrypted_password = decrypt_password(encrypted_password, key)

    print("Hashed:", hashed_password.hex())
    print("Negative:", negative_password)
    print("Encrypted:", encrypted_password.hex())
    print("Decrypted:", decrypted_password.decode())  # Assuming the password is in string format
    print("Key:", key)

    return hashed_password, negative_password, encrypted_password

def hash_password(password):
    digest = hashlib.sha256()
    digest.update(password.encode())
    hashed_password = digest.digest()
    print(type(hashed_password))
    return hashed_password

def generate_negative_password(password):
    negative_password = ''.join(str(-ord(char)) for char in password)
    print(type(negative_password))
    return negative_password

def generate_binary_negative_password(password):
    negative_password = ''.join(str(-ord(char)) for char in password)
    binary_password = '*'.join(format(ord(char), '08b') for char in negative_password)
    return binary_password

def encrypt_password(password, key):
    # Initialize AES cipher in ECB mode
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_password = padder.update(password.encode()) + padder.finalize()
    encrypted_password = encryptor.update(padded_password) + encryptor.finalize()
    print(type(encrypted_password))
    return encrypted_password

def decrypt_password(encrypted_password, key):
    # Initialize AES cipher in ECB mode
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_password = unpadder.update(decrypted_password) + unpadder.finalize()
    return unpadded_password


getpasswords("demo1234")
