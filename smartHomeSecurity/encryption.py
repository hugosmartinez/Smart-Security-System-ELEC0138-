from hashlib import pbkdf2_hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from io import BytesIO
from bcrypt import gensalt

def encryptFile(inputFile, encryptionKey):
    plaintext = inputFile.read()
    
    # Generate a random initialization vector (IV)
    iv = os.urandom(16)

    # Create cipher and encryptor objects
    cipher = Cipher(algorithms.AES(encryptionKey), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the plaintext
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    encryptedData = iv + ciphertext

    return BytesIO(encryptedData)

def decryptFile(inputFile, encryptionKey):
    # Read the IV and ciphertext from the input file object
    iv = inputFile.read(16)  # IV size is 16 bytes
    ciphertext = inputFile.read()

    # Create cipher and decryptor objects
    cipher = Cipher(algorithms.AES(encryptionKey), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Return a file-like object containing the decrypted data
    return BytesIO(plaintext)

#Using PBKDF2, we can take the user password and their previously generated 
#random salt to create the encryption key that we will use
def generateEncryptionKey(password, salt, iterations=100000, keyLength=32):
    passwordBytes = password.encode('utf-8')

    # Generate encryption key using PBKDF2
    encryptionKey = pbkdf2_hmac('sha256', passwordBytes, salt, iterations, keyLength)

    print(len(encryptionKey.hex()))
    return encryptionKey