from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import os
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# This module converts binary data to hexadecimal
from binascii import hexlify

KEYS = {}  # Store generated keys in memory

def generate_key(key_type: str, key_size: int):
    """Generates AES or RSA keys"""
    if key_type.upper() == "AES":
        key = os.urandom(key_size // 8)  # Generate random AES key
        key_id = str(len(KEYS) + 1)
        KEYS[key_id] = key
        return {"key_id": key_id, "key_value": base64.b64encode(key).decode()}
    
    elif key_type.upper() == "RSA":
        key = RSA.generate(key_size)
        private_key = key
        public_key = key.publickey()
        
        # Export the private key in PEM format
        private_key_pem = private_key.export_key()
        # Export the public key in PEM format
        public_key_pem = public_key.export_key()
        
        key_id = str(len(KEYS) + 1)
        
        # Store only the private key and public key as base64-encoded strings in memory
        KEYS[key_id] = {
            "private_key": base64.b64encode(private_key_pem).decode(),
            "public_key": base64.b64encode(public_key_pem).decode()
        }
        
        return {
            "key_id": key_id,  # Return only the key_id, not the private key itself
            "key_value": base64.b64encode(public_key_pem).decode()  # Only return the public key
        }
    
    return {"error": "Unsupported key type"}


def encrypt_data(key_id: str, plaintext: str):
    """Encrypts data using AES or RSA based on the key type"""
    key = KEYS.get(key_id)
    if not key:
        return {"error": "Invalid key ID"}
    
    # Check if the key is AES (bytes) or RSA (private key object)
    if isinstance(key, bytes):  # AES key
        iv = os.urandom(16)  # AES requires a random IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Padding to 16 bytes
        plaintext_bytes = plaintext.encode()
        pad_len = 16 - (len(plaintext_bytes) % 16)
        padded_plaintext = plaintext_bytes + bytes([pad_len] * pad_len)

        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return {"ciphertext": base64.b64encode(iv + ciphertext).decode()}

    elif isinstance(key, dict) and "public_key" in key:  # RSA key (stored in dict)
        public_key_pem = base64.b64decode(key["public_key"])  # Decode PEM
        public_key = RSA.import_key(public_key_pem)

        # Encrypt with PKCS1_OAEP
        cipher_rsa = PKCS1_OAEP.new(public_key)
        ciphertext = cipher_rsa.encrypt(plaintext.encode())

        return {"ciphertext": base64.b64encode(ciphertext).decode()}

    return {"error": "Unsupported key type"}


def decrypt_data(key_id: str, ciphertext: str):
    """Decrypts data using AES or RSA based on the key type"""
    key = KEYS.get(key_id)
    if not key:
        return {"error": "Invalid key ID"}
    
    # Check if the key is AES (bytes) or RSA (private key object)
    if isinstance(key, bytes):  # AES key
        decoded_cipher = base64.b64decode(ciphertext)
        iv, encrypted_text = decoded_cipher[:16], decoded_cipher[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(encrypted_text) + decryptor.finalize()
        
        # Remove padding
        pad_len = padded_plaintext[-1]
        plaintext = padded_plaintext[:-pad_len]
        
        return {"plaintext": plaintext.decode()}
    
    elif isinstance(key, dict) and "private_key" in key:  # RSA key
        private_key_pem = base64.b64decode(key["private_key"])
        private_key = RSA.import_key(private_key_pem)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted = cipher_rsa.decrypt(base64.b64decode(ciphertext))
        return {"plaintext": decrypted.decode()}  # no extra return statement here


        return {"error": "Unsupported key type"}


def generate_hash(data: str, algorithm: str):
    """Generates a hash of the given data"""
    if algorithm.upper() == "SHA-256":
        digest = hashes.Hash(hashes.SHA256())
    elif algorithm.upper() == "SHA-512":
        digest = hashes.Hash(hashes.SHA512())
    else:
        return {"error": "Unsupported hashing algorithm"}
    
    digest.update(data.encode())
    hash_value = base64.b64encode(digest.finalize()).decode()
    return {"hash_value": hash_value, "algorithm": algorithm}


def verify_hash(data: str, hash_value: str, algorithm: str):
    """Verifies if the hash matches the data"""
    new_hash = generate_hash(data, algorithm)["hash_value"]
    return {"is_valid": new_hash == hash_value, "message": "Hash matches the data." if new_hash == hash_value else "Hash mismatch."}  
