from fastapi import FastAPI
from pydantic import BaseModel
import crypto_utils

app = FastAPI()

class KeyRequest(BaseModel):
    key_type: str
    key_size: int

class EncryptRequest(BaseModel):
    key_id: str
    plaintext: str

class DecryptRequest(BaseModel):
    key_id: str
    ciphertext: str

class HashRequest(BaseModel):
    data: str
    algorithm: str

class VerifyHashRequest(BaseModel):
    data: str
    hash_value: str
    algorithm: str

@app.post("/generate-key")
def generate_key(request: KeyRequest):
    return crypto_utils.generate_key(request.key_type, request.key_size)

@app.post("/encrypt")
def encrypt(request: EncryptRequest):
    return crypto_utils.encrypt_data(request.key_id, request.plaintext)

@app.post("/decrypt")
def decrypt(request: DecryptRequest):
    return crypto_utils.decrypt_data(request.key_id, request.ciphertext)

@app.post("/generate-hash")
def generate_hash(request: HashRequest):
    return crypto_utils.generate_hash(request.data, request.algorithm)

@app.post("/verify-hash")
def verify_hash(request: VerifyHashRequest):
    return crypto_utils.verify_hash(request.data, request.hash_value, request.algorithm)
