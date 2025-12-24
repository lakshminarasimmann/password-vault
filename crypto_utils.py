import os
import json
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

SALT_SIZE = 16
ITERATIONS = 300_000

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_vault(password: str, data: dict) -> bytes:
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    f = Fernet(key)
    return salt + f.encrypt(json.dumps(data).encode())

def decrypt_vault(password: str, blob: bytes) -> dict:
    salt = blob[:SALT_SIZE]
    encrypted = blob[SALT_SIZE:]
    key = derive_key(password, salt)
    f = Fernet(key)
    return json.loads(f.decrypt(encrypted).decode())
