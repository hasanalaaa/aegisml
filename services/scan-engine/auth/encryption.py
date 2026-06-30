import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Derive a Fernet key from the SECRET_KEY so we don't need a separate ENCRYPTION_KEY env var
def get_fernet() -> Fernet:
    secret = os.getenv("SECRET_KEY", "fallback-secret-for-development-only").encode()
    # Simple static salt for deriving the fernet key (must be consistent)
    salt = b"aegisml_static_salt_1234"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(secret))
    return Fernet(key)

fernet = get_fernet()

def encrypt_key(api_key: str) -> str:
    return fernet.encrypt(api_key.encode()).decode()

def decrypt_key(encrypted_key: str) -> str:
    return fernet.decrypt(encrypted_key.encode()).decode()
