import os
import logging
from cryptography.fernet import Fernet

logger = logging.getLogger("aegisml.crypto")

_ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
_fernet = None

if _ENCRYPTION_KEY:
    try:
        _fernet = Fernet(_ENCRYPTION_KEY.encode("utf-8"))
    except Exception as e:
        logger.error(f"Failed to initialize Fernet: {e}")
else:
    logger.warning("ENCRYPTION_KEY is not set. API Keys cannot be securely encrypted/decrypted.")

def encrypt_key(plain_key: str) -> str:
    """Encrypt a plaintext API key."""
    if not _fernet:
        raise ValueError("Encryption system is not initialized properly (Missing ENCRYPTION_KEY).")
    return _fernet.encrypt(plain_key.encode("utf-8")).decode("utf-8")

def decrypt_key(encrypted_key: str) -> str:
    """Decrypt an encrypted API key back to plaintext."""
    if not _fernet:
        raise ValueError("Encryption system is not initialized properly (Missing ENCRYPTION_KEY).")
    return _fernet.decrypt(encrypted_key.encode("utf-8")).decode("utf-8")
