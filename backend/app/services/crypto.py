"""Simple encryption for API keys at rest using Fernet symmetric encryption."""
import base64
import hashlib
from cryptography.fernet import Fernet
from ..config import settings


def _get_key() -> bytes:
    key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    return base64.urlsafe_b64encode(key)


def encrypt_value(plaintext: str) -> str:
    if not plaintext:
        return ""
    f = Fernet(_get_key())
    return f.encrypt(plaintext.encode()).decode()


def decrypt_value(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    f = Fernet(_get_key())
    return f.decrypt(ciphertext.encode()).decode()
