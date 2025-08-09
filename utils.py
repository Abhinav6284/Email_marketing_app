# utils.py
from cryptography.fernet import Fernet
import base64

# This key MUST be kept secret and consistent.
ENCRYPTION_KEY = base64.urlsafe_b64encode(b'5dC\xa5\x14yTD\xdb\x9b\x04\x01\x17f\xfeI/u\xd3\xb9\xd0W\xebM\xfe\xfe3\xa5\x18\x02\xc1\xcc') # Use a secure, persistent key

def encrypt_password(password: str) -> str:
    """Encrypt password for secure storage"""
    if not password:
        return None
    f = Fernet(ENCRYPTION_KEY)
    return f.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password: str) -> str:
    """Decrypt password for use"""
    if not encrypted_password:
        return None
    f = Fernet(ENCRYPTION_KEY)
    return f.decrypt(encrypted_password.encode()).decode()