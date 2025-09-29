# config.py
from cryptography.fernet import Fernet
import base64
from datetime import timedelta

SECRET_KEY = "a1b2c3d4e5f6789012345678901234567890abcdef123456789012345678901234"
REMEMBER_COOKIE_DURATION = timedelta(days=15)
