import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet

from .config import get_settings

settings = get_settings()
_hasher = PasswordHasher()
_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    """Lazily build the Fernet instance so startup validation runs first."""
    global _fernet
    if _fernet is None:
        _fernet = Fernet(settings.effective_fernet_key().encode())
    return _fernet


# --- Passwords (Argon2id) ---------------------------------------------------

def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


# --- JWT access tokens ------------------------------------------------------
# Note: no role claim — the database is the single source of truth for roles.

def create_access_token(user_id: int) -> tuple[str, int]:
    expires = timedelta(minutes=settings.access_token_expire_minutes)
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "type": "access",
        "iat": now,
        "exp": now + expires,
    }
    return jwt.encode(payload, settings.effective_secret_key(), algorithm="HS256"), settings.access_token_expire_minutes * 60


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, settings.effective_secret_key(), algorithms=["HS256"])


# --- Refresh tokens (opaque, stored hashed) ----------------------------------

def generate_refresh_token() -> tuple[str, str]:
    token = secrets.token_urlsafe(48)
    return token, hash_token(token)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def refresh_expiry() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=settings.refresh_token_expire_days)


# --- Fernet for stored secrets (TSIG keys) -----------------------------------

def encrypt_secret(value: str) -> str:
    return _get_fernet().encrypt(value.encode()).decode()


def decrypt_secret(value: str) -> str:
    return _get_fernet().decrypt(value.encode()).decode()