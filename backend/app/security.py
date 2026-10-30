"""Security primitives: password hashing, opaque tokens, API keys, secret encryption."""
import base64
import hashlib
import hmac
import json
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings

# argon2-cffi's PasswordHasher defaults to Argon2id.
_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


# A real Argon2id hash verified when the account does not exist, so login timing does not reveal
# which emails are registered.
DUMMY_PASSWORD_HASH = hash_password(secrets.token_urlsafe(16))


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def generate_api_key() -> tuple[str, str, str]:
    """Return (full_key, prefix, key_hash). The full key is shown to the user once and never stored.

    API keys are 256-bit random values, so a fast SHA-256 hash is appropriate (no password-style
    stretching needed); the prefix is only a lookup handle.
    """
    prefix = "tiq_" + secrets.token_hex(4)
    secret = secrets.token_urlsafe(32)
    full = f"{prefix}_{secret}"
    return full, prefix, sha256_hex(full)


def split_api_key(full_key: str) -> str | None:
    """Return the lookup prefix of a presented key, or None if it is not shaped like one."""
    parts = full_key.split("_", 2)
    if len(parts) != 3 or parts[0] != "tiq" or not parts[1]:
        return None
    return f"{parts[0]}_{parts[1]}"


def _fernet() -> Fernet:
    digest = hashlib.sha256(get_settings().secret_key.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_json(data: dict) -> str:
    return _fernet().encrypt(json.dumps(data).encode("utf-8")).decode("utf-8")


def decrypt_json(token: str) -> dict:
    try:
        return json.loads(_fernet().decrypt(token.encode("utf-8")))
    except InvalidToken as exc:
        raise ValueError("Stored credentials cannot be decrypted with the current SECRET_KEY.") from exc
