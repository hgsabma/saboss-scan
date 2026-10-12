"""Password hashing and secure tokens.

- Passwords: Argon2id via argon2-cffi (the algorithm recommended by OWASP).
- Session, reset and API tokens: 256-bit random values from the OS
  (secrets module). Only their SHA-256 hash is stored, so a database leak
  does not reveal usable tokens.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

MIN_PASSWORD_LENGTH = 10
MAX_PASSWORD_LENGTH = 128
API_KEY_PREFIX = "sbk_"

_hasher = PasswordHasher()
# Used to spend the same time when an e-mail address does not exist, so
# response timing does not reveal which accounts exist.
_DUMMY_HASH = _hasher.hash("saboss-dummy-password-for-timing")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def password_problem(password: str, email: str = "") -> str | None:
    """Return a message if the password is not acceptable, else None."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Use at least {MIN_PASSWORD_LENGTH} characters."
    if len(password) > MAX_PASSWORD_LENGTH:
        return f"Use at most {MAX_PASSWORD_LENGTH} characters."
    if email and password.strip().lower() == email.strip().lower():
        return "The password must not be your e-mail address."
    if len(set(password)) < 4:
        return "The password is too simple."
    return None


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_api_key() -> str:
    return API_KEY_PREFIX + secrets.token_urlsafe(32)


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
