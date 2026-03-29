"""
Yashigani Auth — Argon2id password hashing.
OWASP ASVS V2.4: m=65536, t=3, p=4 minimum parameters.
"""
from __future__ import annotations

import secrets
import string

_MIN_PASSWORD_LENGTH = 36
_AUTO_PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"


def _import_argon2():
    try:
        from argon2 import PasswordHasher
        from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
        return PasswordHasher, VerifyMismatchError, VerificationError, InvalidHashError
    except ImportError as exc:
        raise ImportError(
            "argon2-cffi is required. Install with: pip install argon2-cffi"
        ) from exc


def _hasher():
    PasswordHasher, *_ = _import_argon2()
    return PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        salt_len=16,
    )


def hash_password(password: str) -> str:
    """Return Argon2id hash of password. Never log the input."""
    if len(password) < _MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"Password must be at least {_MIN_PASSWORD_LENGTH} characters"
        )
    return _hasher().hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    """Return True if password matches hash. Never raise on mismatch."""
    _, VerifyMismatchError, VerificationError, InvalidHashError = _import_argon2()
    try:
        return _hasher().verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """Return True if the hash parameters are outdated and should be upgraded."""
    try:
        return _hasher().check_needs_rehash(stored_hash)
    except Exception:
        return False


def generate_password(length: int = 36) -> str:
    """
    Generate a cryptographically random password of the given length.
    Displayed once to stdout at deployment — never stored in plaintext.
    """
    if length < _MIN_PASSWORD_LENGTH:
        raise ValueError(f"Generated password must be at least {_MIN_PASSWORD_LENGTH} chars")
    return "".join(secrets.choice(_AUTO_PASSWORD_ALPHABET) for _ in range(length))
