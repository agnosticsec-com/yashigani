"""
Yashigani Auth — Argon2id password hashing + HIBP breach check.
OWASP ASVS V2.4: m=65536, t=3, p=4 minimum parameters.
OWASP ASVS V2.1.7: Passwords must be checked against breach databases.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import string
from typing import Optional

logger = logging.getLogger(__name__)

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


def hash_password(password: str, *, check_breach: bool = True) -> str:
    """
    Return Argon2id hash of password. Never log the input.

    Args:
        password: Plaintext password (min 36 chars).
        check_breach: If True (default), checks password against HIBP
            breach database before hashing. Raises PasswordBreachedError
            if the password has been compromised. Set to False for
            bootstrap/migration paths where the check was already done.

    Raises:
        ValueError: Password too short.
        PasswordBreachedError: Password found in breach database.
    """
    if len(password) < _MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"Password must be at least {_MIN_PASSWORD_LENGTH} characters"
        )
    if check_breach:
        validate_password_not_breached(password)
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


# =========================================================================
# HIBP (Have I Been Pwned) k-Anonymity breach check
# =========================================================================
# OWASP ASVS V2.1.7: "Verify that passwords submitted during account
# registration, login, and password change are checked against a set of
# breached passwords."
#
# Protocol: SHA-1 hash the password, send the first 5 characters to the
# HIBP Passwords API, receive all matching suffixes, check locally.
# The actual password NEVER leaves the system.
#
# See: https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange
# =========================================================================

_HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
_HIBP_TIMEOUT = 5  # seconds


class PasswordBreachedError(ValueError):
    """Raised when a password is found in the HIBP breach database."""

    def __init__(self, breach_count: int):
        self.breach_count = breach_count
        super().__init__(
            f"This password has appeared in {breach_count:,} data breach(es). "
            "Choose a different password."
        )


def check_hibp(password: str) -> Optional[int]:
    """
    Check a password against the HIBP Passwords API using k-Anonymity.

    Returns:
        None if the password is clean (not found in any breach).
        int (breach count) if the password has been compromised.

    The password is NEVER transmitted. Only the first 5 characters of its
    SHA-1 hash are sent to the API. All matching is done locally.

    Returns None (clean) if the API is unreachable (fail-open — never
    blocks authentication due to a third-party API outage).
    """
    try:
        import httpx
    except ImportError:
        try:
            import urllib.request
            return _check_hibp_urllib(password)
        except Exception:
            logger.debug("HIBP check skipped — no HTTP client available")
            return None

    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    try:
        response = httpx.get(
            f"{_HIBP_API_URL}{prefix}",
            timeout=_HIBP_TIMEOUT,
            headers={"User-Agent": "Yashigani-PasswordCheck/1.0"},
        )
        response.raise_for_status()
    except Exception:
        logger.debug("HIBP API unreachable — skipping breach check (fail-open)")
        return None

    for line in response.text.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0].upper() == suffix:
            return int(parts[1])

    return None


def _check_hibp_urllib(password: str) -> Optional[int]:
    """Fallback HIBP check using stdlib urllib (no httpx dependency)."""
    import urllib.request
    import urllib.error

    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    req = urllib.request.Request(
        f"{_HIBP_API_URL}{prefix}",
        headers={"User-Agent": "Yashigani-PasswordCheck/1.0"},
    )

    try:
        with urllib.request.urlopen(req, timeout=_HIBP_TIMEOUT) as resp:
            body = resp.read().decode("utf-8")
    except (urllib.error.URLError, OSError):
        logger.debug("HIBP API unreachable (urllib) — skipping breach check")
        return None

    for line in body.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0].upper() == suffix:
            return int(parts[1])

    return None


def validate_password_not_breached(password: str, *, raise_on_breach: bool = True) -> Optional[int]:
    """
    Check a password against HIBP and optionally raise PasswordBreachedError.

    Args:
        password: The plaintext password to check.
        raise_on_breach: If True (default), raises PasswordBreachedError when
            the password is found in a breach. If False, returns the breach
            count silently.

    Returns:
        None if clean, int (breach count) if compromised and raise_on_breach=False.

    Raises:
        PasswordBreachedError if the password is compromised and raise_on_breach=True.
    """
    breach_count = check_hibp(password)
    if breach_count is not None and breach_count > 0:
        logger.warning(
            "Password rejected — found in %d HIBP breach(es)", breach_count
        )
        if raise_on_breach:
            raise PasswordBreachedError(breach_count)
    return breach_count
