"""
Yashigani Identity — API key generation, hashing, and verification.

Keys are 256-bit hex strings (64 chars). Hashed with bcrypt cost 12.
Max lifetime 1 year, default rotation 90 days, 7-day grace period.
"""
from __future__ import annotations

import datetime
import logging
import secrets

import bcrypt

logger = logging.getLogger(__name__)

_BCRYPT_COST = 12
_KEY_BYTES = 32  # 256-bit

# Rotation policy defaults
DEFAULT_ROTATION_DAYS = 90
MAX_LIFETIME_DAYS = 365
GRACE_PERIOD_DAYS = 7
WARN_BEFORE_EXPIRY_DAYS = 14
ADMIN_WARN_BEFORE_EXPIRY_DAYS = 7


def generate_api_key() -> str:
    """Generate a 256-bit hex API key (64 chars)."""
    return secrets.token_bytes(_KEY_BYTES).hex()


def hash_api_key(plaintext: str) -> str:
    """Hash an API key with bcrypt cost 12."""
    return bcrypt.hashpw(
        plaintext.encode("utf-8"),
        bcrypt.gensalt(rounds=_BCRYPT_COST),
    ).decode("utf-8")


def verify_api_key(plaintext: str, hashed: str) -> bool:
    """
    Verify a plaintext API key against a bcrypt hash. Fail-closed.
    bcrypt.checkpw uses constant-time comparison internally (ASVS 11.2.4).
    """
    try:
        return bcrypt.checkpw(
            plaintext.encode("utf-8"),
            hashed.encode("utf-8") if isinstance(hashed, str) else hashed,
        )
    except Exception as exc:
        logger.error("API key verification error: %s", exc)
        return False


def is_expired(expires_at: datetime.datetime | None) -> bool:
    """Check if an API key has exceeded its max lifetime."""
    if expires_at is None:
        return False
    return datetime.datetime.now(tz=datetime.timezone.utc) > expires_at


def needs_rotation(rotated_at: datetime.datetime | None, rotation_days: int = DEFAULT_ROTATION_DAYS) -> bool:
    """Check if an API key should be rotated based on age."""
    if rotated_at is None:
        return True
    age = datetime.datetime.now(tz=datetime.timezone.utc) - rotated_at
    return age.days >= rotation_days


def expiry_from_now(days: int = MAX_LIFETIME_DAYS) -> datetime.datetime:
    """Calculate expiry timestamp from now."""
    return datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=days)
