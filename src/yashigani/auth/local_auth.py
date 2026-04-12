"""
Yashigani Auth — Local authentication handler.
Covers admin and user accounts in YASHIGANI_AUTH_MODE=local.
OWASP ASVS V2.1, V2.4, V2.8, V3.2, V3.3, V5 (TOTP exponential backoff).

TOTP backoff schedule (v0.2.0, ASVS v5 V2 compensating control):
  1st failure → 1 s
  2nd failure → 2 s
  3rd failure → 4 s
  4th failure → 8 s
  5th failure → 1800 s (30-minute hard lockout, same as password lockout)
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from yashigani.auth.password import hash_password, verify_password, generate_password
from yashigani.auth.totp import (
    generate_provisioning,
    generate_recovery_code_set,
    verify_totp,
    verify_recovery_code,
    codes_remaining,
    TotpProvisioning,
    RecoveryCodeSet,
)

logger = logging.getLogger(__name__)

_MAX_FAILED_ATTEMPTS = 5
_LOCKOUT_SECONDS = 1800   # 30 minutes

# TOTP exponential backoff delays (seconds) indexed by failure count 1-4.
# 5th failure triggers the same hard lockout as password failures.
_TOTP_BACKOFF_SECONDS = [0, 1, 2, 4, 8]   # index = failure count (0 = unused)


@dataclass
class AccountRecord:
    account_id: str
    username: str
    password_hash: str
    totp_secret: str
    recovery_codes: Optional[RecoveryCodeSet]
    account_tier: str                       # "admin" | "user"
    email: Optional[str] = None             # explicit email; falls back to username@yashigani.local
    force_password_change: bool = True
    force_totp_provision: bool = True
    disabled: bool = False
    failed_attempts: int = 0
    locked_until: float = 0.0
    # TOTP-specific exponential backoff (independent of password lockout)
    totp_failed_attempts: int = 0
    totp_backoff_until: float = 0.0
    created_at: float = field(default_factory=time.time)
    password_changed_at: float = field(default_factory=time.time)


class LocalAuthService:
    """
    In-memory account store for local auth mode.
    Production deployments back this with a database — this implementation
    uses a dict as a starting point for testing and local dev.
    """

    def __init__(self, used_totp_codes: Optional[set] = None) -> None:
        self._accounts: dict[str, AccountRecord] = {}       # username → record
        self._used_totp_codes: set[str] = used_totp_codes or set()

    # -- Account lifecycle ---------------------------------------------------

    def create_admin(
        self,
        username: str,
        auto_generate: bool = True,
        plaintext_password: Optional[str] = None,
    ) -> tuple[AccountRecord, Optional[str]]:
        """
        Create an admin account.
        If auto_generate=True: generate a 36-char password, hash it,
        and return the plaintext once (caller prints to stdout).
        Returns (record, plaintext_password_or_None).
        """
        plaintext = plaintext_password or (generate_password(36) if auto_generate else None)
        if plaintext is None:
            raise ValueError("Must provide password or set auto_generate=True")

        record = AccountRecord(
            account_id=_new_id(),
            username=username,
            password_hash=hash_password(plaintext),
            totp_secret="",              # set at first login via provisioning
            recovery_codes=None,
            account_tier="admin",
            email=username,              # admin usernames are already emails
            force_password_change=True,
            force_totp_provision=True,
        )
        self._accounts[username] = record
        # Return plaintext only to caller — caller must print once and discard
        return record, plaintext if auto_generate else None

    def create_user(
        self,
        username: str,
        plaintext_password: str,
    ) -> AccountRecord:
        record = AccountRecord(
            account_id=_new_id(),
            username=username,
            password_hash=hash_password(plaintext_password),
            totp_secret="",
            recovery_codes=None,
            account_tier="user",
            force_password_change=True,
            force_totp_provision=True,
        )
        self._accounts[username] = record
        return record

    # -- Authentication ------------------------------------------------------

    def authenticate(
        self,
        username: str,
        password: str,
        totp_code: str,
    ) -> tuple[bool, Optional[AccountRecord], str]:
        """
        Verify username, password, and TOTP.
        Returns (success, record_or_None, failure_reason).
        """
        record = self._accounts.get(username)
        # Use same error message for unknown user, wrong password, locked account
        # to prevent username enumeration (ASVS V2.1)
        generic_fail = "invalid_credentials"

        if record is None or record.disabled:
            return False, None, generic_fail

        if _is_locked(record):
            return False, None, generic_fail

        if not verify_password(password, record.password_hash):
            record.failed_attempts += 1
            if record.failed_attempts >= _MAX_FAILED_ATTEMPTS:
                record.locked_until = time.time() + _LOCKOUT_SECONDS
                logger.warning("Account locked after %d failures: %s",
                               _MAX_FAILED_ATTEMPTS, username)
            return False, None, generic_fail

        # Password OK — check TOTP
        if record.force_totp_provision:
            # TOTP not yet provisioned — let caller handle provisioning flow
            record.failed_attempts = 0
            return True, record, "totp_provision_required"

        # Exponential backoff check — ASVS v5 V2 compensating control
        if record.totp_backoff_until > time.time():
            return False, None, generic_fail

        if not verify_totp(record.totp_secret, totp_code, self._used_totp_codes):
            record.totp_failed_attempts += 1
            n = record.totp_failed_attempts
            if n >= _MAX_FAILED_ATTEMPTS:
                # 5th failure → hard lockout (same as password lockout)
                record.locked_until = time.time() + _LOCKOUT_SECONDS
                record.totp_failed_attempts = 0
                record.totp_backoff_until = 0.0
                logger.warning(
                    "Account locked after %d TOTP failures: %s",
                    _MAX_FAILED_ATTEMPTS, username,
                )
            else:
                delay = _TOTP_BACKOFF_SECONDS[min(n, len(_TOTP_BACKOFF_SECONDS) - 1)]
                record.totp_backoff_until = time.time() + delay
                logger.info(
                    "TOTP backoff applied: %ds for %s (attempt %d)",
                    delay, username, n,
                )
            return False, None, generic_fail

        # Full success — clear all failure counters
        record.failed_attempts = 0
        record.totp_failed_attempts = 0
        record.totp_backoff_until = 0.0
        return True, record, "ok"

    # -- TOTP provisioning ---------------------------------------------------

    def provision_totp(
        self, username: str
    ) -> tuple[TotpProvisioning, RecoveryCodeSet]:
        """
        Generate and store TOTP seed + recovery codes for an account.
        Returns provisioning data for one-time display.
        """
        record = self._accounts[username]
        prov = generate_provisioning(account_name=username)
        code_set = generate_recovery_code_set(prov.recovery_codes)

        record.totp_secret = prov.secret_b32
        record.recovery_codes = code_set
        record.force_totp_provision = False
        # secret_b32 is stored in the record for TOTP verification
        # — in production this would be encrypted at rest via KSM
        return prov, code_set

    # -- Password change -----------------------------------------------------

    def change_password(
        self,
        username: str,
        current_password: str,
        totp_code: str,
        new_password: str,
    ) -> tuple[bool, str]:
        """
        Self-service password change. All sessions must be invalidated by caller.
        Returns (success, reason).
        """
        record = self._accounts.get(username)
        if record is None:
            return False, "invalid_credentials"

        if not verify_password(current_password, record.password_hash):
            return False, "invalid_credentials"

        if not verify_totp(record.totp_secret, totp_code, self._used_totp_codes):
            return False, "invalid_totp"

        record.password_hash = hash_password(new_password)
        record.force_password_change = False
        return True, "ok"

    # -- Admin actions -------------------------------------------------------

    def full_reset_user(
        self,
        username: str,
        admin_totp_secret: str,
        admin_totp_code: str,
    ) -> tuple[bool, str]:
        """
        Admin full-reset a user account (strips all access).
        Requires admin's TOTP re-verification (ASVS V2.8).
        """
        if not verify_totp(admin_totp_secret, admin_totp_code, self._used_totp_codes):
            return False, "invalid_admin_totp"

        record = self._accounts.get(username)
        if record is None:
            return False, "user_not_found"

        # Strip all access
        record.totp_secret = ""
        record.recovery_codes = None
        record.force_password_change = True
        record.force_totp_provision = True
        record.failed_attempts = 0
        record.locked_until = 0.0
        # Password is reset by generating a new temporary one
        temp_password = generate_password(36)
        record.password_hash = hash_password(temp_password)

        return True, "ok"

    def disable(self, username: str) -> bool:
        record = self._accounts.get(username)
        if record:
            record.disabled = True
            return True
        return False

    def enable(self, username: str) -> bool:
        record = self._accounts.get(username)
        if record:
            record.disabled = False
            return True
        return False

    def active_admin_count(self) -> int:
        return sum(
            1 for r in self._accounts.values()
            if r.account_tier == "admin" and not r.disabled
        )

    def total_admin_count(self) -> int:
        return sum(
            1 for r in self._accounts.values()
            if r.account_tier == "admin"
        )

    def total_user_count(self) -> int:
        return sum(
            1 for r in self._accounts.values()
            if r.account_tier == "user"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_locked(record: AccountRecord) -> bool:
    return record.locked_until > time.time()


def _new_id() -> str:
    import uuid
    return str(uuid.uuid4())
