"""Yashigani Auth — local auth, TOTP, session management, SPIFFE gate."""
# Last updated: 2026-04-23T23:32:19+01:00
from yashigani.auth.password import hash_password, verify_password, generate_password
from yashigani.auth.totp import (
    generate_provisioning, generate_recovery_code_set,
    verify_totp, verify_recovery_code, codes_remaining,
    TotpProvisioning, RecoveryCodeSet,
)
from yashigani.auth.session import SessionStore, Session
from yashigani.auth.local_auth import LocalAuthService, AccountRecord
from yashigani.auth.spiffe import require_spiffe_id

__all__ = [
    "hash_password", "verify_password", "generate_password",
    "generate_provisioning", "generate_recovery_code_set",
    "verify_totp", "verify_recovery_code", "codes_remaining",
    "TotpProvisioning", "RecoveryCodeSet",
    "SessionStore", "Session",
    "LocalAuthService", "AccountRecord",
    "require_spiffe_id",
]
