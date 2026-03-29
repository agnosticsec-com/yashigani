"""
Yashigani Auth — TOTP (RFC 6238) + 8-code recovery system.
OWASP ASVS V2.8: per-account seeds, replay prevention, one-time display.
"""
from __future__ import annotations

import base64
import hashlib
import io
import secrets
import time
from dataclasses import dataclass
from typing import Optional


def _import_pyotp():
    try:
        import pyotp
        return pyotp
    except ImportError as exc:
        raise ImportError(
            "pyotp is required. Install with: pip install pyotp"
        ) from exc


def _import_qrcode():
    try:
        import qrcode
        return qrcode
    except ImportError as exc:
        raise ImportError(
            "qrcode is required. Install with: pip install qrcode[pil]"
        ) from exc


_RECOVERY_CODE_COUNT = 8
_RECOVERY_CODE_FORMAT = "{:04X}-{:04X}-{:04X}"  # XXXX-XXXX-XXXX


@dataclass
class TotpProvisioning:
    """Returned once at provisioning. Values shown once, never stored."""
    secret_b32: str             # base32 secret — display only, then discard
    provisioning_uri: str       # otpauth:// URI for QR code
    qr_code_png_b64: str        # base64-encoded PNG for browser display
    recovery_codes: list[str]   # 8 plaintext codes — display once


@dataclass
class RecoveryCodeSet:
    """Stored form of recovery codes (hashes only)."""
    hashes: list[str]           # Argon2id hash of each code
    used: list[bool]            # parallel list — True = already used


def generate_totp_secret() -> str:
    """Generate a cryptographically random base32 TOTP secret."""
    pyotp = _import_pyotp()
    return pyotp.random_base32()


def generate_provisioning(
    account_name: str,
    issuer: str = "Yashigani",
    existing_secret: Optional[str] = None,
) -> TotpProvisioning:
    """
    Generate TOTP provisioning data. Call once; display once.
    existing_secret allows re-provisioning with a forced new seed.
    """
    pyotp = _import_pyotp()
    secret = existing_secret or generate_totp_secret()
    totp = pyotp.TOTP(secret, issuer=issuer)
    uri = totp.provisioning_uri(name=account_name, issuer_name=issuer)

    qr_b64 = _generate_qr_b64(uri)
    codes = _generate_recovery_codes()

    return TotpProvisioning(
        secret_b32=secret,
        provisioning_uri=uri,
        qr_code_png_b64=qr_b64,
        recovery_codes=codes,
    )


def verify_totp(secret_b32: str, code: str, used_codes_cache: set[str]) -> bool:
    """
    Verify a TOTP code. Returns True on valid, unused code.
    Replay prevention: adds the window key to used_codes_cache on success.
    """
    pyotp = _import_pyotp()
    totp = pyotp.TOTP(secret_b32)
    window_key = f"{secret_b32}:{int(time.time()) // 30}"
    if window_key in used_codes_cache:
        return False  # replay
    valid = totp.verify(code, valid_window=1)
    if valid:
        used_codes_cache.add(window_key)
    return valid


def generate_recovery_code_set(plaintext_codes: list[str]) -> RecoveryCodeSet:
    """Hash recovery codes for storage. Plaintext is discarded after this call."""
    from yashigani.auth.password import _hasher
    hashes = [_hasher().hash(code) for code in plaintext_codes]
    return RecoveryCodeSet(hashes=hashes, used=[False] * len(hashes))


def verify_recovery_code(
    code: str,
    code_set: RecoveryCodeSet,
) -> tuple[bool, int]:
    """
    Verify a recovery code against the stored hash set.
    Returns (matched, index). If matched, caller must mark code_set.used[index]=True.
    """
    from yashigani.auth.password import verify_password
    for i, (h, used) in enumerate(zip(code_set.hashes, code_set.used)):
        if used:
            continue
        if verify_password(code, h):
            return True, i
    return False, -1


def codes_remaining(code_set: RecoveryCodeSet) -> int:
    return sum(1 for u in code_set.used if not u)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _generate_recovery_codes() -> list[str]:
    codes = []
    for _ in range(_RECOVERY_CODE_COUNT):
        a = secrets.randbits(16)
        b = secrets.randbits(16)
        c = secrets.randbits(16)
        codes.append(_RECOVERY_CODE_FORMAT.format(a, b, c))
    return codes


def _generate_qr_b64(uri: str) -> str:
    try:
        qrcode = _import_qrcode()
        qr = qrcode.QRCode(box_size=6, border=2)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode("ascii")
    except Exception:
        # QR generation is non-critical — return empty string if unavailable
        return ""
