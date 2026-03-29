"""
ECDSA P-256 / SHA-256 offline license verifier.

License file format (v3):
    {base64url(utf8(json_payload))}.{base64url(der_ecdsa_signature)}

Payload versions:
    v1 — max_agents, max_orgs only
    v2 — adds max_users (renamed to max_end_users in v3)
    v3 — max_agents, max_end_users, max_admin_seats, max_orgs (current)

Backwards compat: v1/v2 payloads missing new fields fall back to
TIER_DEFAULTS[tier] so existing customer license files keep working.

Fail-open on corrupt/unparseable licenses; fail-closed on invalid signatures.
"""
from __future__ import annotations

import base64
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from yashigani.licensing.model import (
    COMMUNITY_LICENSE,
    TIER_DEFAULTS,
    LicenseState,
    LicenseTier,
)

logger = logging.getLogger(__name__)

# ECDSA P-256 public key — generated 2026-03-28 with scripts/keygen.py
# Private key is stored in KMS. Do NOT commit the private key.
_PUBLIC_KEY_PEM = """\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9v3e5INc8Mr7yoN5rSsaJROahk58
HPYAxfkKlcJDVSH47HIERSL19ceu3JVS28uHRJw1WJ13JbUYI/vWAE1zNQ==
-----END PUBLIC KEY-----
"""

_PLACEHOLDER_MARKER = "PLACEHOLDER_YASHIGANI_PUBLIC_KEY_P256"
_placeholder_warned = False


def base64url_decode(s: str) -> bytes:
    """Decode a base64url string (no padding required)."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _is_placeholder() -> bool:
    return _PLACEHOLDER_MARKER in _PUBLIC_KEY_PEM


def _warn_placeholder_once() -> None:
    global _placeholder_warned
    if not _placeholder_warned:
        logger.warning(
            "Yashigani license verifier: public key is a placeholder — "
            "all license files will be ignored and COMMUNITY tier will be used. "
            "Replace _PUBLIC_KEY_PEM in verifier.py before release."
        )
        _placeholder_warned = True


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    value = value.replace("Z", "+00:00")
    return datetime.fromisoformat(value)


def _build_license_state(payload: dict, valid: bool, error: Optional[str] = None) -> LicenseState:
    tier_str = payload.get("tier", "community")
    try:
        tier = LicenseTier(tier_str)
    except ValueError:
        tier = LicenseTier.COMMUNITY
        tier_str = "community"

    features_list = payload.get("features", [])
    features = frozenset(features_list) if isinstance(features_list, list) else frozenset()

    issued_at = _parse_datetime(payload.get("issued_at")) or datetime(2020, 1, 1, tzinfo=timezone.utc)
    expires_at = _parse_datetime(payload.get("expires_at"))

    # Resolve limits with backwards-compat fallback to tier defaults
    defaults = TIER_DEFAULTS.get(tier_str, TIER_DEFAULTS["community"])
    max_agents      = int(payload.get("max_agents",      defaults["max_agents"]))
    max_end_users   = int(payload.get("max_end_users",   payload.get("max_users", defaults["max_end_users"])))
    max_admin_seats = int(payload.get("max_admin_seats", defaults["max_admin_seats"]))
    max_orgs        = int(payload.get("max_orgs",        defaults["max_orgs"]))

    return LicenseState(
        tier=tier,
        org_domain=payload.get("org_domain", "*"),
        max_agents=max_agents,
        max_end_users=max_end_users,
        max_admin_seats=max_admin_seats,
        max_orgs=max_orgs,
        features=features,
        issued_at=issued_at,
        expires_at=expires_at,
        license_id=payload.get("license_id"),
        valid=valid,
        error=error,
    )


def _community_invalid(error: str) -> LicenseState:
    """Return a typed invalid LicenseState using community defaults."""
    d = TIER_DEFAULTS["community"]
    return LicenseState(
        tier=LicenseTier.COMMUNITY,
        org_domain="*",
        max_agents=d["max_agents"],
        max_end_users=d["max_end_users"],
        max_admin_seats=d["max_admin_seats"],
        max_orgs=d["max_orgs"],
        features=frozenset(),
        issued_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
        expires_at=None,
        license_id=None,
        valid=False,
        error=error,
    )


def verify_license(content: str) -> LicenseState:
    """
    Verify a license string and return a LicenseState.

    Returns COMMUNITY_LICENSE if the public key is a placeholder.
    Returns LicenseState(valid=False, error="invalid_signature") for bad signatures.
    Returns LicenseState(valid=False, error="license_expired") for expired licenses.
    Returns COMMUNITY_LICENSE (fail-open) for any other parse/crypto error.
    """
    if _is_placeholder():
        _warn_placeholder_once()
        return COMMUNITY_LICENSE

    content = content.strip()

    dot_idx = content.rfind(".")
    if dot_idx == -1:
        logger.warning("License verifier: no '.' separator found in license content")
        return COMMUNITY_LICENSE

    payload_b64 = content[:dot_idx]
    sig_b64 = content[dot_idx + 1:]

    try:
        payload_bytes = base64url_decode(payload_b64)
        sig_bytes = base64url_decode(sig_b64)
    except Exception as exc:
        logger.warning("License verifier: base64url decode failed: %s", exc)
        return COMMUNITY_LICENSE

    # Verify ECDSA P-256 / SHA-256 signature
    try:
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.exceptions import InvalidSignature

        public_key = load_pem_public_key(_PUBLIC_KEY_PEM.encode("utf-8"))
        public_key.verify(sig_bytes, payload_bytes, ECDSA(SHA256()))
    except InvalidSignature:
        logger.warning("License verifier: signature verification failed")
        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
            return _build_license_state(payload, valid=False, error="invalid_signature")
        except Exception:
            return _community_invalid("invalid_signature")
    except Exception as exc:
        logger.warning("License verifier: unexpected error during verification: %s", exc)
        return COMMUNITY_LICENSE

    # Signature valid — parse payload
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:
        logger.warning("License verifier: JSON parse error after valid signature: %s", exc)
        return COMMUNITY_LICENSE

    license_state = _build_license_state(payload, valid=True)

    # Check expiry
    if license_state.is_expired():
        return LicenseState(
            tier=license_state.tier,
            org_domain=license_state.org_domain,
            max_agents=license_state.max_agents,
            max_end_users=license_state.max_end_users,
            max_admin_seats=license_state.max_admin_seats,
            max_orgs=license_state.max_orgs,
            features=license_state.features,
            issued_at=license_state.issued_at,
            expires_at=license_state.expires_at,
            license_id=license_state.license_id,
            valid=False,
            error="license_expired",
        )

    return license_state
