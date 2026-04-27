"""
Tests for license anti-tampering: counter-signature (v4) and self-integrity check.

Covers:
  - valid v4 license with correct counter-signature → accepted
  - v3 license (2-segment, no counter-sig) → REJECTED: license_format_too_old (LAURA-V231-003)
  - v4 license with wrong counter-signature → rejected (counter_signature_invalid)
  - v4 license with replaced primary public key → counter-sig fails
  - integrity check detects modified verifier.py source (VERIFIER_HASH mismatch)
  - integrity check passes with correct hash
  - integrity violation forces COMMUNITY tier on all verify_license() calls
  - placeholder VERIFIER_HASH in dev → skip (fail-open permitted)
  - placeholder VERIFIER_HASH in prod → violation flag set (fail-closed, #104)
  - placeholder COUNTER_PUBLIC_KEY_PEM in dev → skip (fail-open permitted)
  - placeholder COUNTER_PUBLIC_KEY_PEM in prod → counter-sig fails (fail-closed, #103)
  - domain-bound license with matching YASHIGANI_TLS_DOMAIN → accepted (#102)
  - domain-bound license with mismatched YASHIGANI_TLS_DOMAIN → COMMUNITY (#102)
  - domain-bound license with unset YASHIGANI_TLS_DOMAIN → COMMUNITY (#102)
  - wildcard org_domain ("*") → no domain check (#102)

Last updated: 2026-04-27T21:53:12+01:00
"""
from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Tuple

import pytest


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def _make_keypair():
    """Generate an ephemeral ECDSA P-256 keypair.  Skip test if cryptography absent."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat, PrivateFormat, NoEncryption
        )
    except ImportError:
        pytest.skip("cryptography package not installed")

    priv = generate_private_key(SECP256R1())
    priv_pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub_pem = priv.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return priv, priv_pem, pub_pem.decode("utf-8")


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _ecdsa_sign(message: bytes, private_pem: bytes) -> bytes:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
    from cryptography.hazmat.primitives.hashes import SHA256
    priv = load_pem_private_key(private_pem, password=None)
    return priv.sign(message, ECDSA(SHA256()))


def _compute_counter_sig_message(payload_bytes: bytes, primary_pub_pem: str) -> bytes:
    """Mirrors verifier._compute_counter_sig_message()."""
    pem_bytes = primary_pub_pem.encode("utf-8")
    pem_hash = hashlib.sha256(pem_bytes).digest()
    return hashlib.sha256(payload_bytes + pem_hash).digest()


def _make_payload(
    tier: str = "professional",
    expires_offset_days: int = 30,
) -> dict:
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=expires_offset_days)
    return {
        "v": 3,
        "key_alg": "ECDSA-P256",
        "tier": tier,
        "license_type": "production",
        "org_domain": "test.example.com",
        "license_id": str(uuid.uuid4()),
        "max_agents": 500,
        "max_end_users": 1000,
        "max_admin_seats": 50,
        "max_orgs": 1,
        "features": ["oidc", "saml"],
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _build_v3_license(payload: dict, primary_priv_pem: bytes) -> str:
    """Build a v3 license string: payload.primary_sig"""
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig = _ecdsa_sign(payload_bytes, primary_priv_pem)
    return f"{_b64url_encode(payload_bytes)}.{_b64url_encode(sig)}"


def _build_v4_license(
    payload: dict,
    primary_priv_pem: bytes,
    primary_pub_pem: str,
    counter_priv_pem: bytes,
) -> str:
    """Build a v4 license string: payload.primary_sig.counter_sig"""
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    primary_sig = _ecdsa_sign(payload_bytes, primary_priv_pem)
    message = _compute_counter_sig_message(payload_bytes, primary_pub_pem)
    counter_sig = _ecdsa_sign(message, counter_priv_pem)
    return (
        f"{_b64url_encode(payload_bytes)}"
        f".{_b64url_encode(primary_sig)}"
        f".{_b64url_encode(counter_sig)}"
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def primary_keys():
    """Ephemeral primary keypair."""
    _, priv_pem, pub_pem = _make_keypair()
    return priv_pem, pub_pem


@pytest.fixture()
def counter_keys():
    """Ephemeral counter-signing keypair."""
    _, priv_pem, pub_pem = _make_keypair()
    return priv_pem, pub_pem


@pytest.fixture()
def patched_verifier(primary_keys, counter_keys, monkeypatch):
    """
    Monkeypatch verifier module with real test keys and reset integrity state.

    Yields (primary_priv_pem, primary_pub_pem, counter_priv_pem, counter_pub_pem).
    """
    primary_priv_pem, primary_pub_pem = primary_keys
    counter_priv_pem, counter_pub_pem = counter_keys

    import yashigani.licensing.verifier as verifier_mod
    import yashigani.licensing._integrity as integrity_mod

    monkeypatch.setattr(verifier_mod, "_PUBLIC_KEY_PEM", primary_pub_pem)
    monkeypatch.setattr(verifier_mod, "_placeholder_warned", False)
    monkeypatch.setattr(verifier_mod, "_integrity_violated", False)
    monkeypatch.setattr(integrity_mod, "COUNTER_PUBLIC_KEY_PEM", counter_pub_pem)
    monkeypatch.setattr(integrity_mod, "VERIFIER_HASH",
                        integrity_mod._PLACEHOLDER_INTEGRITY + "_VERIFIER_HASH")

    yield primary_priv_pem, primary_pub_pem, counter_priv_pem, counter_pub_pem


# ---------------------------------------------------------------------------
# v4 license tests
# ---------------------------------------------------------------------------

class TestV4License:
    def test_valid_v4_license_accepted(self, patched_verifier):
        primary_priv_pem, primary_pub_pem, counter_priv_pem, _ = patched_verifier
        from yashigani.licensing.verifier import verify_license
        from yashigani.licensing.model import LicenseTier

        payload = _make_payload()
        lic_str = _build_v4_license(payload, primary_priv_pem, primary_pub_pem, counter_priv_pem)

        result = verify_license(lic_str)
        assert result.valid is True
        assert result.tier == LicenseTier.PROFESSIONAL

    def test_v4_wrong_counter_signature_rejected(self, patched_verifier):
        primary_priv_pem, primary_pub_pem, counter_priv_pem, _ = patched_verifier
        from yashigani.licensing.verifier import verify_license

        payload = _make_payload()
        # Build a valid v4 then corrupt the counter-sig segment
        lic_str = _build_v4_license(payload, primary_priv_pem, primary_pub_pem, counter_priv_pem)
        parts = lic_str.split(".")
        # Replace counter-sig with garbage (valid base64url but wrong signature bytes)
        corrupted = parts[0] + "." + parts[1] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        result = verify_license(corrupted)
        assert result.valid is False
        assert result.error == "counter_signature_invalid"

    def test_v4_wrong_primary_signature_rejected(self, patched_verifier):
        primary_priv_pem, primary_pub_pem, counter_priv_pem, _ = patched_verifier
        from yashigani.licensing.verifier import verify_license

        payload = _make_payload()
        lic_str = _build_v4_license(payload, primary_priv_pem, primary_pub_pem, counter_priv_pem)
        parts = lic_str.split(".")
        # Corrupt primary sig
        corrupted = parts[0] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA." + parts[2]
        result = verify_license(corrupted)
        assert result.valid is False
        assert result.error == "invalid_signature"

    def test_v4_replaced_primary_key_counter_sig_fails(self, patched_verifier, monkeypatch):
        """
        If an attacker replaces _PUBLIC_KEY_PEM with their own key, the counter-signature
        (which commits to the original primary public key hash) must fail.
        """
        primary_priv_pem, primary_pub_pem, counter_priv_pem, _ = patched_verifier

        # Build a valid v4 with the patched (original) primary key
        payload = _make_payload()
        lic_str = _build_v4_license(payload, primary_priv_pem, primary_pub_pem, counter_priv_pem)

        # Now swap in a different primary keypair in the verifier (simulates attacker
        # replacing the public key after signing)
        _, attacker_priv_pem, attacker_pub_pem = _make_keypair()

        import yashigani.licensing.verifier as verifier_mod
        # Re-sign the payload with the attacker primary key so it passes primary verification,
        # but the counter-sig still binds to the original public key
        payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        attacker_primary_sig = _ecdsa_sign(payload_bytes, attacker_priv_pem)

        # Keep the original counter-sig (bound to original primary key hash)
        parts = lic_str.split(".")
        tampered = (
            parts[0]
            + "." + _b64url_encode(attacker_primary_sig)
            + "." + parts[2]
        )

        # Swap verifier to accept the attacker primary key
        monkeypatch.setattr(verifier_mod, "_PUBLIC_KEY_PEM", attacker_pub_pem)

        from yashigani.licensing.verifier import verify_license
        result = verify_license(tampered)
        # Primary sig passes (attacker-signed), but counter-sig bound to original key must fail
        assert result.valid is False
        assert result.error == "counter_signature_invalid"

    def test_v4_does_not_fall_back_to_v3_on_bad_counter_sig(self, patched_verifier):
        """A v4 license must never be accepted as a v3 by stripping the counter-sig."""
        primary_priv_pem, primary_pub_pem, counter_priv_pem, _ = patched_verifier
        from yashigani.licensing.verifier import verify_license

        payload = _make_payload()
        lic_str = _build_v4_license(payload, primary_priv_pem, primary_pub_pem, counter_priv_pem)
        parts = lic_str.split(".")
        # Corrupt counter-sig
        tampered = parts[0] + "." + parts[1] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        result = verify_license(tampered)
        assert result.valid is False
        assert result.error == "counter_signature_invalid"


# ---------------------------------------------------------------------------
# v3 format rejection (LAURA-V231-003)
# Counter-signature is now mandatory; v3 (2-segment) licenses are rejected.
# ---------------------------------------------------------------------------

class TestV3BackwardsCompat:
    """
    LAURA-V231-003: v3 format (2-segment, no counter-signature) must be rejected.

    These tests were previously named "backwards compatibility" and asserted that
    v3 was accepted.  They have been updated to assert rejection.  The class name
    is preserved to maintain continuity with the test history.
    """

    def test_valid_v3_license_rejected_format_too_old(self, patched_verifier):
        """A validly-signed 2-segment license is rejected: license_format_too_old."""
        primary_priv_pem, _, _, _ = patched_verifier
        from yashigani.licensing.verifier import verify_license
        from yashigani.licensing.model import LicenseTier

        payload = _make_payload()
        lic_str = _build_v3_license(payload, primary_priv_pem)
        assert len(lic_str.split(".")) == 2, "v3 builder must produce 2-segment string"

        result = verify_license(lic_str)
        assert result.valid is False
        assert result.error == "license_format_too_old"
        # Must fall back to COMMUNITY tier — not the payload's claimed tier
        assert result.tier == LicenseTier.COMMUNITY

    def test_v3_rejected_even_with_valid_primary_sig(self, patched_verifier):
        """Primary-sig validity is irrelevant — v3 is always rejected before sig check."""
        primary_priv_pem, _, _, _ = patched_verifier
        from yashigani.licensing.verifier import verify_license

        payload = _make_payload()
        lic_str = _build_v3_license(payload, primary_priv_pem)
        # Both the valid-sig and corrupted-sig 2-segment licenses return the same error
        result_valid = verify_license(lic_str)
        corrupted = lic_str.split(".")[0] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        result_corrupt = verify_license(corrupted)
        assert result_valid.error == "license_format_too_old"
        assert result_corrupt.error == "license_format_too_old"


# ---------------------------------------------------------------------------
# Counter-key placeholder (fail-open) tests
# ---------------------------------------------------------------------------

class TestCounterKeyPlaceholder:
    def test_v4_accepted_when_counter_key_is_placeholder(self, primary_keys, monkeypatch):
        """
        If COUNTER_PUBLIC_KEY_PEM is still a placeholder AND YASHIGANI_ENV=dev,
        counter-sig check is skipped and v4 licenses are accepted (dev/CI builds).
        (#103: in prod mode placeholder is fail-closed — see test below.)
        """
        primary_priv_pem, primary_pub_pem = primary_keys
        _, counter_priv_pem, _ = _make_keypair()

        import yashigani.licensing.verifier as verifier_mod
        import yashigani.licensing._integrity as integrity_mod

        monkeypatch.setenv("YASHIGANI_ENV", "dev")  # #103: permit placeholder skip in dev
        monkeypatch.setattr(verifier_mod, "_PUBLIC_KEY_PEM", primary_pub_pem)
        monkeypatch.setattr(verifier_mod, "_placeholder_warned", False)
        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)
        # Leave COUNTER_PUBLIC_KEY_PEM as placeholder
        monkeypatch.setattr(
            integrity_mod,
            "COUNTER_PUBLIC_KEY_PEM",
            integrity_mod._PLACEHOLDER_INTEGRITY + "_COUNTER_KEY",
        )
        monkeypatch.setattr(
            integrity_mod,
            "VERIFIER_HASH",
            integrity_mod._PLACEHOLDER_INTEGRITY + "_VERIFIER_HASH",
        )

        from yashigani.licensing.verifier import verify_license
        from yashigani.licensing.model import LicenseTier

        # Build with a random counter key (will be ignored by verifier)
        payload = _make_payload()
        lic_str = _build_v4_license(payload, primary_priv_pem, primary_pub_pem, counter_priv_pem)

        result = verify_license(lic_str)
        assert result.valid is True
        assert result.tier == LicenseTier.PROFESSIONAL

    def test_v4_counter_key_placeholder_fails_closed_in_prod(self, primary_keys, monkeypatch):
        """
        #103 (LICENSE-2024-001 / CVSS 9.1): In non-dev environments, a
        placeholder COUNTER_PUBLIC_KEY_PEM must NOT skip the counter-sig check.
        The verification must fail (counter_signature_invalid), not accept the
        license, because a placeholder means the build pipeline failed to embed
        the real counter key.
        """
        primary_priv_pem, primary_pub_pem = primary_keys
        _, counter_priv_pem, _ = _make_keypair()

        import yashigani.licensing.verifier as verifier_mod
        import yashigani.licensing._integrity as integrity_mod

        # Explicitly unset YASHIGANI_ENV to simulate prod
        monkeypatch.delenv("YASHIGANI_ENV", raising=False)
        monkeypatch.setattr(verifier_mod, "_PUBLIC_KEY_PEM", primary_pub_pem)
        monkeypatch.setattr(verifier_mod, "_placeholder_warned", False)
        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)
        monkeypatch.setattr(
            integrity_mod,
            "COUNTER_PUBLIC_KEY_PEM",
            integrity_mod._PLACEHOLDER_INTEGRITY + "_COUNTER_KEY",
        )
        # VERIFIER_HASH is real (non-placeholder) so integrity doesn't interfere
        monkeypatch.setattr(integrity_mod, "VERIFIER_HASH", "a" * 64)

        # The verifier will try to load the placeholder PEM as a real key, which
        # will fail, so the counter_sig check returns False → counter_signature_invalid.
        from yashigani.licensing.verifier import verify_license

        payload = _make_payload()
        lic_str = _build_v4_license(payload, primary_priv_pem, primary_pub_pem, counter_priv_pem)

        result = verify_license(lic_str)
        assert result.valid is False
        assert result.error == "counter_signature_invalid"


# ---------------------------------------------------------------------------
# Self-integrity tests
# ---------------------------------------------------------------------------

class TestSelfIntegrity:
    def test_correct_hash_passes(self, monkeypatch):
        """
        When VERIFIER_HASH matches the actual SHA-256 of verifier.py,
        integrity check must pass and verify_license() works normally.
        """
        import yashigani.licensing.verifier as verifier_mod
        import yashigani.licensing._integrity as integrity_mod
        from pathlib import Path

        # Compute the real hash of the verifier source
        verifier_path = Path(verifier_mod.__file__)
        real_hash = hashlib.sha256(verifier_path.read_bytes()).hexdigest()

        # Generate test keys
        _, primary_priv_pem, primary_pub_pem = _make_keypair()
        _, counter_priv_pem, counter_pub_pem = _make_keypair()

        monkeypatch.setattr(verifier_mod, "_PUBLIC_KEY_PEM", primary_pub_pem)
        monkeypatch.setattr(verifier_mod, "_placeholder_warned", False)
        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)
        monkeypatch.setattr(integrity_mod, "VERIFIER_HASH", real_hash)
        monkeypatch.setattr(integrity_mod, "COUNTER_PUBLIC_KEY_PEM", counter_pub_pem)

        # Re-run the integrity check with the correct hash
        import importlib
        verifier_mod._check_self_integrity()

        assert verifier_mod._integrity_violated is False

    def test_modified_hash_sets_violation_flag(self, monkeypatch):
        """
        When VERIFIER_HASH does not match the actual digest, the integrity
        violation flag must be set.
        """
        import yashigani.licensing.verifier as verifier_mod
        import yashigani.licensing._integrity as integrity_mod

        # Use an obviously wrong hash (all zeros)
        monkeypatch.setattr(integrity_mod, "VERIFIER_HASH", "a" * 64)
        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)

        verifier_mod._check_self_integrity()

        assert verifier_mod._integrity_violated is True

    def test_integrity_violation_forces_community_tier(self, patched_verifier, monkeypatch):
        """
        When _integrity_violated is True, verify_license() must return
        COMMUNITY_LICENSE regardless of the license content.
        """
        primary_priv_pem, primary_pub_pem, counter_priv_pem, _ = patched_verifier

        import yashigani.licensing.verifier as verifier_mod
        # Simulate a previously detected violation
        monkeypatch.setattr(verifier_mod, "_integrity_violated", True)

        from yashigani.licensing.verifier import verify_license
        from yashigani.licensing.model import LicenseTier

        payload = _make_payload(tier="enterprise")
        lic_str = _build_v4_license(payload, primary_priv_pem, primary_pub_pem, counter_priv_pem)

        result = verify_license(lic_str)
        assert result.tier == LicenseTier.COMMUNITY

    def test_placeholder_verifier_hash_skips_integrity_check(self, monkeypatch):
        """
        When VERIFIER_HASH is a placeholder AND YASHIGANI_ENV=dev, the
        self-integrity check is skipped and _integrity_violated must stay False.
        (#104: in prod mode placeholder sets the violation flag — see test below.)
        """
        import yashigani.licensing.verifier as verifier_mod
        import yashigani.licensing._integrity as integrity_mod

        monkeypatch.setenv("YASHIGANI_ENV", "dev")  # #104: only permit skip in dev
        monkeypatch.setattr(
            integrity_mod,
            "VERIFIER_HASH",
            integrity_mod._PLACEHOLDER_INTEGRITY + "_VERIFIER_HASH",
        )
        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)

        verifier_mod._check_self_integrity()

        assert verifier_mod._integrity_violated is False

    def test_placeholder_verifier_hash_sets_violation_in_prod(self, monkeypatch):
        """
        #104 (LICENSE-2024-002 / CVSS 9.1): In non-dev environments, a
        placeholder VERIFIER_HASH means the build pipeline did not embed the
        real hash.  This is treated as a tamper event: _integrity_violated must
        be set to True (fail-closed), ensuring verify_license() returns COMMUNITY
        tier for all subsequent calls.
        """
        import yashigani.licensing.verifier as verifier_mod
        import yashigani.licensing._integrity as integrity_mod

        monkeypatch.delenv("YASHIGANI_ENV", raising=False)  # simulate prod
        monkeypatch.setattr(
            integrity_mod,
            "VERIFIER_HASH",
            integrity_mod._PLACEHOLDER_INTEGRITY + "_VERIFIER_HASH",
        )
        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)

        verifier_mod._check_self_integrity()

        assert verifier_mod._integrity_violated is True


# ---------------------------------------------------------------------------
# _integrity module unit tests
# ---------------------------------------------------------------------------

class TestIntegrityModule:
    def test_placeholder_detection_verifier_hash(self):
        import yashigani.licensing._integrity as integrity_mod
        # The shipped source has placeholder values
        assert integrity_mod.is_verifier_hash_placeholder() is True

    def test_placeholder_detection_counter_key(self):
        import yashigani.licensing._integrity as integrity_mod
        assert integrity_mod.is_counter_key_placeholder() is True

    def test_non_placeholder_verifier_hash(self, monkeypatch):
        import yashigani.licensing._integrity as integrity_mod
        monkeypatch.setattr(integrity_mod, "VERIFIER_HASH", "a" * 64)
        assert integrity_mod.is_verifier_hash_placeholder() is False

    def test_non_placeholder_counter_key(self, monkeypatch):
        import yashigani.licensing._integrity as integrity_mod
        monkeypatch.setattr(integrity_mod, "COUNTER_PUBLIC_KEY_PEM",
                            "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----\n")
        assert integrity_mod.is_counter_key_placeholder() is False


# ---------------------------------------------------------------------------
# Domain binding tests (#102 / LICENSE-2024-003 / CVSS 9.3)
# ---------------------------------------------------------------------------

class TestDomainBinding:
    """
    loader.load_license() must enforce org_domain binding.

    A license with org_domain != "*" is only accepted when YASHIGANI_TLS_DOMAIN
    matches exactly.  Mismatch or absence of the env var must downgrade to
    COMMUNITY tier (fail-closed) regardless of signature validity.
    """

    def _write_license_file(self, tmp_path, content: str) -> str:
        """Write license content to a temp file and return its path."""
        p = tmp_path / "license.ysg"
        p.write_text(content, encoding="utf-8")
        return str(p)

    def _setup_verifier(self, monkeypatch):
        """Patch verifier to use ephemeral test keys."""
        _, primary_priv_pem, primary_pub_pem = _make_keypair()
        _, counter_priv_pem, counter_pub_pem = _make_keypair()

        import yashigani.licensing.verifier as verifier_mod
        import yashigani.licensing._integrity as integrity_mod

        monkeypatch.setenv("YASHIGANI_ENV", "dev")
        monkeypatch.setattr(verifier_mod, "_PUBLIC_KEY_PEM", primary_pub_pem)
        monkeypatch.setattr(verifier_mod, "_placeholder_warned", False)
        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)
        monkeypatch.setattr(integrity_mod, "COUNTER_PUBLIC_KEY_PEM", counter_pub_pem)
        monkeypatch.setattr(
            integrity_mod, "VERIFIER_HASH",
            integrity_mod._PLACEHOLDER_INTEGRITY + "_VERIFIER_HASH",
        )
        return primary_priv_pem, primary_pub_pem, counter_priv_pem

    def test_domain_bound_license_accepted_when_domain_matches(self, tmp_path, monkeypatch):
        """
        A domain-bound license (org_domain = "acme.example.com") is accepted
        when YASHIGANI_TLS_DOMAIN="acme.example.com".
        """
        primary_priv_pem, primary_pub_pem, counter_priv_pem = self._setup_verifier(monkeypatch)

        payload = _make_payload()
        payload["org_domain"] = "acme.example.com"
        lic_str = _build_v4_license(payload, primary_priv_pem, primary_pub_pem, counter_priv_pem)
        lic_path = self._write_license_file(tmp_path, lic_str)

        monkeypatch.setenv("YASHIGANI_LICENSE_FILE", lic_path)
        monkeypatch.setenv("YASHIGANI_TLS_DOMAIN", "acme.example.com")

        from yashigani.licensing.loader import load_license
        from yashigani.licensing.model import LicenseTier

        result = load_license()
        assert result.valid is True
        assert result.tier == LicenseTier.PROFESSIONAL
        assert result.org_domain == "acme.example.com"

    def test_domain_bound_license_rejected_when_domain_mismatches(self, tmp_path, monkeypatch):
        """
        #102: A license bound to "acme.example.com" must be rejected (→ COMMUNITY)
        when YASHIGANI_TLS_DOMAIN="other.example.com".
        """
        primary_priv_pem, primary_pub_pem, counter_priv_pem = self._setup_verifier(monkeypatch)

        payload = _make_payload()
        payload["org_domain"] = "acme.example.com"
        lic_str = _build_v4_license(payload, primary_priv_pem, primary_pub_pem, counter_priv_pem)
        lic_path = self._write_license_file(tmp_path, lic_str)

        monkeypatch.setenv("YASHIGANI_LICENSE_FILE", lic_path)
        monkeypatch.setenv("YASHIGANI_TLS_DOMAIN", "other.example.com")

        from yashigani.licensing.loader import load_license
        from yashigani.licensing.model import LicenseTier

        result = load_license()
        assert result.tier == LicenseTier.COMMUNITY

    def test_domain_bound_license_rejected_when_domain_env_unset(self, tmp_path, monkeypatch):
        """
        #102: A domain-bound license must be rejected (→ COMMUNITY) when
        YASHIGANI_TLS_DOMAIN is not set in the environment.
        """
        primary_priv_pem, primary_pub_pem, counter_priv_pem = self._setup_verifier(monkeypatch)

        payload = _make_payload()
        payload["org_domain"] = "acme.example.com"
        lic_str = _build_v4_license(payload, primary_priv_pem, primary_pub_pem, counter_priv_pem)
        lic_path = self._write_license_file(tmp_path, lic_str)

        monkeypatch.setenv("YASHIGANI_LICENSE_FILE", lic_path)
        monkeypatch.delenv("YASHIGANI_TLS_DOMAIN", raising=False)

        from yashigani.licensing.loader import load_license
        from yashigani.licensing.model import LicenseTier

        result = load_license()
        assert result.tier == LicenseTier.COMMUNITY

    def test_wildcard_org_domain_skips_domain_check(self, tmp_path, monkeypatch):
        """
        A license with org_domain="*" is accepted regardless of
        YASHIGANI_TLS_DOMAIN (wildcard = not domain-bound).
        """
        primary_priv_pem, primary_pub_pem, counter_priv_pem = self._setup_verifier(monkeypatch)

        payload = _make_payload()
        payload["org_domain"] = "*"
        lic_str = _build_v4_license(payload, primary_priv_pem, primary_pub_pem, counter_priv_pem)
        lic_path = self._write_license_file(tmp_path, lic_str)

        monkeypatch.setenv("YASHIGANI_LICENSE_FILE", lic_path)
        monkeypatch.delenv("YASHIGANI_TLS_DOMAIN", raising=False)  # unset — must still work

        from yashigani.licensing.loader import load_license
        from yashigani.licensing.model import LicenseTier

        result = load_license()
        assert result.valid is True
        assert result.tier == LicenseTier.PROFESSIONAL


# ---------------------------------------------------------------------------
# sign_license.py v4 integration roundtrip
# ---------------------------------------------------------------------------

class TestSignLicenseV4Roundtrip:
    """
    Full roundtrip: sign_payload_v4 → verify_license.
    Exercises the scripts/sign_license.py path end-to-end.
    """

    def _import_sign_license(self):
        import sys
        from pathlib import Path
        scripts_dir = Path(__file__).parents[3] / "scripts"
        sys.path.insert(0, str(scripts_dir))
        try:
            import sign_license
            return sign_license
        finally:
            sys.path.pop(0)

    def test_v4_roundtrip(self, patched_verifier):
        primary_priv_pem, primary_pub_pem, counter_priv_pem, counter_pub_pem = patched_verifier

        import yashigani.licensing._integrity as integrity_mod
        from yashigani.licensing.verifier import verify_license
        from yashigani.licensing.model import LicenseTier

        sl = self._import_sign_license()
        payload = _make_payload()

        lic_str = sl.sign_payload_v4(
            payload,
            primary_priv_pem,
            primary_pub_pem,
            counter_priv_pem,
        )

        assert lic_str.count(".") == 2, "v4 license must have exactly 2 dots"

        result = verify_license(lic_str)
        assert result.valid is True
        assert result.tier == LicenseTier.PROFESSIONAL

    def test_v3_roundtrip_still_works(self, patched_verifier):
        primary_priv_pem, _, _, _ = patched_verifier
        from yashigani.licensing.verifier import verify_license
        from yashigani.licensing.model import LicenseTier

        sl = self._import_sign_license()
        payload = _make_payload()

        lic_str = sl.sign_payload(payload, primary_priv_pem)
        assert lic_str.count(".") == 1, "v3 license must have exactly 1 dot"

        result = verify_license(lic_str)
        assert result.valid is True
        assert result.tier == LicenseTier.PROFESSIONAL
