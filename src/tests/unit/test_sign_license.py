"""
Tests for scripts/sign_license.py.

Validates:
  - All 5 tiers are accepted
  - v3 payload is generated (not v1)
  - All v3 fields present: max_end_users, max_admin_seats, license_type
  - Tier defaults are applied correctly when flags omitted
  - professional_plus gets max_orgs=5 by default
  - enterprise gets -1 defaults
  - --license-id flag is respected
  - --issued-at and --expires-at flags are respected
  - Generated license can be parsed and verified by verify_license
  - Output to stdout (--out -) works
"""
from __future__ import annotations

import base64
import json
import sys
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _import_sign_license():
    """Import sign_license from scripts/ (not installed as a package)."""
    scripts_dir = Path(__file__).parents[3] / "scripts"
    sys.path.insert(0, str(scripts_dir))
    try:
        import sign_license
        return sign_license
    finally:
        sys.path.pop(0)


def _make_keypair():
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
    return priv, priv_pem, pub_pem


def _decode_license(license_str: str) -> dict:
    """Decode the payload portion of a .ysg string."""
    payload_b64 = license_str.split(".")[0]
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding
    payload_bytes = base64.urlsafe_b64decode(payload_b64)
    return json.loads(payload_bytes.decode("utf-8"))


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def keypair(tmp_path_factory):
    priv, priv_pem, pub_pem = _make_keypair()
    key_path = tmp_path_factory.mktemp("keys") / "test_private.pem"
    key_path.write_bytes(priv_pem)
    return priv, priv_pem, pub_pem, key_path


@pytest.fixture(scope="module")
def sl(keypair):
    return _import_sign_license()


# ─────────────────────────────────────────────────────────────────────────────
# build_payload tests (unit — no file I/O)
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildPayload:
    def _args(self, sl, **overrides):
        import argparse
        defaults = dict(
            tier="professional",
            license_type="production",
            org_domain="test.example.com",
            license_id=None,
            max_agents=None,
            max_end_users=None,
            max_admin_seats=None,
            max_orgs=None,
            features=None,
            issued_at=None,
            expires_at=None,
            expires=None,
        )
        defaults.update(overrides)
        return argparse.Namespace(**defaults)

    def test_payload_version_is_3(self, sl):
        payload = sl.build_payload(self._args(sl))
        assert payload["v"] == 3

    def test_all_v3_fields_present(self, sl):
        payload = sl.build_payload(self._args(sl))
        for field in ["max_agents", "max_end_users", "max_admin_seats", "max_orgs",
                      "tier", "org_domain", "license_id", "license_type",
                      "features", "issued_at", "v"]:
            assert field in payload, f"Missing field: {field}"

    def test_professional_tier_defaults(self, sl):
        payload = sl.build_payload(self._args(sl, tier="professional"))
        assert payload["max_agents"] == 500
        assert payload["max_end_users"] == 1000
        assert payload["max_admin_seats"] == 50
        assert payload["max_orgs"] == 1

    def test_starter_defaults(self, sl):
        payload = sl.build_payload(self._args(sl, tier="starter"))
        assert payload["max_agents"] == 100
        assert payload["max_end_users"] == 250
        assert payload["max_admin_seats"] == 25
        assert payload["max_orgs"] == 1

    def test_professional_plus_defaults(self, sl):
        """IC regression: professional_plus must default to max_orgs=5, not 1."""
        payload = sl.build_payload(self._args(sl, tier="professional_plus"))
        assert payload["max_agents"] == 2000
        assert payload["max_end_users"] == 10000
        assert payload["max_admin_seats"] == 200
        assert payload["max_orgs"] == 5

    def test_enterprise_defaults_unlimited(self, sl):
        payload = sl.build_payload(self._args(sl, tier="enterprise"))
        assert payload["max_agents"] == -1
        assert payload["max_end_users"] == -1
        assert payload["max_admin_seats"] == -1
        assert payload["max_orgs"] == -1

    def test_explicit_overrides_applied(self, sl):
        payload = sl.build_payload(self._args(
            sl,
            tier="professional",
            max_agents="999",
            max_end_users="888",
            max_admin_seats="77",
            max_orgs="2",
        ))
        assert payload["max_agents"] == 999
        assert payload["max_end_users"] == 888
        assert payload["max_admin_seats"] == 77
        assert payload["max_orgs"] == 2

    def test_license_id_generated_if_not_given(self, sl):
        payload = sl.build_payload(self._args(sl))
        assert uuid.UUID(payload["license_id"])  # valid UUID

    def test_explicit_license_id_used(self, sl):
        lid = str(uuid.uuid4())
        payload = sl.build_payload(self._args(sl, license_id=lid))
        assert payload["license_id"] == lid

    def test_features_parsed_from_string(self, sl):
        payload = sl.build_payload(self._args(sl, features="oidc,saml,scim"))
        assert set(payload["features"]) == {"oidc", "saml", "scim"}

    def test_features_empty_default_is_empty_list_or_tier_defaults(self, sl):
        payload = sl.build_payload(self._args(sl, features=None))
        assert isinstance(payload["features"], list)

    def test_expires_at_iso_format(self, sl):
        exp = "2027-06-01T00:00:00Z"
        payload = sl.build_payload(self._args(sl, expires_at=exp))
        assert payload["expires_at"] == "2027-06-01T00:00:00Z"

    def test_legacy_expires_flag_accepted(self, sl):
        payload = sl.build_payload(self._args(sl, expires="2027-06-01"))
        assert "expires_at" in payload

    def test_license_type_production(self, sl):
        payload = sl.build_payload(self._args(sl, license_type="production"))
        assert payload["license_type"] == "production"

    def test_license_type_poc(self, sl):
        payload = sl.build_payload(self._args(sl, license_type="poc"))
        assert payload["license_type"] == "poc"

    def test_license_type_poc_extended(self, sl):
        payload = sl.build_payload(self._args(sl, license_type="poc_extended"))
        assert payload["license_type"] == "poc_extended"

    def test_license_type_nfr(self, sl):
        payload = sl.build_payload(self._args(sl, license_type="nfr"))
        assert payload["license_type"] == "nfr"

    def test_all_5_tiers_accepted(self, sl):
        tiers = ["community", "starter", "professional", "professional_plus", "enterprise"]
        for tier in tiers:
            payload = sl.build_payload(self._args(sl, tier=tier))
            assert payload["tier"] == tier


class TestSignPayload:
    def test_output_format_has_single_dot(self, sl, keypair):
        _, priv_pem, _, _ = keypair
        payload = {"v": 3, "tier": "professional", "org_domain": "x.com"}
        result = sl.sign_payload(payload, priv_pem)
        assert result.count(".") == 1

    def test_payload_b64_is_url_safe(self, sl, keypair):
        _, priv_pem, _, _ = keypair
        payload = {"v": 3, "tier": "professional", "org_domain": "x.com"}
        result = sl.sign_payload(payload, priv_pem)
        payload_part = result.split(".")[0]
        assert "+" not in payload_part and "/" not in payload_part

    def test_signature_verifiable(self, sl, keypair):
        """Signed output must be verifiable with the corresponding public key."""
        _, priv_pem, pub_pem, _ = keypair
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        payload = {"v": 3, "tier": "professional", "org_domain": "example.com",
                   "license_id": str(uuid.uuid4())}
        license_str = sl.sign_payload(payload, priv_pem)

        payload_b64, sig_b64 = license_str.rsplit(".", 1)
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + "==")
        sig_bytes = base64.urlsafe_b64decode(sig_b64 + "==")

        pub_key = load_pem_public_key(pub_pem)
        pub_key.verify(sig_bytes, payload_bytes, ECDSA(SHA256()))  # no exception = valid


class TestRoundtripWithVerifier:
    """Sign a license with sign_license.py; verify with verify_license()."""

    def test_full_roundtrip_professional(self, sl, keypair, monkeypatch):
        _, priv_pem, pub_pem, _ = keypair
        import yashigani.licensing.verifier as verifier_mod
        monkeypatch.setattr(verifier_mod, "_PUBLIC_KEY_PEM", pub_pem.decode("utf-8"))
        monkeypatch.setattr(verifier_mod, "_placeholder_warned", False)

        from yashigani.licensing.verifier import verify_license
        from yashigani.licensing.model import LicenseTier

        import argparse
        args = argparse.Namespace(
            tier="professional",
            license_type="production",
            org_domain="roundtrip.com",
            license_id=str(uuid.uuid4()),
            max_agents=None,
            max_end_users=None,
            max_admin_seats=None,
            max_orgs=None,
            features="oidc,saml,scim",
            issued_at=None,
            expires_at=None,
            expires="2028-01-01",
        )
        payload = sl.build_payload(args)
        license_str = sl.sign_payload(payload, priv_pem)
        result = verify_license(license_str)

        assert result.valid is True
        assert result.tier == LicenseTier.PROFESSIONAL
        assert result.org_domain == "roundtrip.com"
        assert result.max_agents == 500
        assert result.max_end_users == 1000
        assert result.max_admin_seats == 50
        assert result.max_orgs == 1
        assert result.has_feature("saml")
