"""
Comprehensive tests for yashigani.licensing.

Covers:
  - LicenseState model and tier enum
  - TIER_DEFAULTS consistency
  - LicenseState.has_feature() and is_expired()
  - verify_license() placeholder behaviour
  - verify_license() with real ECDSA P-256 keypair (generated in fixture)
  - verify_license() invalid signature path
  - verify_license() expired license path
  - verify_license() v1/v2 backwards-compat field fallback
  - enforcer: set/get license, require_feature, all four limit checks
  - enforcer: -1 (unlimited) bypasses limit checks
  - enforcer: HTTP response helpers
  - enforcer: upgrade URL points to agnosticsec.com
"""
from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timezone, timedelta

import pytest

from yashigani.licensing.model import (
    COMMUNITY_LICENSE,
    TIER_DEFAULTS,
    LicenseState,
    LicenseTier,
)
from yashigani.licensing.enforcer import (
    LicenseFeatureGated,
    LicenseLimitExceeded,
    check_admin_seat_limit,
    check_agent_limit,
    check_end_user_limit,
    check_org_limit,
    get_license,
    license_feature_gated_response,
    license_limit_exceeded_response,
    require_feature,
    set_license,
)
from yashigani.licensing.verifier import (
    COMMUNITY_LICENSE as _VERIFIER_COMMUNITY,  # verify_license uses this too
    base64url_decode,
    verify_license,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_test_keypair():
    """Generate an ephemeral ECDSA P-256 keypair for testing."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ec import (
            SECP256R1, generate_private_key, ECDSA
        )
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat, PrivateFormat, NoEncryption
        )
    except ImportError:
        pytest.skip("cryptography package not installed")

    private_key = generate_private_key(SECP256R1())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    public_pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return private_key, public_key, private_pem, public_pem


def _sign_payload(payload: dict, private_pem: bytes) -> str:
    """Sign payload dict and return .ysg format string."""
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    private_key = load_pem_private_key(private_pem, password=None)
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    payload_bytes = payload_json.encode("utf-8")
    sig = private_key.sign(payload_bytes, ECDSA(SHA256()))
    return f"{_b64url_encode(payload_bytes)}.{_b64url_encode(sig)}"


def _patch_verifier_key(public_pem: bytes, monkeypatch):
    """Monkeypatch the verifier module to use a test public key."""
    import yashigani.licensing.verifier as verifier_mod
    monkeypatch.setattr(verifier_mod, "_PUBLIC_KEY_PEM", public_pem.decode("utf-8"))
    monkeypatch.setattr(verifier_mod, "_placeholder_warned", False)


def _make_payload(
    tier="professional",
    org_domain="test.example.com",
    max_agents=500,
    max_end_users=1000,
    max_admin_seats=50,
    max_orgs=1,
    features=None,
    issued_offset_days=0,
    expires_offset_days=30,
    license_type="production",
    version=3,
    license_id=None,
) -> dict:
    now = datetime.now(timezone.utc)
    issued = now + timedelta(days=issued_offset_days)
    expires = now + timedelta(days=expires_offset_days) if expires_offset_days is not None else None

    payload = {
        "v": version,
        "tier": tier,
        "license_type": license_type,
        "org_domain": org_domain,
        "license_id": license_id or str(uuid.uuid4()),
        "max_agents": max_agents,
        "max_end_users": max_end_users,
        "max_admin_seats": max_admin_seats,
        "max_orgs": max_orgs,
        "features": features if features is not None else ["oidc", "saml", "scim"],
        "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if expires:
        payload["expires_at"] = expires.strftime("%Y-%m-%dT%H:%M:%SZ")
    return payload


# ─────────────────────────────────────────────────────────────────────────────
# Model tests
# ─────────────────────────────────────────────────────────────────────────────

class TestLicenseTier:
    def test_all_expected_tiers_exist(self):
        expected = {"community", "starter", "professional", "professional_plus", "enterprise"}
        actual = {t.value for t in LicenseTier}
        assert actual == expected

    def test_tier_values_are_lowercase_strings(self):
        for tier in LicenseTier:
            assert tier.value == tier.value.lower()
            assert tier.value == tier.value.replace("-", "_")


class TestTierDefaults:
    def test_all_tiers_have_defaults(self):
        for tier in LicenseTier:
            assert tier.value in TIER_DEFAULTS, f"TIER_DEFAULTS missing entry for {tier.value}"

    def test_community_limits(self):
        d = TIER_DEFAULTS["community"]
        assert d["max_agents"] == 20
        assert d["max_end_users"] == 50
        assert d["max_admin_seats"] == 10
        assert d["max_orgs"] == 1

    def test_starter_limits(self):
        d = TIER_DEFAULTS["starter"]
        assert d["max_agents"] == 100
        assert d["max_end_users"] == 250
        assert d["max_admin_seats"] == 25
        assert d["max_orgs"] == 1

    def test_professional_limits(self):
        d = TIER_DEFAULTS["professional"]
        assert d["max_agents"] == 500
        assert d["max_end_users"] == 1000
        assert d["max_admin_seats"] == 50
        assert d["max_orgs"] == 1

    def test_professional_plus_limits(self):
        d = TIER_DEFAULTS["professional_plus"]
        assert d["max_agents"] == 2000
        assert d["max_end_users"] == 10000
        assert d["max_admin_seats"] == 200
        assert d["max_orgs"] == 5

    def test_enterprise_unlimited(self):
        d = TIER_DEFAULTS["enterprise"]
        assert d["max_agents"] == -1
        assert d["max_end_users"] == -1
        assert d["max_admin_seats"] == -1
        assert d["max_orgs"] == -1

    def test_tier_limits_are_strictly_increasing(self):
        """Starter ≤ Professional ≤ Professional Plus for all positive limits."""
        tiers = ["starter", "professional", "professional_plus"]
        for field in ["max_agents", "max_end_users", "max_admin_seats"]:
            values = [TIER_DEFAULTS[t][field] for t in tiers]
            assert values == sorted(values), \
                f"Expected {field} to increase across {tiers}, got {values}"


class TestLicenseState:
    def test_community_license_is_valid(self):
        assert COMMUNITY_LICENSE.valid is True
        assert COMMUNITY_LICENSE.tier == LicenseTier.COMMUNITY
        assert COMMUNITY_LICENSE.expires_at is None

    def test_community_license_never_expires(self):
        assert COMMUNITY_LICENSE.is_expired() is False

    def test_has_feature_true(self):
        state = LicenseState(
            tier=LicenseTier.PROFESSIONAL,
            org_domain="example.com",
            max_agents=500,
            max_end_users=1000,
            max_admin_seats=50,
            max_orgs=1,
            features=frozenset(["oidc", "saml"]),
            issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            expires_at=None,
            license_id=None,
            valid=True,
            error=None,
        )
        assert state.has_feature("oidc") is True
        assert state.has_feature("saml") is True
        assert state.has_feature("scim") is False

    def test_is_expired_past(self):
        state = LicenseState(
            tier=LicenseTier.PROFESSIONAL,
            org_domain="example.com",
            max_agents=500,
            max_end_users=1000,
            max_admin_seats=50,
            max_orgs=1,
            features=frozenset(),
            issued_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
            expires_at=datetime(2025, 6, 1, tzinfo=timezone.utc),
            license_id=None,
            valid=True,
            error=None,
        )
        assert state.is_expired() is True

    def test_is_expired_future(self):
        future = datetime.now(timezone.utc) + timedelta(days=30)
        state = LicenseState(
            tier=LicenseTier.PROFESSIONAL,
            org_domain="example.com",
            max_agents=500,
            max_end_users=1000,
            max_admin_seats=50,
            max_orgs=1,
            features=frozenset(),
            issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            expires_at=future,
            license_id=None,
            valid=True,
            error=None,
        )
        assert state.is_expired() is False


# ─────────────────────────────────────────────────────────────────────────────
# Verifier tests
# ─────────────────────────────────────────────────────────────────────────────

class TestBase64UrlDecode:
    def test_no_padding_needed(self):
        encoded = base64.urlsafe_b64encode(b"hello").rstrip(b"=").decode()
        assert base64url_decode(encoded) == b"hello"

    def test_with_padding_needed(self):
        encoded = base64.urlsafe_b64encode(b"ab").rstrip(b"=").decode()
        assert base64url_decode(encoded) == b"ab"

    def test_url_safe_chars(self):
        # Bytes that produce +/ in standard base64, should work with urlsafe
        data = bytes([0xFB, 0xFF, 0xFE])
        encoded = base64.urlsafe_b64encode(data).rstrip(b"=").decode()
        assert base64url_decode(encoded) == data


class TestVerifyLicensePlaceholder:
    """When public key is the placeholder, verify_license returns COMMUNITY_LICENSE."""

    def test_returns_community_on_placeholder(self):
        result = verify_license("any.content")
        assert result.tier == LicenseTier.COMMUNITY

    def test_returns_valid_state_on_placeholder(self):
        result = verify_license("any.content")
        assert result.valid is True


class TestVerifyLicenseWithRealKey:
    """Uses a generated keypair to test the full signature verification path."""

    @pytest.fixture(autouse=True)
    def setup_keypair(self, monkeypatch):
        keys = _make_test_keypair()
        self.private_key, self.public_key, self.private_pem, self.public_pem = keys
        _patch_verifier_key(self.public_pem, monkeypatch)

    def test_valid_v3_license(self):
        payload = _make_payload()
        license_str = _sign_payload(payload, self.private_pem)
        result = verify_license(license_str)
        assert result.valid is True
        assert result.tier == LicenseTier.PROFESSIONAL
        assert result.max_agents == 500
        assert result.max_end_users == 1000
        assert result.max_admin_seats == 50
        assert result.max_orgs == 1

    def test_valid_starter_license(self):
        payload = _make_payload(
            tier="starter",
            max_agents=100, max_end_users=250, max_admin_seats=25, max_orgs=1,
            features=["oidc"],
        )
        license_str = _sign_payload(payload, self.private_pem)
        result = verify_license(license_str)
        assert result.valid is True
        assert result.tier == LicenseTier.STARTER
        assert result.has_feature("oidc") is True
        assert result.has_feature("saml") is False
        assert result.max_end_users == 250
        assert result.max_admin_seats == 25

    def test_valid_professional_plus_license(self):
        payload = _make_payload(
            tier="professional_plus",
            max_agents=2000, max_end_users=10000, max_admin_seats=200, max_orgs=5,
        )
        license_str = _sign_payload(payload, self.private_pem)
        result = verify_license(license_str)
        assert result.valid is True
        assert result.tier == LicenseTier.PROFESSIONAL_PLUS
        assert result.max_orgs == 5

    def test_valid_enterprise_unlimited(self):
        payload = _make_payload(
            tier="enterprise",
            max_agents=-1, max_end_users=-1, max_admin_seats=-1, max_orgs=-1,
        )
        license_str = _sign_payload(payload, self.private_pem)
        result = verify_license(license_str)
        assert result.valid is True
        assert result.tier == LicenseTier.ENTERPRISE
        assert result.max_agents == -1

    def test_expired_license_returns_invalid(self):
        payload = _make_payload(expires_offset_days=-1)  # expired yesterday
        license_str = _sign_payload(payload, self.private_pem)
        result = verify_license(license_str)
        assert result.valid is False
        assert result.error == "license_expired"
        # Tier and org info are still present even when expired
        assert result.tier == LicenseTier.PROFESSIONAL
        assert result.org_domain == "test.example.com"

    def test_invalid_signature_returns_invalid(self):
        payload = _make_payload()
        license_str = _sign_payload(payload, self.private_pem)
        # Corrupt the signature portion
        parts = license_str.split(".")
        corrupted = parts[0] + ".AAAAAAAAAAAAAAAAAAAAAAAA"
        result = verify_license(corrupted)
        assert result.valid is False
        assert result.error == "invalid_signature"

    def test_missing_separator_falls_back_to_community(self):
        result = verify_license("no_dot_here")
        assert result.tier == LicenseTier.COMMUNITY

    def test_features_parsed_correctly(self):
        payload = _make_payload(features=["oidc", "saml", "scim"])
        license_str = _sign_payload(payload, self.private_pem)
        result = verify_license(license_str)
        assert result.has_feature("oidc") is True
        assert result.has_feature("saml") is True
        assert result.has_feature("scim") is True

    def test_community_features_empty(self):
        payload = _make_payload(tier="community", features=[], max_agents=20,
                                max_end_users=50, max_admin_seats=10, max_orgs=1)
        license_str = _sign_payload(payload, self.private_pem)
        result = verify_license(license_str)
        assert result.has_feature("oidc") is False

    def test_org_domain_stored(self):
        payload = _make_payload(org_domain="mycorp.io")
        license_str = _sign_payload(payload, self.private_pem)
        result = verify_license(license_str)
        assert result.org_domain == "mycorp.io"

    def test_license_id_stored(self):
        lid = str(uuid.uuid4())
        payload = _make_payload(license_id=lid)
        license_str = _sign_payload(payload, self.private_pem)
        result = verify_license(license_str)
        assert result.license_id == lid

    def test_v1_payload_backwards_compat(self):
        """v1 payloads lack max_end_users and max_admin_seats — must fall back to tier defaults."""
        payload = _make_payload(version=1)
        # Remove v3-only fields to simulate v1
        del payload["max_end_users"]
        del payload["max_admin_seats"]
        license_str = _sign_payload(payload, self.private_pem)
        result = verify_license(license_str)
        assert result.valid is True
        assert result.max_end_users == TIER_DEFAULTS["professional"]["max_end_users"]
        assert result.max_admin_seats == TIER_DEFAULTS["professional"]["max_admin_seats"]

    def test_v2_max_users_field_maps_to_max_end_users(self):
        """v2 payloads use 'max_users' instead of 'max_end_users'."""
        payload = _make_payload(version=2)
        del payload["max_end_users"]
        payload["max_users"] = 999
        license_str = _sign_payload(payload, self.private_pem)
        result = verify_license(license_str)
        assert result.max_end_users == 999

    def test_unknown_tier_falls_back_to_community(self):
        payload = _make_payload()
        payload["tier"] = "nonexistent_tier"
        license_str = _sign_payload(payload, self.private_pem)
        result = verify_license(license_str)
        assert result.tier == LicenseTier.COMMUNITY


# ─────────────────────────────────────────────────────────────────────────────
# Enforcer tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def reset_enforcer_license():
    """Reset enforcer state to COMMUNITY between each test."""
    original = get_license()
    yield
    set_license(original)


def _make_license_state(
    tier=LicenseTier.PROFESSIONAL,
    features=("oidc", "saml", "scim"),
    max_agents=500,
    max_end_users=1000,
    max_admin_seats=50,
    max_orgs=1,
    valid=True,
    error=None,
) -> LicenseState:
    return LicenseState(
        tier=tier,
        org_domain="example.com",
        max_agents=max_agents,
        max_end_users=max_end_users,
        max_admin_seats=max_admin_seats,
        max_orgs=max_orgs,
        features=frozenset(features),
        issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        expires_at=datetime(2027, 1, 1, tzinfo=timezone.utc),
        license_id=str(uuid.uuid4()),
        valid=valid,
        error=error,
    )


class TestEnforcerSetGet:
    def test_default_is_community(self):
        # Fresh module state defaults to community
        # (enforcer resets to original via fixture)
        set_license(COMMUNITY_LICENSE)
        assert get_license().tier == LicenseTier.COMMUNITY

    def test_set_and_get(self):
        lic = _make_license_state()
        set_license(lic)
        assert get_license() is lic


class TestRequireFeature:
    def test_feature_present_does_not_raise(self):
        set_license(_make_license_state(features=["saml"]))
        require_feature("saml")  # should not raise

    def test_missing_feature_raises(self):
        set_license(_make_license_state(features=["oidc"]))
        with pytest.raises(LicenseFeatureGated) as exc_info:
            require_feature("saml")
        assert exc_info.value.feature == "saml"
        assert exc_info.value.tier == LicenseTier.PROFESSIONAL

    def test_community_has_no_features(self):
        set_license(COMMUNITY_LICENSE)
        with pytest.raises(LicenseFeatureGated):
            require_feature("oidc")


class TestAgentLimit:
    def test_under_limit_ok(self):
        set_license(_make_license_state(max_agents=10))
        check_agent_limit(9)  # no raise

    def test_at_limit_raises(self):
        set_license(_make_license_state(max_agents=10))
        with pytest.raises(LicenseLimitExceeded) as exc_info:
            check_agent_limit(10)
        assert exc_info.value.limit_name == "max_agents"
        assert exc_info.value.current == 10
        assert exc_info.value.max_val == 10

    def test_unlimited_always_ok(self):
        set_license(_make_license_state(max_agents=-1))
        check_agent_limit(1_000_000)  # no raise


class TestEndUserLimit:
    def test_under_limit_ok(self):
        set_license(_make_license_state(max_end_users=100))
        check_end_user_limit(99)

    def test_at_limit_raises(self):
        set_license(_make_license_state(max_end_users=100))
        with pytest.raises(LicenseLimitExceeded) as exc_info:
            check_end_user_limit(100)
        assert exc_info.value.limit_name == "max_end_users"

    def test_unlimited_always_ok(self):
        set_license(_make_license_state(max_end_users=-1))
        check_end_user_limit(999_999)


class TestAdminSeatLimit:
    def test_under_limit_ok(self):
        set_license(_make_license_state(max_admin_seats=5))
        check_admin_seat_limit(4)

    def test_at_limit_raises(self):
        set_license(_make_license_state(max_admin_seats=5))
        with pytest.raises(LicenseLimitExceeded) as exc_info:
            check_admin_seat_limit(5)
        assert exc_info.value.limit_name == "max_admin_seats"

    def test_unlimited_always_ok(self):
        set_license(_make_license_state(max_admin_seats=-1))
        check_admin_seat_limit(10_000)


class TestOrgLimit:
    def test_under_limit_ok(self):
        set_license(_make_license_state(max_orgs=5))
        check_org_limit(4)

    def test_at_limit_raises(self):
        set_license(_make_license_state(max_orgs=5))
        with pytest.raises(LicenseLimitExceeded) as exc_info:
            check_org_limit(5)
        assert exc_info.value.limit_name == "max_orgs"

    def test_unlimited_always_ok(self):
        set_license(_make_license_state(max_orgs=-1))
        check_org_limit(9_999)


class TestResponseHelpers:
    def test_feature_gated_response_structure(self):
        set_license(_make_license_state())
        exc = LicenseFeatureGated(feature="saml", tier=LicenseTier.COMMUNITY)
        resp = license_feature_gated_response(exc)
        assert resp["error"] == "LICENSE_FEATURE_GATED"
        assert resp["feature"] == "saml"
        assert "upgrade_url" in resp
        assert "agnosticsec.com" in resp["upgrade_url"]

    def test_limit_exceeded_response_structure(self):
        set_license(_make_license_state())
        exc = LicenseLimitExceeded("max_agents", current=500, max_val=500)
        resp = license_limit_exceeded_response(exc)
        assert resp["error"] == "LICENSE_LIMIT_EXCEEDED"
        assert resp["limit"] == "max_agents"
        assert resp["current"] == 500
        assert resp["maximum"] == 500
        assert "agnosticsec.com" in resp["upgrade_url"]

    def test_upgrade_url_points_to_agnosticsecurity(self):
        """IC-NEW-3 regression: URLs must not point to yashigani.io."""
        set_license(_make_license_state())
        exc = LicenseFeatureGated("scim", LicenseTier.COMMUNITY)
        resp = license_feature_gated_response(exc)
        assert "yashigani.io" not in resp["upgrade_url"], \
            "upgrade_url must point to agnosticsec.com, not yashigani.io"

    def test_all_limit_names_have_labels(self):
        limit_names = ["max_agents", "max_end_users", "max_admin_seats", "max_orgs"]
        set_license(_make_license_state())
        for name in limit_names:
            exc = LicenseLimitExceeded(name, current=1, max_val=1)
            resp = license_limit_exceeded_response(exc)
            assert resp["message"]  # message must not be empty
            assert resp["limit"] == name
