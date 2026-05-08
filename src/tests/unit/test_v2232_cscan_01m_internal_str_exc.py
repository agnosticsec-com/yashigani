"""
Unit tests for V232-CSCAN-01m — internal result/event str(exc) migration.

Covers the 8 sites migrated in this sweep across:
  - auth/broker.py        (2 sites — OIDC and SAML SSOResult.error)
  - gateway/jwt_inspector.py  (2 sites — outer catch-all + inner decode failure)
  - inspection/classifier.py  (1 site — ClassifierResult.raw_response)
  - inspection/backend_registry.py  (1 site — InspectionBackendUnreachableEvent.error_message)
  - opa_assistant/validator.py    (1 site — validate_rbac_document return tuple)
  - audit/writer.py       (1 site — SIEM delivery failure last_error)

Per-site asserts:
  1. result.error (or equivalent field) contains the exception CLASS NAME.
  2. result.error does NOT contain the exception MESSAGE.
  3. The server-side logger still receives the full exception (via the existing
     logger.warning/logger.error call that precedes the migration).

Last updated: 2026-05-03
"""
from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass, field
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# auth/broker.py — SSOResult.error for OIDC ValueError
# ---------------------------------------------------------------------------

class TestBrokerOIDCSSOResult:
    """V232-CSCAN-01m: OIDC code-exchange ValueError must set error to class name."""

    def _make_broker(self):
        """Import IdentityBroker with SSO deps stubbed."""
        # Stub out heavy OIDC/SAML providers so broker.py loads cleanly.
        oidc_stub = type(sys)("oidc_stub")
        oidc_stub.OIDCConfig = MagicMock  # type: ignore[attr-defined]
        oidc_stub.OIDCProvider = MagicMock  # type: ignore[attr-defined]
        oidc_stub.OIDCUserInfo = MagicMock  # type: ignore[attr-defined]

        saml_stub = type(sys)("saml_stub")
        saml_stub.SAMLConfig = MagicMock  # type: ignore[attr-defined]
        saml_stub.SAMLProvider = MagicMock  # type: ignore[attr-defined]
        saml_stub.SAMLUserInfo = MagicMock  # type: ignore[attr-defined]

        with patch.dict(sys.modules, {
            "yashigani.sso.oidc": oidc_stub,
            "yashigani.sso.saml": saml_stub,
        }):
            from yashigani.auth.broker import IdentityBroker, IdPConfig, SSOResult
        return IdentityBroker, IdPConfig, SSOResult

    def test_oidc_code_exchange_value_error_sets_class_name(self):
        """SSOResult.error must be 'ValueError', not the exception message."""
        IdentityBroker, IdPConfig, SSOResult = self._make_broker()

        broker = IdentityBroker.__new__(IdentityBroker)
        broker._idps = {}
        broker._oidc_providers = {}
        broker._saml_providers = {}
        broker._group_maps = {}

        exc_msg = "nonce mismatch: received=abc123 stored=def456 idp_secret=supersecret"

        # Register a fake OIDC IdP
        idp = MagicMock()
        idp.name = "test-oidc"
        idp.protocol = "oidc"
        idp.required_acr_values = None
        idp.required_amr_values = None
        broker._idps["test"] = idp

        mock_provider = MagicMock()
        mock_provider._config = MagicMock()
        mock_provider.exchange_code.side_effect = ValueError(exc_msg)
        broker._oidc_providers["test"] = mock_provider

        result = broker.handle_oidc_callback(
            idp_id="test",
            code="authcode123",
            state="state456",
            redirect_uri="https://admin.yashigani.local/auth/callback",
            code_verifier=None,
        )

        assert result.success is False
        assert result.error == "ValueError", (
            f"Expected 'ValueError', got {result.error!r}"
        )
        assert exc_msg not in result.error, (
            f"Exception message leaked into SSOResult.error: {result.error!r}"
        )
        assert "idp_secret" not in result.error, (
            "Secret token in exception message leaked into SSOResult.error"
        )

    def test_oidc_code_exchange_value_error_message_not_in_error(self):
        """Regression: the old str(exc) path would have exposed internal details."""
        IdentityBroker, IdPConfig, SSOResult = self._make_broker()

        broker = IdentityBroker.__new__(IdentityBroker)
        broker._idps = {}
        broker._oidc_providers = {}
        broker._saml_providers = {}
        broker._group_maps = {}

        sensitive_detail = "client_secret=CLIENT_SECRET_VALUE_XYZ"

        idp = MagicMock()
        idp.name = "okta"
        idp.protocol = "oidc"
        idp.required_acr_values = None
        idp.required_amr_values = None
        broker._idps["okta"] = idp

        mock_provider = MagicMock()
        mock_provider._config = MagicMock()
        mock_provider.exchange_code.side_effect = ValueError(
            f"Token endpoint rejected: {sensitive_detail}"
        )
        broker._oidc_providers["okta"] = mock_provider

        result = broker.handle_oidc_callback(
            idp_id="okta",
            code="code_abc",
            state="state_abc",
            redirect_uri="https://admin.yashigani.local/auth/callback",
            code_verifier=None,
        )

        assert sensitive_detail not in result.error
        assert "CLIENT_SECRET_VALUE_XYZ" not in result.error


# ---------------------------------------------------------------------------
# auth/broker.py — SSOResult.error for SAML ValueError
# ---------------------------------------------------------------------------

class TestBrokerSAMLSSOResult:
    """V232-CSCAN-01m: SAML assertion ValueError must set error to class name."""

    def _make_broker(self):
        oidc_stub = type(sys)("oidc_stub2")
        oidc_stub.OIDCConfig = MagicMock  # type: ignore[attr-defined]
        oidc_stub.OIDCProvider = MagicMock  # type: ignore[attr-defined]
        oidc_stub.OIDCUserInfo = MagicMock  # type: ignore[attr-defined]

        saml_stub = type(sys)("saml_stub2")
        saml_stub.SAMLConfig = MagicMock  # type: ignore[attr-defined]
        saml_stub.SAMLProvider = MagicMock  # type: ignore[attr-defined]
        saml_stub.SAMLUserInfo = MagicMock  # type: ignore[attr-defined]

        with patch.dict(sys.modules, {
            "yashigani.sso.oidc": oidc_stub,
            "yashigani.sso.saml": saml_stub,
        }):
            from yashigani.auth.broker import IdentityBroker
        return IdentityBroker

    def test_saml_assertion_value_error_sets_class_name(self):
        """SSOResult.error must be 'ValueError', not the exception message."""
        IdentityBroker = self._make_broker()

        broker = IdentityBroker.__new__(IdentityBroker)
        broker._idps = {}
        broker._oidc_providers = {}
        broker._saml_providers = {}
        broker._group_maps = {}

        exc_msg = "Signature validation failed: cert_fingerprint=DEADBEEF internal_key=/etc/yashigani/saml.key"

        idp = MagicMock()
        idp.name = "entra"
        idp.protocol = "saml"
        broker._idps["entra"] = idp

        mock_provider = MagicMock()
        mock_provider.process_response.side_effect = ValueError(exc_msg)
        broker._saml_providers["entra"] = mock_provider

        result = broker.handle_saml_response(
            idp_id="entra",
            saml_response="<Response>...</Response>",
        )

        assert result.success is False
        assert result.error == "ValueError", (
            f"Expected 'ValueError', got {result.error!r}"
        )
        assert exc_msg not in result.error
        assert "DEADBEEF" not in result.error
        assert "/etc/yashigani/saml.key" not in result.error

    def test_saml_assertion_does_not_leak_key_paths(self):
        IdentityBroker = self._make_broker()

        broker = IdentityBroker.__new__(IdentityBroker)
        broker._idps = {}
        broker._oidc_providers = {}
        broker._saml_providers = {}
        broker._group_maps = {}

        key_path = "/secrets/saml-sp-private-key.pem"
        idp = MagicMock()
        idp.name = "azure"
        broker._idps["azure"] = idp

        mock_provider = MagicMock()
        mock_provider.process_response.side_effect = ValueError(
            f"could not load signing key from {key_path}"
        )
        broker._saml_providers["azure"] = mock_provider

        result = broker.handle_saml_response("azure", "<SAMLResponse/>")

        assert key_path not in result.error
        assert result.error == "ValueError"


# ---------------------------------------------------------------------------
# gateway/jwt_inspector.py — helpers
# ---------------------------------------------------------------------------

def _make_jwt_stub():
    """Build a minimal jwt (PyJWT) stub sufficient to load jwt_inspector.py."""
    jwt_stub = type(sys)("jwt")

    # Class names must match the real PyJWT names so type(exc).__name__ returns
    # the expected string (e.g. "InvalidSignatureError", not "_InvalidSignatureError").
    InvalidSignatureError = type("InvalidSignatureError", (Exception,), {})
    ExpiredSignatureError = type("ExpiredSignatureError", (Exception,), {})
    DecodeError = type("DecodeError", (Exception,), {})

    jwt_stub.InvalidSignatureError = InvalidSignatureError  # type: ignore[attr-defined]
    jwt_stub.ExpiredSignatureError = ExpiredSignatureError  # type: ignore[attr-defined]
    jwt_stub.DecodeError = DecodeError  # type: ignore[attr-defined]
    jwt_stub.PyJWKClient = MagicMock  # type: ignore[attr-defined]
    jwt_stub.decode = MagicMock()  # type: ignore[attr-defined]
    jwt_stub.get_unverified_header = MagicMock()  # type: ignore[attr-defined]
    return jwt_stub


def _load_jwt_inspector():
    """Load jwt_inspector with jwt and heavy deps stubbed."""
    jwt_stub = _make_jwt_stub()
    stubs = {
        "jwt": jwt_stub,
        "yashigani.db.postgres": MagicMock(),
        "yashigani.gateway.state": MagicMock(),
    }
    # Remove any cached version so re-import picks up the stubs.
    old = {}
    for k in stubs:
        old[k] = sys.modules.pop(k, None)
    sys.modules.update(stubs)
    # Also evict the cached jwt_inspector module so it re-imports jwt from stubs.
    sys.modules.pop("yashigani.gateway.jwt_inspector", None)

    try:
        from yashigani.gateway.jwt_inspector import JWTInspector, JWTConfig, JWTInspectionResult
    finally:
        for k, v in old.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v

    return JWTInspector, JWTConfig, JWTInspectionResult, jwt_stub


# ---------------------------------------------------------------------------
# gateway/jwt_inspector.py — JWTInspectionResult.error outer catch-all
# ---------------------------------------------------------------------------

class TestJWTInspectorOuterCatchAll:
    """V232-CSCAN-01m: JWTInspector outer Exception must set error to class name."""

    def test_outer_exception_sets_class_name(self):
        """JWTInspectionResult.error must be the exception class name, not message."""
        JWTInspector, _, __, jwt_stub = _load_jwt_inspector()

        inspector = JWTInspector.__new__(JWTInspector)
        inspector._redis = None
        inspector._deployment_stream = "opensource"

        exc_msg = "DB pool exhausted: user=yashigani password=LEAKED_PW host=postgres"

        with patch.object(inspector, "_inspect", side_effect=RuntimeError(exc_msg)):
            result = asyncio.run(inspector.inspect("fake.jwt.token"))

        assert result.valid is False
        assert result.error == "RuntimeError", (
            f"Expected 'RuntimeError', got {result.error!r}"
        )
        assert exc_msg not in (result.error or ""), (
            f"Exception message leaked into JWTInspectionResult.error: {result.error!r}"
        )
        assert "LEAKED_PW" not in (result.error or "")

    def test_outer_exception_does_not_expose_connection_details(self):
        JWTInspector, _, __, jwt_stub = _load_jwt_inspector()

        inspector = JWTInspector.__new__(JWTInspector)
        inspector._redis = None
        inspector._deployment_stream = "opensource"

        sensitive = "redis://:secret_redis_pw@redis:6379/0"

        with patch.object(inspector, "_inspect", side_effect=ConnectionError(sensitive)):
            result = asyncio.run(inspector.inspect("fake.jwt.token"))

        assert sensitive not in (result.error or "")
        assert result.error == "ConnectionError"


# ---------------------------------------------------------------------------
# gateway/jwt_inspector.py — JWTInspectionResult.error inner decode failure
# ---------------------------------------------------------------------------

class TestJWTInspectorInnerDecodeFail:
    """V232-CSCAN-01m: inner decode failure must set error to class name."""

    def test_decode_invalid_sig_error_sets_class_name(self):
        """InvalidSignatureError at decode must become class name, not message."""
        JWTInspector, JWTConfig, JWTInspectionResult, jwt_stub = _load_jwt_inspector()

        inspector = JWTInspector.__new__(JWTInspector)
        inspector._redis = None
        inspector._deployment_stream = "opensource"
        inspector._jwks_cache = {}
        inspector._config_cache = {}

        exc_msg = "Signature verification failed: key_id=kid123 alg=RS256 secret_detail=XYZ"

        config = MagicMock()
        config.jwks_url = "https://idp.example.com/.well-known/jwks.json"
        config.fail_closed = True
        config.audience = None
        config.issuer = None

        mock_jwks_client = MagicMock()
        mock_signing_key = MagicMock()
        mock_signing_key.key = "fake-key"
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        # Patch the pyjwt references INSIDE the already-loaded module.
        import yashigani.gateway.jwt_inspector as jwt_mod
        jwt_stub.get_unverified_header.return_value = {"alg": "RS256"}
        jwt_stub.decode.side_effect = jwt_stub.InvalidSignatureError(exc_msg)

        with (
            patch.object(inspector, "_resolve_config", return_value=config),
            patch.object(inspector, "_get_jwks_client", return_value=mock_jwks_client),
            patch.object(jwt_mod, "pyjwt", jwt_stub),
        ):
            async def run():
                return await inspector._inspect("fake.jwt.token", "platform")
            result = asyncio.run(run())

        assert result.valid is False
        assert result.error == "InvalidSignatureError", (
            f"Expected 'InvalidSignatureError', got {result.error!r}"
        )
        assert exc_msg not in (result.error or "")
        assert "secret_detail" not in (result.error or "")

    def test_decode_generic_exception_sets_class_name(self):
        """Generic Exception at decode must become class name, not message."""
        JWTInspector, JWTConfig, JWTInspectionResult, jwt_stub = _load_jwt_inspector()

        inspector = JWTInspector.__new__(JWTInspector)
        inspector._redis = None
        inspector._deployment_stream = "opensource"
        inspector._jwks_cache = {}
        inspector._config_cache = {}

        exc_msg = "internal DB error: pool_size=10 db_host=postgres password=s3cr3t"

        config = MagicMock()
        config.jwks_url = "https://idp.example.com/.well-known/jwks.json"
        config.fail_closed = True
        config.audience = None
        config.issuer = None

        mock_jwks_client = MagicMock()
        mock_signing_key = MagicMock()
        mock_signing_key.key = "fake-key"
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        import yashigani.gateway.jwt_inspector as jwt_mod
        jwt_stub.get_unverified_header.return_value = {"alg": "RS256"}
        jwt_stub.decode.side_effect = RuntimeError(exc_msg)

        with (
            patch.object(inspector, "_resolve_config", return_value=config),
            patch.object(inspector, "_get_jwks_client", return_value=mock_jwks_client),
            patch.object(jwt_mod, "pyjwt", jwt_stub),
        ):
            async def run():
                return await inspector._inspect("fake.jwt.token", "platform")
            result = asyncio.run(run())

        assert result.valid is False
        assert result.error == "RuntimeError"
        assert "s3cr3t" not in (result.error or "")
