"""
Unit tests for OIDC endpoint validation — YSG-RISK-003 (CWE-601).

Verifies that _assert_oidc_endpoint() on OIDCProvider:
  - PASS: endpoint hostname matches discovery_url hostname
  - PASS: glob-allowed hostname matches allowed_auth_endpoint_pattern
  - REJECT: mismatched hostname raises HTTPException(502)
  - REJECT: http:// scheme raises HTTPException(502)
  - REJECT: glob pattern that does not match raises HTTPException(502)

These tests do NOT require a live OIDC server, authlib, or asyncpg.
"""
from __future__ import annotations

import pytest


def _make_provider(discovery_url: str, pattern: str | None = None):
    """Build an OIDCProvider with a dummy config for validation testing."""
    from yashigani.sso.oidc import OIDCConfig, OIDCProvider
    cfg = OIDCConfig(
        client_id="test-client",
        client_secret="test-secret",
        discovery_url=discovery_url,
        redirect_uri="https://yashigani.example.com/callback",
        allowed_auth_endpoint_pattern=pattern,
    )
    p = OIDCProvider(cfg)
    return p


class TestAssertOidcEndpointMatchingHost:
    def test_same_host_passes(self):
        """Endpoint on same host as discovery_url must pass."""
        p = _make_provider("https://accounts.example.com/.well-known/openid-configuration")
        # Should not raise
        p._assert_oidc_endpoint(
            "authorization_endpoint",
            "https://accounts.example.com/authorize",
        )

    def test_same_host_different_path_passes(self):
        """Endpoint on same host, different path, must pass."""
        p = _make_provider("https://login.microsoftonline.com/tenant/.well-known/openid-configuration")
        p._assert_oidc_endpoint(
            "token_endpoint",
            "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
        )

    def test_same_host_case_insensitive(self):
        """Hostname comparison is case-insensitive."""
        p = _make_provider("https://Accounts.EXAMPLE.COM/.well-known/openid-configuration")
        p._assert_oidc_endpoint(
            "jwks_uri",
            "https://accounts.example.com/jwks",
        )


class TestAssertOidcEndpointMismatchedHost:
    def test_different_host_raises(self):
        """Endpoint on a different hostname must raise HTTPException(502)."""
        from fastapi import HTTPException
        p = _make_provider("https://legit.example.com/.well-known/openid-configuration")
        with pytest.raises(HTTPException) as exc_info:
            p._assert_oidc_endpoint(
                "authorization_endpoint",
                "https://attacker.evil.com/authorize",
            )
        assert exc_info.value.status_code == 502
        assert exc_info.value.detail == "oidc_discovery_invalid"

    def test_subdomain_of_discovery_host_raises_without_pattern(self):
        """A subdomain of discovery host is still a different host — rejected."""
        from fastapi import HTTPException
        p = _make_provider("https://example.com/.well-known/openid-configuration")
        with pytest.raises(HTTPException) as exc_info:
            p._assert_oidc_endpoint(
                "authorization_endpoint",
                "https://evil.example.com/authorize",
            )
        assert exc_info.value.status_code == 502

    def test_internal_service_host_raises(self):
        """An attacker-supplied jwks_uri pointing at postgres must be rejected."""
        from fastapi import HTTPException
        p = _make_provider("https://legit-idp.example.com/.well-known/openid-configuration")
        with pytest.raises(HTTPException) as exc_info:
            p._assert_oidc_endpoint(
                "jwks_uri",
                "https://postgres:5432/",
            )
        assert exc_info.value.status_code == 502


class TestAssertOidcEndpointScheme:
    def test_http_scheme_raises(self):
        """http:// endpoint must be rejected regardless of host."""
        from fastapi import HTTPException
        p = _make_provider("https://accounts.example.com/.well-known/openid-configuration")
        with pytest.raises(HTTPException) as exc_info:
            p._assert_oidc_endpoint(
                "authorization_endpoint",
                "http://accounts.example.com/authorize",
            )
        assert exc_info.value.status_code == 502
        assert exc_info.value.detail == "oidc_discovery_invalid"

    def test_ftp_scheme_raises(self):
        """Non-http(s) scheme must be rejected."""
        from fastapi import HTTPException
        p = _make_provider("https://accounts.example.com/.well-known/openid-configuration")
        with pytest.raises(HTTPException) as exc_info:
            p._assert_oidc_endpoint(
                "authorization_endpoint",
                "ftp://accounts.example.com/authorize",
            )
        assert exc_info.value.status_code == 502

    def test_javascript_scheme_raises(self):
        """javascript: URI is rejected by scheme check."""
        from fastapi import HTTPException
        p = _make_provider("https://accounts.example.com/.well-known/openid-configuration")
        with pytest.raises(HTTPException) as exc_info:
            p._assert_oidc_endpoint(
                "authorization_endpoint",
                "javascript:alert(1)",
            )
        assert exc_info.value.status_code == 502


class TestAssertOidcEndpointGlobPattern:
    def test_glob_allowed_host_passes(self):
        """When pattern is set and endpoint hostname matches glob, it passes."""
        p = _make_provider(
            "https://primary-idp.corp.example.com/.well-known/openid-configuration",
            pattern="*.corp.example.com",
        )
        # Different subdomain allowed by glob
        p._assert_oidc_endpoint(
            "authorization_endpoint",
            "https://auth.corp.example.com/authorize",
        )

    def test_glob_non_matching_host_raises(self):
        """When pattern is set and endpoint hostname does NOT match glob, raises 502."""
        from fastapi import HTTPException
        p = _make_provider(
            "https://primary-idp.corp.example.com/.well-known/openid-configuration",
            pattern="*.corp.example.com",
        )
        with pytest.raises(HTTPException) as exc_info:
            p._assert_oidc_endpoint(
                "authorization_endpoint",
                "https://evil.other.com/authorize",
            )
        assert exc_info.value.status_code == 502

    def test_glob_http_still_rejected(self):
        """http:// scheme is rejected even when glob pattern would match the host."""
        from fastapi import HTTPException
        p = _make_provider(
            "https://primary-idp.corp.example.com/.well-known/openid-configuration",
            pattern="*.corp.example.com",
        )
        with pytest.raises(HTTPException) as exc_info:
            p._assert_oidc_endpoint(
                "authorization_endpoint",
                "http://auth.corp.example.com/authorize",
            )
        assert exc_info.value.status_code == 502

    def test_exact_hostname_pattern_passes(self):
        """A fully-qualified hostname pattern (no glob) still works."""
        p = _make_provider(
            "https://idp1.example.com/.well-known/openid-configuration",
            pattern="auth.example.com",
        )
        p._assert_oidc_endpoint(
            "authorization_endpoint",
            "https://auth.example.com/authorize",
        )
