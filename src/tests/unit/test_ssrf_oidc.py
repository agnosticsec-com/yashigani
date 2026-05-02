"""
Unit tests for OIDC discovery SSRF allowlist — YSG-RISK-007.B (CWE-918).

Verifies:
  B1 — _assert_safe_discovery_url():
    - https scheme required
    - YASHIGANI_OIDC_DISCOVERY_HOSTS env allowlist enforced (when set)
    - "*" wildcard allows any https host
    - No env var = any https host allowed

  B2 — jwks_uri host-binding (tested via _assert_oidc_endpoint in
        test_oidc_endpoint_validation.py; an additional integration-style
        assertion here confirms the postgres:5432 scenario).
"""
from __future__ import annotations

import os
import pytest


def _make_provider(discovery_url: str = "https://idp.example.com/.well-known/openid-configuration",
                   pattern: str | None = None):
    from yashigani.sso.oidc import OIDCConfig, OIDCProvider
    cfg = OIDCConfig(
        client_id="test-client",
        client_secret="test-secret",
        discovery_url=discovery_url,
        redirect_uri="https://yashigani.example.com/callback",
        allowed_auth_endpoint_pattern=pattern,
    )
    return OIDCProvider(cfg)


def _call_safe_discovery(discovery_url: str, hosts_env: str = ""):
    p = _make_provider(discovery_url=discovery_url)
    if hosts_env is not None:
        old = os.environ.get("YASHIGANI_OIDC_DISCOVERY_HOSTS")
        os.environ["YASHIGANI_OIDC_DISCOVERY_HOSTS"] = hosts_env
        try:
            return p._assert_safe_discovery_url(discovery_url)
        finally:
            if old is None:
                os.environ.pop("YASHIGANI_OIDC_DISCOVERY_HOSTS", None)
            else:
                os.environ["YASHIGANI_OIDC_DISCOVERY_HOSTS"] = old
    else:
        return p._assert_safe_discovery_url(discovery_url)


class TestAssertSafeDiscoveryUrl:
    def test_https_no_allowlist_passes(self):
        """https:// with no YASHIGANI_OIDC_DISCOVERY_HOSTS set must pass."""
        old = os.environ.pop("YASHIGANI_OIDC_DISCOVERY_HOSTS", None)
        try:
            _call_safe_discovery(
                "https://accounts.google.com/.well-known/openid-configuration",
                hosts_env="",
            )
        finally:
            if old is not None:
                os.environ["YASHIGANI_OIDC_DISCOVERY_HOSTS"] = old

    def test_http_scheme_rejected(self):
        """http:// discovery_url must be rejected (B1 — CWE-918)."""
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            _call_safe_discovery("http://idp.example.com/.well-known/openid-configuration")
        assert exc_info.value.status_code == 502

    def test_metadata_endpoint_http_rejected(self):
        """http://169.254.169.254/ as discovery_url must be rejected."""
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            _call_safe_discovery("http://169.254.169.254/latest/meta-data/")
        assert exc_info.value.status_code == 502

    def test_allowlist_permits_listed_host(self):
        """Host in YASHIGANI_OIDC_DISCOVERY_HOSTS passes."""
        _call_safe_discovery(
            "https://idp.corp.example.com/.well-known/openid-configuration",
            hosts_env="idp.corp.example.com,other.corp.example.com",
        )

    def test_allowlist_blocks_unlisted_host(self):
        """Host not in YASHIGANI_OIDC_DISCOVERY_HOSTS is blocked."""
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            _call_safe_discovery(
                "https://evil.example.com/.well-known/openid-configuration",
                hosts_env="idp.corp.example.com",
            )
        assert exc_info.value.status_code == 502

    def test_wildcard_allows_any_https_host(self):
        """YASHIGANI_OIDC_DISCOVERY_HOSTS=* allows any https host."""
        _call_safe_discovery(
            "https://random-idp.anything.com/.well-known/openid-configuration",
            hosts_env="*",
        )

    def test_glob_pattern_in_allowlist(self):
        """fnmatch glob in allowlist (*.corp.example.com) matches subdomains."""
        _call_safe_discovery(
            "https://sub.corp.example.com/.well-known/openid-configuration",
            hosts_env="*.corp.example.com",
        )

    def test_glob_pattern_does_not_match_unrelated(self):
        """fnmatch glob does not match unrelated host."""
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            _call_safe_discovery(
                "https://attacker.evil.com/.well-known/openid-configuration",
                hosts_env="*.corp.example.com",
            )
        assert exc_info.value.status_code == 502


class TestJwksUriHostBinding:
    """B2: jwks_uri hostname must equal discovery_url hostname (no pattern)."""

    def test_postgres_ssrf_in_jwks_uri_rejected(self):
        """meta['jwks_uri'] pointing at postgres must be rejected."""
        from fastapi import HTTPException
        p = _make_provider("https://legit-idp.example.com/.well-known/openid-configuration")
        with pytest.raises(HTTPException) as exc_info:
            p._assert_oidc_endpoint("jwks_uri", "http://postgres:5432/")
        assert exc_info.value.status_code == 502

    def test_http_jwks_uri_rejected(self):
        """http:// jwks_uri must be rejected even if hostname matches."""
        from fastapi import HTTPException
        p = _make_provider("https://legit-idp.example.com/.well-known/openid-configuration")
        with pytest.raises(HTTPException) as exc_info:
            p._assert_oidc_endpoint("jwks_uri", "http://legit-idp.example.com/jwks")
        assert exc_info.value.status_code == 502

    def test_same_host_jwks_uri_passes(self):
        """jwks_uri on the same host as discovery_url must pass."""
        p = _make_provider("https://legit-idp.example.com/.well-known/openid-configuration")
        p._assert_oidc_endpoint("jwks_uri", "https://legit-idp.example.com/jwks.json")
