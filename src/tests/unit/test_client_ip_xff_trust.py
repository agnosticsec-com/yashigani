"""
Unit tests: trusted-proxy-boundary XFF resolution.

Covers V232-NEG03 / LAURA-2026-04-29-006 (CWE-345).
Regression guard: spoofed XFF must NOT be trusted; real client through
trusted proxy MUST be extracted; empty chain falls back to peer_addr.

Last updated: 2026-05-01T00:00:00+01:00
"""
from __future__ import annotations

import importlib
import ipaddress
import sys
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# Helpers: build a minimal Starlette Request-like object
# ---------------------------------------------------------------------------

def _make_request(
    xff: str | None = None,
    peer_host: str = "10.0.0.1",
) -> MagicMock:
    """
    Return a mock that looks enough like a Starlette Request for
    _get_client_ip() to consume.
    """
    req = MagicMock()
    req.headers = {}
    if xff is not None:
        req.headers["x-forwarded-for"] = xff
    req.client = MagicMock()
    req.client.host = peer_host
    return req


def _reload_proxy(trusted_cidrs: str) -> object:
    """
    Reload yashigani.gateway.proxy with TRUSTED_PROXY_CIDRS set to
    *trusted_cidrs* so the module-level cache is re-computed.
    Returns the module object.
    """
    import os
    old = os.environ.get("TRUSTED_PROXY_CIDRS")
    os.environ["TRUSTED_PROXY_CIDRS"] = trusted_cidrs
    try:
        # Force re-import so _TRUSTED_PROXY_CIDRS is re-evaluated
        if "yashigani.gateway.proxy" in sys.modules:
            del sys.modules["yashigani.gateway.proxy"]
        import yashigani.gateway.proxy as m
        return m
    finally:
        if old is None:
            os.environ.pop("TRUSTED_PROXY_CIDRS", None)
        else:
            os.environ["TRUSTED_PROXY_CIDRS"] = old


# ---------------------------------------------------------------------------
# Core algorithm tests (module-level function)
# ---------------------------------------------------------------------------

class TestGetClientIpTrustedProxyBoundary:
    """
    _get_client_ip() must walk XFF right-to-left and return the first IP
    that is NOT in TRUSTED_PROXY_CIDRS.
    """

    def test_no_xff_returns_peer_addr(self):
        """Empty XFF → fall back to TCP peer address."""
        m = _reload_proxy("10.10.10.0/24")
        req = _make_request(xff=None, peer_host="203.0.113.5")
        assert m._get_client_ip(req) == "203.0.113.5"

    def test_empty_xff_returns_peer_addr(self):
        """Whitespace-only XFF → fall back to TCP peer address."""
        m = _reload_proxy("10.10.10.0/24")
        req = _make_request(xff="   ", peer_host="203.0.113.5")
        assert m._get_client_ip(req) == "203.0.113.5"

    def test_real_client_behind_one_trusted_proxy(self):
        """
        XFF: <real_client>, <trusted_proxy>
        → real_client must be returned.
        """
        m = _reload_proxy("10.10.10.1/32")
        req = _make_request(xff="203.0.113.99, 10.10.10.1")
        assert m._get_client_ip(req) == "203.0.113.99"

    def test_real_client_behind_two_trusted_proxies(self):
        """
        XFF: <real_client>, <proxy1>, <proxy2>
        Both proxy IPs are trusted → real_client is returned.
        """
        m = _reload_proxy("10.0.0.0/8")
        req = _make_request(xff="198.51.100.7, 10.0.0.5, 10.0.0.6")
        assert m._get_client_ip(req) == "198.51.100.7"

    def test_spoofed_first_hop_is_not_trusted(self):
        """
        CWE-345 regression: an attacker prepends a fake IP.
        XFF: <attacker_ip>, <real_client>, <trusted_proxy>
        → The REAL client (not the spoofed one) must be returned.
        """
        m = _reload_proxy("10.10.10.0/24")
        req = _make_request(xff="1.2.3.4, 203.0.113.50, 10.10.10.1")
        # Walk right-to-left: 10.10.10.1 trusted → 203.0.113.50 NOT trusted → return it
        assert m._get_client_ip(req) == "203.0.113.50"

    def test_spoofed_xff_only_no_trusted_proxy_in_chain(self):
        """
        XFF: <attacker_ip>  (no trusted proxy in chain)
        Peer address is localhost (trusted) → XFF[0] is returned as the
        real client because the attacker is NOT in a trusted CIDR.
        """
        m = _reload_proxy("127.0.0.1/32,::1/128")
        req = _make_request(xff="9.9.9.9", peer_host="127.0.0.1")
        # Walk right-to-left: 9.9.9.9 NOT trusted → return it immediately
        assert m._get_client_ip(req) == "9.9.9.9"

    def test_entire_chain_trusted_returns_leftmost(self):
        """
        If every hop in XFF is trusted, return the leftmost entry — as
        close to real origin as we can get from this chain.
        """
        m = _reload_proxy("10.0.0.0/8")
        req = _make_request(xff="10.0.1.100, 10.0.2.200, 10.0.3.1")
        assert m._get_client_ip(req) == "10.0.1.100"

    def test_ipv6_real_client_behind_trusted_ipv4_proxy(self):
        """IPv6 client addresses are parsed correctly."""
        m = _reload_proxy("10.0.0.1/32")
        req = _make_request(xff="2001:db8::1, 10.0.0.1")
        assert m._get_client_ip(req) == "2001:db8::1"

    def test_malformed_hop_treated_as_untrusted(self):
        """Malformed XFF entry → fail closed: treat as real client (do not crash)."""
        m = _reload_proxy("10.0.0.0/8")
        req = _make_request(xff="not-an-ip, 10.0.0.5")
        # Walk right: 10.0.0.5 trusted; then not-an-ip is malformed → return it
        result = m._get_client_ip(req)
        assert result == "not-an-ip"

    def test_single_real_client_no_proxy(self):
        """No proxy in deployment — XFF has one entry, which is the real client."""
        m = _reload_proxy("127.0.0.1/32,::1/128")
        req = _make_request(xff="198.51.100.42")
        assert m._get_client_ip(req) == "198.51.100.42"

    def test_whitespace_trimming_in_xff(self):
        """Entries with extra spaces are handled correctly."""
        m = _reload_proxy("10.0.0.1/32")
        req = _make_request(xff="  203.0.113.1  ,  10.0.0.1  ")
        assert m._get_client_ip(req) == "203.0.113.1"

    def test_no_client_object_and_no_xff(self):
        """If request.client is None and XFF is empty, return 'unknown'."""
        m = _reload_proxy("10.0.0.0/8")
        req = MagicMock()
        req.headers = {}
        req.client = None
        assert m._get_client_ip(req) == "unknown"


# ---------------------------------------------------------------------------
# CIDR parser tests
# ---------------------------------------------------------------------------

class TestParseTrustedProxyCidrs:
    def test_default_loopback_only(self, monkeypatch):
        monkeypatch.delenv("TRUSTED_PROXY_CIDRS", raising=False)
        if "yashigani.gateway.proxy" in sys.modules:
            del sys.modules["yashigani.gateway.proxy"]
        import yashigani.gateway.proxy as m
        cidrs = m._parse_trusted_proxy_cidrs()
        assert ipaddress.ip_network("127.0.0.1/32") in cidrs
        assert ipaddress.ip_network("::1/128") in cidrs

    def test_custom_cidrs_parsed(self, monkeypatch):
        monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "10.0.0.0/8,172.16.0.0/12")
        if "yashigani.gateway.proxy" in sys.modules:
            del sys.modules["yashigani.gateway.proxy"]
        import yashigani.gateway.proxy as m
        cidrs = m._parse_trusted_proxy_cidrs()
        assert ipaddress.ip_network("10.0.0.0/8") in cidrs
        assert ipaddress.ip_network("172.16.0.0/12") in cidrs

    def test_invalid_cidr_skipped_with_fallback(self, monkeypatch):
        """All-invalid CIDR env falls back to loopback."""
        monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "not-a-cidr,also-bad")
        if "yashigani.gateway.proxy" in sys.modules:
            del sys.modules["yashigani.gateway.proxy"]
        import yashigani.gateway.proxy as m
        cidrs = m._parse_trusted_proxy_cidrs()
        assert ipaddress.ip_network("127.0.0.1/32") in cidrs
        assert ipaddress.ip_network("::1/128") in cidrs

    def test_mixed_valid_invalid_skips_bad(self, monkeypatch):
        """One good CIDR survives even if others are malformed."""
        monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "10.0.0.0/8,garbage,192.168.0.0/16")
        if "yashigani.gateway.proxy" in sys.modules:
            del sys.modules["yashigani.gateway.proxy"]
        import yashigani.gateway.proxy as m
        cidrs = m._parse_trusted_proxy_cidrs()
        assert ipaddress.ip_network("10.0.0.0/8") in cidrs
        assert ipaddress.ip_network("192.168.0.0/16") in cidrs


# ---------------------------------------------------------------------------
# agent_auth.py delegation test
# ---------------------------------------------------------------------------

class TestAgentAuthDelegates:
    def test_agent_auth_get_client_ip_delegates_to_proxy(self):
        """
        agent_auth._get_client_ip must delegate to proxy._get_client_ip —
        not use the old first-XFF-trust local copy.
        """
        # Force reload of proxy with a known trusted CIDR
        m = _reload_proxy("10.0.0.1/32")
        # Force reload of agent_auth so it picks up the reloaded proxy
        if "yashigani.gateway.agent_auth" in sys.modules:
            del sys.modules["yashigani.gateway.agent_auth"]
        import yashigani.gateway.agent_auth as aa
        req = _make_request(xff="203.0.113.77, 10.0.0.1")
        # Spoofed first-hop scenario: 10.0.0.1 is trusted proxy, 203.0.113.77 is client
        result = aa._get_client_ip(req)
        assert result == "203.0.113.77", (
            "agent_auth._get_client_ip trusted first XFF hop (CWE-345 regression)"
        )

    def test_agent_auth_old_first_hop_bug_is_gone(self):
        """
        Regression: old code returned XFF[0] unconditionally.
        With a spoofed chain <attacker>, <real_client>, <trusted_proxy>,
        the result must NOT be <attacker>.
        """
        m = _reload_proxy("10.0.0.0/8")
        if "yashigani.gateway.agent_auth" in sys.modules:
            del sys.modules["yashigani.gateway.agent_auth"]
        import yashigani.gateway.agent_auth as aa
        req = _make_request(xff="1.1.1.1, 203.0.113.5, 10.0.0.3")
        result = aa._get_client_ip(req)
        assert result != "1.1.1.1", (
            "agent_auth returned spoofed attacker IP from XFF[0] (CWE-345)"
        )
        assert result == "203.0.113.5"
