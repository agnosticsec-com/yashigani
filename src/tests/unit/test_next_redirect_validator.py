"""
Server-side next= redirect validator — unit tests.

Closes drift audit finding #6: the JS guard in login.js (safeNext()) runs at
the client trust boundary only.  GET /auth/post-login-redirect enforces the
same rules at the HTTP trust boundary.

These tests exercise _validate_next() directly (pure function, no I/O) and
the /auth/post-login-redirect endpoint via FastAPI TestClient (no Redis/Postgres
required — audit_writer is stubbed).

References:
  ASVS V5.1.5 / CWE-601 / OWASP A01:2021 / drift audit finding #6.

Last updated: 2026-05-24
"""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Unit tests for _validate_next()
# ---------------------------------------------------------------------------

from yashigani.backoffice.routes.auth import _validate_next, _hash_ip, _sanitise_for_audit


class TestValidateNextValid:
    """Valid paths must be accepted and returned unchanged."""

    def test_simple_path(self):
        ok, val = _validate_next("/dashboard")
        assert ok is True
        assert val == "/dashboard"

    def test_admin_agents(self):
        ok, val = _validate_next("/admin/agents")
        assert ok is True
        assert val == "/admin/agents"

    def test_root_slash(self):
        ok, val = _validate_next("/")
        assert ok is True
        assert val == "/"

    def test_path_with_query(self):
        ok, val = _validate_next("/admin/agents?tab=active")
        assert ok is True
        assert val == "/admin/agents?tab=active"

    def test_path_with_hash(self):
        ok, val = _validate_next("/dashboard#health")
        assert ok is True
        assert val == "/dashboard#health"

    def test_path_with_query_and_hash(self):
        ok, val = _validate_next("/admin/users?page=2#list")
        assert ok is True
        assert val == "/admin/users?page=2#list"

    def test_deep_path(self):
        ok, val = _validate_next("/admin/rbac/policies/edit")
        assert ok is True
        assert val == "/admin/rbac/policies/edit"

    def test_path_with_hyphen_and_underscore(self):
        ok, val = _validate_next("/admin/kms-vault/key_rotation")
        assert ok is True
        assert val == "/admin/kms-vault/key_rotation"


class TestValidateNextInvalid:
    """Invalid values must be rejected with the correct reason code."""

    def test_empty_string(self):
        ok, reason = _validate_next("")
        assert ok is False
        assert reason == "empty"

    def test_backslash_bypass(self):
        """IE/Edge normalise /\\ → // producing off-origin redirect."""
        ok, reason = _validate_next(r"\evil.com")
        assert ok is False

    def test_backslash_after_slash(self):
        """/\\ is the primary V232-CSCAN-01d bypass vector."""
        ok, reason = _validate_next("/\\evil.com")
        assert ok is False
        assert reason == "double_slash"

    def test_backslash_traversal(self):
        ok, reason = _validate_next("/foo\\..\\..\\etc\\passwd")
        assert ok is False
        assert reason in ("double_slash", "backslash")

    def test_double_slash(self):
        ok, reason = _validate_next("//evil.com")
        assert ok is False
        assert reason == "double_slash"

    def test_triple_slash(self):
        ok, reason = _validate_next("///evil.com")
        assert ok is False
        assert reason == "double_slash"

    def test_https_absolute(self):
        ok, reason = _validate_next("https://evil.com/path")
        assert ok is False
        assert reason in ("not_relative", "absolute_url")

    def test_http_absolute(self):
        ok, reason = _validate_next("http://evil.com")
        assert ok is False
        assert reason in ("not_relative", "absolute_url")

    def test_javascript_scheme(self):
        ok, reason = _validate_next("javascript:alert(1)")
        assert ok is False
        assert reason in ("not_relative", "absolute_url")

    def test_ftp_scheme(self):
        ok, reason = _validate_next("ftp://files.evil.com")
        assert ok is False

    def test_userinfo_at(self):
        """URL-userinfo trick: /user@evil.com parsed as authority=user@evil.com."""
        ok, reason = _validate_next("/user@evil.com")
        assert ok is False
        assert reason == "userinfo_at"

    def test_userinfo_at_in_path(self):
        ok, reason = _validate_next("/admin/redirect@evil.com")
        assert ok is False
        assert reason == "userinfo_at"

    def test_too_long(self):
        ok, reason = _validate_next("/" + "a" * 5000)
        assert ok is False
        assert reason == "too_long"

    def test_exactly_at_limit(self):
        """Exactly at _NEXT_MAX_LENGTH = 2048 chars: still valid."""
        from yashigani.backoffice.routes.auth import _NEXT_MAX_LENGTH
        path = "/" + "a" * (_NEXT_MAX_LENGTH - 1)
        assert len(path) == _NEXT_MAX_LENGTH
        ok, val = _validate_next(path)
        assert ok is True

    def test_one_over_limit(self):
        from yashigani.backoffice.routes.auth import _NEXT_MAX_LENGTH
        path = "/" + "a" * _NEXT_MAX_LENGTH  # len = _NEXT_MAX_LENGTH + 1
        ok, reason = _validate_next(path)
        assert ok is False
        assert reason == "too_long"

    def test_no_leading_slash(self):
        ok, reason = _validate_next("admin/agents")
        assert ok is False
        assert reason == "not_relative"

    def test_backslash_anywhere(self):
        ok, reason = _validate_next("/foo/bar\\baz")
        assert ok is False
        assert reason == "backslash"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_hash_ip_deterministic(self):
        h1 = _hash_ip("192.168.1.1")
        h2 = _hash_ip("192.168.1.1")
        assert h1 == h2
        assert len(h1) == 16

    def test_hash_ip_different_ips(self):
        assert _hash_ip("192.168.1.1") != _hash_ip("10.0.0.1")

    def test_sanitise_truncates(self):
        long_val = "/foo" + "x" * 200
        result = _sanitise_for_audit(long_val)
        assert len(result) == 128

    def test_sanitise_replaces_non_printable(self):
        val = "/foo\x00bar\x1f"
        result = _sanitise_for_audit(val)
        assert "\x00" not in result
        assert "\x1f" not in result
        assert "?" in result

    def test_sanitise_preserves_printable_ascii(self):
        val = "/admin/agents?tab=active"
        assert _sanitise_for_audit(val) == val


# ---------------------------------------------------------------------------
# Endpoint tests via FastAPI TestClient
#
# These tests stub the backoffice_state.audit_writer so no Redis/Postgres is
# needed.  They exercise the HTTP-layer redirect behaviour.
# ---------------------------------------------------------------------------


def _make_app_with_stub_state():
    """
    Import the auth router and mount it in a minimal FastAPI app.
    Patch backoffice_state.audit_writer with a MagicMock so the endpoint
    can emit audit events without a live Redis connection.
    """
    from fastapi import FastAPI
    from yashigani.backoffice.routes.auth import router

    app = FastAPI()
    app.include_router(router)
    return app


@pytest.fixture()
def client_and_writer():
    """Return (TestClient, mock_audit_writer)."""
    app = _make_app_with_stub_state()
    mock_writer = MagicMock()
    with patch("yashigani.backoffice.routes.auth.backoffice_state") as mock_state:
        mock_state.audit_writer = mock_writer
        with TestClient(app, raise_server_exceptions=True, follow_redirects=False) as c:
            yield c, mock_writer


class TestPostLoginRedirectEndpoint:
    """HTTP-layer tests for GET /post-login-redirect."""

    def test_valid_path_redirects(self, client_and_writer):
        client, writer = client_and_writer
        resp = client.get("/post-login-redirect", params={"next": "/dashboard"})
        assert resp.status_code == 302
        assert resp.headers["location"] == "/dashboard"
        writer.write.assert_not_called()

    def test_valid_root_redirects(self, client_and_writer):
        client, writer = client_and_writer
        resp = client.get("/post-login-redirect", params={"next": "/"})
        assert resp.status_code == 302
        assert resp.headers["location"] == "/"

    def test_valid_admin_agents(self, client_and_writer):
        client, writer = client_and_writer
        resp = client.get("/post-login-redirect", params={"next": "/admin/agents"})
        assert resp.status_code == 302
        assert resp.headers["location"] == "/admin/agents"

    def test_backslash_blocked_redirects_to_root(self, client_and_writer):
        client, writer = client_and_writer
        resp = client.get("/post-login-redirect", params={"next": "/\\evil.com"})
        assert resp.status_code == 302
        assert resp.headers["location"] == "/"

    def test_backslash_emits_audit_event(self, client_and_writer):
        client, writer = client_and_writer
        client.get("/post-login-redirect", params={"next": "/\\evil.com"})
        writer.write.assert_called_once()
        event = writer.write.call_args[0][0]
        from yashigani.audit.schema import OpenRedirectAttemptBlockedEvent
        assert isinstance(event, OpenRedirectAttemptBlockedEvent)
        assert event.reason == "double_slash"

    def test_double_slash_blocked(self, client_and_writer):
        client, writer = client_and_writer
        resp = client.get("/post-login-redirect", params={"next": "//evil.com"})
        assert resp.status_code == 302
        assert resp.headers["location"] == "/"
        writer.write.assert_called_once()

    def test_https_absolute_blocked(self, client_and_writer):
        client, writer = client_and_writer
        resp = client.get("/post-login-redirect", params={"next": "https://evil.com"})
        assert resp.status_code == 302
        assert resp.headers["location"] == "/"
        event = writer.write.call_args[0][0]
        assert event.reason in ("not_relative", "absolute_url")

    def test_userinfo_at_blocked(self, client_and_writer):
        client, writer = client_and_writer
        resp = client.get("/post-login-redirect", params={"next": "/foo@evil.com"})
        assert resp.status_code == 302
        assert resp.headers["location"] == "/"
        event = writer.write.call_args[0][0]
        assert event.reason == "userinfo_at"

    def test_too_long_blocked(self, client_and_writer):
        client, writer = client_and_writer
        long_next = "/" + "a" * 5000
        resp = client.get("/post-login-redirect", params={"next": long_next})
        assert resp.status_code == 302
        assert resp.headers["location"] == "/"
        event = writer.write.call_args[0][0]
        assert event.reason == "too_long"

    def test_empty_next_blocked(self, client_and_writer):
        client, writer = client_and_writer
        resp = client.get("/post-login-redirect", params={"next": ""})
        assert resp.status_code == 302
        assert resp.headers["location"] == "/"
        event = writer.write.call_args[0][0]
        assert event.reason == "empty"

    def test_empty_next_no_param_blocked(self, client_and_writer):
        """No next= param at all → empty string default → redirect to /."""
        client, writer = client_and_writer
        resp = client.get("/post-login-redirect")
        assert resp.status_code == 302
        assert resp.headers["location"] == "/"

    def test_backslash_traversal_blocked(self, client_and_writer):
        client, writer = client_and_writer
        resp = client.get("/post-login-redirect", params={"next": "/foo\\..\\..\\etc\\passwd"})
        assert resp.status_code == 302
        assert resp.headers["location"] == "/"

    def test_javascript_scheme_blocked(self, client_and_writer):
        client, writer = client_and_writer
        resp = client.get("/post-login-redirect", params={"next": "javascript:alert(1)"})
        assert resp.status_code == 302
        assert resp.headers["location"] == "/"

    def test_audit_event_has_hashed_ip(self, client_and_writer):
        """Client IP in the audit event is SHA-256 hashed, not raw."""
        client, writer = client_and_writer
        client.get("/post-login-redirect", params={"next": "//evil.com"})
        event = writer.write.call_args[0][0]
        # The TestClient uses testclient as host; hash must be 16 hex chars
        assert len(event.client_ip_hash) == 16
        assert all(c in "0123456789abcdef" for c in event.client_ip_hash)

    def test_audit_event_truncates_attempted_next(self, client_and_writer):
        """attempted_next_truncated must be at most 128 chars."""
        client, writer = client_and_writer
        long_next = "//evil.com/" + "a" * 500
        client.get("/post-login-redirect", params={"next": long_next})
        event = writer.write.call_args[0][0]
        assert len(event.attempted_next_truncated) <= 128

    def test_no_audit_event_on_valid_path(self, client_and_writer):
        """Valid redirects must NOT emit an audit event."""
        client, writer = client_and_writer
        client.get("/post-login-redirect", params={"next": "/admin/agents"})
        writer.write.assert_not_called()

    def test_no_audit_when_audit_writer_is_none(self):
        """If audit_writer is None (pre-init), endpoint must not crash."""
        app = _make_app_with_stub_state()
        with patch("yashigani.backoffice.routes.auth.backoffice_state") as mock_state:
            mock_state.audit_writer = None
            with TestClient(app, raise_server_exceptions=True, follow_redirects=False) as c:
                resp = c.get("/post-login-redirect", params={"next": "//evil.com"})
        assert resp.status_code == 302
        assert resp.headers["location"] == "/"
