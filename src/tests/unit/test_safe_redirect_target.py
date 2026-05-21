"""
Unit tests for yashigani.backoffice.redirect_guard.assert_safe_redirect_target.

Parametrised over the 11 attack classes documented in Laura's threat model
(laura-acs-scan-findings-threat-model.md §Finding 1) and Iris's architectural
validation (iris-acs-scan-findings-validation.md §Finding 1).

Finding reference: F1 — open-redirect defence-in-depth (ACS scan 2026-05-21).
OWASP: WSTG-ATHZ-01, ASVS V5.1.5, CWE-601.
"""
from __future__ import annotations

import pytest
from fastapi.exceptions import HTTPException

from yashigani.backoffice.redirect_guard import assert_safe_redirect_target


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _should_pass(url: str, *, allow_absolute_https: bool = False) -> None:
    """Assert that the URL is accepted without raising."""
    assert_safe_redirect_target(url, allow_absolute_https=allow_absolute_https)


def _should_reject(url: str, *, allow_absolute_https: bool = False) -> None:
    """Assert that the URL is rejected with HTTP 400."""
    with pytest.raises(HTTPException) as exc_info:
        assert_safe_redirect_target(url, allow_absolute_https=allow_absolute_https)
    assert exc_info.value.status_code == 400
    assert exc_info.value.detail["error"] == "unsafe_redirect_target"


# ---------------------------------------------------------------------------
# Attack class 1 — Absolute URLs with scheme + netloc (open-redirect)
# ---------------------------------------------------------------------------

class TestAbsoluteUrls:
    def test_absolute_http_rejected(self):
        _should_reject("http://evil.com/phishing")

    def test_absolute_https_rejected_by_default(self):
        """https:// absolute URL is rejected unless allow_absolute_https=True."""
        _should_reject("https://evil.com/phishing")

    def test_absolute_https_accepted_when_flag_set(self):
        """allow_absolute_https=True is needed for OIDC IdP redirects."""
        _should_pass("https://idp.example.com/oauth/authorize?response_type=code", allow_absolute_https=True)

    def test_absolute_https_accepted_with_port(self):
        _should_pass("https://idp.example.com:8443/authorize", allow_absolute_https=True)

    def test_ftp_rejected(self):
        _should_reject("ftp://evil.com/payload")

    def test_javascript_rejected(self):
        _should_reject("javascript:alert(1)")

    def test_data_uri_rejected(self):
        _should_reject("data:text/html,<script>alert(1)</script>")


# ---------------------------------------------------------------------------
# Attack class 2 — Protocol-relative URLs
# ---------------------------------------------------------------------------

class TestProtocolRelativeUrls:
    def test_protocol_relative_rejected(self):
        _should_reject("//evil.com/fake-login")

    def test_protocol_relative_with_path_rejected(self):
        _should_reject("//evil.com/some/deep/path")

    def test_triple_slash_rejected(self):
        _should_reject("///evil.com/")


# ---------------------------------------------------------------------------
# Attack class 3 — Backslash escape variants
# ---------------------------------------------------------------------------

class TestBackslashEscape:
    def test_backslash_immediately_after_slash_rejected(self):
        _should_reject("/\\evil.com")

    def test_double_backslash_rejected(self):
        _should_reject("/\\\\evil.com")

    def test_backslash_forward_slash_rejected(self):
        _should_reject("/\\/evil.com")


# ---------------------------------------------------------------------------
# Attack class 4 — URL-encoded path traversal
# ---------------------------------------------------------------------------

class TestUrlEncodedTraversal:
    def test_percent_2e_2e_traversal_rejected(self):
        _should_reject("/%2e%2e/etc/passwd")

    def test_percent_2E_2E_uppercase_rejected(self):
        _should_reject("/%2E%2E/etc/shadow")

    def test_dotdot_slash_traversal_rejected(self):
        _should_reject("/../etc/passwd")

    def test_dotdot_backslash_traversal_rejected(self):
        _should_reject("/..\\etc\\passwd")


# ---------------------------------------------------------------------------
# Attack class 5 — Null bytes
# ---------------------------------------------------------------------------

class TestNullBytes:
    def test_null_byte_in_path_rejected(self):
        _should_reject("/admin\x00.jpg")

    def test_null_byte_url_encoded_rejected(self):
        _should_reject("/admin%00.jpg")

    def test_null_byte_at_start_rejected(self):
        _should_reject("\x00/admin")


# ---------------------------------------------------------------------------
# Attack class 6 — Unicode bidi-override characters
# ---------------------------------------------------------------------------

class TestBidiOverride:
    def test_rtl_mark_rejected(self):
        _should_reject("/admin‏/path")

    def test_ltr_mark_rejected(self):
        _should_reject("/admin‎/path")

    def test_rtl_override_rejected(self):
        _should_reject("/admin‮/evil")

    def test_ltr_override_rejected(self):
        _should_reject("/admin‭/evil")

    def test_pop_directional_formatting_rejected(self):
        _should_reject("/admin‬/evil")


# ---------------------------------------------------------------------------
# Attack class 7 — Unicode full-width characters
# ---------------------------------------------------------------------------

class TestFullWidthUnicode:
    def test_fullwidth_dot_rejected(self):
        # U+FF0E FULLWIDTH FULL STOP (．)
        _should_reject("/admin．．/etc/passwd")

    def test_fullwidth_slash_rejected(self):
        # U+FF0F FULLWIDTH SOLIDUS (／)
        _should_reject("/admin／／/evil.com")

    def test_fullwidth_colon_rejected(self):
        # U+FF1A FULLWIDTH COLON
        _should_reject("https：//evil.com")


# ---------------------------------------------------------------------------
# Attack class 8 — Zero-width joiners / non-joiners
# ---------------------------------------------------------------------------

class TestZeroWidth:
    def test_zero_width_joiner_rejected(self):
        # U+200D ZERO WIDTH JOINER
        _should_reject("/admin‍/panel")

    def test_zero_width_non_joiner_rejected(self):
        # U+200C ZERO WIDTH NON-JOINER
        _should_reject("/admin‌/panel")

    def test_bom_rejected(self):
        # U+FEFF BOM / ZERO WIDTH NO-BREAK SPACE
        _should_reject("/admin﻿/panel")

    def test_zero_width_space_rejected(self):
        # U+200B ZERO WIDTH SPACE
        _should_reject("/admin​/panel")


# ---------------------------------------------------------------------------
# Attack class 9 — Mixed-scheme / case variants
# ---------------------------------------------------------------------------

class TestMixedScheme:
    def test_uppercase_http_rejected(self):
        _should_reject("HTTP://evil.com/")

    def test_mixed_case_javascript_rejected(self):
        _should_reject("JaVaScRiPt:alert(1)")


# ---------------------------------------------------------------------------
# Attack class 10 — Empty / edge-case inputs
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_string_rejected(self):
        _should_reject("")

    def test_root_slash_accepted(self):
        """Bare '/' is a valid relative path (redirect to root)."""
        _should_pass("/")

    def test_double_slash_rejected(self):
        """'//' is protocol-relative."""
        _should_reject("//")

    def test_none_like_string_rejected(self):
        _should_reject("None")


# ---------------------------------------------------------------------------
# Attack class 11 — Space / whitespace bypass attempts
# ---------------------------------------------------------------------------

class TestWhitespaceBypasses:
    def test_space_before_scheme_rejected(self):
        _should_reject(" https://evil.com/")

    def test_tab_before_scheme_rejected(self):
        _should_reject("\thttps://evil.com/")

    def test_newline_before_scheme_rejected(self):
        _should_reject("\nhttps://evil.com/")


# ---------------------------------------------------------------------------
# Safe inputs — must NOT raise
# ---------------------------------------------------------------------------

class TestSafeInputs:
    def test_simple_relative_path_accepted(self):
        _should_pass("/admin/dashboard")

    def test_relative_path_with_query_accepted(self):
        _should_pass("/admin/login?next=/admin/agents")

    def test_relative_path_with_fragment_accepted(self):
        _should_pass("/admin/dashboard#section")

    def test_deep_relative_path_accepted(self):
        _should_pass("/admin/accounts/users/123")

    def test_root_with_query_accepted(self):
        _should_pass("/?foo=bar")

    def test_chat_path_accepted(self):
        _should_pass("/chat")

    def test_login_path_accepted(self):
        _should_pass("/login?error=sso_failed&idp=google")

    def test_auth_sso_2fa_path_accepted(self):
        _should_pass("/auth/sso/2fa")

    def test_idp_absolute_https_accepted_with_flag(self):
        _should_pass(
            "https://accounts.google.com/o/oauth2/v2/auth?client_id=123&response_type=code",
            allow_absolute_https=True,
        )

    def test_admin_next_path_accepted(self):
        """Simulates request.url.path from app.py:703 — should always pass."""
        _should_pass("/admin/agents")
        _should_pass("/admin/accounts")
        _should_pass("/admin/audit")
