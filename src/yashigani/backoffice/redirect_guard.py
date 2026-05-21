"""
Server-side redirect target guard — defence-in-depth (CWE-601, ASVS V5.1.5).

The primary protection for open-redirect vectors in Yashigani is the
client-side ``safeNext()`` guard in ``login.js``, ``user_login.js``, and
``webauthn_login.js`` (comment V232-CSCAN-01d, 2026-05-09).  This module
adds a server-side assertion layer so the protection holds even if JavaScript
is disabled, replaced, or bypassed.

Usage::

    from yashigani.backoffice.redirect_guard import assert_safe_redirect_target

    # Raises HTTP 400 if url is unsafe:
    assert_safe_redirect_target(url)

Accepted URLs
-------------
* Relative paths that start with exactly ``/`` followed by a non-slash,
  non-backslash character: ``/admin/dashboard``, ``/chat``.
* Absolute ``https://`` URLs — permitted for server-side IdP redirects
  (OIDC authorisation endpoint, SAML ACS).  These must not point at
  private/loopback IP ranges (additional guard via ``validate_siem_url``
  semantics at the OIDC broker layer).

Rejected URLs
-------------
* Protocol-relative: ``//evil.com/...``
* Backslash-escape variants: ``/\\evil.com``, ``/\\\\evil.com``
* Absolute non-HTTPS: ``http://...``, ``ftp://...``, ``javascript:...``
* Path-traversal: ``/../etc/passwd``, ``/%2e%2e/etc/passwd``
* Null bytes: ``/path\\x00injected``
* Unicode bidi-override (RTL, LTR, Pop Directional Formatting)
* Unicode full-width characters (U+FF01–U+FF5E) that normalise to ASCII
  special chars
* Zero-width joiners / non-joiners (U+200C, U+200D, U+FEFF)

Finding reference: ACS scan F1 (open-redirect 8 sites), downgraded to LOW
by Iris+Laura (2026-05-21).  Server-side guard ships in
``feat/acs-scan-defence-in-depth``; see iris-acs-scan-findings-validation.md.

OWASP: WSTG-ATHZ-01, ASVS V5.1.5, CWE-601.
Last updated: 2026-05-21T00:00:00+01:00
"""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlparse, unquote

from fastapi import Request
from fastapi.exceptions import HTTPException

import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Banned Unicode character ranges / categories
# ---------------------------------------------------------------------------

# Bidi override characters (RTL/LTR mark, isolate, etc.)
_BIDI_OVERRIDES = frozenset(
    "‎"   # LEFT-TO-RIGHT MARK
    "‏"   # RIGHT-TO-LEFT MARK
    "‪"   # LEFT-TO-RIGHT EMBEDDING
    "‫"   # RIGHT-TO-LEFT EMBEDDING
    "‬"   # POP DIRECTIONAL FORMATTING
    "‭"   # LEFT-TO-RIGHT OVERRIDE
    "‮"   # RIGHT-TO-LEFT OVERRIDE
    "⁦"   # LEFT-TO-RIGHT ISOLATE
    "⁧"   # RIGHT-TO-LEFT ISOLATE
    "⁨"   # FIRST STRONG ISOLATE
    "⁩"   # POP DIRECTIONAL ISOLATE
)

# Zero-width characters
_ZERO_WIDTH = frozenset(
    "​"   # ZERO WIDTH SPACE
    "‌"   # ZERO WIDTH NON-JOINER
    "‍"   # ZERO WIDTH JOINER
    "﻿"   # ZERO WIDTH NO-BREAK SPACE / BOM
)

# URL-encoded traversal patterns (after decoding)
_TRAVERSAL_RE = re.compile(r"\.{2}[/\\]|[/\\]\.{2}")

# Path must start with / and the next char must not be / or \
_SAFE_RELATIVE_RE = re.compile(r"^/[^/\\]")

# Full-width Unicode range U+FF01–U+FF5E (normalises to ASCII printable)
_FULLWIDTH_RE = re.compile(r"[！-～]")

# Null bytes
_NULL_BYTE_RE = re.compile(r"\x00")


def _contains_suspicious_unicode(url: str) -> bool:
    """Return True if the URL contains bidi-override, zero-width, or full-width chars."""
    for ch in url:
        if ch in _BIDI_OVERRIDES or ch in _ZERO_WIDTH:
            return True
    if _FULLWIDTH_RE.search(url):
        return True
    return False


def assert_safe_redirect_target(
    url: str,
    *,
    request: Request | None = None,
    allow_absolute_https: bool = False,
) -> None:
    """Assert that *url* is safe to use as a server-controlled redirect target.

    Parameters
    ----------
    url:
        The URL to validate.
    request:
        Optional FastAPI ``Request`` — used for structured logging only.
    allow_absolute_https:
        When ``True``, accept absolute ``https://`` URLs in addition to
        relative paths.  Use this flag for IdP redirect targets
        (``sso.py:516``) where the URL is produced by the OIDC broker
        and pre-validated against ``allowed_auth_endpoint_pattern``.

    Raises
    ------
    fastapi.exceptions.HTTPException
        HTTP 400 with ``error: "unsafe_redirect_target"`` if the URL
        fails any check.
    """
    _reject = _make_rejector(url, request)

    if not url:
        _reject("empty URL")

    # Null bytes
    if _NULL_BYTE_RE.search(url):
        _reject("null byte in URL")

    # Suspicious Unicode
    if _contains_suspicious_unicode(url):
        _reject("suspicious Unicode (bidi-override, zero-width, or full-width characters)")

    # Decode percent-encoding once and re-check
    decoded = unquote(url)
    if _NULL_BYTE_RE.search(decoded):
        _reject("null byte in URL after percent-decode")
    if _contains_suspicious_unicode(decoded):
        _reject("suspicious Unicode after percent-decode")

    # Traverse checks (both raw and decoded forms)
    if _TRAVERSAL_RE.search(url) or _TRAVERSAL_RE.search(decoded):
        _reject("path-traversal sequence (/../) detected")

    # Parse the URL
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    netloc = (parsed.netloc or "")

    # Protocol-relative URLs: no scheme but netloc present (e.g. //evil.com)
    if url.startswith("//"):
        _reject("protocol-relative URL (//...) rejected")

    # Backslash variant: /\evil.com
    if url.startswith("/\\") or url.startswith("/\\/"):
        _reject("backslash redirect escape (/\\...) rejected")

    # Scheme present
    if scheme:
        if scheme == "https" and allow_absolute_https:
            # Absolute HTTPS allowed (IdP redirect target).
            # Must have a netloc and not be a path-only pseudo-URL.
            if not netloc:
                _reject("absolute https:// URL lacks hostname")
            return
        # Any other scheme is rejected outright.
        _reject(f"scheme {scheme!r} not allowed as redirect target")

    # No scheme → must be a relative path.
    # Allow "/" alone (root) or "/letter-or-digit..." but NOT "//" or "/\"
    if url == "/":
        return

    if not _SAFE_RELATIVE_RE.match(url):
        _reject(
            "relative URL must start with '/' followed by a non-slash, "
            "non-backslash character"
        )


def _make_rejector(url: str, request: Request | None):
    """Return a callable that logs and raises HTTP 400."""

    def _reject(reason: str) -> None:
        logger.warning(
            "assert_safe_redirect_target: REJECTED url=%r reason=%s path=%s",
            url,
            reason,
            request.url.path if request else "(unknown)",
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "unsafe_redirect_target",
                "reason": reason,
            },
        )

    return _reject
