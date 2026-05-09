"""
yashigani.net — centralised outbound HTTP client with SSRF guardrails.

QA Wave 2 finding #5 (API7): 17 outbound `httpx` / `requests` call
sites across the code base lacked a uniform allowlist wrapper. The gateway
upstream is admin-configured (fine), but alert sinks, backoffice routes
for agents/models, and a handful of other callers made raw outbound HTTP
with no centralised safety.

This module provides a single entry point that every outbound caller
should use. It enforces:

  * URL scheme allowlist (only https:// by default; http:// opt-in per
    call AND only for explicitly-trusted hosts)
  * Host allowlist / blocklist resolved against env-driven config
  * Timeout default (no more than 30 s, unless overridden)
  * No auto-follow of redirects to hosts outside the allowlist
  * Optional mTLS client-cert loading (integrates with task #29)
  * Logged audit event on blocked attempts

v2.23.3 — DNS-rebinding defence (OWASP API7, issue #91):
  :func:`pinned_resolver` is an async context manager that resolves the
  target hostname once, pins the resulting IP, and monkey-patches
  ``socket.getaddrinfo`` for the underlying transport so that subsequent
  DNS changes cannot redirect the connection to a different (internal) host.

Usage:

    from yashigani.net import HttpClient, BlockedByPolicy
    client = HttpClient()
    try:
        r = await client.get("https://api.pwnedpasswords.com/range/ABCDE")
    except BlockedByPolicy as exc:
        logger.warning("Outbound blocked: %s", exc)

    from yashigani.net import pinned_resolver
    async with pinned_resolver("api.pwnedpasswords.com",
                               allowlist=["api.pwnedpasswords.com"]) as session:
        r = await session.get("https://api.pwnedpasswords.com/range/ABCDE")

Migration of the existing 17 call sites happens as task #32b (tracked
separately) — this module lands first so callers can opt in incrementally.
"""

from .http_client import HttpClient, BlockedByPolicy
from .pinned_resolver import pinned_resolver

__all__ = ["HttpClient", "BlockedByPolicy", "pinned_resolver"]
