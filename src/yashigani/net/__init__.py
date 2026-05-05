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

Usage:

    from yashigani.net import HttpClient, BlockedByPolicy
    client = HttpClient()
    try:
        r = await client.get("https://api.pwnedpasswords.com/range/ABCDE")
    except BlockedByPolicy as exc:
        logger.warning("Outbound blocked: %s", exc)

Migration of the existing 17 call sites happens as task #32b (tracked
separately) — this module lands first so callers can opt in incrementally.
"""

from .http_client import HttpClient, BlockedByPolicy

__all__ = ["HttpClient", "BlockedByPolicy"]
