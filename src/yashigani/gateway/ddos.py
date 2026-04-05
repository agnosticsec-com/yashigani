"""
Yashigani Gateway — Application-level DDoS mitigation (v2.2).

Tracks concurrent/recent connections per IP address using Redis counters with
a fixed-window TTL.  A single Redis INCR + EXPIRE pair is the hot path;
no Lua scripting or blocking calls required.

Key namespace: ddos:{ip}:{window_bucket}
  where window_bucket = int(time.time() / window_seconds)

Design rationale:
  - Counter is incremented on every inbound request (call record()).
  - check() reads the current counter and returns False when the IP has
    exceeded max_connections_per_ip within the rolling window.
  - Both operations are O(1) and synchronous — safe to call inline in
    the gateway request path before any expensive processing.
  - The namespace "ddos:" is intentionally separate from "rl:" (rate limit)
    to allow independent monitoring and per-dimension metrics.
  - Never raises: any Redis error causes check() to allow the request
    (fail-open), matching the existing EndpointRateLimiter behaviour.
    A failed Redis connection should not gate legitimate traffic when the
    risk signal is unavailable.

OWASP ASVS Level 3 alignment:
  V4.2.1 — Enforced at application layer (not solely network layer).
  V4.2.2 — Per-IP isolation prevents one tenant flooding another.
  V11.1.4 — Counters are stored in Redis, not in-process, so they survive
             multiple gateway replicas.
"""
from __future__ import annotations

import logging
import time

logger = logging.getLogger(__name__)

# Default thresholds — can be overridden at construction time or via env.
_DEFAULT_MAX_CONNECTIONS_PER_IP: int = 50
_DEFAULT_WINDOW_SECONDS: int = 60

# Paths exempt from DDoS tracking (health/metrics must always respond).
_EXEMPT_PATHS: frozenset[str] = frozenset({
    "/healthz",
    "/readyz",
    "/internal/metrics",
    "/metrics",
    "/-/healthy",
})


class DDoSProtector:
    """
    Per-IP connection rate counter backed by Redis.

    Usage (inside gateway request handler)::

        protector = DDoSProtector(redis_client=redis)
        protector.record(client_ip)          # always call first
        if not protector.check(client_ip):
            return 429 / drop connection

    Parameters
    ----------
    redis_client:
        Synchronous Redis client (redis-py or fakeredis).  Must support
        INCR, EXPIRE, and GET commands.
    max_connections_per_ip:
        Maximum requests allowed from a single IP within ``window_seconds``.
        Default: 50.
    window_seconds:
        Fixed-window duration in seconds.  Default: 60.
    """

    def __init__(
        self,
        redis_client,
        max_connections_per_ip: int = _DEFAULT_MAX_CONNECTIONS_PER_IP,
        window_seconds: int = _DEFAULT_WINDOW_SECONDS,
    ) -> None:
        self._redis = redis_client
        self.max_connections_per_ip = max_connections_per_ip
        self.window_seconds = window_seconds

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, ip: str, path: str = "") -> bool:
        """
        Return True if the IP is within its connection budget, False if it
        has exceeded the threshold and should be blocked.

        Never raises — Redis failures return True (fail-open).

        Parameters
        ----------
        ip:
            Client IP address string (IPv4 or IPv6).
        path:
            Optional request path used to skip exempt paths (e.g. /healthz).
        """
        if path in _EXEMPT_PATHS:
            return True
        try:
            key = self._key(ip)
            raw = self._redis.get(key)
            count = int(raw) if raw is not None else 0
            return count <= self.max_connections_per_ip
        except Exception as exc:
            logger.warning(
                "DDoSProtector.check failed for ip=%s: %s — allowing (fail-open)",
                _redact_ip(ip),
                exc,
            )
            return True

    def record(self, ip: str, path: str = "") -> None:
        """
        Increment the connection counter for ``ip``.  Sets the key TTL on
        first increment so the counter expires automatically.

        Silently ignores Redis errors.

        Parameters
        ----------
        ip:
            Client IP address string.
        path:
            Optional request path used to skip exempt paths.
        """
        if path in _EXEMPT_PATHS:
            return
        try:
            key = self._key(ip)
            count = self._redis.incr(key)
            if count == 1:
                # First request in this window — set expiry.
                # Expire after 2x the window so the key overlaps slightly and
                # avoids a race between INCR and EXPIRE on the bucket boundary.
                self._redis.expire(key, self.window_seconds * 2)
        except Exception as exc:
            logger.warning(
                "DDoSProtector.record failed for ip=%s: %s",
                _redact_ip(ip),
                exc,
            )

    def current_count(self, ip: str) -> int:
        """Return the current window counter for ``ip``.  Returns 0 on error."""
        try:
            key = self._key(ip)
            raw = self._redis.get(key)
            return int(raw) if raw is not None else 0
        except Exception:
            return 0

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _key(self, ip: str) -> str:
        bucket = int(time.time() / self.window_seconds)
        return f"ddos:{ip}:{bucket}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _redact_ip(ip: str) -> str:
    """Partially redact an IP for logging (last octet/group zeroed)."""
    if ":" in ip:
        # IPv6 — keep first 4 groups
        parts = ip.split(":")
        return ":".join(parts[:4]) + ":****"
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.*"
    return "****"
