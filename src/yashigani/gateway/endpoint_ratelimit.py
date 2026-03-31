"""
Per-endpoint rate limiting — Phase 5.

Fixed-window counter keyed by SHA-256(normalized_path_template) + time bucket.
Simpler than sliding window; adequate for per-endpoint abuse detection.

Redis key pattern: rl:ep:{endpoint_hash}:{window_bucket}
where window_bucket = int(time.time() / window_seconds)

Health/metrics paths are hard-coded exemptions — they must always respond.

Admin overrides are stored in Redis under rl:ep:cfg:{endpoint_hash} and
loaded at check() time. The DB (endpoint_ratelimit_overrides table) is the
authoritative store; Redis is the cache. Admin routes sync both.
"""
from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Paths that bypass all rate limiting (hard-coded)
_EXEMPT_PATHS: frozenset[str] = frozenset({
    "/healthz",
    "/readyz",
    "/internal/metrics",
    "/metrics",
    "/-/healthy",
})

# Default limits (when no override is configured)
DEFAULT_RPS = 100
DEFAULT_BURST = 20
DEFAULT_WINDOW_SECONDS = 1

# Path patterns → normalized template
_PATH_PATTERNS = [
    (re.compile(r"^/agents/[^/]+/(.*)$"), "/agents/{agent_id}/\\1"),
    (re.compile(r"^/agents/[^/]+$"), "/agents/{agent_id}"),
    (re.compile(r"^/admin/users/[^/]+$"), "/admin/users/{user_id}"),
    (re.compile(r"^/admin/rbac/groups/[^/]+$"), "/admin/rbac/groups/{group_id}"),
]


@dataclass
class EndpointRLResult:
    allowed: bool
    remaining: int
    retry_after: Optional[int]  # seconds
    endpoint_hash: str


@dataclass
class EndpointRLConfig:
    rps: int = DEFAULT_RPS
    burst: int = DEFAULT_BURST
    window_seconds: int = DEFAULT_WINDOW_SECONDS
    label: str = ""


class EndpointRateLimiter:
    """
    Check and enforce per-endpoint rate limits.
    Redis client must be synchronous (used in sync gateway context).
    """

    def __init__(self, redis_client) -> None:
        self._redis = redis_client

    def check(self, path: str, user_id: str = "") -> EndpointRLResult:
        """
        Returns EndpointRLResult. Never raises — errors allow the request.
        """
        if path in _EXEMPT_PATHS:
            return EndpointRLResult(
                allowed=True, remaining=9999, retry_after=None,
                endpoint_hash="exempt",
            )
        try:
            return self._check(path, user_id)
        except Exception as exc:
            logger.error("EndpointRateLimiter error: %s", exc)
            return EndpointRLResult(
                allowed=True, remaining=0, retry_after=None,
                endpoint_hash="error",
            )

    def _check(self, path: str, user_id: str) -> EndpointRLResult:
        template = _normalize_path(path)
        ep_hash = hashlib.sha256(template.encode()).hexdigest()[:16]

        cfg = self._load_config(ep_hash)
        bucket = int(time.time() / cfg.window_seconds)
        key = f"rl:ep:{ep_hash}:{bucket}"

        count = self._redis.incr(key)
        if count == 1:
            self._redis.expire(key, cfg.window_seconds * 2)

        limit = cfg.burst if count <= cfg.burst else cfg.rps
        allowed = count <= cfg.burst

        if not allowed:
            try:
                from yashigani.metrics.registry import endpoint_ratelimit_violations_total
                endpoint_ratelimit_violations_total.labels(endpoint_hash=ep_hash).inc()
            except Exception:
                logger.debug("endpoint_ratelimit: metric increment failed for endpoint_ratelimit_violations_total", exc_info=True)

        return EndpointRLResult(
            allowed=allowed,
            remaining=max(0, cfg.burst - count),
            retry_after=cfg.window_seconds if not allowed else None,
            endpoint_hash=ep_hash,
        )

    def _load_config(self, ep_hash: str) -> EndpointRLConfig:
        """Load config from Redis cache. Fall back to defaults."""
        try:
            cfg_key = f"rl:ep:cfg:{ep_hash}"
            data = self._redis.hgetall(cfg_key)
            if data:
                return EndpointRLConfig(
                    rps=int(data.get(b"rps", DEFAULT_RPS)),
                    burst=int(data.get(b"burst", DEFAULT_BURST)),
                    window_seconds=int(data.get(b"window_seconds", DEFAULT_WINDOW_SECONDS)),
                    label=data.get(b"label", b"").decode(),
                )
        except Exception:
            logger.debug("endpoint_ratelimit: Redis config load failed for ep_hash=%s", ep_hash, exc_info=True)
        return EndpointRLConfig()

    def set_config(self, endpoint_template: str, rps: int, burst: int, window_seconds: int = 1) -> str:
        """Set a rate limit override. Returns endpoint_hash."""
        ep_hash = hashlib.sha256(endpoint_template.encode()).hexdigest()[:16]
        cfg_key = f"rl:ep:cfg:{ep_hash}"
        self._redis.hset(cfg_key, mapping={
            "rps": rps,
            "burst": burst,
            "window_seconds": window_seconds,
            "label": endpoint_template,
        })
        return ep_hash

    def delete_config(self, ep_hash: str) -> None:
        self._redis.delete(f"rl:ep:cfg:{ep_hash}")

    def list_configs(self) -> list[dict]:
        keys = list(self._redis.scan_iter("rl:ep:cfg:*", count=100))
        result = []
        for key in keys:
            data = self._redis.hgetall(key)
            if data:
                ep_hash = key.decode().split(":")[-1] if isinstance(key, bytes) else key.split(":")[-1]
                result.append({
                    "endpoint_hash": ep_hash,
                    "label": data.get(b"label", b"").decode(),
                    "rps": int(data.get(b"rps", DEFAULT_RPS)),
                    "burst": int(data.get(b"burst", DEFAULT_BURST)),
                    "window_seconds": int(data.get(b"window_seconds", DEFAULT_WINDOW_SECONDS)),
                })
        return result


def _normalize_path(path: str) -> str:
    """Replace path parameters with {placeholder} for consistent hashing."""
    for pattern, template in _PATH_PATTERNS:
        m = pattern.match(path)
        if m:
            return template
    return path


def is_exempt_path(path: str) -> bool:
    return path in _EXEMPT_PATHS
