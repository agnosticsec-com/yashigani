"""
Yashigani Rate Limiter — Adaptive token bucket, Redis-backed.

Algorithm: token bucket per dimension (global / IP / agent / session).
Each bucket has capacity=burst and refills at rps tokens/second.
Effective rps is multiplied by the RPI adaptive factor before each check.

Redis key schema:
    yashigani:rl:global
    yashigani:rl:ip:<hashed_ip>
    yashigani:rl:agent:<agent_id>
    yashigani:rl:session:<session_id_prefix>

Lua script executes atomically — no TOCTOU race between read and write.
Returns HTTP 429 with Retry-After on violation.
Audit event written on every violation.
"""
from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass
from typing import Optional

from yashigani.ratelimit.config import RateLimitConfig

logger = logging.getLogger(__name__)

# Lua token bucket script — atomic read-modify-write
_LUA_TOKEN_BUCKET = """
local key        = KEYS[1]
local capacity   = tonumber(ARGV[1])
local refill_rps = tonumber(ARGV[2])
local now        = tonumber(ARGV[3])
local ttl        = tonumber(ARGV[4])

local bucket     = redis.call('HMGET', key, 'tokens', 'last_ts')
local tokens     = tonumber(bucket[1])
local last_ts    = tonumber(bucket[2])

if tokens == nil then
    tokens  = capacity
    last_ts = now
end

-- Refill proportional to elapsed time
local elapsed = math.max(0, now - last_ts)
tokens = math.min(capacity, tokens + elapsed * refill_rps)

local allowed = 0
if tokens >= 1 then
    tokens  = tokens - 1
    allowed = 1
end

redis.call('HMSET', key, 'tokens', tokens, 'last_ts', now)
redis.call('EXPIRE', key, ttl)

-- Return: allowed (1/0), remaining tokens (floor), retry_after_ms
local retry_ms = 0
if allowed == 0 and refill_rps > 0 then
    retry_ms = math.ceil((1 - tokens) / refill_rps * 1000)
end
return {allowed, math.floor(tokens), retry_ms}
"""


@dataclass
class RateLimitResult:
    allowed: bool
    dimension: str          # which bucket blocked/allowed (global/ip/agent/session)
    remaining: int          # tokens remaining in the blocking bucket
    retry_after_ms: int     # milliseconds until one token is available


class RateLimiter:
    """
    Multi-dimensional adaptive token bucket rate limiter.
    Requires a Redis connection (same instance used for sessions).
    """

    def __init__(
        self,
        redis_client,
        config: Optional[RateLimitConfig] = None,
        resource_monitor=None,  # ResourceMonitor — optional, enables adaptive mode
    ) -> None:
        self._redis = redis_client
        self._config = config or RateLimitConfig()
        self._monitor = resource_monitor
        self._script_sha: Optional[str] = None
        # Per-session RBAC overrides: {session_key_prefix: (rps, burst)}
        self._session_overrides: dict[str, tuple[float, int]] = {}
        self._load_script()

    # -- Public API ----------------------------------------------------------

    def check(
        self,
        client_ip: str,
        agent_id: str,
        session_id: str,
    ) -> RateLimitResult:
        """
        Check all applicable dimensions. Returns the first violation found,
        or an allowed result if all pass. Checks in order: global → IP → agent → session.
        """
        if not self._config.enabled:
            return RateLimitResult(allowed=True, dimension="disabled", remaining=0, retry_after_ms=0)

        multiplier = self._rpi_multiplier()
        cfg = self._config

        # Per-session RBAC override: most permissive group wins (already set by caller)
        session_key = session_id[:16] if session_id else ""
        override = self._session_overrides.get(session_key)
        session_rps   = override[0] if override else cfg.per_session_rps
        session_burst = override[1] if override else cfg.per_session_burst

        checks = [
            ("global",  "yashigani:rl:global",
             cfg.global_rps,  cfg.global_burst),
            ("ip",      f"yashigani:rl:ip:{_hash(client_ip)}",
             cfg.per_ip_rps,  cfg.per_ip_burst),
            ("agent",   f"yashigani:rl:agent:{_safe(agent_id)}",
             cfg.per_agent_rps, cfg.per_agent_burst),
            ("session", f"yashigani:rl:session:{session_key}",
             session_rps, session_burst),
        ]

        for dimension, key, rps, burst in checks:
            # Skip unknown/anonymous dimensions — they fall through to global
            if dimension in ("agent", "session") and (not agent_id or not session_id):
                continue
            result = self._consume(key, rps * multiplier, burst)
            if not result.allowed:
                result.dimension = dimension
                return result

        return RateLimitResult(allowed=True, dimension="none", remaining=-1, retry_after_ms=0)

    def set_session_override(
        self,
        session_id: str,
        per_session_rps: float,
        per_session_burst: int,
    ) -> None:
        """
        Set a per-session rate limit override derived from RBAC group policy.

        The override is stored in-memory for this session prefix and applied
        on the next check() call.  It is intentionally not persisted to Redis
        because the gateway re-evaluates group membership on every request.
        """
        key = session_id[:16] if session_id else ""
        if key:
            self._session_overrides[key] = (per_session_rps, per_session_burst)

    def update_config(self, new_config: RateLimitConfig) -> None:
        """Hot-update config without restart."""
        self._config = new_config

    def current_config(self) -> RateLimitConfig:
        return self._config

    def current_rpi_multiplier(self) -> float:
        return self._rpi_multiplier()

    # -- Internal ------------------------------------------------------------

    def _load_script(self) -> None:
        try:
            self._script_sha = self._redis.script_load(_LUA_TOKEN_BUCKET)
        except Exception as exc:
            logger.warning("Could not pre-load rate limit Lua script: %s", exc)
            self._script_sha = None

    def _consume(self, key: str, rps: float, burst: int) -> RateLimitResult:
        """Execute the token bucket Lua script for one key."""
        effective_rps = max(0.01, rps)   # never zero — avoid division by zero in Lua
        now = time.time()
        ttl = self._config.bucket_ttl_seconds

        try:
            if self._script_sha:
                result = self._redis.evalsha(
                    self._script_sha, 1, key,
                    burst, effective_rps, now, ttl,
                )
            else:
                result = self._redis.eval(
                    _LUA_TOKEN_BUCKET, 1, key,
                    burst, effective_rps, now, ttl,
                )
            allowed, remaining, retry_ms = int(result[0]), int(result[1]), int(result[2])
            return RateLimitResult(
                allowed=bool(allowed),
                dimension="",
                remaining=remaining,
                retry_after_ms=retry_ms,
            )
        except Exception as exc:
            # Redis unavailable → fail open (log, allow)
            logger.error("Rate limiter Redis error (failing open): %s", exc)
            return RateLimitResult(allowed=True, dimension="redis_error", remaining=-1, retry_after_ms=0)

    def _rpi_multiplier(self) -> float:
        if not self._config.adaptive_enabled or self._monitor is None:
            return 1.0
        try:
            rpi = self._monitor.get_metrics().pressure_index
        except Exception:
            return 1.0

        cfg = self._config
        if rpi > 0.80:
            return cfg.rpi_scale_critical
        if rpi > 0.60:
            return cfg.rpi_scale_high
        if rpi > 0.30:
            return cfg.rpi_scale_medium
        return 1.0


def _hash(value: str) -> str:
    """16-char hex prefix of SHA-256 — enough to identify but not reconstruct."""
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def _safe(value: str) -> str:
    """Strip characters unsafe for Redis keys."""
    return "".join(c for c in value if c.isalnum() or c in "-_.")[:64]
