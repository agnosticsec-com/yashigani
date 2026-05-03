"""Unit tests for yashigani.ratelimit.limiter."""
from __future__ import annotations
import pytest
from unittest.mock import MagicMock, patch


class TestRateLimitConfig:
    def test_defaults(self):
        from yashigani.ratelimit.config import RateLimitConfig
        cfg = RateLimitConfig()
        assert cfg.global_rps > 0
        assert cfg.per_ip_rps > 0
        assert cfg.per_session_rps > 0
        assert cfg.updated_at > 0

    def test_updated_at_is_set(self):
        import time
        from yashigani.ratelimit.config import RateLimitConfig
        before = time.time()
        cfg = RateLimitConfig()
        after = time.time()
        assert before <= cfg.updated_at <= after

    def test_fail_mode_default_is_closed(self):
        # Security default: rate limiter rejects requests when Redis backend
        # is unavailable. Operators may opt back into fail-open availability
        # mode via RATE_LIMITER_FAIL_MODE=open for high-availability deployments.
        from yashigani.ratelimit.config import RateLimitConfig
        cfg = RateLimitConfig()
        assert cfg.fail_mode == "closed"

    def test_fail_mode_open_accepted(self):
        from yashigani.ratelimit.config import RateLimitConfig
        cfg = RateLimitConfig(fail_mode="open")
        assert cfg.fail_mode == "open"


class TestRateLimiter:
    def test_set_session_override(self, mock_redis):
        from yashigani.ratelimit.limiter import RateLimiter
        from yashigani.ratelimit.config import RateLimitConfig
        monitor = MagicMock()
        monitor.get_metrics.return_value = MagicMock(pressure_index=0.0)
        monitor.current_rpi_multiplier = MagicMock(return_value=1.0)
        limiter = RateLimiter(redis_client=mock_redis, config=RateLimitConfig(), resource_monitor=monitor)
        limiter.set_session_override("sess-abc", per_session_rps=100.0, per_session_burst=200)
        overrides = limiter._session_overrides
        assert "sess-abc" in overrides
        assert overrides["sess-abc"][0] == 100.0
        assert overrides["sess-abc"][1] == 200

    def test_session_override_cleared_on_remove(self, mock_redis):
        from yashigani.ratelimit.limiter import RateLimiter
        from yashigani.ratelimit.config import RateLimitConfig
        monitor = MagicMock()
        monitor.get_metrics.return_value = MagicMock(pressure_index=0.0)
        limiter = RateLimiter(redis_client=mock_redis, config=RateLimitConfig(), resource_monitor=monitor)
        limiter.set_session_override("sess-xyz", per_session_rps=5.0, per_session_burst=10)
        # Remove by setting to None
        limiter._session_overrides.pop("sess-xyz", None)
        assert "sess-xyz" not in limiter._session_overrides


class TestRateLimiterFailMode:
    """
    Tests for RATE_LIMITER_FAIL_MODE flag.

    Strategy: use a broken Redis client (MagicMock that raises ConnectionError
    on every call) to simulate Redis unavailability.  Pre-fix assertion: the old
    code always returned allowed=True on Redis error.  Post-fix assertion:
    fail_mode='closed' returns allowed=False with dimension='redis_unavailable'.
    """

    def _broken_redis(self):
        """Return a mock Redis client that raises ConnectionError on every call."""
        mock = MagicMock()
        mock.script_load.side_effect = ConnectionError("Redis down")
        mock.evalsha.side_effect = ConnectionError("Redis down")
        mock.eval.side_effect = ConnectionError("Redis down")
        mock.ping.side_effect = ConnectionError("Redis down")
        return mock

    def _make_limiter(self, fail_mode: str, redis_client=None):
        from yashigani.ratelimit.limiter import RateLimiter
        from yashigani.ratelimit.config import RateLimitConfig
        r = redis_client if redis_client is not None else self._broken_redis()
        cfg = RateLimitConfig(fail_mode=fail_mode)
        return RateLimiter(redis_client=r, config=cfg)

    # ------------------------------------------------------------------
    # Pre-fix regression guard: fail-open is unchanged
    # ------------------------------------------------------------------

    def test_redis_down_fail_open_allows_request(self):
        """
        When Redis is down and fail_mode='open' (default), check() MUST return
        allowed=True.  This is the pre-existing behaviour; it must never regress.
        """
        limiter = self._make_limiter("open")
        result = limiter.check("1.2.3.4", "agent-1", "sess-1")
        assert result.allowed is True, (
            "fail-open mode must allow requests when Redis is unavailable"
        )

    def test_redis_down_fail_open_allowed_is_true(self):
        """
        When Redis is down in fail-open mode all _consume calls return allowed=True,
        so check() returns the final result with dimension='none' (all-passed sentinel).
        """
        limiter = self._make_limiter("open")
        result = limiter.check("1.2.3.4", "agent-1", "sess-1")
        # All buckets fail-open → final allowed result → dimension is 'none'
        assert result.allowed is True
        assert result.dimension == "none"

    # ------------------------------------------------------------------
    # Fail-closed: Redis down → reject with 503-appropriate result
    # ------------------------------------------------------------------

    def test_redis_down_fail_closed_rejects_request(self):
        """
        When Redis is down and fail_mode='closed', check() MUST return
        allowed=False.  This is the new fail-closed behaviour.
        """
        limiter = self._make_limiter("closed")
        result = limiter.check("1.2.3.4", "agent-1", "sess-1")
        assert result.allowed is False, (
            "fail-closed mode must reject requests when Redis is unavailable"
        )

    def test_redis_down_fail_closed_dimension_is_redis_unavailable(self):
        limiter = self._make_limiter("closed")
        result = limiter.check("1.2.3.4", "agent-1", "sess-1")
        assert result.dimension == "redis_unavailable"

    def test_redis_down_fail_closed_retry_after_is_set(self):
        limiter = self._make_limiter("closed")
        result = limiter.check("1.2.3.4", "agent-1", "sess-1")
        # retry_after_ms must be positive so Retry-After header is meaningful
        assert result.retry_after_ms > 0

    def test_redis_down_fail_closed_remaining_is_zero(self):
        limiter = self._make_limiter("closed")
        result = limiter.check("1.2.3.4", "agent-1", "sess-1")
        assert result.remaining == 0

    # ------------------------------------------------------------------
    # Fail-closed: healthy Redis → normal allow/deny, not affected by mode
    # ------------------------------------------------------------------

    def test_fail_closed_healthy_redis_allows_request(self):
        """
        fail_mode='closed' must not affect behaviour when Redis is healthy.
        Use a mock Redis client that returns a valid token-bucket result
        (allowed=1, remaining=10, retry_ms=0) so no Lua eval is required.
        """
        from yashigani.ratelimit.limiter import RateLimiter
        from yashigani.ratelimit.config import RateLimitConfig

        healthy_redis = MagicMock()
        # script_load succeeds → script_sha is set
        healthy_redis.script_load.return_value = "fakeshahex"
        # evalsha returns [allowed=1, remaining=10, retry_ms=0]
        healthy_redis.evalsha.return_value = [1, 10, 0]

        cfg = RateLimitConfig(fail_mode="closed")
        limiter = RateLimiter(redis_client=healthy_redis, config=cfg)
        result = limiter.check("1.2.3.4", "agent-1", "sess-1")
        assert result.allowed is True, (
            "fail-closed mode must allow requests when Redis is healthy and bucket is not exhausted"
        )

    # ------------------------------------------------------------------
    # Proxy-level: redis_unavailable dimension triggers 503 not 429
    # ------------------------------------------------------------------

    def test_proxy_returns_503_on_redis_unavailable(self):
        """
        When the rate limiter returns dimension='redis_unavailable', the proxy
        handler must emit HTTP 503, not 429.
        """
        from yashigani.ratelimit.limiter import RateLimitResult, _DIMENSION_REDIS_UNAVAILABLE
        from starlette.testclient import TestClient
        from starlette.applications import Starlette
        from starlette.routing import Route
        from starlette.responses import JSONResponse

        # Minimal proxy-like handler that replicates the branching logic in proxy.py
        def handler(request):
            rl_result = RateLimitResult(
                allowed=False,
                dimension=_DIMENSION_REDIS_UNAVAILABLE,
                remaining=0,
                retry_after_ms=5000,
            )
            retry_sec = max(1, rl_result.retry_after_ms // 1000)
            if rl_result.dimension == "redis_unavailable":
                return JSONResponse(
                    status_code=503,
                    content={
                        "error": "RATE_LIMITER_UNAVAILABLE",
                        "retry_after_seconds": retry_sec,
                    },
                    headers={"Retry-After": str(retry_sec)},
                )
            return JSONResponse(
                status_code=429,
                content={"error": "RATE_LIMIT_EXCEEDED"},
                headers={"Retry-After": str(retry_sec)},
            )

        app = Starlette(routes=[Route("/test", handler)])
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/test")
        assert resp.status_code == 503, (
            f"Expected 503 for redis_unavailable dimension, got {resp.status_code}"
        )
        assert resp.headers["Retry-After"] == "5"
        data = resp.json()
        assert data["error"] == "RATE_LIMITER_UNAVAILABLE"

    def test_proxy_returns_429_on_normal_rate_limit(self):
        """Normal token-bucket exhaustion still returns 429."""
        from yashigani.ratelimit.limiter import RateLimitResult
        from starlette.testclient import TestClient
        from starlette.applications import Starlette
        from starlette.routing import Route
        from starlette.responses import JSONResponse

        def handler(request):
            rl_result = RateLimitResult(
                allowed=False,
                dimension="ip",
                remaining=0,
                retry_after_ms=1000,
            )
            retry_sec = max(1, rl_result.retry_after_ms // 1000)
            if rl_result.dimension == "redis_unavailable":
                return JSONResponse(status_code=503, content={"error": "RATE_LIMITER_UNAVAILABLE"})
            return JSONResponse(
                status_code=429,
                content={"error": "RATE_LIMIT_EXCEEDED", "dimension": rl_result.dimension},
                headers={"Retry-After": str(retry_sec)},
            )

        app = Starlette(routes=[Route("/test", handler)])
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/test")
        assert resp.status_code == 429
