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
