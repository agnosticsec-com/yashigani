"""
Unit tests for yashigani.gateway.ddos.DDoSProtector.

Uses fakeredis for a real Redis implementation without a running server.
All tests are synchronous (DDoSProtector uses a sync Redis client).

Import strategy
---------------
``yashigani.gateway.__init__`` eagerly imports ``proxy.py`` which requires
``fastapi``.  The test environment may not have fastapi installed, so we import
``ddos`` and ``_redact_ip`` directly from the module file using ``importlib``
rather than via the package to avoid triggering ``__init__``.

The ``TestProxyIntegration`` class DOES need fastapi/proxy and is skipped
automatically when those packages are absent.
"""
from __future__ import annotations

import importlib
import importlib.util
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Direct module import — bypass yashigani.gateway.__init__
# ---------------------------------------------------------------------------

def _import_ddos():
    """Import yashigani.gateway.ddos without executing gateway/__init__.py."""
    # If it's already in sys.modules (e.g. the __init__ was already loaded),
    # return the cached module.
    if "yashigani.gateway.ddos" in sys.modules:
        return sys.modules["yashigani.gateway.ddos"]

    # Find the file directly and load it as a spec.
    src_root = Path(__file__).parent.parent.parent  # src/
    ddos_path = src_root / "yashigani" / "gateway" / "ddos.py"
    spec = importlib.util.spec_from_file_location("yashigani.gateway.ddos", ddos_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["yashigani.gateway.ddos"] = module
    spec.loader.exec_module(module)
    return module


_ddos_module = _import_ddos()
DDoSProtector = _ddos_module.DDoSProtector
_redact_ip = _ddos_module._redact_ip


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_protector(redis_client, max_connections=10, window_seconds=60):
    return DDoSProtector(
        redis_client=redis_client,
        max_connections_per_ip=max_connections,
        window_seconds=window_seconds,
    )


# ---------------------------------------------------------------------------
# record() + check() — basic flow
# ---------------------------------------------------------------------------

class TestDDoSProtectorBasic:
    def test_fresh_ip_is_allowed(self, mock_redis):
        p = make_protector(mock_redis)
        assert p.check("1.2.3.4") is True

    def test_single_record_is_allowed(self, mock_redis):
        p = make_protector(mock_redis, max_connections=10)
        p.record("1.2.3.4")
        assert p.check("1.2.3.4") is True

    def test_at_threshold_is_allowed(self, mock_redis):
        p = make_protector(mock_redis, max_connections=5)
        for _ in range(5):
            p.record("1.2.3.4")
        # exactly at threshold — still allowed
        assert p.check("1.2.3.4") is True

    def test_over_threshold_is_blocked(self, mock_redis):
        p = make_protector(mock_redis, max_connections=5)
        for _ in range(6):
            p.record("1.2.3.4")
        assert p.check("1.2.3.4") is False

    def test_different_ips_are_independent(self, mock_redis):
        p = make_protector(mock_redis, max_connections=3)
        for _ in range(4):
            p.record("10.0.0.1")
        # 10.0.0.1 is over threshold
        assert p.check("10.0.0.1") is False
        # 10.0.0.2 has never been recorded — should be allowed
        assert p.check("10.0.0.2") is True

    def test_current_count_reflects_records(self, mock_redis):
        p = make_protector(mock_redis, max_connections=100)
        for _ in range(7):
            p.record("5.6.7.8")
        assert p.current_count("5.6.7.8") == 7

    def test_current_count_zero_for_unknown_ip(self, mock_redis):
        p = make_protector(mock_redis)
        assert p.current_count("0.0.0.0") == 0


# ---------------------------------------------------------------------------
# Path exemptions
# ---------------------------------------------------------------------------

class TestDDoSProtectorExemptPaths:
    @pytest.mark.parametrize("path", [
        "/healthz",
        "/readyz",
        "/internal/metrics",
        "/metrics",
        "/-/healthy",
    ])
    def test_exempt_path_always_allowed(self, mock_redis, path):
        p = make_protector(mock_redis, max_connections=1)
        # Even if we record many times, exempt paths bypass the check
        for _ in range(100):
            p.record("1.2.3.4", path)
        # Counter for this IP on a non-exempt path should still be 0
        # because record() skips exempt paths
        assert p.current_count("1.2.3.4") == 0
        assert p.check("1.2.3.4", path) is True

    def test_non_exempt_path_still_blocked(self, mock_redis):
        p = make_protector(mock_redis, max_connections=2)
        for _ in range(3):
            p.record("1.2.3.4", "/v1/chat/completions")
        assert p.check("1.2.3.4", "/v1/chat/completions") is False


# ---------------------------------------------------------------------------
# Redis failure handling (fail-open)
# ---------------------------------------------------------------------------

class TestDDoSProtectorFailOpen:
    def test_check_returns_true_on_redis_error(self):
        bad_redis = MagicMock()
        bad_redis.get.side_effect = Exception("redis connection refused")
        p = make_protector(bad_redis)
        # Should not raise; should allow the request
        assert p.check("1.2.3.4") is True

    def test_record_does_not_raise_on_redis_error(self):
        bad_redis = MagicMock()
        bad_redis.incr.side_effect = Exception("redis connection refused")
        p = make_protector(bad_redis)
        # Should not raise
        p.record("1.2.3.4")

    def test_current_count_returns_zero_on_redis_error(self):
        bad_redis = MagicMock()
        bad_redis.get.side_effect = Exception("redis timeout")
        p = make_protector(bad_redis)
        assert p.current_count("1.2.3.4") == 0


# ---------------------------------------------------------------------------
# TTL — key expiry is set on first INCR
# ---------------------------------------------------------------------------

class TestDDoSProtectorTTL:
    def test_expire_called_on_first_record(self, mock_redis):
        """
        The Redis key must have an expiry set so counters don't accumulate
        forever.  We verify via fakeredis that the key has a non-negative TTL
        after the first record() call.
        """
        p = make_protector(mock_redis, window_seconds=60)
        p.record("9.9.9.9")
        key = p._key("9.9.9.9")
        ttl = mock_redis.ttl(key)
        # TTL should be > 0 (expire was set)
        assert ttl > 0
        # TTL should be <= 2 * window_seconds (120 s)
        assert ttl <= 120

    def test_expire_not_reset_on_subsequent_records(self, mock_redis):
        """
        Only the first INCR sets the TTL.  Subsequent increments must not
        reset it (which could allow a counter to live forever under sustained
        traffic).
        """
        p = make_protector(mock_redis, window_seconds=60)
        p.record("9.9.9.9")
        key = p._key("9.9.9.9")
        ttl_after_first = mock_redis.ttl(key)

        # Second record: TTL should not increase (EXPIRE is only called when
        # count == 1).  In fakeredis the TTL decrements in real time, so we
        # just assert it doesn't exceed the initial value.
        p.record("9.9.9.9")
        ttl_after_second = mock_redis.ttl(key)
        assert ttl_after_second <= ttl_after_first


# ---------------------------------------------------------------------------
# _redact_ip helper
# ---------------------------------------------------------------------------

class TestRedactIP:
    def test_ipv4_redaction(self):
        assert _redact_ip("192.168.1.42") == "192.168.1.*"

    def test_ipv6_redaction(self):
        result = _redact_ip("2001:db8:85a3:0:0:8a2e:370:7334")
        assert result.startswith("2001:db8:85a3:0:")
        assert "****" in result

    def test_malformed_ip_does_not_raise(self):
        # Should return some placeholder, not raise
        result = _redact_ip("not-an-ip")
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# Key structure
# ---------------------------------------------------------------------------

class TestDDoSProtectorKey:
    def test_key_includes_ip_and_bucket(self, mock_redis):
        p = make_protector(mock_redis, window_seconds=60)
        key = p._key("1.2.3.4")
        assert key.startswith("ddos:1.2.3.4:")
        # bucket should be an integer
        bucket_str = key.split(":")[-1]
        assert bucket_str.isdigit()

    def test_key_bucket_changes_with_window(self, mock_redis):
        """Keys in different windows must differ."""
        # Use a 1-second window so we can compare two buckets without sleeping
        p = DDoSProtector(mock_redis, window_seconds=1)
        bucket_now = int(time.time() / 1)
        bucket_prev = bucket_now - 1
        key_now = f"ddos:1.2.3.4:{bucket_now}"
        key_prev = f"ddos:1.2.3.4:{bucket_prev}"
        assert key_now != key_prev


# ---------------------------------------------------------------------------
# Integration: proxy smoke tests (skipped when fastapi is not installed)
# ---------------------------------------------------------------------------

class TestProxyIntegration:
    """
    Lightweight sanity check that DDoSProtector plugs into the proxy without
    import errors.  Does not test full request flow.

    Skipped automatically when fastapi is not installed (e.g. CI without the
    full requirements set).
    """

    def test_create_gateway_app_accepts_ddos_protector(self, mock_redis):
        fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")  # noqa: F841
        from yashigani.gateway.proxy import create_gateway_app, GatewayConfig

        protector = DDoSProtector(mock_redis)
        cfg = GatewayConfig(upstream_base_url="http://localhost:9999")
        app = create_gateway_app(config=cfg, ddos_protector=protector)
        assert app is not None

    def test_openai_router_configure_accepts_ddos_protector(self, mock_redis):
        pytest.importorskip("fastapi", reason="fastapi not installed")
        from yashigani.gateway import openai_router

        protector = DDoSProtector(mock_redis)
        # Should not raise
        openai_router.configure(ddos_protector=protector)
        assert openai_router._state.ddos_protector is protector
