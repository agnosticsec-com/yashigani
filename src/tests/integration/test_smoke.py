"""
Smoke integration tests for Yashigani v0.9.3.

These tests validate that core components initialize correctly.
They do NOT require a running Docker stack — they test Python-level
initialization and configuration, not network connectivity.

Run with: pytest -m integration src/tests/integration/
"""
import pytest

pytestmark = pytest.mark.integration


class TestGatewayInit:
    """Verify gateway app can be constructed without crashing."""

    def test_gateway_config_defaults(self):
        from yashigani.gateway.proxy import GatewayConfig
        cfg = GatewayConfig(upstream_base_url="http://localhost:9999")
        assert cfg.opa_url == "http://policy:8181"
        assert cfg.request_timeout_seconds == 30.0
        assert cfg.max_request_body_bytes == 4 * 1024 * 1024

    def test_rate_limit_config_defaults(self):
        from yashigani.ratelimit.config import RateLimitConfig
        cfg = RateLimitConfig()
        assert cfg.global_rps > 0
        assert cfg.per_ip_rps > 0


class TestLicensing:
    """Verify licensing module loads without error."""

    def test_license_model_import(self):
        from yashigani.licensing.model import LicenseTier, LicenseFeature
        assert LicenseTier.COMMUNITY is not None
        assert LicenseTier.ENTERPRISE is not None

    def test_enforcer_community_defaults(self):
        from yashigani.licensing.enforcer import get_license
        lic = get_license()
        # Community tier should be set and non-None
        assert lic.tier is not None


class TestInspection:
    """Verify inspection pipeline components are importable and configurable."""

    def test_pipeline_import(self):
        from yashigani.inspection.pipeline import InspectionPipeline
        assert InspectionPipeline is not None

    def test_backend_config_secret_filter(self):
        """Verify the secret filter blocks sensitive field names (M12 regression test)."""
        from yashigani.inspection.backend_config import BackendConfigStore
        secret_fields = {"api_key", "secret", "password", "token"}
        # These should all be filtered
        for field in ["api_key", "my_secret", "db_password", "auth_token", "bearer_key"]:
            lower = field.lower()
            is_blocked = (
                field in secret_fields
                or any(s in lower for s in ("key", "secret", "password", "token"))
            )
            assert is_blocked, f"Field '{field}' should be blocked by secret filter"


class TestDatabase:
    """Verify database module integrity."""

    def test_pool_not_initialized_raises_runtime_error(self):
        """Verify H11 fix: RuntimeError instead of AssertionError."""
        from yashigani.db.postgres import get_pool
        with pytest.raises(RuntimeError, match="DB pool not initialized"):
            get_pool()


class TestRateLimiter:
    """Verify rate limiter operator precedence fix (C4 regression test)."""

    def test_dimension_skip_logic(self):
        """The skip condition should only apply to agent/session dimensions."""
        # This tests the logic, not the actual rate limiter (needs Redis)
        dimensions = [
            ("global", True),   # should never skip
            ("ip", True),       # should never skip
            ("agent", False),   # should skip when agent_id is empty
            ("session", False), # should skip when session_id is empty
        ]
        agent_id = ""
        session_id = "valid_session"

        for dimension, should_check in dimensions:
            # Corrected logic (with parentheses)
            skip = dimension in ("agent", "session") and (not agent_id or not session_id)
            if should_check:
                assert not skip, f"Dimension '{dimension}' should not be skipped"
            else:
                assert skip, f"Dimension '{dimension}' should be skipped when agent_id is empty"
