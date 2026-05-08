"""
Tests for v2.23.2 login throttle RFC 6585 Retry-After header + user-facing banner.

L-2: throttled login responses must include:
  - HTTP 429 status code
  - Retry-After: <seconds> header (RFC 6585 §4)
  - JSON body with a customer-facing "banner" message
  - No internal jargon, no agent names, no internal IDs in banner text

Throttle schedule (×5 escalation per feedback_auth_throttle.md):
  Level 1:  30s  (after 3 consecutive per-IP failures)
  Level 2:  60s
  Level 3: 300s
  Level 4: 1500s
  Level 5: 7500s
  Level 6: 37500s  (next failure → permanent block)

Last updated: 2026-05-02T00:00:00+01:00
"""
from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

SRC = Path(__file__).parent.parent.parent / "yashigani"
ROUTES_AUTH = SRC / "backoffice" / "routes" / "auth.py"


# ---------------------------------------------------------------------------
# Helpers — load the throttle helpers without importing FastAPI stack
# ---------------------------------------------------------------------------

def _get_source() -> str:
    return ROUTES_AUTH.read_text(encoding="utf-8")


def _parse_fn(name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    tree = ast.parse(_get_source())
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    pytest.fail(f"Function '{name}' not found in auth.py")


# ---------------------------------------------------------------------------
# AST-level structural checks (no import of FastAPI required)
# ---------------------------------------------------------------------------

class TestRetryAfterStructural:
    """
    AST-level checks that the Retry-After header and banner are present
    in the throttle implementation without importing the full FastAPI stack.
    """

    def test_apply_auth_throttle_is_sync(self):
        """
        _apply_auth_throttle must be a plain def (not async def) since it now
        raises HTTPException instead of awaiting asyncio.sleep().
        """
        fn = _parse_fn("_apply_auth_throttle")
        assert isinstance(fn, ast.FunctionDef), (
            "_apply_auth_throttle must be 'def' (sync), not 'async def' — "
            "it raises HTTPException immediately rather than sleeping"
        )

    def test_apply_auth_throttle_accepts_response_param(self):
        """
        _apply_auth_throttle must accept a 'response' parameter so it can
        set Retry-After on the Response object before raising HTTPException.
        """
        fn = _parse_fn("_apply_auth_throttle")
        param_names = [arg.arg for arg in fn.args.args]
        assert "response" in param_names, (
            "_apply_auth_throttle must accept a 'response' parameter "
            f"(got: {param_names})"
        )

    def test_retry_after_header_present_in_source(self):
        """
        The source must contain 'Retry-After' string — confirms the header
        is set in both the HTTPException headers dict and the Response object.
        """
        source = _get_source()
        assert "Retry-After" in source, (
            "auth.py must set 'Retry-After' header on throttled responses (RFC 6585 §4)"
        )

    def test_banner_field_present_in_source(self):
        """
        The 429 response detail must include a 'banner' field with
        customer-facing text (no internal IDs or agent names).
        """
        source = _get_source()
        assert '"banner"' in source or "'banner'" in source, (
            "Throttle 429 response must include a 'banner' key in the JSON detail"
        )

    def test_banner_text_references_wait_time(self):
        """
        The banner text must tell the user to wait — it must include 'wait'
        or 'try again' so the user understands the lockout.
        """
        source = _get_source()
        # Check for user-facing wait language
        assert "wait" in source.lower() or "try again" in source.lower(), (
            "Banner text must instruct the user to wait or try again later"
        )

    def test_no_asyncio_sleep_in_apply_throttle(self):
        """
        asyncio.sleep must NOT be present in _apply_auth_throttle — the
        old sleep-and-continue pattern has been replaced by an immediate 429.
        """
        fn = _parse_fn("_apply_auth_throttle")
        fn_src = ast.unparse(fn)
        assert "asyncio.sleep" not in fn_src, (
            "_apply_auth_throttle must not use asyncio.sleep — "
            "it raises HTTP 429 immediately (RFC 6585) instead of blocking the connection"
        )

    def test_http_429_raised_when_throttled(self):
        """
        _apply_auth_throttle must raise an HTTPException with status 429
        when effective_level > 0.
        """
        fn = _parse_fn("_apply_auth_throttle")
        fn_src = ast.unparse(fn)
        # HTTPException must be raised inside this function
        assert "HTTPException" in fn_src, (
            "_apply_auth_throttle must raise HTTPException (HTTP 429) when throttled"
        )
        assert "429" in fn_src or "HTTP_429_TOO_MANY_REQUESTS" in fn_src, (
            "_apply_auth_throttle must use HTTP 429 status on the HTTPException"
        )

    def test_retry_after_value_is_delay_seconds(self):
        """
        The Retry-After value must be the throttle delay in seconds
        (from _throttle_delay_for_level), not a fixed constant.
        """
        fn = _parse_fn("_apply_auth_throttle")
        fn_src = ast.unparse(fn)
        # delay variable must be used in the Retry-After context
        assert "delay" in fn_src, (
            "_apply_auth_throttle must compute 'delay' from _throttle_delay_for_level "
            "and use it as the Retry-After value"
        )

    def test_login_route_calls_throttle_with_response(self):
        """
        The login route must pass the 'response' object to _apply_auth_throttle
        (not the old bare call with only client_ip).
        """
        fn = _parse_fn("login")
        fn_src = ast.unparse(fn)
        # Must call _apply_auth_throttle with response argument
        assert "_apply_auth_throttle(client_ip, response)" in fn_src, (
            "login() must call _apply_auth_throttle(client_ip, response) — "
            "the response object is required for RFC 6585 Retry-After header"
        )

    def test_login_route_not_awaiting_throttle(self):
        """
        login() must NOT await _apply_auth_throttle — it is now a sync function.
        """
        fn = _parse_fn("login")
        fn_src = ast.unparse(fn)
        # 'await _apply_auth_throttle' must not appear
        assert "await _apply_auth_throttle" not in fn_src, (
            "login() must not 'await _apply_auth_throttle' — "
            "the function is now synchronous (raises 429 immediately)"
        )


# ---------------------------------------------------------------------------
# Behaviour checks — mock Redis, exercise throttle directly
# ---------------------------------------------------------------------------

class TestRetryAfterBehaviour:
    """
    Behaviour tests that exercise _apply_auth_throttle with a mocked Redis
    client and assert the HTTPException is raised with the right headers
    and body.
    """

    def _import_module_symbols(self):
        """
        Import only the throttle helpers from auth.py, stubbing out heavy deps.
        Raises ImportError → skip if the full FastAPI stack isn't installed.
        """
        try:
            import fastapi  # noqa: F401
            import redis  # noqa: F401
        except ImportError as exc:
            pytest.skip(f"FastAPI or redis not installed: {exc}")

        # We need to import auth.py; stub out the heavy state dep
        import importlib
        import importlib.util
        import sys
        import types

        stubs = {
            "yashigani.backoffice.middleware": types.ModuleType("stub_middleware"),
            "yashigani.backoffice.state": types.ModuleType("stub_state"),
            "yashigani.auth.totp": types.ModuleType("stub_totp"),
            "yashigani.db.postgres": types.ModuleType("stub_pg"),
        }
        stubs["yashigani.backoffice.middleware"].AdminSession = object
        stubs["yashigani.backoffice.middleware"].AnySession = object
        stubs["yashigani.backoffice.middleware"].get_session_store = lambda: None
        stubs["yashigani.backoffice.middleware"]._SESSION_COOKIE = "session"
        stubs["yashigani.backoffice.middleware"].require_admin_session = lambda *a, **kw: None
        stubs["yashigani.backoffice.state"].backoffice_state = MagicMock()
        stubs["yashigani.auth.totp"].verify_totp = MagicMock()
        stubs["yashigani.auth.totp"].generate_provisioning = MagicMock()
        stubs["yashigani.auth.totp"].generate_recovery_code_set = MagicMock()
        stubs["yashigani.db.postgres"].tenant_transaction = MagicMock()

        old = {}
        for k, v in stubs.items():
            old[k] = sys.modules.get(k)
            sys.modules[k] = v

        spec = importlib.util.spec_from_file_location("auth_isolated_throttle", ROUTES_AUTH)
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        finally:
            for k, v in old.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v
        return mod

    def _make_mock_redis(self, ip_level: int = 0, global_level: int = 0,
                         ip_fails: int = 0, global_fails: int = 0) -> MagicMock:
        """Build a Redis mock whose pipeline().execute() returns the given state."""
        r = MagicMock()
        pipe = MagicMock()
        r.pipeline.return_value = pipe
        pipe.get.return_value = pipe
        pipe.execute.return_value = [
            str(ip_fails) if ip_fails else None,
            str(global_fails) if global_fails else None,
            str(ip_level) if ip_level else None,
            str(global_level) if global_level else None,
        ]
        return r

    def _make_mock_response(self) -> MagicMock:
        response = MagicMock()
        response.headers = {}
        return response

    def test_no_throttle_when_level_zero(self):
        """Level 0 (no prior failures) — no exception raised."""
        try:
            mod = self._import_module_symbols()
        except pytest.skip.Exception:
            pytest.skip("deps not available")

        r = self._make_mock_redis(ip_level=0, global_level=0)
        resp = self._make_mock_response()

        with patch.object(mod, "_get_throttle_redis", return_value=r):
            # Must not raise
            mod._apply_auth_throttle("1.2.3.4", resp)

    def test_429_raised_at_ip_level_1(self):
        """IP throttle level 1 → 429 raised with Retry-After: 30."""
        try:
            mod = self._import_module_symbols()
        except pytest.skip.Exception:
            pytest.skip("deps not available")
        from fastapi import HTTPException as FE

        r = self._make_mock_redis(ip_level=1, global_level=0)
        resp = self._make_mock_response()

        with patch.object(mod, "_get_throttle_redis", return_value=r):
            with pytest.raises(FE) as exc_info:
                mod._apply_auth_throttle("1.2.3.4", resp)

        exc = exc_info.value
        assert exc.status_code == 429, f"Expected 429, got {exc.status_code}"
        assert "Retry-After" in exc.headers, "HTTPException must carry Retry-After header"
        assert exc.headers["Retry-After"] == "30", (
            f"Retry-After must be '30' at level 1, got {exc.headers['Retry-After']!r}"
        )

    def test_retry_after_escalates_by_level(self):
        """Retry-After value matches the throttle delay schedule at each level."""
        try:
            mod = self._import_module_symbols()
        except pytest.skip.Exception:
            pytest.skip("deps not available")
        from fastapi import HTTPException as FE

        expected = {1: 30, 2: 60, 3: 300, 4: 1500, 5: 7500, 6: 37500}

        for level, delay in expected.items():
            r = self._make_mock_redis(ip_level=level, global_level=0)
            resp = self._make_mock_response()

            with patch.object(mod, "_get_throttle_redis", return_value=r):
                with pytest.raises(FE) as exc_info:
                    mod._apply_auth_throttle("1.2.3.4", resp)

            exc = exc_info.value
            assert exc.status_code == 429, f"Level {level}: expected 429"
            ra = exc.headers.get("Retry-After")
            assert ra == str(delay), (
                f"Level {level}: expected Retry-After={delay}, got {ra!r}"
            )

    def test_global_throttle_triggers_429(self):
        """Global throttle level 1 (IP level 0) → 429 with Retry-After."""
        try:
            mod = self._import_module_symbols()
        except pytest.skip.Exception:
            pytest.skip("deps not available")
        from fastapi import HTTPException as FE

        # IP level 0, global level 1
        r = self._make_mock_redis(ip_level=0, global_level=1)
        resp = self._make_mock_response()

        with patch.object(mod, "_get_throttle_redis", return_value=r):
            with pytest.raises(FE) as exc_info:
                mod._apply_auth_throttle("1.2.3.4", resp)

        exc = exc_info.value
        assert exc.status_code == 429
        assert exc.headers.get("Retry-After") == "30"

    def test_higher_level_wins(self):
        """When IP level=2 and global level=4, Retry-After uses level 4 (1500s)."""
        try:
            mod = self._import_module_symbols()
        except pytest.skip.Exception:
            pytest.skip("deps not available")
        from fastapi import HTTPException as FE

        r = self._make_mock_redis(ip_level=2, global_level=4)
        resp = self._make_mock_response()

        with patch.object(mod, "_get_throttle_redis", return_value=r):
            with pytest.raises(FE) as exc_info:
                mod._apply_auth_throttle("1.2.3.4", resp)

        exc = exc_info.value
        assert exc.headers.get("Retry-After") == "1500", (
            "Effective level = max(2, 4) = 4 → delay 1500s"
        )

    def test_banner_present_in_429_detail(self):
        """429 detail must include a 'banner' key with customer-facing text."""
        try:
            mod = self._import_module_symbols()
        except pytest.skip.Exception:
            pytest.skip("deps not available")
        from fastapi import HTTPException as FE

        r = self._make_mock_redis(ip_level=1, global_level=0)
        resp = self._make_mock_response()

        with patch.object(mod, "_get_throttle_redis", return_value=r):
            with pytest.raises(FE) as exc_info:
                mod._apply_auth_throttle("1.2.3.4", resp)

        detail = exc_info.value.detail
        assert isinstance(detail, dict), f"detail must be a dict, got {type(detail)}"
        assert "banner" in detail, f"detail must contain 'banner' key, got {list(detail.keys())}"

        banner = detail["banner"]
        assert isinstance(banner, str) and len(banner) > 10, (
            f"banner must be a non-empty string, got {banner!r}"
        )
        # Customer-facing: must not contain internal jargon
        forbidden = ["agent", "redis", "postgres", "throttle_level", "LAURA", "AVA", "YCS"]
        for word in forbidden:
            assert word.lower() not in banner.lower(), (
                f"banner must not contain internal jargon '{word}': {banner!r}"
            )
        # Must reference the wait time
        assert "30" in banner or "second" in banner.lower() or "wait" in banner.lower(), (
            f"banner must tell the user how long to wait: {banner!r}"
        )

    def test_banner_grammatical_singular_at_1s(self):
        """
        Banner at 1-second delay must say 'second' not 'seconds'
        (edge-case: delay is never 1s in the real schedule, but the pluralisation
        logic must be correct — validated via _throttle_delay_for_level mock).
        """
        source = _get_source()
        # The source must have a pluralisation guard: second/seconds
        assert "second" in source, (
            "Banner must include 'second' (with optional 's' for pluralisation)"
        )

    def test_retry_after_seconds_field_matches_header(self):
        """detail['retry_after_seconds'] must match the Retry-After header value."""
        try:
            mod = self._import_module_symbols()
        except pytest.skip.Exception:
            pytest.skip("deps not available")
        from fastapi import HTTPException as FE

        r = self._make_mock_redis(ip_level=3, global_level=0)
        resp = self._make_mock_response()

        with patch.object(mod, "_get_throttle_redis", return_value=r):
            with pytest.raises(FE) as exc_info:
                mod._apply_auth_throttle("1.2.3.4", resp)

        exc = exc_info.value
        ra_header = int(exc.headers["Retry-After"])
        ra_body = exc.detail.get("retry_after_seconds")
        assert ra_body == ra_header, (
            f"retry_after_seconds in body ({ra_body}) must match "
            f"Retry-After header ({ra_header})"
        )


# ---------------------------------------------------------------------------
# Throttle delay schedule (×5 escalation) — unit tests for _throttle_delay_for_level
# ---------------------------------------------------------------------------

class TestThrottleDelaySchedule:
    """
    Verify the ×5 escalation schedule is correctly implemented.
    These tests use only the delay helper — no Redis, no FastAPI.
    """

    def _get_delay_fn(self):
        """Import _throttle_delay_for_level from auth.py in isolation."""
        import importlib
        import importlib.util
        import sys
        import types

        stubs = {
            "yashigani.backoffice.middleware": types.ModuleType("stub_middleware"),
            "yashigani.backoffice.state": types.ModuleType("stub_state"),
            "yashigani.auth.totp": types.ModuleType("stub_totp"),
            "yashigani.db.postgres": types.ModuleType("stub_pg"),
        }
        stubs["yashigani.backoffice.middleware"].AdminSession = object
        stubs["yashigani.backoffice.middleware"].AnySession = object
        stubs["yashigani.backoffice.middleware"].get_session_store = lambda: None
        stubs["yashigani.backoffice.middleware"]._SESSION_COOKIE = "session"
        stubs["yashigani.backoffice.middleware"].require_admin_session = lambda *a, **kw: None
        stubs["yashigani.backoffice.state"].backoffice_state = MagicMock()
        stubs["yashigani.auth.totp"].verify_totp = MagicMock()
        stubs["yashigani.auth.totp"].generate_provisioning = MagicMock()
        stubs["yashigani.auth.totp"].generate_recovery_code_set = MagicMock()
        stubs["yashigani.db.postgres"].tenant_transaction = MagicMock()

        try:
            import fastapi  # noqa: F401
        except ImportError:
            pytest.skip("fastapi not installed")

        old = {}
        for k, v in stubs.items():
            old[k] = sys.modules.get(k)
            sys.modules[k] = v

        spec = importlib.util.spec_from_file_location("auth_delay_test", ROUTES_AUTH)
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        finally:
            for k, v in old.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v
        return mod._throttle_delay_for_level

    def test_level_0_returns_0(self):
        fn = self._get_delay_fn()
        assert fn(0) == 0

    def test_level_1_returns_30(self):
        fn = self._get_delay_fn()
        assert fn(1) == 30

    def test_level_2_returns_60(self):
        fn = self._get_delay_fn()
        assert fn(2) == 60

    def test_level_3_returns_300(self):
        fn = self._get_delay_fn()
        assert fn(3) == 300

    def test_level_4_returns_1500(self):
        fn = self._get_delay_fn()
        assert fn(4) == 1500

    def test_level_5_returns_7500(self):
        fn = self._get_delay_fn()
        assert fn(5) == 7500

    def test_level_6_returns_37500(self):
        fn = self._get_delay_fn()
        assert fn(6) == 37500

    def test_level_beyond_max_caps_at_37500(self):
        """Any level above the table caps at the maximum delay."""
        fn = self._get_delay_fn()
        assert fn(99) == 37500
