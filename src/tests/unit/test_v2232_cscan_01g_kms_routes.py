"""
Unit tests for V232-CSCAN-01g — safe_error_envelope migration in kms.py routes.

Covers the three sites at (original) lines 89, 131, 162:
  - POST /kms/schedule  — invalid_cron_expression (ValueError from _validate_cron)
  - POST /kms/rotate-now — rotation_failed (Exception from scheduler.trigger_now)
  - GET  /kms/secrets   — list_failed (Exception from provider.list_secrets)

Asserts per site:
  1. HTTPException is raised with the correct status code.
  2. detail is a dict with keys "error" and "request_id".
  3. detail does NOT contain the exception class name.
  4. detail does NOT contain str(exc) (the raw exception message).

# Last updated: 2026-05-03T00:00:00+01:00
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Module isolation helpers
# ---------------------------------------------------------------------------

_KMS_PATH = Path(__file__).parents[2] / "yashigani" / "backoffice" / "routes" / "kms.py"


def _load_kms_module():
    """Load kms.py with its heavy dependencies stubbed out."""
    stubs = {
        "yashigani.backoffice.middleware": type(sys)("stub"),
        "yashigani.backoffice.state": type(sys)("stub"),
        "yashigani.common.error_envelope": importlib.import_module(
            "yashigani.common.error_envelope"
        ),
        "fastapi": importlib.import_module("fastapi"),
        "pydantic": importlib.import_module("pydantic"),
    }

    # Minimal middleware stubs
    stubs["yashigani.backoffice.middleware"].AdminSession = object
    stubs["yashigani.backoffice.middleware"].StepUpAdminSession = object

    # backoffice_state will be patched per-test
    state_stub = MagicMock()
    state_stub.kms_provider = None
    state_stub.rotation_scheduler = None
    state_stub.audit_writer = MagicMock()
    stubs["yashigani.backoffice.state"].backoffice_state = state_stub

    old: dict = {}
    for k, v in stubs.items():
        old[k] = sys.modules.get(k)
        sys.modules[k] = v

    spec = importlib.util.spec_from_file_location("kms_isolated_01g", _KMS_PATH)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    finally:
        for k, v in old.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v
    return mod, stubs["yashigani.backoffice.state"].backoffice_state


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _assert_safe_envelope(detail: object, exc_msg: str, exc_class: str) -> None:
    """Assert detail is a safe envelope dict without exception leakage."""
    assert isinstance(detail, dict), f"detail must be a dict, got {type(detail)}"
    assert "error" in detail, "detail must contain 'error' key"
    assert "request_id" in detail, "detail must contain 'request_id' key"
    # Must not contain the raw exception message
    detail_str = str(detail)
    assert exc_msg not in detail_str, (
        f"Exception message {exc_msg!r} leaked into HTTP detail: {detail_str}"
    )
    # Must not contain the exception class name
    assert exc_class not in detail_str, (
        f"Exception class {exc_class!r} leaked into HTTP detail: {detail_str}"
    )


# ---------------------------------------------------------------------------
# POST /kms/schedule — invalid cron expression
# ---------------------------------------------------------------------------

class TestKmsScheduleInvalidCron:
    """
    V232-CSCAN-01g site 1 (original line 89).
    ValueError from _validate_cron must NOT surface str(exc) to the client.
    """

    def test_invalid_cron_returns_safe_envelope(self):
        """HTTPException detail must be safe envelope; exception message must not appear."""
        from fastapi import HTTPException

        kms_mod, state = _load_kms_module()

        exc_msg = "Cron interval too frequent: minimum is 1 hour. Got every 1 minute."

        def _fake_validate_cron(expr: str):
            raise ValueError(exc_msg)

        # Patch _validate_cron inside the dynamically loaded module's local import
        with patch.dict(
            sys.modules,
            {"yashigani.kms.rotation": MagicMock(_validate_cron=_fake_validate_cron)},
        ):
            body = MagicMock()
            body.cron_expr = "* * * * *"  # every minute — too frequent
            session = MagicMock()

            import asyncio

            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(kms_mod.update_schedule(body, session))

        assert exc_info.value.status_code == 422
        _assert_safe_envelope(exc_info.value.detail, exc_msg, "ValueError")

    def test_invalid_cron_detail_has_error_key(self):
        """detail["error"] must be the hardcoded public message, not the exc text."""
        from fastapi import HTTPException

        kms_mod, state = _load_kms_module()

        with patch.dict(
            sys.modules,
            {
                "yashigani.kms.rotation": MagicMock(
                    _validate_cron=MagicMock(
                        side_effect=ValueError("INTERNAL: too frequent — interval 59s < 3600s")
                    )
                )
            },
        ):
            body = MagicMock()
            body.cron_expr = "*/1 * * * *"
            session = MagicMock()

            import asyncio

            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(kms_mod.update_schedule(body, session))

        detail = exc_info.value.detail
        assert isinstance(detail, dict)
        assert "INTERNAL" not in str(detail)
        assert "3600" not in str(detail)
        assert detail["error"] == "invalid cron expression"


# ---------------------------------------------------------------------------
# POST /kms/rotate-now — rotation failure
# ---------------------------------------------------------------------------

class TestKmsRotateNowFailure:
    """
    V232-CSCAN-01g site 2 (original line 131).
    Exception from scheduler.trigger_now() must NOT surface str(exc) to the client.
    """

    def test_rotation_failure_returns_safe_envelope(self):
        from fastapi import HTTPException

        kms_mod, state = _load_kms_module()

        exc_msg = "VaultTokenExpired: token lease /auth/token/xyz expired at 2026-05-03T00:00:00Z"

        mock_scheduler = MagicMock()
        mock_scheduler.trigger_now.side_effect = RuntimeError(exc_msg)
        state.rotation_scheduler = mock_scheduler

        # Patch the module's backoffice_state reference
        with patch.object(kms_mod, "backoffice_state", state):
            session = MagicMock()

            import asyncio

            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(kms_mod.rotate_now(session))

        assert exc_info.value.status_code == 500
        _assert_safe_envelope(exc_info.value.detail, exc_msg, "RuntimeError")

    def test_rotation_failure_detail_has_request_id(self):
        from fastapi import HTTPException

        kms_mod, state = _load_kms_module()

        mock_scheduler = MagicMock()
        mock_scheduler.trigger_now.side_effect = Exception("Vault TOTP seed /secrets/kms leaked")
        state.rotation_scheduler = mock_scheduler

        with patch.object(kms_mod, "backoffice_state", state):
            session = MagicMock()

            import asyncio

            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(kms_mod.rotate_now(session))

        detail = exc_info.value.detail
        assert "request_id" in detail
        # request_id must be a non-empty string (UUID hex)
        assert isinstance(detail["request_id"], str)
        assert len(detail["request_id"]) > 0
        # Vault path must not leak
        assert "secrets/kms" not in str(detail)

    def test_rotation_failure_error_is_hardcoded_string(self):
        from fastapi import HTTPException

        kms_mod, state = _load_kms_module()

        mock_scheduler = MagicMock()
        mock_scheduler.trigger_now.side_effect = OSError("ECONNREFUSED vault:8200")
        state.rotation_scheduler = mock_scheduler

        with patch.object(kms_mod, "backoffice_state", state):
            session = MagicMock()

            import asyncio

            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(kms_mod.rotate_now(session))

        # The hardcoded public message from 01g
        assert exc_info.value.detail["error"] == "rotation failed"
        assert "ECONNREFUSED" not in str(exc_info.value.detail)


# ---------------------------------------------------------------------------
# GET /kms/secrets — list failure
# ---------------------------------------------------------------------------

class TestKmsListSecretsFailure:
    """
    V232-CSCAN-01g site 3 (original line 162).
    Exception from provider.list_secrets() must NOT surface str(exc) to the client.
    """

    def test_list_failure_returns_safe_envelope(self):
        from fastapi import HTTPException

        kms_mod, state = _load_kms_module()

        exc_msg = "ProviderError: Vault at https://vault.internal:8200/v1/kms returned 403"

        mock_provider = MagicMock()
        mock_provider.list_secrets.side_effect = RuntimeError(exc_msg)
        state.kms_provider = mock_provider

        with patch.object(kms_mod, "backoffice_state", state):
            session = MagicMock()

            import asyncio

            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(kms_mod.list_secrets(session))

        assert exc_info.value.status_code == 500
        _assert_safe_envelope(exc_info.value.detail, exc_msg, "RuntimeError")

    def test_list_failure_does_not_leak_vault_url(self):
        from fastapi import HTTPException

        kms_mod, state = _load_kms_module()

        # Exc message contains an internal URL that must not reach the client
        vault_url = "https://vault.internal.agnosticsec.com:8200/v1/secret/data"
        mock_provider = MagicMock()
        mock_provider.list_secrets.side_effect = ConnectionError(
            f"Connection refused: {vault_url}"
        )
        state.kms_provider = mock_provider

        with patch.object(kms_mod, "backoffice_state", state):
            session = MagicMock()

            import asyncio

            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(kms_mod.list_secrets(session))

        detail = exc_info.value.detail
        assert vault_url not in str(detail)
        assert "vault.internal" not in str(detail)
        assert detail["error"] == "failed to list secrets"

    def test_list_failure_envelope_shape(self):
        """Envelope must have exactly error + request_id keys at minimum."""
        from fastapi import HTTPException

        kms_mod, state = _load_kms_module()

        mock_provider = MagicMock()
        mock_provider.list_secrets.side_effect = Exception("arbitrary internal detail")
        state.kms_provider = mock_provider

        with patch.object(kms_mod, "backoffice_state", state):
            session = MagicMock()

            import asyncio

            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(kms_mod.list_secrets(session))

        detail = exc_info.value.detail
        assert set(detail.keys()) == {"error", "request_id"}
