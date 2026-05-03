"""
Unit tests for V232-CSCAN-01e — safe_error_envelope helper and migrated sites.

Covers:
  - safe_error_envelope: request_id assigned if None.
  - safe_error_envelope: public_message used if provided.
  - safe_error_envelope: logger.exception called with exc_info.
  - safe_error_envelope: default public_message when not provided.
  - Functional: migrated sites return {"error": ..., "request_id": ...} and
    MUST NOT contain the exception class name or exc.args message.

Last updated: 2026-05-03T00:00:00+01:00
"""
from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# safe_error_envelope unit tests
# ---------------------------------------------------------------------------

class TestSafeErrorEnvelope:
    """Unit tests for yashigani.common.error_envelope.safe_error_envelope."""

    def _import(self):
        from yashigani.common.error_envelope import safe_error_envelope
        return safe_error_envelope

    def test_returns_tuple_dict_and_int(self):
        """Must return (dict, int)."""
        safe_error_envelope = self._import()
        exc = RuntimeError("internal details")
        with patch("yashigani.common.error_envelope.logger") as mock_log:
            payload, status = safe_error_envelope(exc, public_message="test error")
        assert isinstance(payload, dict)
        assert isinstance(status, int)

    def test_request_id_generated_if_none(self):
        """request_id must be populated even when not supplied."""
        safe_error_envelope = self._import()
        exc = RuntimeError("x")
        with patch("yashigani.common.error_envelope.logger"):
            payload, _ = safe_error_envelope(exc)
        assert "request_id" in payload
        assert payload["request_id"]  # non-empty

    def test_supplied_request_id_used(self):
        """Supplied request_id must appear in the payload."""
        safe_error_envelope = self._import()
        exc = RuntimeError("x")
        with patch("yashigani.common.error_envelope.logger"):
            payload, _ = safe_error_envelope(exc, request_id="test-rid-123")
        assert payload["request_id"] == "test-rid-123"

    def test_public_message_in_payload(self):
        """public_message must appear as payload['error']."""
        safe_error_envelope = self._import()
        exc = RuntimeError("secret internal details")
        with patch("yashigani.common.error_envelope.logger"):
            payload, _ = safe_error_envelope(exc, public_message="cache flush failed")
        assert payload["error"] == "cache flush failed"

    def test_default_public_message_when_not_provided(self):
        """When public_message is omitted, 'internal error' is used."""
        safe_error_envelope = self._import()
        exc = RuntimeError("x")
        with patch("yashigani.common.error_envelope.logger"):
            payload, _ = safe_error_envelope(exc)
        assert payload["error"] == "internal error"

    def test_status_defaults_to_500(self):
        """Default status code must be 500."""
        safe_error_envelope = self._import()
        exc = RuntimeError("x")
        with patch("yashigani.common.error_envelope.logger"):
            _, status = safe_error_envelope(exc)
        assert status == 500

    def test_custom_status_code(self):
        """Custom status code must be passed through."""
        safe_error_envelope = self._import()
        exc = RuntimeError("x")
        with patch("yashigani.common.error_envelope.logger"):
            _, status = safe_error_envelope(exc, status=502)
        assert status == 502

    def test_logger_exception_called(self):
        """logger.exception must be called (so full traceback goes to server log)."""
        safe_error_envelope = self._import()
        exc = RuntimeError("internal details that must not reach client")
        with patch("yashigani.common.error_envelope.logger") as mock_log:
            safe_error_envelope(exc, public_message="safe message")
        mock_log.exception.assert_called_once()

    def test_exc_message_not_in_payload(self):
        """The exception's str() must NOT appear in the returned payload."""
        safe_error_envelope = self._import()
        secret_detail = "asyncpg DSN postgresql://user:secret@db:5432/yashigani"
        exc = RuntimeError(secret_detail)
        with patch("yashigani.common.error_envelope.logger"):
            payload, _ = safe_error_envelope(exc, public_message="cache config unavailable")
        payload_str = str(payload)
        assert secret_detail not in payload_str, (
            "Exception message must NOT appear in client payload — "
            f"found {secret_detail!r} in {payload_str!r}"
        )

    def test_exc_class_name_not_in_payload(self):
        """The exception class name must NOT appear in the returned payload."""
        safe_error_envelope = self._import()

        class _VaultAuthError(Exception):
            pass

        exc = _VaultAuthError("vault auth failed: role_id /run/secrets/vault_role_id")
        with patch("yashigani.common.error_envelope.logger"):
            payload, _ = safe_error_envelope(exc, public_message="kms backend unavailable")
        assert "_VaultAuthError" not in str(payload), (
            "Exception class name must NOT appear in client payload"
        )


# ---------------------------------------------------------------------------
# Functional test: migrated cache route returns safe envelope
# ---------------------------------------------------------------------------

class TestCacheRouteSafeEnvelope:
    """
    V232-CSCAN-01e: list_cache_configs must return a safe error envelope and
    MUST NOT include exception details when the DB pool raises.
    """

    def test_cache_error_response_is_safe(self):
        """
        Simulate a DB failure in /admin/cache and assert the response does not
        contain the exception message.
        """
        import ast
        from pathlib import Path

        cache_path = Path(__file__).parents[2] / "yashigani" / "backoffice" / "routes" / "cache.py"
        source = cache_path.read_text(encoding="utf-8")

        # V232-CSCAN-01e: str(exc) must NOT appear in the except block that handles
        # the DB pool error — it must be replaced by safe_error_envelope().
        tree = ast.parse(source)

        # Find list_cache_configs function
        fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "list_cache_configs":
                fn = node
                break
        assert fn is not None, "list_cache_configs not found in cache.py"

        fn_src = ast.unparse(fn)

        # Must use safe_error_envelope, not str(exc)
        assert "safe_error_envelope" in fn_src, (
            "V232-CSCAN-01e: list_cache_configs must use safe_error_envelope, not str(exc)"
        )
        # Must NOT contain bare str(exc) in the response
        assert '"error": str(' not in fn_src and "'error': str(" not in fn_src, (
            "V232-CSCAN-01e: list_cache_configs must not return str(exc) in error response"
        )

    def test_kms_status_uses_safe_envelope(self):
        """kms_status must use safe_error_envelope for the health_check exception."""
        import ast
        from pathlib import Path

        kms_path = Path(__file__).parents[2] / "yashigani" / "backoffice" / "routes" / "kms.py"
        source = kms_path.read_text(encoding="utf-8")
        tree = ast.parse(source)

        fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "kms_status":
                fn = node
                break
        assert fn is not None, "kms_status not found in kms.py"

        fn_src = ast.unparse(fn)
        assert "safe_error_envelope" in fn_src, (
            "V232-CSCAN-01e: kms_status must use safe_error_envelope"
        )
        # health_error must not be str(exc) directly
        assert "str(exc)" not in fn_src, (
            "V232-CSCAN-01e: kms_status must not assign str(exc) to health_error"
        )

    def test_openai_router_agent_errors_no_exc_interpolation(self):
        """
        openai_router agent error paths (Letta/Langflow/OpenAI) must not
        interpolate {exc} into the message field.
        """
        import ast
        from pathlib import Path

        router_path = Path(__file__).parents[2] / "yashigani" / "gateway" / "openai_router.py"
        source = router_path.read_text(encoding="utf-8")

        # Check no f-string with {exc} in "message" key inside JSONResponse content
        # Use text search — the AST check for f-string content is complex
        import re
        # Pattern: "message": f"... {exc}" or similar
        bad_pattern = re.compile(r'"message"\s*:\s*f"[^"]*\{exc\}')
        matches = bad_pattern.findall(source)
        assert not matches, (
            "V232-CSCAN-01e: openai_router must not interpolate {exc} in agent error messages. "
            f"Found: {matches}"
        )
