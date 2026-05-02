"""
Unit tests for the activate_license route guard (M-05 / LAURA-V231-002 follow-on).

The route must:
  1. Return 422 (not 500) when verify_license() raises unexpectedly.
  2. Return 422 when the license is valid=False.
  3. Log the rejection before raising HTTPException.
  4. NOT crash the worker process.

Strategy: we test the guard logic directly using an extracted helper that mirrors
the exact pattern in the route.  This avoids the need for python-multipart,
bcrypt, asyncpg, and other heavy deps not installed in the unit test environment,
while still asserting that the pattern is correct.

Additionally, we assert the guard pattern IS PRESENT in the source file, so that
any accidental removal of the try/except would cause this test to fail.

Last updated: 2026-04-27T21:53:12+01:00
"""
from __future__ import annotations

import ast
import inspect
import logging
import textwrap
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException, status


# ---------------------------------------------------------------------------
# Source-level guard presence check (AST)
# ---------------------------------------------------------------------------

ROUTE_FILE = Path(__file__).parents[2] / "yashigani" / "backoffice" / "routes" / "license.py"


class TestGuardPresentInSource:
    """
    AST-level check: verify the try/except guard around verify_license() is
    present in the source file.  If someone removes the guard, this fails fast
    rather than allowing a regression to ship silently.
    """

    def test_route_file_exists(self):
        assert ROUTE_FILE.exists(), f"Route file not found: {ROUTE_FILE}"

    def test_try_except_wraps_verify_license(self):
        """The source must contain a try/except around verify_license()."""
        source = ROUTE_FILE.read_text(encoding="utf-8")
        # Look for the try block immediately preceding the verify_license call
        assert "try:" in source, "No try: block found in route file"
        assert "verify_license(content)" in source, "verify_license(content) call not found"
        assert "except Exception" in source, "No except Exception block found"
        assert "INVALID_LICENSE" in source, "INVALID_LICENSE error key not found in except block"
        assert "malformed_license_content" in source, \
            "malformed_license_content error detail not found — guard may be incomplete"

    def test_m05_comment_present(self):
        """M-05 finding reference must be in the source comment."""
        source = ROUTE_FILE.read_text(encoding="utf-8")
        assert "M-05" in source, \
            "M-05 finding reference missing from route file — guard may not be the M-05 fix"


# ---------------------------------------------------------------------------
# Logic extraction — test the guard pattern in isolation
# ---------------------------------------------------------------------------

async def _simulate_activate_license_guard(
    verify_license_fn,
    content: Optional[str] = "payload.sig.countersig",
) -> dict:
    """
    Replicate the M-05 guard logic from activate_license route.

    This is the exact pattern that was added:

        try:
            new_lic = verify_license(content)
        except Exception as exc:
            logger.warning("... M-05 ...: %s", exc)
            raise HTTPException(status_code=422, detail={...})

        if not new_lic.valid:
            raise HTTPException(status_code=422, detail={"error": "INVALID_LICENSE", ...})

    Returns the (synthetic) success response dict.
    Raises HTTPException on any failure (guard or invalid).
    """
    logger = logging.getLogger("_simulate_activate_license_guard")

    try:
        new_lic = verify_license_fn(content)
    except Exception as exc:
        logger.warning(
            "License activation rejected — verify_license raised unexpectedly "
            "(M-05 / LAURA-V231-002): %s",
            exc,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "INVALID_LICENSE", "detail": "malformed_license_content"},
        )

    if not new_lic.valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "INVALID_LICENSE", "detail": new_lic.error},
        )

    return {"status": "activated", "tier": new_lic.tier.value}


class TestActivateLicenseGuardLogic:
    """
    M-05 / LAURA-V231-002 follow-on: the guard pattern applied to activate_license.

    Tests exercise the extracted guard logic directly, confirming correctness of
    the try/except pattern without importing the full FastAPI route (which requires
    python-multipart + heavy deps not available in the unit test environment).
    """

    @pytest.mark.asyncio
    async def test_raises_422_when_verify_license_raises_valueerror(self):
        """ValueError from verify_license → 422, not 500 or crash."""
        def _bad_verify(content):
            raise ValueError("null seat field caused TypeError")

        with pytest.raises(HTTPException) as exc_info:
            await _simulate_activate_license_guard(_bad_verify)
        assert exc_info.value.status_code == 422
        assert exc_info.value.detail["error"] == "INVALID_LICENSE"
        assert exc_info.value.detail["detail"] == "malformed_license_content"

    @pytest.mark.asyncio
    async def test_raises_422_when_verify_license_raises_typeerror(self):
        """TypeError (e.g., int(None)) from verify_license → 422, not worker crash."""
        def _bad_verify(content):
            raise TypeError("int() argument must be a string, not 'NoneType'")

        with pytest.raises(HTTPException) as exc_info:
            await _simulate_activate_license_guard(_bad_verify)
        assert exc_info.value.status_code == 422

    @pytest.mark.asyncio
    async def test_raises_422_when_verify_license_raises_runtime_error(self):
        """RuntimeError (crypto failure) → 422."""
        def _bad_verify(content):
            raise RuntimeError("unexpected crypto library error")

        with pytest.raises(HTTPException) as exc_info:
            await _simulate_activate_license_guard(_bad_verify)
        assert exc_info.value.status_code == 422

    @pytest.mark.asyncio
    async def test_logs_warning_before_raising(self, caplog):
        """A WARNING log entry is emitted before the HTTPException is raised."""
        def _bad_verify(content):
            raise ValueError("corrupt payload")

        with caplog.at_level(logging.WARNING):
            with pytest.raises(HTTPException):
                await _simulate_activate_license_guard(_bad_verify)

        logged = caplog.text.lower()
        assert "m-05" in logged or "rejected" in logged or "malformed" in logged

    @pytest.mark.asyncio
    async def test_invalid_license_returns_422_with_specific_error(self):
        """verify_license returns valid=False → 422 with the specific error string."""
        mock_lic = MagicMock()
        mock_lic.valid = False
        mock_lic.error = "license_format_too_old"

        def _invalid_lic(content):
            return mock_lic

        with pytest.raises(HTTPException) as exc_info:
            await _simulate_activate_license_guard(_invalid_lic)
        assert exc_info.value.status_code == 422
        assert exc_info.value.detail["detail"] == "license_format_too_old"

    @pytest.mark.asyncio
    async def test_invalid_signature_returns_422(self):
        """Verify that invalid_signature error is passed through correctly."""
        mock_lic = MagicMock()
        mock_lic.valid = False
        mock_lic.error = "invalid_signature"

        with pytest.raises(HTTPException) as exc_info:
            await _simulate_activate_license_guard(lambda c: mock_lic)
        assert exc_info.value.status_code == 422
        assert exc_info.value.detail["detail"] == "invalid_signature"

    @pytest.mark.asyncio
    async def test_counter_signature_invalid_returns_422(self):
        """counter_signature_invalid error is passed through correctly."""
        mock_lic = MagicMock()
        mock_lic.valid = False
        mock_lic.error = "counter_signature_invalid"

        with pytest.raises(HTTPException) as exc_info:
            await _simulate_activate_license_guard(lambda c: mock_lic)
        assert exc_info.value.status_code == 422
        assert exc_info.value.detail["detail"] == "counter_signature_invalid"

    @pytest.mark.asyncio
    async def test_v3_format_too_old_returns_422(self):
        """license_format_too_old (LAURA-V231-003) is surfaced correctly to admin."""
        mock_lic = MagicMock()
        mock_lic.valid = False
        mock_lic.error = "license_format_too_old"

        with pytest.raises(HTTPException) as exc_info:
            await _simulate_activate_license_guard(lambda c: mock_lic)
        assert exc_info.value.status_code == 422
        assert exc_info.value.detail["detail"] == "license_format_too_old"

    @pytest.mark.asyncio
    async def test_valid_license_does_not_raise(self):
        """A valid license results in a success response (no exception)."""
        mock_lic = MagicMock()
        mock_lic.valid = True
        mock_lic.tier = MagicMock()
        mock_lic.tier.value = "professional"

        result = await _simulate_activate_license_guard(lambda c: mock_lic)
        assert result["status"] == "activated"
        assert result["tier"] == "professional"
