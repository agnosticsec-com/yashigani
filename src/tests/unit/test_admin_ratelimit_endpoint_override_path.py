"""
Regression test — /admin/ratelimit/endpoints must resolve correctly.

The ratelimit router is mounted at prefix /admin/ratelimit. Route decorators
inside the router must use RELATIVE paths (e.g. /endpoints) so that FastAPI
concatenates prefix + path to produce the correct resolved path.

If decorators use the full absolute path (/admin/ratelimit/endpoints), FastAPI
concatenates prefix + full path, producing an unreachable doubled path:
  /admin/ratelimit/admin/ratelimit/endpoints

These tests assert:
  1. ratelimit.py source does NOT contain absolute-path decorators for /endpoints.
  2. ratelimit.py source DOES contain the relative /endpoints decorators.
  3. All three HTTP methods (GET, POST, DELETE) are present at relative /endpoints.
  4. No route decorator contains the doubled /admin/ratelimit/admin/... pattern.

Source-level checks avoid the need for the full backoffice app stack.

Last updated: 2026-05-02T00:00:00+01:00
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

_RATELIMIT_PY = (
    Path(__file__).parents[2] / "yashigani" / "backoffice" / "routes" / "ratelimit.py"
)


class TestRatelimitEndpointOverridePath:
    """Source-level assertions that the path resolution is correct."""

    def test_ratelimit_py_exists(self):
        assert _RATELIMIT_PY.exists(), f"Missing: {_RATELIMIT_PY}"

    def test_no_absolute_path_in_get_decorator(self):
        """
        @router.get("/admin/ratelimit/endpoints") must NOT appear in source.
        That produces the doubled path /admin/ratelimit/admin/ratelimit/endpoints.
        The correct form is @router.get("/endpoints").
        """
        source = _RATELIMIT_PY.read_text(encoding="utf-8")
        assert '@router.get("/admin/ratelimit/endpoints")' not in source, (
            "REGRESSION: @router.get('/admin/ratelimit/endpoints') found in ratelimit.py. "
            "This produces the doubled path /admin/ratelimit/admin/ratelimit/endpoints. "
            "Must be @router.get('/endpoints')."
        )

    def test_no_absolute_path_in_post_decorator(self):
        """@router.post('/admin/ratelimit/endpoints') must NOT appear."""
        source = _RATELIMIT_PY.read_text(encoding="utf-8")
        assert '@router.post("/admin/ratelimit/endpoints")' not in source, (
            "REGRESSION: @router.post('/admin/ratelimit/endpoints') found in ratelimit.py. "
            "Must be @router.post('/endpoints')."
        )

    def test_no_absolute_path_in_delete_decorator(self):
        """@router.delete('/admin/ratelimit/endpoints/{...}') must NOT appear."""
        source = _RATELIMIT_PY.read_text(encoding="utf-8")
        assert '@router.delete("/admin/ratelimit/endpoints' not in source, (
            "REGRESSION: @router.delete('/admin/ratelimit/endpoints/...') found in ratelimit.py. "
            "Must be @router.delete('/endpoints/{endpoint_hash}')."
        )

    def test_relative_get_endpoints_present(self):
        """@router.get('/endpoints') must be present."""
        source = _RATELIMIT_PY.read_text(encoding="utf-8")
        assert '@router.get("/endpoints")' in source, (
            "@router.get('/endpoints') not found in ratelimit.py. "
            "The GET list_endpoint_overrides handler must use the relative path."
        )

    def test_relative_post_endpoints_present(self):
        """@router.post('/endpoints') must be present."""
        source = _RATELIMIT_PY.read_text(encoding="utf-8")
        assert '@router.post("/endpoints")' in source, (
            "@router.post('/endpoints') not found in ratelimit.py. "
            "The POST set_endpoint_override handler must use the relative path."
        )

    def test_relative_delete_endpoints_present(self):
        """@router.delete('/endpoints/{endpoint_hash}') must be present."""
        source = _RATELIMIT_PY.read_text(encoding="utf-8")
        assert '@router.delete("/endpoints/{endpoint_hash}")' in source, (
            "@router.delete('/endpoints/{endpoint_hash}') not found in ratelimit.py. "
            "The DELETE delete_endpoint_override handler must use the relative path."
        )

    def test_all_three_handler_functions_exist(self):
        """The three endpoint handler functions must exist in the source."""
        source = _RATELIMIT_PY.read_text(encoding="utf-8")
        assert "async def list_endpoint_overrides" in source, (
            "list_endpoint_overrides (GET /endpoints) not found."
        )
        assert "async def set_endpoint_override" in source, (
            "set_endpoint_override (POST /endpoints) not found."
        )
        assert "async def delete_endpoint_override" in source, (
            "delete_endpoint_override (DELETE /endpoints/{hash}) not found."
        )

    def test_doubled_path_not_in_route_decorators(self):
        """
        The doubled path /admin/ratelimit/admin/ratelimit must NOT appear inside
        any route decorator in the source. We check decorator strings specifically
        (not the docstring, which may mention the pattern for context).
        """
        source = _RATELIMIT_PY.read_text(encoding="utf-8")
        decorator_pattern = re.compile(
            r'@router\.\w+\s*\(\s*["\']([^"\']+)["\']',
        )
        for match in decorator_pattern.finditer(source):
            path = match.group(1)
            assert "/admin/ratelimit/admin" not in path, (
                f"Route decorator uses doubled path '{path}'. "
                "This produces the /admin/ratelimit/admin/ratelimit/... pattern. "
                "Use relative paths (/endpoints, /endpoints/{{hash}}) instead."
            )

    def test_path_fix_note_present(self):
        """A path fix note must be present in ratelimit.py for traceability."""
        source = _RATELIMIT_PY.read_text(encoding="utf-8")
        # The docstring must mention the fix and the corrected path pattern
        assert "relative" in source or "doubled" in source, (
            "Path fix note not found in ratelimit.py docstring."
        )
