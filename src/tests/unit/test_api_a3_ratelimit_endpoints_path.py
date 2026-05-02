"""
Regression test — A3: /admin/ratelimit/endpoints must resolve correctly.

Before the fix, ratelimit.py lines 189/198/213 used the full absolute path
/admin/ratelimit/endpoints in route decorators. The router is mounted at prefix
/admin/ratelimit (app.py line 546). FastAPI concatenates prefix + path, producing
the doubled path /admin/ratelimit/admin/ratelimit/endpoints — unreachable.

Fix: changed decorator paths from /admin/ratelimit/endpoints to /endpoints
(and /endpoints/{endpoint_hash}) so the resolved paths are correct.

These tests assert:
  1. ratelimit.py source does NOT contain the doubled-path decorators.
  2. ratelimit.py source DOES contain the relative /endpoints decorators.
  3. All three HTTP methods (GET, POST, DELETE) are present at /endpoints.
  4. The doubled path /admin/ratelimit/admin/ratelimit/endpoints does NOT appear.

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


class TestA3RatelimitEndpointsPath:
    """Source-level assertions that the path bug is fixed."""

    def test_ratelimit_py_exists(self):
        assert _RATELIMIT_PY.exists(), f"Missing: {_RATELIMIT_PY}"

    def test_no_absolute_path_in_get_decorator(self):
        """
        @router.get("/admin/ratelimit/endpoints") must NOT appear in source.
        That was the bug — absolute path inside a prefixed router.
        """
        source = _RATELIMIT_PY.read_text(encoding="utf-8")
        assert '@router.get("/admin/ratelimit/endpoints")' not in source, (
            "A3 REGRESSION: @router.get('/admin/ratelimit/endpoints') found in ratelimit.py. "
            "This produces the doubled path /admin/ratelimit/admin/ratelimit/endpoints. "
            "Must be @router.get('/endpoints')."
        )

    def test_no_absolute_path_in_post_decorator(self):
        """@router.post('/admin/ratelimit/endpoints') must NOT appear."""
        source = _RATELIMIT_PY.read_text(encoding="utf-8")
        assert '@router.post("/admin/ratelimit/endpoints")' not in source, (
            "A3 REGRESSION: @router.post('/admin/ratelimit/endpoints') found in ratelimit.py. "
            "Must be @router.post('/endpoints')."
        )

    def test_no_absolute_path_in_delete_decorator(self):
        """@router.delete('/admin/ratelimit/endpoints/{...}') must NOT appear."""
        source = _RATELIMIT_PY.read_text(encoding="utf-8")
        # Match any form of the absolute path in a delete decorator
        assert '@router.delete("/admin/ratelimit/endpoints' not in source, (
            "A3 REGRESSION: @router.delete('/admin/ratelimit/endpoints/...') found in ratelimit.py. "
            "Must be @router.delete('/endpoints/{endpoint_hash}')."
        )

    def test_relative_get_endpoints_present(self):
        """@router.get('/endpoints') must be present."""
        source = _RATELIMIT_PY.read_text(encoding="utf-8")
        assert '@router.get("/endpoints")' in source, (
            "A3: @router.get('/endpoints') not found in ratelimit.py. "
            "The GET list_endpoint_overrides handler must use the relative path."
        )

    def test_relative_post_endpoints_present(self):
        """@router.post('/endpoints') must be present."""
        source = _RATELIMIT_PY.read_text(encoding="utf-8")
        assert '@router.post("/endpoints")' in source, (
            "A3: @router.post('/endpoints') not found in ratelimit.py. "
            "The POST set_endpoint_override handler must use the relative path."
        )

    def test_relative_delete_endpoints_present(self):
        """@router.delete('/endpoints/{endpoint_hash}') must be present."""
        source = _RATELIMIT_PY.read_text(encoding="utf-8")
        assert '@router.delete("/endpoints/{endpoint_hash}")' in source, (
            "A3: @router.delete('/endpoints/{endpoint_hash}') not found in ratelimit.py. "
            "The DELETE delete_endpoint_override handler must use the relative path."
        )

    def test_all_three_methods_at_endpoints(self):
        """Exactly the three endpoint handler functions must exist."""
        source = _RATELIMIT_PY.read_text(encoding="utf-8")
        assert "async def list_endpoint_overrides" in source, (
            "A3: list_endpoint_overrides (GET /endpoints) not found."
        )
        assert "async def set_endpoint_override" in source, (
            "A3: set_endpoint_override (POST /endpoints) not found."
        )
        assert "async def delete_endpoint_override" in source, (
            "A3: delete_endpoint_override (DELETE /endpoints/{hash}) not found."
        )

    def test_doubled_path_not_in_route_decorators(self):
        """
        The doubled path /admin/ratelimit/admin/ratelimit must NOT appear inside
        any route decorator in the source. We check decorator strings specifically
        (not docstrings, which may mention the bug for traceability).
        """
        import re
        source = _RATELIMIT_PY.read_text(encoding="utf-8")
        # Match @router.<method>("...") decorator patterns
        decorator_pattern = re.compile(
            r'@router\.\w+\s*\(\s*["\']([^"\']+)["\']',
        )
        for match in decorator_pattern.finditer(source):
            path = match.group(1)
            assert "/admin/ratelimit/admin" not in path, (
                f"A3: Route decorator uses doubled path '{path}'. "
                "This produces the /admin/ratelimit/admin/ratelimit/... pattern. "
                "Use relative paths (/endpoints, /endpoints/{{hash}}) instead."
            )

    def test_a3_fix_comment_present(self):
        """A3 fix traceability comment must be present."""
        source = _RATELIMIT_PY.read_text(encoding="utf-8")
        assert "A3" in source, (
            "A3 fix traceability comment not found in ratelimit.py."
        )
