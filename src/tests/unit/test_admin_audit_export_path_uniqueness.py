"""
Regression test — GET /admin/audit/export/raw must resolve to exactly ONE handler.

Both audit.py and audit_search.py register GET handlers under the /admin/audit
prefix. audit_search.py owns GET /export (filtered, 10k row cap, full filter
suite — the canonical user-facing export). audit.py owns GET /export/raw
(unfiltered streaming dump, no row cap, date range only — operator/compliance).

If both files use the same route path (/export), FastAPI retains both handlers
but the one registered last shadows the one registered first, leaving one handler
as unreachable dead code.

These tests assert:
  1. audit.py does NOT register GET /export (would shadow audit_search.py).
  2. audit.py DOES register GET /export/raw (the unfiltered streaming export).
  3. audit_search.py retains GET /export (the filtered export).
  4. Neither file registers the other's path (no cross-contamination).
  5. The export_audit_log handler is async (required for streaming).

Source-level checks avoid the need for the full backoffice app stack
(asyncpg, python-multipart, etc.) in the unit test environment.

Last updated: 2026-05-02T00:00:00+01:00
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

_ROUTES_DIR = Path(__file__).parents[2] / "yashigani" / "backoffice" / "routes"
_AUDIT_PY = _ROUTES_DIR / "audit.py"
_AUDIT_SEARCH_PY = _ROUTES_DIR / "audit_search.py"


class TestAuditExportPathUniqueness:
    """Source-level assertions that the path collision is resolved."""

    def test_audit_py_exists(self):
        assert _AUDIT_PY.exists(), f"Missing: {_AUDIT_PY}"

    def test_audit_search_py_exists(self):
        assert _AUDIT_SEARCH_PY.exists(), f"Missing: {_AUDIT_SEARCH_PY}"

    def test_audit_py_does_not_register_bare_export_path(self):
        """
        audit.py must NOT have @router.get("/export") — that path is owned
        exclusively by audit_search.py (filtered export). If audit.py also
        registers /export the handlers collide and FastAPI silently routes
        to whichever is registered last, leaving the other unreachable.
        """
        source = _AUDIT_PY.read_text(encoding="utf-8")
        assert '@router.get("/export")' not in source, (
            "REGRESSION: audit.py still registers @router.get('/export'). "
            "This collides with audit_search.py's filtered export handler. "
            "The unfiltered handler must be at /export/raw."
        )

    def test_audit_py_registers_export_raw(self):
        """audit.py must register the unfiltered handler at /export/raw."""
        source = _AUDIT_PY.read_text(encoding="utf-8")
        assert '@router.get("/export/raw")' in source, (
            "audit.py must register @router.get('/export/raw') for the "
            "unfiltered streaming export. The handler was not found."
        )

    def test_audit_search_py_retains_export(self):
        """
        audit_search.py retains ownership of /export (filtered, capped export).
        This is the canonical user-facing export path.
        """
        source = _AUDIT_SEARCH_PY.read_text(encoding="utf-8")
        assert '@router.get("/export")' in source, (
            "audit_search.py must retain @router.get('/export'). "
            "This is the canonical filtered export endpoint."
        )

    def test_audit_py_exactly_one_get_export_route(self):
        """audit.py must register exactly one GET export-family route."""
        source = _AUDIT_PY.read_text(encoding="utf-8")
        bare_export = source.count('@router.get("/export")')
        raw_export = source.count('@router.get("/export/raw")')
        assert bare_export == 0, (
            f"Found {bare_export} occurrence(s) of @router.get('/export') in audit.py — must be 0."
        )
        assert raw_export == 1, (
            f"Expected exactly 1 occurrence of @router.get('/export/raw') in audit.py, got {raw_export}."
        )

    def test_no_duplicate_export_raw_in_audit_search(self):
        """audit_search.py must not also register /export/raw."""
        source = _AUDIT_SEARCH_PY.read_text(encoding="utf-8")
        assert '@router.get("/export/raw")' not in source, (
            "audit_search.py unexpectedly registers /export/raw — "
            "that path belongs to audit.py (unfiltered exporter)."
        )

    def test_path_note_present_in_audit_py(self):
        """A path collision fix note must be present in audit.py for traceability."""
        source = _AUDIT_PY.read_text(encoding="utf-8")
        assert "export/raw" in source, (
            "Path fix note not found in audit.py docstring — "
            "expected a comment referencing /export/raw and the path collision resolution."
        )

    def test_export_raw_function_is_async(self):
        """The /export/raw handler must be async (required for streaming response)."""
        source = _AUDIT_PY.read_text(encoding="utf-8")
        tree = ast.parse(source)
        found = False
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "export_audit_log":
                found = True
                break
        assert found, (
            "export_audit_log must be an async function in audit.py."
        )
