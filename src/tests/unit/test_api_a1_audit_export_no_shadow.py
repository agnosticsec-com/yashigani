"""
Regression test — A1: GET /admin/audit/export must resolve to exactly ONE handler.

Before the fix, both audit.py and audit_search.py registered a GET handler at
the relative path /export, both mounted under prefix /admin/audit. FastAPI
retains both but the audit_search handler (registered last in app.py line 590)
shadows the audit.py handler, leaving it unreachable dead code.

Fix: audit.py's handler was renamed to /export/raw. These tests assert:
  1. Exactly one handler exists for GET /admin/audit/export.
  2. A handler exists for GET /admin/audit/export/raw.
  3. The audit.py module source uses the path "/export/raw", not "/export".
  4. The audit_search.py module source retains "/export" (canonical filtered export).

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


class TestA1AuditExportShadowFixed:
    """Source-level assertions that the path shadow is resolved."""

    def test_audit_py_exists(self):
        assert _AUDIT_PY.exists(), f"Missing: {_AUDIT_PY}"

    def test_audit_search_py_exists(self):
        assert _AUDIT_SEARCH_PY.exists(), f"Missing: {_AUDIT_SEARCH_PY}"

    def test_audit_py_does_not_register_export_without_raw(self):
        """
        audit.py must NOT have @router.get("/export") — that path is now
        owned exclusively by audit_search.py.
        The handler must be at /export/raw.
        """
        source = _AUDIT_PY.read_text(encoding="utf-8")
        # Must NOT have the bare /export path as a route decorator
        assert '@router.get("/export")' not in source, (
            "A1 REGRESSION: audit.py still registers @router.get('/export'). "
            "This shadows audit_search.py's filtered export. "
            "The handler must be moved to /export/raw."
        )

    def test_audit_py_registers_export_raw(self):
        """audit.py must register the handler at /export/raw."""
        source = _AUDIT_PY.read_text(encoding="utf-8")
        assert '@router.get("/export/raw")' in source, (
            "A1: audit.py must register @router.get('/export/raw') for the "
            "unfiltered streaming export. The handler was not found."
        )

    def test_audit_search_py_retains_export(self):
        """
        audit_search.py retains ownership of /export (filtered, capped export).
        This is the canonical user-facing export path.
        """
        source = _AUDIT_SEARCH_PY.read_text(encoding="utf-8")
        assert '@router.get("/export")' in source, (
            "A1: audit_search.py must retain @router.get('/export'). "
            "This is the canonical filtered export endpoint."
        )

    def test_audit_py_exactly_one_get_export_route(self):
        """audit.py must register exactly one GET export-family route."""
        source = _AUDIT_PY.read_text(encoding="utf-8")
        # Count occurrences of get("/export...") decorator patterns
        bare_export = source.count('@router.get("/export")')
        raw_export = source.count('@router.get("/export/raw")')
        assert bare_export == 0, (
            f"A1: Found {bare_export} occurrence(s) of @router.get('/export') in audit.py — must be 0."
        )
        assert raw_export == 1, (
            f"A1: Expected exactly 1 occurrence of @router.get('/export/raw') in audit.py, got {raw_export}."
        )

    def test_no_duplicate_export_raw_in_audit_search(self):
        """audit_search.py must not also register /export/raw."""
        source = _AUDIT_SEARCH_PY.read_text(encoding="utf-8")
        assert '@router.get("/export/raw")' not in source, (
            "A1: audit_search.py unexpectedly registers /export/raw — "
            "that path belongs to audit.py (unfiltered exporter)."
        )

    def test_a1_fix_note_in_audit_py_docstring(self):
        """The A1 fix comment must be present in audit.py for traceability."""
        source = _AUDIT_PY.read_text(encoding="utf-8")
        assert "A1" in source, (
            "A1 fix traceability comment not found in audit.py — "
            "add a comment referencing the anomaly ID."
        )

    def test_export_raw_function_is_async(self):
        """The /export/raw handler must be async (streaming generator)."""
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
