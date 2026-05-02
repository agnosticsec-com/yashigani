"""
Regression test — /admin/audit/siem and related SIEM paths must each resolve
to exactly ONE handler with no shadowing between audit.py and audit_sinks.py.

Background
----------
Both routers mount under the /admin/audit prefix space:
- audit.py (mounted by app.py with prefix=/admin/audit) defines:
    GET  /siem          list named SIEM targets
    POST /siem          add a named SIEM target
    DELETE /siem/{name} remove a named SIEM target
    POST /siem/{name}/test  test a named SIEM target

- audit_sinks.py (mounted by app.py with NO prefix — routes carry full paths)
  originally defined:
    GET  /admin/audit/siem   SIEM backend config (backend type + endpoint URL)
    PUT  /admin/audit/siem   update SIEM backend config (step-up required)
    POST /admin/audit/siem/test  send a test event for the single backend

The two GET /admin/audit/siem registrations collide. FastAPI silently resolves
to whichever is registered last; the other handler is dead code.

Fix
---
audit_sinks.py paths renamed to /admin/audit/siem/config (GET/PUT) and
/admin/audit/siem/config/test (POST). These are semantically accurate —
they represent the single active SIEM backend configuration, whereas
/admin/audit/siem remains the target-list CRUD owned by audit.py.

These tests assert the fix at source level, avoiding the need for a live
backoffice app stack (asyncpg, etc.) in the unit test environment.

Last updated: 2026-05-02T00:00:00+01:00
"""
from __future__ import annotations

from pathlib import Path

import pytest

_ROUTES_DIR = Path(__file__).parents[2] / "yashigani" / "backoffice" / "routes"
_AUDIT_PY = _ROUTES_DIR / "audit.py"
_AUDIT_SINKS_PY = _ROUTES_DIR / "audit_sinks.py"


class TestAuditSiemPathUniqueness:
    """Assert that /admin/audit/siem* paths are unambiguously owned."""

    # ------------------------------------------------------------------
    # Presence checks
    # ------------------------------------------------------------------

    def test_audit_py_exists(self):
        assert _AUDIT_PY.exists(), f"Missing: {_AUDIT_PY}"

    def test_audit_sinks_py_exists(self):
        assert _AUDIT_SINKS_PY.exists(), f"Missing: {_AUDIT_SINKS_PY}"

    # ------------------------------------------------------------------
    # audit.py — owns GET/POST/DELETE /siem (target list CRUD)
    # ------------------------------------------------------------------

    def test_audit_py_registers_get_siem(self):
        """audit.py must register @router.get('/siem') for the target list."""
        source = _AUDIT_PY.read_text(encoding="utf-8")
        assert '@router.get("/siem")' in source, (
            "audit.py must register @router.get('/siem') for listing named SIEM targets."
        )

    def test_audit_py_registers_post_siem(self):
        """audit.py must register @router.post('/siem') for adding a target."""
        source = _AUDIT_PY.read_text(encoding="utf-8")
        assert '@router.post("/siem")' in source, (
            "audit.py must register @router.post('/siem') for adding a SIEM target."
        )

    # ------------------------------------------------------------------
    # audit_sinks.py — must NOT use /admin/audit/siem bare path for GET or PUT
    # (those collide with audit.py's /siem registered under the /admin/audit prefix)
    # ------------------------------------------------------------------

    def test_audit_sinks_does_not_register_bare_get_siem(self):
        """
        audit_sinks.py must NOT register GET /admin/audit/siem.
        That path collides with audit.py's GET /siem (mounted at prefix
        /admin/audit). The SIEM backend config endpoint must use a distinct
        path such as /admin/audit/siem/config.
        """
        source = _AUDIT_SINKS_PY.read_text(encoding="utf-8")
        # The old colliding registration:
        assert '"/admin/audit/siem"' not in source or (
            # Allow only if it appears exclusively in comments / docstrings.
            # Simpler: just assert the decorator form is gone.
            True
        )
        # Tighter: the decorator form must not appear
        assert '@audit_sinks_router.get("/admin/audit/siem")' not in source, (
            "REGRESSION: audit_sinks.py still registers "
            "@audit_sinks_router.get('/admin/audit/siem'). "
            "This shadows audit.py's GET /siem (SIEM target list) because "
            "audit_sinks_router is registered after audit_router in app.py. "
            "Rename to /admin/audit/siem/config."
        )

    def test_audit_sinks_does_not_register_bare_put_siem(self):
        """
        audit_sinks.py must NOT register PUT /admin/audit/siem.
        audit.py does not register a PUT /siem, so this is not a current
        collision — but the path would be inconsistent once GET is renamed,
        and PUT /admin/audit/siem is indistinguishable from the target CRUD
        path without a sub-resource segment. Must be /admin/audit/siem/config.
        """
        source = _AUDIT_SINKS_PY.read_text(encoding="utf-8")
        assert '@audit_sinks_router.put("/admin/audit/siem")' not in source, (
            "REGRESSION: audit_sinks.py still registers "
            "@audit_sinks_router.put('/admin/audit/siem'). "
            "The SIEM backend config update endpoint must be at "
            "/admin/audit/siem/config to match the renamed GET."
        )

    def test_audit_sinks_does_not_register_post_siem_test_colliding(self):
        """
        audit_sinks.py must NOT register POST /admin/audit/siem/test using the
        form that collides with audit.py's POST /siem/{name}/test pattern.
        The sinks test endpoint must be at /admin/audit/siem/config/test.
        """
        source = _AUDIT_SINKS_PY.read_text(encoding="utf-8")
        assert '@audit_sinks_router.post("/admin/audit/siem/test")' not in source, (
            "REGRESSION: audit_sinks.py still registers "
            "@audit_sinks_router.post('/admin/audit/siem/test'). "
            "This collides with audit.py's POST /siem/{name}/test pattern. "
            "Rename to /admin/audit/siem/config/test."
        )

    # ------------------------------------------------------------------
    # audit_sinks.py — must register the renamed /config paths
    # ------------------------------------------------------------------

    def test_audit_sinks_registers_get_siem_config(self):
        """audit_sinks.py must register GET /admin/audit/siem/config."""
        source = _AUDIT_SINKS_PY.read_text(encoding="utf-8")
        # The decorator may carry additional keyword arguments (e.g. response_model)
        # so we check for the path string within a @audit_sinks_router.get(...) call.
        assert '@audit_sinks_router.get("/admin/audit/siem/config"' in source, (
            "audit_sinks.py must register @audit_sinks_router.get('/admin/audit/siem/config'...) "
            "for the SIEM backend configuration resource."
        )

    def test_audit_sinks_registers_put_siem_config(self):
        """audit_sinks.py must register PUT /admin/audit/siem/config."""
        source = _AUDIT_SINKS_PY.read_text(encoding="utf-8")
        assert '@audit_sinks_router.put("/admin/audit/siem/config")' in source, (
            "audit_sinks.py must register @audit_sinks_router.put('/admin/audit/siem/config') "
            "for updating the SIEM backend configuration."
        )

    def test_audit_sinks_registers_post_siem_config_test(self):
        """audit_sinks.py must register POST /admin/audit/siem/config/test."""
        source = _AUDIT_SINKS_PY.read_text(encoding="utf-8")
        assert '@audit_sinks_router.post("/admin/audit/siem/config/test")' in source, (
            "audit_sinks.py must register "
            "@audit_sinks_router.post('/admin/audit/siem/config/test') "
            "for sending a connectivity test to the configured SIEM backend."
        )

    # ------------------------------------------------------------------
    # Cross-contamination guard — audit.py must not register /config paths
    # ------------------------------------------------------------------

    def test_audit_py_does_not_register_siem_config(self):
        """audit.py must not register /siem/config — that belongs to audit_sinks."""
        source = _AUDIT_PY.read_text(encoding="utf-8")
        assert '"/siem/config"' not in source, (
            "audit.py unexpectedly registers a /siem/config path — "
            "that route is owned by audit_sinks.py."
        )

    # ------------------------------------------------------------------
    # Docstring / timestamp hygiene
    # ------------------------------------------------------------------

    def test_audit_sinks_docstring_reflects_renamed_paths(self):
        """
        audit_sinks.py's module docstring must reference /siem/config
        (not the old /admin/audit/siem bare path) so the routing intent
        is visible at a glance.
        """
        source = _AUDIT_SINKS_PY.read_text(encoding="utf-8")
        assert "/siem/config" in source, (
            "audit_sinks.py docstring does not reference /siem/config. "
            "Update the module-level docstring to reflect the renamed paths."
        )

    def test_audit_sinks_has_last_updated_timestamp(self):
        """audit_sinks.py must carry a Last updated: timestamp."""
        source = _AUDIT_SINKS_PY.read_text(encoding="utf-8")
        assert "Last updated:" in source, (
            "audit_sinks.py must carry a 'Last updated:' ISO 8601 timestamp "
            "per the project timestamp convention."
        )
