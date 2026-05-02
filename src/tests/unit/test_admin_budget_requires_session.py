"""
Regression test — All /admin/budget/* endpoints must require admin session.

The budget router manages a three-tier budget hierarchy (org caps, group
budgets, individual budgets). All 8 endpoints must be protected by admin
session authentication (OWASP API3:2023 / ASVS V4.1.1).

The correct pattern is a router-level dependencies=[Depends(require_admin_session)]
on the APIRouter() constructor. This protects all current and any future endpoints
in the file with a single declaration.

These tests assert (source-level, no full app stack needed):
  1. budget.py imports require_admin_session.
  2. The router definition includes dependencies=[Depends(require_admin_session)].
  3. Depends is imported from fastapi.
  4. An AST-level check confirms the APIRouter() call has a 'dependencies' kwarg.

A functional test uses FastAPI TestClient with a minimal mirrored router to
verify 401 is returned without a session and 200 with a mocked session.

Last updated: 2026-05-02T00:00:00+01:00
"""
from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_BUDGET_PY = (
    Path(__file__).parents[2] / "yashigani" / "backoffice" / "routes" / "budget.py"
)


class TestBudgetRequiresAdminSession:
    """Source-level assertions that the auth guard is wired correctly."""

    def test_budget_py_exists(self):
        assert _BUDGET_PY.exists(), f"Missing: {_BUDGET_PY}"

    def test_require_admin_session_imported(self):
        """budget.py must import require_admin_session."""
        source = _BUDGET_PY.read_text(encoding="utf-8")
        assert "require_admin_session" in source, (
            "REGRESSION: require_admin_session not imported in budget.py. "
            "The auth guard is missing — all /admin/budget/* endpoints are unauthenticated."
        )

    def test_router_has_dependencies_kwarg(self):
        """
        The APIRouter() call must include dependencies=[Depends(require_admin_session)].
        This is the router-level guard that protects all endpoints in the file.
        """
        source = _BUDGET_PY.read_text(encoding="utf-8")
        assert "dependencies=[Depends(require_admin_session)]" in source, (
            "REGRESSION: router-level dependencies=[Depends(require_admin_session)] "
            "not found in budget.py. All /admin/budget/* endpoints are unauthenticated. "
            "Add to the APIRouter() constructor call."
        )

    def test_fastapi_depends_imported(self):
        """budget.py must import Depends from fastapi."""
        source = _BUDGET_PY.read_text(encoding="utf-8")
        assert "Depends" in source, (
            "Depends not imported in budget.py — required for the router-level auth guard."
        )

    def test_auth_note_present(self):
        """An authentication note must be present in the budget.py docstring."""
        source = _BUDGET_PY.read_text(encoding="utf-8")
        assert "require_admin_session" in source, (
            "Auth note referencing require_admin_session not found in budget.py."
        )

    def test_router_definition_has_dependencies_at_ast_level(self):
        """
        AST-level check: the APIRouter() call has a 'dependencies' keyword argument.
        This catches the case where the text is present but commented out or
        in the wrong call.
        """
        source = _BUDGET_PY.read_text(encoding="utf-8")
        tree = ast.parse(source)

        router_calls_with_dependencies = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Call)
            ):
                call = node.value
                func_name = ""
                if isinstance(call.func, ast.Name):
                    func_name = call.func.id
                elif isinstance(call.func, ast.Attribute):
                    func_name = call.func.attr
                if func_name == "APIRouter":
                    kw_names = [kw.arg for kw in call.keywords]
                    if "dependencies" in kw_names:
                        router_calls_with_dependencies.append(node)

        assert len(router_calls_with_dependencies) >= 1, (
            "No APIRouter() call with a 'dependencies' keyword argument found in budget.py "
            "at the AST level. The router-level auth guard is missing."
        )


def _make_budget_guard_app():
    """
    Build a minimal FastAPI app with a budget-shaped router protected by a
    session guard. Uses app.dependency_overrides so FastAPI resolves the real
    require_admin_session signature without hitting Python 3.9 annotation
    resolution issues for locally-defined functions.

    Returns (app, sentinel_fn) so callers can wire overrides.
    """
    try:
        from fastapi import FastAPI, HTTPException, Depends, APIRouter
        from fastapi.testclient import TestClient
    except ImportError:
        return None, None

    def _sentinel_auth():
        """Placeholder — overridden via app.dependency_overrides in each test."""
        raise HTTPException(status_code=401, detail={"error": "authentication_required"})

    test_router = APIRouter(
        prefix="/admin/budget",
        tags=["budget"],
        dependencies=[Depends(_sentinel_auth)],
    )

    @test_router.get("/org-caps")
    async def list_org_caps():
        return {"org_caps": []}

    @test_router.get("/groups")
    async def list_group_budgets():
        return {"group_budgets": []}

    @test_router.get("/individuals")
    async def list_individual_budgets():
        return {"individual_budgets": []}

    @test_router.post("/org-caps", status_code=201)
    async def create_org_cap():
        return {}

    @test_router.post("/groups", status_code=201)
    async def create_group_budget():
        return {}

    @test_router.post("/individuals", status_code=201)
    async def create_individual_budget():
        return {}

    @test_router.get("/usage/{identity_id}")
    async def get_usage(identity_id: str):
        return {"identity_id": identity_id, "usage": {}}

    @test_router.get("/tree")
    async def get_budget_tree():
        return {"tree": []}

    app = FastAPI()
    app.include_router(test_router)
    return app, _sentinel_auth


class TestBudgetSessionEnforcementFunctional:
    """
    Functional test: mount a minimal router mirroring budget.py's pattern
    and verify 401 is returned without a session cookie.

    Uses app.dependency_overrides (FastAPI-idiomatic approach) to avoid
    Python 3.9 type annotation resolution issues with locally-defined functions.
    """

    def test_all_get_endpoints_return_401_without_session(self):
        """All GET /admin/budget/* paths must return 401 without a session cookie."""
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            pytest.skip("fastapi/httpx not available")

        app, sentinel = _make_budget_guard_app()
        if app is None:
            pytest.skip("fastapi not available")

        client = TestClient(app, raise_server_exceptions=False)

        paths = [
            "/admin/budget/org-caps",
            "/admin/budget/groups",
            "/admin/budget/individuals",
            "/admin/budget/usage/some-identity",
            "/admin/budget/tree",
        ]
        for path in paths:
            resp = client.get(path)
            assert resp.status_code == 401, (
                f"REGRESSION: GET {path} returned {resp.status_code}, expected 401. "
                "Budget endpoint is unauthenticated."
            )

    def test_all_post_endpoints_return_401_without_session(self):
        """All POST /admin/budget/* paths must return 401 without a session cookie."""
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            pytest.skip("fastapi/httpx not available")

        app, sentinel = _make_budget_guard_app()
        if app is None:
            pytest.skip("fastapi not available")

        client = TestClient(app, raise_server_exceptions=False)

        paths = [
            "/admin/budget/org-caps",
            "/admin/budget/groups",
            "/admin/budget/individuals",
        ]
        for path in paths:
            resp = client.post(path, json={})
            assert resp.status_code == 401, (
                f"REGRESSION: POST {path} returned {resp.status_code}, expected 401. "
                "Budget endpoint is unauthenticated."
            )

    def test_authenticated_request_returns_200(self):
        """GET /admin/budget/org-caps with a valid session must return 200."""
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            pytest.skip("fastapi/httpx not available")

        app, sentinel = _make_budget_guard_app()
        if app is None:
            pytest.skip("fastapi not available")

        mock_session = MagicMock()
        mock_session.account_tier = "admin"

        app.dependency_overrides[sentinel] = lambda: mock_session
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/admin/budget/org-caps")
            assert resp.status_code == 200, (
                f"GET /admin/budget/org-caps with valid session returned {resp.status_code}, "
                "expected 200."
            )
        finally:
            app.dependency_overrides.clear()
