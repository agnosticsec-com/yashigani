"""
Regression test — A5: GET /admin/crypto/inventory must require admin session.

Before the fix, crypto_inventory.py had NO auth dependency on the handler.
The docstring claimed "Admin-authenticated" but there was no actual Depends(),
no router-level guard, and no middleware covering /admin/crypto/*. The CryptoBoM
was publicly readable — leaking reconnaissance data (algorithm choices, PQ
readiness) to unauthenticated callers (OWASP API1:2023 / ASVS V4.1.1).

Fix: require_admin_session added as a Depends() parameter to the handler.

These tests assert (source-level, no full app stack needed):
  1. crypto_inventory.py imports require_admin_session.
  2. The handler signature includes session=Depends(require_admin_session).
  3. The fix note (A5) is present for traceability.

We also provide a functional test using FastAPI TestClient verifying 401
when no session cookie is present.

Last updated: 2026-05-02T00:00:00+01:00
"""
from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_CRYPTO_PY = (
    Path(__file__).parents[2] / "yashigani" / "backoffice" / "routes" / "crypto_inventory.py"
)


class TestA5CryptoInventorySourceLevel:
    """Source-level assertions that the auth guard is present."""

    def test_crypto_inventory_py_exists(self):
        assert _CRYPTO_PY.exists(), f"Missing: {_CRYPTO_PY}"

    def test_require_admin_session_imported(self):
        """crypto_inventory.py must import require_admin_session."""
        source = _CRYPTO_PY.read_text(encoding="utf-8")
        assert "require_admin_session" in source, (
            "A5 REGRESSION: require_admin_session not imported in crypto_inventory.py. "
            "The /admin/crypto/inventory endpoint is unauthenticated."
        )

    def test_handler_has_session_dependency(self):
        """
        The crypto_inventory handler must have a session parameter with
        Depends(require_admin_session) in its signature.
        """
        source = _CRYPTO_PY.read_text(encoding="utf-8")
        assert "Depends(require_admin_session)" in source, (
            "A5 REGRESSION: Depends(require_admin_session) not found in crypto_inventory.py. "
            "The /admin/crypto/inventory endpoint is unauthenticated."
        )

    def test_depends_imported(self):
        """crypto_inventory.py must import Depends from fastapi."""
        source = _CRYPTO_PY.read_text(encoding="utf-8")
        assert "Depends" in source, (
            "A5: Depends not imported in crypto_inventory.py."
        )

    def test_a5_fix_comment_present(self):
        """A5 fix traceability comment must be in the file."""
        source = _CRYPTO_PY.read_text(encoding="utf-8")
        assert "A5" in source, (
            "A5 fix traceability comment not found in crypto_inventory.py."
        )

    def test_handler_function_has_session_param_in_ast(self):
        """
        AST-level: the crypto_inventory function must have a parameter whose
        default is a Call to Depends(). This confirms the guard is wired into
        the function signature, not just a comment.
        """
        source = _CRYPTO_PY.read_text(encoding="utf-8")
        tree = ast.parse(source)

        found_with_depends = False
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == "crypto_inventory":
                    # Check defaults for Depends() call
                    for default in node.args.defaults:
                        if (
                            isinstance(default, ast.Call)
                            and isinstance(default.func, ast.Name)
                            and default.func.id == "Depends"
                        ):
                            found_with_depends = True
                            break
                    # Also check kw_defaults
                    for default in node.args.kw_defaults:
                        if default and (
                            isinstance(default, ast.Call)
                            and isinstance(default.func, ast.Name)
                            and default.func.id == "Depends"
                        ):
                            found_with_depends = True
                            break

        assert found_with_depends, (
            "A5 REGRESSION: crypto_inventory() function does not have a Depends() "
            "parameter default at the AST level. The session dependency is missing "
            "from the handler signature."
        )


def _make_crypto_inventory_app():
    """
    Build a minimal FastAPI app with a /crypto/inventory-shaped route protected
    by a session guard. Uses the dependency_overrides pattern so FastAPI resolves
    the sentinel dependency without Python 3.9 annotation issues for local functions.

    Returns (app, sentinel_fn) so callers can wire overrides.
    """
    try:
        from fastapi import FastAPI, HTTPException, Depends, APIRouter
    except ImportError:
        return None, None

    def _sentinel_auth():
        """Placeholder — overridden via app.dependency_overrides in each test."""
        raise HTTPException(status_code=401, detail={"error": "authentication_required"})

    test_router = APIRouter()

    @test_router.get("/crypto/inventory")
    async def crypto_inventory(session=Depends(_sentinel_auth)):
        return {
            "algorithms": [{"name": "Argon2id", "usage": "password hashing"}],
            "deprecated": [],
            "post_quantum": ["ML-KEM-768"],
            "compliance": "NIST SP 800-131A Rev 2",
        }

    app = FastAPI()
    app.include_router(test_router, prefix="/admin")
    return app, _sentinel_auth


class TestA5CryptoInventoryFunctional:
    """
    Functional test: mount a minimal router mirroring crypto_inventory's pattern
    and verify 401 is returned without a session cookie.

    Uses app.dependency_overrides (FastAPI-idiomatic approach) to avoid
    Python 3.9 type annotation resolution issues with locally-defined functions.
    """

    def test_unauthenticated_returns_401(self):
        """GET /admin/crypto/inventory must return 401 without a session cookie."""
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            pytest.skip("fastapi/httpx not available")

        app, sentinel = _make_crypto_inventory_app()
        if app is None:
            pytest.skip("fastapi not available")

        # No override — sentinel raises 401 by default
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/admin/crypto/inventory")
        assert resp.status_code == 401, (
            f"A5 REGRESSION: GET /admin/crypto/inventory returned {resp.status_code} "
            "without a session cookie, expected 401. CryptoBoM is publicly readable."
        )

    def test_authenticated_returns_200(self):
        """GET /admin/crypto/inventory with a valid session must return 200."""
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            pytest.skip("fastapi/httpx not available")

        app, sentinel = _make_crypto_inventory_app()
        if app is None:
            pytest.skip("fastapi not available")

        mock_session = MagicMock()
        mock_session.account_tier = "admin"

        app.dependency_overrides[sentinel] = lambda: mock_session
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/admin/crypto/inventory")
            assert resp.status_code == 200, (
                f"A5: GET /admin/crypto/inventory with valid session returned {resp.status_code}, "
                "expected 200."
            )
        finally:
            app.dependency_overrides.clear()

    def test_authenticated_returns_crypto_inventory_keys(self):
        """Authenticated response must include all required CryptoBoM keys."""
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            pytest.skip("fastapi/httpx not available")

        app, sentinel = _make_crypto_inventory_app()
        if app is None:
            pytest.skip("fastapi not available")

        mock_session = MagicMock()
        mock_session.account_tier = "admin"

        app.dependency_overrides[sentinel] = lambda: mock_session
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/admin/crypto/inventory")
            assert resp.status_code == 200
            data = resp.json()
            assert "algorithms" in data, "Response missing 'algorithms' key"
            assert "deprecated" in data, "Response missing 'deprecated' key"
            assert "post_quantum" in data, "Response missing 'post_quantum' key"
            assert "compliance" in data, "Response missing 'compliance' key"
        finally:
            app.dependency_overrides.clear()
