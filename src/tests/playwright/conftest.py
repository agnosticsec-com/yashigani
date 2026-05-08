"""
Playwright test configuration for Yashigani admin UI.

Requires a running Yashigani stack. Tests skip if the stack is not reachable.
CA cert resolution follows the same pattern as src/tests/e2e/conftest.py.

Run with:
    pytest src/tests/playwright/ -v --timeout=60

Last updated: 2026-05-06
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import pytest


# ---------------------------------------------------------------------------
# CA cert resolution (mirrors e2e/conftest.py Pattern A)
# ---------------------------------------------------------------------------

def _resolve_ca_cert() -> Optional[str]:
    explicit = os.getenv("YASHIGANI_CA_CERT")
    if explicit:
        return explicit
    candidates = [
        Path(__file__).parents[4] / "docker" / "secrets" / "ca_root.crt",
        Path("/run/secrets/ca_root.crt"),
    ]
    for p in candidates:
        if p.exists():
            return str(p)
    return None


_CA_CERT_PATH: str | None = _resolve_ca_cert()


# ---------------------------------------------------------------------------
# Base URL resolution
# ---------------------------------------------------------------------------

def _resolve_base_url() -> str:
    override = os.getenv("YASHIGANI_ADMIN_URL")
    if override:
        return override.rstrip("/")
    # Prefer HTTPS; fall back to common installer ports
    candidates = [
        "https://localhost:8443",
        "https://localhost",
        "http://localhost:8080",
    ]
    try:
        import httpx
        for url in candidates:
            verify: bool | str = _CA_CERT_PATH if url.startswith("https://") else False  # type: ignore[assignment]
            try:
                r = httpx.get(f"{url}/healthz", verify=verify, timeout=3)
                if r.status_code == 200:
                    return url
            except Exception:
                continue
    except ImportError:
        pass
    return "https://localhost:8443"


BASE_URL: str = _resolve_base_url()
ADMIN_LOGIN_URL: str = f"{BASE_URL}/admin/login"


# ---------------------------------------------------------------------------
# Stack-running check
# ---------------------------------------------------------------------------

def _stack_running() -> bool:
    try:
        import httpx
    except ImportError:
        return False
    candidates = [BASE_URL + "/healthz", "https://localhost/healthz",
                  "https://localhost:8443/healthz", "http://localhost:8080/healthz"]
    for url in candidates:
        try:
            verify: bool | str = _CA_CERT_PATH if url.startswith("https://") else False  # type: ignore[assignment]
            r = httpx.get(url, verify=verify, timeout=3)
            if r.status_code == 200:
                return True
        except Exception:
            continue
    return False


STACK_RUNNING: bool = _stack_running()

_SKIP_NO_STACK = pytest.mark.skipif(
    not STACK_RUNNING,
    reason="Yashigani stack not running — start with docker/podman compose up",
)


# ---------------------------------------------------------------------------
# Admin credential helpers
# ---------------------------------------------------------------------------

def _read_secret(name: str) -> str:
    """Read a secret from docker/secrets/. Raises FileNotFoundError if absent."""
    repo_root = Path(__file__).parents[4]
    p = repo_root / "docker" / "secrets" / name
    return p.read_text(encoding="utf-8").strip()


def get_admin_credentials() -> tuple[str, str]:
    """Return (username, initial_password) for admin1."""
    username = _read_secret("admin1_username")
    password = _read_secret("admin_initial_password")
    return username, password


# ---------------------------------------------------------------------------
# pytest_configure — register markers
# ---------------------------------------------------------------------------

def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "playwright_ui: marks Playwright browser-based tests",
    )
    config.addinivalue_line(
        "markers",
        "api_contract: marks HTTP-level API contract tests (no browser)",
    )
    config.addinivalue_line(
        "markers",
        "security_probe: marks adversarial / purple-team security tests",
    )


# ---------------------------------------------------------------------------
# pytest_collection_modifyitems — auto-skip when stack not running
# ---------------------------------------------------------------------------

def pytest_collection_modifyitems(config, items):
    if not STACK_RUNNING:
        skip = pytest.mark.skip(
            reason="Yashigani stack not running — start with docker/podman compose up"
        )
        for item in items:
            if "playwright" in str(item.fspath):
                item.add_marker(skip)
