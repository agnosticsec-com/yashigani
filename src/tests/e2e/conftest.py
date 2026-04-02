"""
E2E test configuration.

These tests require a running Yashigani stack (docker compose up).
Skip if the stack is not running.

Run with: pytest src/tests/e2e/ -v
"""
import pytest
import httpx


def _stack_running() -> bool:
    """Check if the gateway is reachable."""
    try:
        # Try gateway directly (internal port 8080 not exposed)
        # Try via Caddy on localhost:443
        r = httpx.get("https://localhost/healthz", verify=False, timeout=3)
        return r.status_code == 200
    except Exception:
        try:
            # Try gateway via docker exec
            import subprocess
            result = subprocess.run(
                ["docker", "exec", "docker-gateway-1", "python3", "-c",
                 "import urllib.request; print(urllib.request.urlopen('http://localhost:8080/healthz').read().decode())"],
                capture_output=True, text=True, timeout=10,
            )
            return "ok" in result.stdout
        except Exception:
            return False


def pytest_collection_modifyitems(config, items):
    """Skip all e2e tests if stack is not running."""
    if not _stack_running():
        skip = pytest.mark.skip(reason="Yashigani stack not running — start with docker compose up")
        for item in items:
            if "e2e" in str(item.fspath):
                item.add_marker(skip)
