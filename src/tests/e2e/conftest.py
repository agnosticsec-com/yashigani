"""
E2E test configuration.

These tests require a running Yashigani stack (docker/podman compose up).
Skip if the stack is not running.

Run with: pytest src/tests/e2e/ -v
"""
import os
import shutil
import subprocess
import pytest
import httpx


def _detect_runtime() -> str:
    """
    Detect whether to use 'podman' or 'docker' for container commands.
    Checks YASHIGANI_RUNTIME env var first, then probes for running containers.
    """
    env_runtime = os.getenv("YASHIGANI_RUNTIME", "").lower()
    if env_runtime in ("podman", "docker"):
        return env_runtime

    # Check if podman has running containers
    if shutil.which("podman"):
        try:
            result = subprocess.run(
                ["podman", "ps", "--format", "{{.Names}}"],
                capture_output=True, text=True, timeout=5,
            )
            if "docker-gateway-1" in result.stdout:
                return "podman"
        except Exception:
            pass

    # Check if docker has running containers
    if shutil.which("docker"):
        try:
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}"],
                capture_output=True, text=True, timeout=5,
            )
            if "docker-gateway-1" in result.stdout:
                return "docker"
        except Exception:
            pass

    # Default to docker
    return "docker"


# Module-level runtime — computed once, used by all tests
RUNTIME = _detect_runtime()


def runtime_exec(container: str, *cmd: str, timeout: int = 15) -> subprocess.CompletedProcess:
    """Execute a command in a container using the detected runtime."""
    return subprocess.run(
        [RUNTIME, "exec", container, *cmd],
        capture_output=True, text=True, timeout=timeout,
    )


def runtime_run(container: str, python_code: str, timeout: int = 30) -> str:
    """Execute Python code inside a container. Returns stdout."""
    result = runtime_exec(container, "python3", "-c", python_code, timeout=timeout)
    return result.stdout.strip()


def container_running(name: str) -> bool:
    """Check if a container is running."""
    result = subprocess.run(
        [RUNTIME, "ps", "--filter", f"name={name}", "--format", "{{.Status}}"],
        capture_output=True, text=True, timeout=5,
    )
    return "Up" in result.stdout


def container_healthy(name: str) -> bool:
    """Check if a container is healthy."""
    result = subprocess.run(
        [RUNTIME, "inspect", name, "--format", "{{.State.Health.Status}}"],
        capture_output=True, text=True, timeout=5,
    )
    return "healthy" in result.stdout


def container_kill(name: str) -> None:
    """
    Kill a container and restart it.

    Podman rootless does not auto-restart containers after 'kill'
    (unlike Docker). We explicitly start the container after killing
    to simulate the self-healing behavior.
    """
    subprocess.run([RUNTIME, "kill", name], capture_output=True, timeout=10)
    import time
    time.sleep(2)
    # Podman needs explicit restart after kill — Docker auto-restarts
    # via restart: unless-stopped, but Podman 4.x doesn't.
    subprocess.run([RUNTIME, "start", name], capture_output=True, timeout=10)


def container_start(name: str) -> None:
    """Start a stopped container."""
    subprocess.run([RUNTIME, "start", name], capture_output=True, timeout=10)


def _stack_running() -> bool:
    """Check if the gateway is reachable."""
    try:
        r = httpx.get("https://localhost/healthz", verify=False, timeout=3)
        return r.status_code == 200
    except Exception:
        try:
            result = runtime_exec(
                "docker-gateway-1", "python3", "-c",
                "import urllib.request; print(urllib.request.urlopen('http://localhost:8080/healthz').read().decode())",
                timeout=10,
            )
            return "ok" in result.stdout
        except Exception:
            return False


def pytest_collection_modifyitems(config, items):
    """Skip all e2e tests if stack is not running."""
    if not _stack_running():
        skip = pytest.mark.skip(reason="Yashigani stack not running — start with docker/podman compose up")
        for item in items:
            if "e2e" in str(item.fspath):
                item.add_marker(skip)
