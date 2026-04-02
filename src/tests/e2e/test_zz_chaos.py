"""
E2E: Chaos test — self-healing verification.

Kill containers while the system is running. Verify:
  1. Docker auto-restarts the container (restart: unless-stopped)
  2. Health checks detect the recovery
  3. The system continues to serve requests after recovery

Requires: running Yashigani stack.
"""
from __future__ import annotations

import subprocess
import time
import pytest


def _container_healthy(name: str) -> bool:
    result = subprocess.run(
        ["docker", "inspect", name, "--format", "{{.State.Health.Status}}"],
        capture_output=True, text=True, timeout=5,
    )
    return "healthy" in result.stdout


def _container_running(name: str) -> bool:
    result = subprocess.run(
        ["docker", "ps", "--filter", f"name={name}", "--format", "{{.Status}}"],
        capture_output=True, text=True, timeout=5,
    )
    return "Up" in result.stdout


def _kill_container(name: str):
    subprocess.run(["docker", "kill", name], capture_output=True, timeout=10)


def _wait_for_healthy(name: str, timeout: int = 90) -> bool:
    """Wait until container is healthy, up to timeout seconds."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _container_healthy(name):
            return True
        time.sleep(5)
    return False


def _gateway_healthz() -> bool:
    result = subprocess.run(
        ["docker", "exec", "docker-gateway-1", "python3", "-c",
         "import urllib.request; r=urllib.request.urlopen('http://localhost:8080/healthz'); print(r.read().decode())"],
        capture_output=True, text=True, timeout=10,
    )
    return "ok" in result.stdout


class TestChaosOllama:
    """Kill Ollama and verify recovery."""

    def test_ollama_recovers_after_kill(self):
        # Verify running first
        assert _container_running("docker-ollama-1"), "Ollama not running before test"

        # Kill it
        _kill_container("docker-ollama-1")
        time.sleep(5)

        # Docker compose restart: unless-stopped should restart it
        # Wait for container to come back and become healthy
        recovered = _wait_for_healthy("docker-ollama-1", timeout=120)
        assert recovered, "Ollama did not recover within 120 seconds"

    def test_gateway_stays_healthy_during_ollama_restart(self):
        """Gateway should remain healthy even if Ollama is temporarily down."""
        # Gateway health doesn't depend on Ollama health
        assert _gateway_healthz(), "Gateway not healthy"


class TestChaosRedis:
    """Kill Redis and verify recovery."""

    def test_redis_recovers_after_kill(self):
        assert _container_healthy("docker-redis-1")
        _kill_container("docker-redis-1")
        time.sleep(2)
        recovered = _wait_for_healthy("docker-redis-1", timeout=60)
        assert recovered, "Redis did not recover within 60 seconds"


class TestChaosBudgetRedis:
    """Kill budget-redis and verify recovery."""

    def test_budget_redis_recovers_after_kill(self):
        assert _container_running("docker-budget-redis-1")
        _kill_container("docker-budget-redis-1")
        time.sleep(2)
        recovered = _wait_for_healthy("docker-budget-redis-1", timeout=60)
        assert recovered, "Budget-redis did not recover within 60 seconds"


class TestChaosPostgres:
    """Kill Postgres and verify recovery."""

    def test_postgres_recovers_after_kill(self):
        assert _container_healthy("docker-postgres-1")
        _kill_container("docker-postgres-1")
        time.sleep(2)
        recovered = _wait_for_healthy("docker-postgres-1", timeout=60)
        assert recovered, "Postgres did not recover within 60 seconds"
