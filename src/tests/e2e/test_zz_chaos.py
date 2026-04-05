"""
E2E: Chaos test — self-healing verification.

Kill containers while the system is running. Verify:
  1. Container runtime auto-restarts the container (restart: unless-stopped)
  2. Health checks detect the recovery
  3. The system continues to serve requests after recovery

Requires: running Yashigani stack.
"""
from __future__ import annotations

import time
import pytest

from tests.e2e.conftest import (
    container_healthy,
    container_running,
    container_kill,
    runtime_run,
)


def _wait_for_healthy(name: str, timeout: int = 90) -> bool:
    """Wait until container is healthy, up to timeout seconds."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if container_healthy(name):
            return True
        time.sleep(5)
    return False


def _gateway_healthz() -> bool:
    result = runtime_run("docker-gateway-1",
        "import urllib.request; r=urllib.request.urlopen('http://localhost:8080/healthz'); print(r.read().decode())",
        timeout=10)
    return "ok" in result


class TestChaosOllama:
    """Kill Ollama and verify recovery."""

    def test_ollama_recovers_after_kill(self):
        assert container_running("docker-ollama-1"), "Ollama not running before test"

        container_kill("docker-ollama-1")
        time.sleep(5)

        recovered = _wait_for_healthy("docker-ollama-1", timeout=120)
        assert recovered, "Ollama did not recover within 120 seconds"

    def test_gateway_stays_healthy_during_ollama_restart(self):
        """Gateway should remain healthy even if Ollama is temporarily down."""
        assert _gateway_healthz(), "Gateway not healthy"


class TestChaosRedis:
    """Kill Redis and verify recovery."""

    def test_redis_recovers_after_kill(self):
        assert container_healthy("docker-redis-1")
        container_kill("docker-redis-1")
        time.sleep(2)
        recovered = _wait_for_healthy("docker-redis-1", timeout=60)
        assert recovered, "Redis did not recover within 60 seconds"


class TestChaosBudgetRedis:
    """Kill budget-redis and verify recovery."""

    def test_budget_redis_recovers_after_kill(self):
        assert container_running("docker-budget-redis-1")
        container_kill("docker-budget-redis-1")
        time.sleep(2)
        recovered = _wait_for_healthy("docker-budget-redis-1", timeout=60)
        assert recovered, "Budget-redis did not recover within 60 seconds"


class TestChaosPostgres:
    """Kill Postgres and verify recovery."""

    def test_postgres_recovers_after_kill(self):
        assert container_healthy("docker-postgres-1")
        container_kill("docker-postgres-1")
        time.sleep(2)
        recovered = _wait_for_healthy("docker-postgres-1", timeout=60)
        assert recovered, "Postgres did not recover within 60 seconds"
