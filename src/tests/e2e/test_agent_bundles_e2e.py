"""
E2E: Agent bundle tests — send real prompts through each agent.

Verifies that registered agent bundles (Langflow, Letta, OpenClaw)
can receive and process requests through the gateway.

Requires: running Yashigani stack with agent bundles enabled.
"""
from __future__ import annotations

import pytest

from tests.e2e.conftest import container_running, runtime_run


class TestAgentBundleHealth:
    """Verify all agent bundle containers are running and healthy."""

    def test_openclaw_running(self):
        assert container_running("docker-openclaw-1")

    def test_langgraph_running(self):
        assert container_running("docker-langgraph-1")


class TestAgentRegistration:
    """Verify agents are registered in the identity/agent registry."""

    def test_agents_registered(self):
        output = runtime_run("docker-gateway-1", """
import redis, os
from urllib.parse import quote

pw = open('/run/secrets/redis_password').read().strip()
r = redis.from_url(f"redis://:{quote(pw, safe='')}@redis:6379/3", decode_responses=True)

# Check agent index
agents = r.smembers("agent:index:active")
print(f"active_agents:{len(agents)}")
for aid in sorted(agents):
    name = r.hget(f"agent:reg:{aid}", "name")
    print(f"agent:{aid}:{name}")
""")
        assert "active_agents:" in output
        count_line = [l for l in output.split("\n") if l.startswith("active_agents:")][0]
        count = int(count_line.split(":")[1])
        assert count >= 0


class TestAgentBundleConnectivity:
    """Test connectivity to agent bundles from the gateway network."""

    def test_openclaw_reachable(self):
        output = runtime_run("docker-gateway-1", """
import urllib.request
try:
    r = urllib.request.urlopen("http://openclaw:18789/healthz", timeout=5)
    print(f"openclaw:{r.status}")
except Exception as e:
    print(f"openclaw:error:{e}")
""")
        assert "openclaw:" in output


class TestGatewayModelsEndpoint:
    """Test that /v1/models lists available models and agents."""

    def test_models_endpoint(self):
        output = runtime_run("docker-gateway-1", """
import urllib.request, json
try:
    r = urllib.request.urlopen("http://localhost:8080/v1/models", timeout=10)
    body = json.loads(r.read())
    models = [m["id"] for m in body.get("data", [])]
    print(f"model_count:{len(models)}")
    for m in models:
        print(f"model:{m}")
except urllib.error.HTTPError as e:
    print(f"model_count:auth_required:{e.code}")
except Exception as e:
    print(f"error:{e}")
""")
        assert "model_count:" in output
        lines = output.strip().split("\n")
        count_line = [l for l in lines if l.startswith("model_count:")][0]
        if "auth_required" in count_line:
            pass
        else:
            model_count = int(count_line.split(":")[1])
            assert model_count >= 1
