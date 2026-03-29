"""Unit tests for yashigani.gateway.agent_auth and agent_router."""
from __future__ import annotations
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from fastapi.testclient import TestClient
from fastapi import FastAPI


class TestAgentAuthMiddleware:
    def test_non_agent_path_passes_through(self):
        """Requests to non-/agents/ paths should bypass agent auth."""
        from yashigani.gateway.agent_auth import AgentAuthMiddleware
        app = FastAPI()

        @app.get("/healthz")
        async def healthz():
            return {"status": "ok"}

        mock_registry = MagicMock()
        mock_audit = MagicMock()
        app.add_middleware(AgentAuthMiddleware, agent_registry=mock_registry, audit_writer=mock_audit)

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/healthz")
        assert response.status_code == 200
        mock_registry.verify_token.assert_not_called()

    def test_agent_path_without_auth_returns_401(self):
        """Requests to /agents/ without Bearer token should return 401."""
        from yashigani.gateway.agent_auth import AgentAuthMiddleware
        app = FastAPI()

        @app.get("/agents/target-id/tools/list")
        async def agent_route():
            return {"ok": True}

        mock_registry = MagicMock()
        mock_registry.verify_token.return_value = False
        mock_audit = MagicMock()
        app.add_middleware(AgentAuthMiddleware, agent_registry=mock_registry, audit_writer=mock_audit)

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/agents/target-id/tools/list")
        assert response.status_code == 401

    def test_agent_path_with_valid_token_passes(self):
        """Valid bearer token should be accepted and request.state set."""
        from yashigani.gateway.agent_auth import AgentAuthMiddleware
        app = FastAPI()
        received_state = {}

        @app.get("/agents/target-id/tools/list")
        async def agent_route(request):
            received_state["caller_type"] = getattr(request.state, "caller_type", None)
            return {"ok": True}

        mock_registry = MagicMock()
        mock_registry.verify_token.return_value = True
        mock_registry.get_agent.return_value = MagicMock(id="caller-id", name="Test Agent")
        mock_audit = MagicMock()
        app.add_middleware(AgentAuthMiddleware, agent_registry=mock_registry, audit_writer=mock_audit)

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get(
            "/agents/target-id/tools/list",
            headers={
                "Authorization": "Bearer " + "a" * 64,
                "X-Yashigani-Caller-Agent-Id": "caller-id",
            }
        )
        assert response.status_code == 200


class TestAgentRegistry:
    def test_register_returns_id_and_token(self, mock_redis):
        from yashigani.agents.registry import AgentRegistry
        registry = AgentRegistry(redis_client=mock_redis)
        agent_id, token = registry.register(
            name="Test Agent",
            upstream_url="http://agent.internal:8080",
            groups=["engineering"],
            allowed_caller_groups=["engineering"],
            allowed_paths=["**"],
        )
        assert len(agent_id) > 0
        assert len(token) >= 64

    def test_verify_token_valid(self, mock_redis):
        from yashigani.agents.registry import AgentRegistry
        registry = AgentRegistry(redis_client=mock_redis)
        agent_id, token = registry.register(
            name="Test Agent",
            upstream_url="http://agent.internal:8080",
            groups=[],
            allowed_caller_groups=[],
            allowed_paths=["**"],
        )
        assert registry.verify_token(agent_id, token) is True

    def test_verify_token_wrong_token(self, mock_redis):
        from yashigani.agents.registry import AgentRegistry
        registry = AgentRegistry(redis_client=mock_redis)
        agent_id, _ = registry.register(
            name="Test Agent",
            upstream_url="http://agent.internal:8080",
            groups=[],
            allowed_caller_groups=[],
            allowed_paths=["**"],
        )
        assert registry.verify_token(agent_id, "wrong" * 20) is False

    def test_count_active(self, mock_redis):
        from yashigani.agents.registry import AgentRegistry
        registry = AgentRegistry(redis_client=mock_redis)
        assert registry.count("active") == 0
        registry.register("A", "http://a:8080", [], [], ["**"])
        assert registry.count("active") == 1
