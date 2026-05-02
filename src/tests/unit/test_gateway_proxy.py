"""Unit tests for yashigani.gateway.proxy."""
from __future__ import annotations
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
import httpx


class TestGatewayConfig:
    def test_defaults(self):
        from yashigani.gateway.proxy import GatewayConfig
        cfg = GatewayConfig(upstream_base_url="http://mcp:8080", opa_url="http://opa:8181")
        assert cfg.upstream_base_url == "http://mcp:8080"
        assert cfg.opa_url == "http://opa:8181"


class TestHealthEndpoint:
    def test_healthz_returns_200(self):
        """GET /healthz must return 200 — used by Docker HEALTHCHECK and K8s liveness."""
        from yashigani.gateway.proxy import create_gateway_app, GatewayConfig
        mock_pipeline = MagicMock()
        mock_pipeline.inspect.return_value = MagicMock(action="ALLOW", sanitized_content=None)
        cfg = GatewayConfig(upstream_base_url="http://mcp:8080", opa_url="http://opa:8181")
        app = create_gateway_app(
            config=cfg,
            inspection_pipeline=mock_pipeline,
            chs=MagicMock(),
            audit_writer=MagicMock(),
            rate_limiter=None,
            rbac_store=None,
            agent_registry=None,
        )
        from fastapi.testclient import TestClient
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/healthz")
        assert response.status_code == 200


class TestMetricsEndpoint:
    def test_metrics_returns_200(self):
        """GET /internal/metrics must return Prometheus text format (or plain text when not installed)."""
        from yashigani.gateway.proxy import create_gateway_app, GatewayConfig
        mock_pipeline = MagicMock()
        cfg = GatewayConfig(upstream_base_url="http://mcp:8080", opa_url="http://opa:8181")
        app = create_gateway_app(
            config=cfg,
            inspection_pipeline=mock_pipeline,
            chs=MagicMock(),
            audit_writer=MagicMock(),
        )
        from fastapi.testclient import TestClient
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/internal/metrics")
        # Returns 200 with prometheus text (or plain fallback when prometheus_client not installed)
        assert response.status_code == 200
