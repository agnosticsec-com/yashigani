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
    def test_metrics_returns_200_with_allowed_spiffe(self, monkeypatch):
        """GET /internal/metrics with a whitelisted X-SPIFFE-ID must succeed.

        v2.23.1 EX-231-08: endpoint is Caddy-gated — the ACL lives in
        service_identities.yaml. Inject an in-memory ACL for the unit test
        so it doesn't depend on the on-disk manifest.
        """
        from yashigani.auth import spiffe as _spiffe
        monkeypatch.setattr(
            _spiffe,
            "_load_acls",
            lambda: {
                "/internal/metrics": frozenset(
                    {"spiffe://yashigani.internal/prometheus"}
                )
            },
        )
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
        response = client.get(
            "/internal/metrics",
            headers={"X-SPIFFE-ID": "spiffe://yashigani.internal/prometheus"},
        )
        assert response.status_code == 200

    def test_metrics_rejects_missing_spiffe(self, monkeypatch):
        """GET /internal/metrics without the header returns 401."""
        from yashigani.auth import spiffe as _spiffe
        monkeypatch.setattr(
            _spiffe,
            "_load_acls",
            lambda: {
                "/internal/metrics": frozenset(
                    {"spiffe://yashigani.internal/prometheus"}
                )
            },
        )
        from yashigani.gateway.proxy import create_gateway_app, GatewayConfig
        cfg = GatewayConfig(upstream_base_url="http://mcp:8080", opa_url="http://opa:8181")
        app = create_gateway_app(
            config=cfg,
            inspection_pipeline=MagicMock(),
            chs=MagicMock(),
            audit_writer=MagicMock(),
        )
        from fastapi.testclient import TestClient
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/internal/metrics")
        assert response.status_code == 401
