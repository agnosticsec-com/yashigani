"""Yashigani Gateway — MCP reverse proxy with inspection and policy enforcement."""
from yashigani.gateway.proxy import create_gateway_app, GatewayConfig

__all__ = ["create_gateway_app", "GatewayConfig"]
