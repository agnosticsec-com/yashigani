"""
Yashigani Metrics — FastAPI/Starlette request metrics middleware.
Records request count, latency, and body size per request.
Skips /healthz and /internal/metrics to avoid self-scrape noise.
"""
from __future__ import annotations

import time
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from yashigani.metrics.registry import (
    gateway_requests_total,
    gateway_request_duration_seconds,
    gateway_request_body_bytes,
    gateway_upstream_status_total,
)

_SKIP_PATHS = frozenset({"/healthz", "/internal/metrics", "/favicon.ico"})


class PrometheusMiddleware(BaseHTTPMiddleware):
    """
    Records per-request Prometheus metrics for the gateway.
    Add to any FastAPI app via app.add_middleware(PrometheusMiddleware).
    """

    def __init__(self, app: ASGIApp, service: str = "gateway") -> None:
        super().__init__(app)
        self._service = service

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path in _SKIP_PATHS:
            return await call_next(request)

        start = time.perf_counter()
        agent_id = request.headers.get("x-yashigani-agent-id", "unknown")

        # Record body size if available
        body = await request.body()
        if body:
            gateway_request_body_bytes.labels(agent_id=agent_id).observe(len(body))

        response = await call_next(request)

        elapsed = time.perf_counter() - start
        action = response.headers.get("x-yashigani-action", "unknown")
        method = request.method

        gateway_requests_total.labels(
            method=method,
            action=action,
            agent_id=agent_id,
        ).inc()

        gateway_request_duration_seconds.labels(
            method=method,
            action=action,
            agent_id=agent_id,
        ).observe(elapsed)

        if response.status_code:
            gateway_upstream_status_total.labels(
                status_code=str(response.status_code),
            ).inc()

        return response
