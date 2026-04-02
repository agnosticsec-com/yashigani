"""
Yashigani Gateway — Reverse proxy for MCP servers and agentic AI systems.

Traffic flow:
  Client → [AuthN/Z] → [Inspection pipeline] → [OPA policy check] → MCP server
                                 ↑
                        Credential masking via CHS
                        before any AI classifier call

All inbound requests are:
1. Authenticated via session cookie or API key
2. Inspected for credential exfiltration and prompt injection
3. Policy-checked via OPA (never cloud-delegated)
4. Forwarded to the upstream MCP server or discarded

Responses from MCP servers are forwarded back as-is.
Audit events are written for every request regardless of disposition.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Optional

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

logger = logging.getLogger(__name__)

_HOP_BY_HOP_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
})


# ---------------------------------------------------------------------------
# Gateway configuration
# ---------------------------------------------------------------------------

@dataclass
class GatewayConfig:
    upstream_base_url: str              # Target MCP server URL
    opa_url: str = "http://policy:8181"
    opa_policy_path: str = "/v1/data/yashigani/allow"
    request_timeout_seconds: float = 30.0
    max_request_body_bytes: int = 4 * 1024 * 1024  # 4 MB
    strip_response_headers: frozenset = frozenset()


# ---------------------------------------------------------------------------
# Gateway application factory
# ---------------------------------------------------------------------------

def create_gateway_app(
    config: GatewayConfig,
    inspection_pipeline=None,
    auth_service=None,
    chs=None,
    audit_writer=None,
    rate_limiter=None,
    rbac_store=None,
    agent_registry=None,
    jwt_inspector=None,
    endpoint_rate_limiter=None,
    response_cache=None,
    fasttext_backend=None,
    inference_logger=None,
    anomaly_detector=None,
    response_inspection_pipeline=None,  # v0.9.0 — ResponseInspectionPipeline | None
) -> FastAPI:
    """
    Create the Yashigani gateway FastAPI application.

    Parameters are injected at startup from the main application entrypoint.
    """
    _state = {
        "config": config,
        "inspection_pipeline": inspection_pipeline,
        "response_inspection_pipeline": response_inspection_pipeline,  # v0.9.0
        "auth_service": auth_service,
        "chs": chs,
        "audit_writer": audit_writer,
        "rate_limiter": rate_limiter,
        "rbac_store": rbac_store,
        "agent_registry": agent_registry,
        "jwt_inspector": jwt_inspector,
        "endpoint_rate_limiter": endpoint_rate_limiter,
        "response_cache": response_cache,
        "fasttext_backend": fasttext_backend,
        "inference_logger": inference_logger,
        "anomaly_detector": anomaly_detector,
        "http_client": None,
    }

    @asynccontextmanager
    async def _lifespan(app: FastAPI):
        # Startup: create shared HTTP client for upstream proxying
        _state["http_client"] = httpx.AsyncClient(
            base_url=config.upstream_base_url,
            timeout=config.request_timeout_seconds,
            follow_redirects=False,
        )
        yield
        # Shutdown: close the HTTP client
        client = _state["http_client"]
        if client:
            await client.aclose()

    app = FastAPI(
        title="Yashigani Gateway",
        version="2.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=_lifespan,
    )

    # Security headers
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # Internal health check — used by Caddy and container health probe
    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    # Internal Prometheus metrics endpoint (scraped by Prometheus on internal network)
    @app.get("/internal/metrics")
    async def internal_metrics():
        from fastapi.responses import PlainTextResponse
        try:
            from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
            return PlainTextResponse(
                generate_latest().decode("utf-8"),
                media_type=CONTENT_TYPE_LATEST,
            )
        except ImportError:
            return PlainTextResponse("# prometheus_client not installed\n")

    # Catch-all reverse proxy route
    @app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    )
    async def proxy_request(path: str, request: Request) -> Response:
        return await _handle_request(request, path, _state)

    return app


# ---------------------------------------------------------------------------
# Core request handler
# ---------------------------------------------------------------------------

async def _handle_request(request: Request, path: str, state: dict) -> Response:
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    cfg: GatewayConfig = state["config"]
    audit_writer = state["audit_writer"]

    start = time.monotonic()

    # ── OTEL span — wraps the full request lifecycle ────────────────────────
    try:
        from yashigani.tracing import get_tracer, current_trace_id
        _tracer = get_tracer()
    except Exception:
        logger.debug("proxy: tracer import or initialisation failed", exc_info=True)
        _tracer = None

    # Agent routing — intercept /agents/* before rate limiting and inspection.
    # AgentAuthMiddleware (added via add_middleware) has already run and set
    # request.state.caller_type when auth succeeded.
    norm_path = path if path.startswith("/") else "/" + path
    if norm_path.startswith("/agents/"):
        from yashigani.gateway.agent_router import route_agent_call
        return await route_agent_call(request, norm_path, state)

    # 0. Rate limiting — before any expensive processing
    rate_limiter = state["rate_limiter"]
    if rate_limiter is not None:
        client_ip = _get_client_ip(request)
        agent_id_rl = request.headers.get("x-yashigani-agent-id", "unknown")
        session_id_rl = request.cookies.get("yashigani_session", "")
        user_email_rl = request.headers.get("x-yashigani-user-id", "")

        # Apply per-role rate limit override: use the most permissive (highest) RPS
        # across all groups the user belongs to that have an override configured.
        rbac_store_rl = state.get("rbac_store")
        if rbac_store_rl is not None and user_email_rl:
            try:
                user_groups = rbac_store_rl.get_user_groups(user_email_rl)
                best_rps = None
                best_burst = None
                for grp in user_groups:
                    if grp.rate_limit_override is not None:
                        ovr = grp.rate_limit_override
                        if best_rps is None or ovr.per_session_rps > best_rps:
                            best_rps = ovr.per_session_rps
                            best_burst = ovr.per_session_burst
                if best_rps is not None:
                    rate_limiter.set_session_override(
                        session_id=session_id_rl,
                        per_session_rps=best_rps,
                        per_session_burst=best_burst,
                    )
            except Exception as exc:
                logger.debug("RBAC rate limit override lookup failed: %s", exc)

        rl_result = rate_limiter.check(client_ip, agent_id_rl, session_id_rl)
        if not rl_result.allowed:
            retry_sec = max(1, rl_result.retry_after_ms // 1000)
            try:
                from yashigani.metrics.registry import ratelimit_violations_total
                ratelimit_violations_total.labels(dimension=rl_result.dimension).inc()
            except Exception:
                logger.debug("proxy: metric increment failed for ratelimit_violations_total", exc_info=True)
            _audit_rate_limit(
                audit_writer=state["audit_writer"],
                request_id=request_id,
                result=rl_result,
                client_ip=client_ip,
                agent_id=agent_id_rl,
                session_id=session_id_rl,
                rate_limiter=rate_limiter,
            )
            return JSONResponse(
                status_code=429,
                content={
                    "error": "RATE_LIMIT_EXCEEDED",
                    "dimension": rl_result.dimension,
                    "request_id": request_id,
                    "retry_after_seconds": retry_sec,
                },
                headers={
                    "X-Yashigani-Request-Id": request_id,
                    "Retry-After": str(retry_sec),
                    "X-RateLimit-Remaining": str(rl_result.remaining),
                },
            )

    # 0b. Per-endpoint rate limiting — Phase 5
    ep_rl = state.get("endpoint_rate_limiter")
    if ep_rl is not None:
        ep_result = ep_rl.check(norm_path)
        if not ep_result.allowed:
            try:
                from yashigani.metrics.registry import endpoint_ratelimit_violations_total
                endpoint_ratelimit_violations_total.labels(path=ep_result.endpoint_hash[:8]).inc()
            except Exception:
                logger.debug("proxy: metric increment failed for endpoint_ratelimit_violations_total", exc_info=True)
            return JSONResponse(
                status_code=429,
                content={
                    "error": "ENDPOINT_RATE_LIMIT_EXCEEDED",
                    "endpoint": norm_path,
                    "request_id": request_id,
                    "retry_after_seconds": ep_result.retry_after_seconds,
                },
                headers={
                    "X-Yashigani-Request-Id": request_id,
                    "Retry-After": str(ep_result.retry_after_seconds),
                },
            )

    # 0c. JWT introspection — Phase 7
    # Only validates if a Bearer token is present; requests without one pass through
    # and are governed by OPA policy (which may reject them).
    auth_header = request.headers.get("authorization", "")
    jwt_claims: dict = {}
    if auth_header.startswith("Bearer ") and state.get("jwt_inspector") is not None:
        token = auth_header[len("Bearer "):]
        jwt_result = await state["jwt_inspector"].inspect(
            token=token,
            tenant_id=request.headers.get("x-yashigani-tenant-id", "00000000-0000-0000-0000-000000000000"),
        )
        if not jwt_result.valid:
            return JSONResponse(
                status_code=401,
                content={"error": "JWT_INVALID", "detail": jwt_result.error, "request_id": request_id},
                headers={"X-Yashigani-Request-Id": request_id},
            )
        jwt_claims = jwt_result.claims

    # 1. Read and size-check the request body
    try:
        body_bytes = await request.body()
    except Exception:
        return _error_response(request_id, 400, "BODY_READ_ERROR")

    if len(body_bytes) > cfg.max_request_body_bytes:
        _audit_request(audit_writer, request_id, "BLOCKED", "body_too_large", request, path)
        return _error_response(request_id, 413, "REQUEST_BODY_TOO_LARGE")

    # 2. Extract session / API key identity
    session_id, agent_id, user_id = _extract_identity(request)
    # Prefer JWT sub over header-provided user_id
    if jwt_claims.get("sub"):
        user_id = jwt_claims["sub"]

    # 3. Run inspection pipeline (if configured)
    pipeline = state["inspection_pipeline"]
    forwarded_body = body_bytes

    if pipeline is not None and body_bytes:
        raw_query = _decode_body_safe(body_bytes)
        if raw_query:
            result = pipeline.process(
                raw_query=raw_query,
                session_id=session_id,
                agent_id=agent_id,
                user_id=user_id,
            )

            if result.action == "DISCARDED":
                _audit_request(
                    audit_writer, request_id, "DISCARDED",
                    result.classification, request, path,
                    confidence=result.confidence,
                )
                # Return user alert as the response — query never forwarded
                return JSONResponse(
                    status_code=200,
                    content=result.user_alert,
                    headers={"X-Yashigani-Request-Id": request_id},
                )

            if result.action == "SANITIZED" and result.clean_query is not None:
                forwarded_body = result.clean_query.encode("utf-8", errors="replace")

    # 4. OPA policy check
    opa_allowed = await _opa_check(cfg, request, path, session_id, agent_id, user_id)
    if not opa_allowed:
        _audit_request(audit_writer, request_id, "DENIED", "opa_policy", request, path)
        return _error_response(request_id, 403, "POLICY_DENIED")

    # 4b. Response cache — only on CLEAN forwarded requests (Phase 6)
    tenant_id = request.headers.get("x-yashigani-tenant-id", "platform")
    response_cache = state.get("response_cache")
    if response_cache is not None and forwarded_body:
        cached = response_cache.get(tenant_id, forwarded_body)
        if cached is not None:
            trace_id = ""
            try:
                trace_id = current_trace_id()
            except Exception:
                logger.debug("proxy: trace ID retrieval failed for cache-hit response", exc_info=True)
            resp_headers = {"X-Yashigani-Request-Id": request_id, "X-Cache": "HIT"}
            if trace_id:
                resp_headers["X-Trace-Id"] = trace_id
            return Response(
                content=cached,
                status_code=200,
                headers=resp_headers,
                media_type="application/json",
            )

    # 5. Forward to upstream MCP server
    client: httpx.AsyncClient = state["http_client"]
    upstream_response = await _forward(client, request, path, forwarded_body, request_id)

    # 5a. Response inspection — v0.9.0 F-01
    # Inspect the upstream response for indirect prompt injection before
    # returning it to the agent. Raw body is never stored; only a hash.
    response_verdict: Optional[str] = None
    resp_pipeline = state.get("response_inspection_pipeline")
    if resp_pipeline is not None:
        resp_body_text = _decode_body_safe(upstream_response.content)
        if resp_body_text:
            resp_content_type = upstream_response.headers.get("content-type", "")
            resp_result = resp_pipeline.inspect(
                response_body=resp_body_text,
                content_type=resp_content_type,
                request_id=request_id,
                session_id=session_id,
                agent_id=agent_id,
            )
            if not resp_result.skipped:
                response_verdict = resp_result.verdict
            if resp_result.verdict == "BLOCKED":
                elapsed_ms = int((time.monotonic() - start) * 1000)
                _audit_request(
                    audit_writer, request_id, "BLOCKED", "response_injection",
                    request, path,
                    upstream_status=upstream_response.status_code,
                    elapsed_ms=elapsed_ms,
                    confidence=resp_result.confidence,
                    response_inspection_verdict=resp_result.verdict,
                )
                return JSONResponse(
                    status_code=502,
                    content={
                        "error": "UPSTREAM_RESPONSE_BLOCKED",
                        "detail": "The upstream response was blocked by Yashigani response inspection.",
                        "request_id": request_id,
                    },
                    headers={
                        "X-Yashigani-Request-Id": request_id,
                        "X-Yashigani-Response-Verdict": resp_result.verdict,
                    },
                )

    elapsed_ms = int((time.monotonic() - start) * 1000)
    _audit_request(
        audit_writer, request_id, "FORWARDED", "clean", request, path,
        upstream_status=upstream_response.status_code,
        elapsed_ms=elapsed_ms,
        response_inspection_verdict=response_verdict,
    )

    try:
        from yashigani.metrics.registry import (
            gateway_requests_total,
            gateway_request_duration_seconds,
            gateway_upstream_status_total,
        )
        agent_id_m = request.headers.get("x-yashigani-agent-id", "unknown")
        gateway_requests_total.labels(method=request.method, action="FORWARDED", agent_id=agent_id_m).inc()
        gateway_request_duration_seconds.labels(method=request.method, action="FORWARDED").observe(elapsed_ms / 1000)
        gateway_upstream_status_total.labels(status_code=str(upstream_response.status_code)).inc()
    except Exception:
        logger.debug("proxy: metric increment failed for gateway forwarded-request counters", exc_info=True)

    # 5b. Store clean 2xx responses in cache (Phase 6)
    if (
        response_cache is not None
        and forwarded_body
        and 200 <= upstream_response.status_code < 300
    ):
        cache_ttl = int(request.headers.get("x-yashigani-cache-ttl", "300"))
        response_cache.set(tenant_id, forwarded_body, upstream_response.content, ttl=cache_ttl)

    # 5c. Inference payload logging + anomaly detection (Phases 1+2)
    inference_logger = state.get("inference_logger")
    if inference_logger is not None and forwarded_body:
        anomaly_detector = state.get("anomaly_detector")
        if anomaly_detector is not None:
            asyncio.ensure_future(
                anomaly_detector.record(tenant_id=tenant_id, payload_bytes=len(forwarded_body))
            )
        asyncio.ensure_future(
            inference_logger.log(
                tenant_id=tenant_id,
                session_id=session_id,
                payload=forwarded_body,
                upstream_status=upstream_response.status_code,
                elapsed_ms=elapsed_ms,
            )
        )

    # 5d. Attach trace ID to response (Phase 9)
    response = _build_response(upstream_response, request_id)
    try:
        trace_id = current_trace_id()
        if trace_id:
            response.headers["X-Trace-Id"] = trace_id
    except Exception:
        logger.debug("proxy: trace ID retrieval failed for forwarded response header", exc_info=True)

    # 5e. Attach response inspection verdict header when present (v0.9.0)
    if response_verdict is not None:
        response.headers["X-Yashigani-Response-Verdict"] = response_verdict

    return response


# ---------------------------------------------------------------------------
# OPA policy check
# ---------------------------------------------------------------------------

async def _opa_check(
    cfg: GatewayConfig,
    request: Request,
    path: str,
    session_id: str,
    agent_id: str,
    user_id: str,
) -> bool:
    """
    Query OPA for an allow/deny decision.
    OPA is always local — never a cloud call (ASVS V4.2).
    On any OPA error: deny (fail-closed).
    """
    import json

    input_doc = {
        "method": request.method,
        "path": path,
        "session_id": session_id,
        "agent_id": agent_id,
        "user_id": user_id,
        # session.email is consumed by rbac.rego allow_rbac
        "session": {"email": user_id},
        "request": {"method": request.method, "path": path},
        "headers": {
            k: v for k, v in request.headers.items()
            if k.lower() not in ("authorization", "cookie")
        },
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                cfg.opa_url + cfg.opa_policy_path,
                json={"input": input_doc},
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
            # OPA returns {"result": true} or {"result": false}
            return bool(data.get("result", False))
    except Exception as exc:
        logger.error(
            "OPA check failed for path '%s' (request_id=%s): %s — denying (fail-closed)",
            path, session_id, exc,
        )
        return False  # fail-closed


# ---------------------------------------------------------------------------
# Upstream forwarding
# ---------------------------------------------------------------------------

async def _forward(
    client: httpx.AsyncClient,
    request: Request,
    path: str,
    body: bytes,
    request_id: str,
) -> httpx.Response:
    # Build forwarded headers — strip hop-by-hop, inject trace ID
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in _HOP_BY_HOP_HEADERS
        and k.lower() != "host"
    }
    headers["X-Yashigani-Request-Id"] = request_id
    headers["X-Forwarded-For"] = _get_client_ip(request)

    query_string = request.url.query
    url = path + ("?" + query_string if query_string else "")

    return await client.request(
        method=request.method,
        url=url,
        content=body,
        headers=headers,
    )


def _build_response(upstream: httpx.Response, request_id: str) -> Response:
    headers = {
        k: v for k, v in upstream.headers.items()
        if k.lower() not in _HOP_BY_HOP_HEADERS
    }
    headers["X-Yashigani-Request-Id"] = request_id

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=headers,
        media_type=upstream.headers.get("content-type"),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_identity(request: Request) -> tuple[str, str, str]:
    """Extract session_id, agent_id, user_id from request headers/cookies."""
    session_id = request.cookies.get("yashigani_session", "")
    if not session_id:
        # API key or Bearer token — use a hash as the session_id handle
        auth = request.headers.get("authorization", "")
        session_id = hashlib.sha256(auth.encode()).hexdigest()[:16] if auth else "anonymous"

    agent_id = request.headers.get("x-yashigani-agent-id", "unknown")
    user_id = request.headers.get("x-yashigani-user-id", "unknown")
    return session_id, agent_id, user_id


def _decode_body_safe(body: bytes) -> Optional[str]:
    """Attempt to decode body as UTF-8 text for inspection. Returns None for binary."""
    try:
        return body.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return None


def _get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _error_response(request_id: str, status_code: int, error_code: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": error_code, "request_id": request_id},
        headers={"X-Yashigani-Request-Id": request_id},
    )


def _audit_rate_limit(
    audit_writer,
    request_id: str,
    result,
    client_ip: str,
    agent_id: str,
    session_id: str,
    rate_limiter,
) -> None:
    if audit_writer is None:
        return
    try:
        from yashigani.audit.schema import RateLimitViolationEvent
        rpi = 0.0
        multiplier = 1.0
        try:
            rpi = rate_limiter._monitor.get_metrics().pressure_index if rate_limiter._monitor else 0.0
            multiplier = rate_limiter.current_rpi_multiplier()
        except Exception:
            logger.debug("proxy: RPI/multiplier retrieval failed for rate limit audit event", exc_info=True)
        event = RateLimitViolationEvent(
            account_tier="system",
            request_id=request_id,
            dimension=result.dimension,
            client_ip_hash=_content_hash(client_ip)[:16],
            agent_id=agent_id,
            session_id_prefix=session_id[:8] if session_id else "",
            retry_after_ms=result.retry_after_ms,
            rpi_at_time=rpi,
            rpi_multiplier=multiplier,
        )
        audit_writer.write(event)
    except Exception as exc:
        logger.error("Failed to write rate limit audit event: %s", exc)


def _audit_request(
    audit_writer,
    request_id: str,
    action: str,
    reason: str,
    request: Request,
    path: str,
    upstream_status: Optional[int] = None,
    elapsed_ms: Optional[int] = None,
    confidence: Optional[float] = None,
    response_inspection_verdict: Optional[str] = None,  # v0.9.0
) -> None:
    if audit_writer is None:
        return
    try:
        from yashigani.audit.schema import GatewayRequestEvent
        event = GatewayRequestEvent(
            account_tier="system",
            request_id=request_id,
            method=request.method,
            path=path,
            action=action,
            reason=reason,
            upstream_status=upstream_status,
            elapsed_ms=elapsed_ms,
            confidence_score=confidence,
            response_inspection_verdict=response_inspection_verdict,
        )
        audit_writer.write(event)
    except Exception as exc:
        logger.error("Failed to write gateway audit event: %s", exc)
