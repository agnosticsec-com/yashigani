"""
Yashigani Gateway — MCP runtime call router.

Handles inbound MCP JSON-RPC calls from agents to onboarded MCP servers.

Route: POST /mcp/{agent_name}

Flow:
  1. Registry lookup — 404 if agent_name unknown.
  2. Strip X-Forwarded-*/X-Real-IP/X-Posture headers (posture is channel-derived).
  3. Derive posture mcp-b via McpHttpTransport.derive_posture() (HTTP channel).
  4. Parse JSON-RPC body.
  5. tools/call: broker.enforce(ctx) → on allow, McpHttpTransport.forward().
  6. initialize / tools/list / notifications: forward through transport WITH gateway
     JWT (gateway attaches a session-level JWT so the server trusts the gateway).
  7. Deny → 403 with deny_reason.  Unknown method → forward (pass-through).

Security:
  - Posture is ALWAYS derived from the channel (mcp-b for HTTP), never from headers.
  - X-Forwarded-For / X-Real-IP / X-Posture headers are stripped before any
    posture derivation.
  - 403 response bodies do NOT include internal error details — only deny_reason.
  - All errors are fail-closed (deny + 403/502/404 as appropriate).

v2.25.0 / P3 gateway integration.
"""
from __future__ import annotations

import json
import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from yashigani.mcp._types import McpCallContext, McpPosture, PostureBinding
from yashigani.mcp._transport_http import McpHttpTransport, HttpTransportError

logger = logging.getLogger(__name__)

# Headers that must be stripped before posture derivation.
# Posture is derived from the physical channel, never from forwarded headers.
_STRIP_HEADERS = frozenset({
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "x-posture",
    "x-forwarded-user",  # stripped from downstream MCP call; preserved for identity resolution
})

# Methods that require tools/call enforcement gate
_GATED_METHODS = frozenset({"tools/call"})

# Methods that are MCP session management — forwarded without tools-gating
# but still with a gateway JWT attached
_SESSION_METHODS = frozenset({
    "initialize",
    "initialized",          # client notification after initialize
    "tools/list",
    "prompts/list",
    "resources/list",
    "ping",
    "notifications/initialized",
    "notifications/cancelled",
    "notifications/progress",
    "notifications/message",
    "notifications/resources/list_changed",
    "notifications/resources/updated",
    "notifications/tools/list_changed",
    "notifications/prompts/list_changed",
})


def create_mcp_call_router(registry: object) -> APIRouter:  # McpBrokerRegistry
    """
    Create the MCP call APIRouter.

    Parameters
    ----------
    registry:
        McpBrokerRegistry instance — maps agent_name → (broker, server_config).
        Typed as object to avoid circular imports.
    """
    mcp_call_router = APIRouter()

    @mcp_call_router.post("/mcp/{agent_name}")
    async def handle_mcp_call(agent_name: str, request: Request) -> Response:
        """
        Inbound MCP JSON-RPC call from an agent to an MCP server.

        agent_name is the path parameter — NEVER read from the request body.
        """
        # ── 1. Registry lookup ────────────────────────────────────────────────
        entry = registry.get(agent_name)  # type: ignore[attr-defined]
        if entry is None:
            logger.info("mcp-runtime: agent_name=%r not in registry — 404", agent_name)
            return JSONResponse(
                status_code=404,
                content={"error": "MCP_SERVER_NOT_FOUND", "agent_name": agent_name},
            )

        broker, server_cfg = entry

        # ── 2. Read + strip forwarding headers (posture is channel-derived) ───
        # Build a sanitised header dict — the XFF headers are removed so
        # nothing downstream can misread them for posture.
        _raw_headers = dict(request.headers)
        stripped_headers = {
            k: v for k, v in _raw_headers.items()
            if k.lower() not in _STRIP_HEADERS
        }

        # ── 3. Derive posture (always mcp-b for HTTP channel) ─────────────────
        transport_descriptor = McpHttpTransport(
            upstream_url=server_cfg.upstream_url,
            is_relay=False,
        )
        posture, posture_binding = transport_descriptor.derive_posture()
        # Verify invariant: HTTP channel must yield mcp-b
        if posture != McpPosture.MCP_B:
            logger.error(
                "mcp-runtime: unexpected posture=%r for HTTP channel (expected mcp-b) "
                "agent=%r — denying fail-closed",
                posture.value, agent_name,
            )
            return JSONResponse(
                status_code=403,
                content={"error": "POSTURE_INVARIANT_VIOLATION"},
            )

        # ── 4. Parse JSON-RPC body ─────────────────────────────────────────────
        try:
            body_bytes = await request.body()
            body_str = body_bytes.decode("utf-8")
            msg = json.loads(body_str)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            logger.warning("mcp-runtime: invalid JSON body agent=%r: %s", agent_name, exc)
            return JSONResponse(
                status_code=400,
                content={"error": "INVALID_JSON"},
            )

        method = msg.get("method", "")
        params = msg.get("params") or {}
        msg_id = msg.get("id")  # None for notifications
        is_notification = msg_id is None

        # Resolve identity from the gateway-injected header (Caddy forward_auth)
        # X-Forwarded-User is stripped from downstream but available in inbound headers.
        user_id = _raw_headers.get("x-forwarded-user", "").strip() or "unknown"
        call_id = str(uuid.uuid4())
        request_id = str(uuid.uuid4())

        # ── 5. Route by method ────────────────────────────────────────────────
        if method in _GATED_METHODS:
            # tools/call — full broker.enforce() pipeline
            tool_name = params.get("name") if isinstance(params, dict) else None
            tool_args = params.get("arguments") if isinstance(params, dict) else None

            ctx = McpCallContext(
                tenant_id=server_cfg.tenant_id,
                agent_name=agent_name,
                user_id=user_id,
                posture=posture,
                posture_binding=posture_binding,
                action="mcp.tools.call",
                tool_name=tool_name,
                tool_args_redacted=tool_args,
                call_id=call_id,
                request_id=request_id,
                server_id=agent_name,
            )

            try:
                decision = await broker.enforce(ctx)  # type: ignore[attr-defined]
            except Exception as exc:
                logger.error(
                    "mcp-runtime: broker.enforce raised unexpectedly agent=%r call_id=%s: %s",
                    agent_name, call_id, exc,
                )
                return JSONResponse(
                    status_code=502,
                    content={"error": "BROKER_ERROR"},
                )

            if not decision.allow:
                logger.info(
                    "mcp-runtime: OPA denied agent=%r method=%r tool=%r reason=%s",
                    agent_name, method, tool_name, decision.deny_reason,
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "MCP_TOOL_CALL_DENIED",
                        "deny_reason": decision.deny_reason,
                    },
                )

            # Allowed — forward to the bridge with the issued JWT
            try:
                async with McpHttpTransport(
                    upstream_url=server_cfg.upstream_url,
                    is_relay=False,
                ) as transport:
                    upstream_response = await transport.forward(
                        mcp_request_json=body_str,
                        gateway_jwt=decision.issued_jwt,
                    )
            except HttpTransportError as exc:
                logger.error(
                    "mcp-runtime: upstream transport error agent=%r call_id=%s: %s",
                    agent_name, call_id, exc,
                )
                return JSONResponse(
                    status_code=502,
                    content={"error": "UPSTREAM_UNREACHABLE"},
                )
            except Exception as exc:
                logger.error(
                    "mcp-runtime: unexpected forward error agent=%r call_id=%s: %s",
                    agent_name, call_id, exc,
                )
                return JSONResponse(
                    status_code=502,
                    content={"error": "UPSTREAM_ERROR"},
                )

            return Response(
                content=upstream_response.encode("utf-8"),
                status_code=200,
                media_type="application/json",
            )

        elif method in _SESSION_METHODS or is_notification:
            # Session management or notification — forward through with a
            # session-level gateway JWT (so the MCP server trusts the gateway).
            # No tools-gating enforce() — these are protocol-level messages.
            ctx_session = McpCallContext(
                tenant_id=server_cfg.tenant_id,
                agent_name=agent_name,
                user_id=user_id,
                posture=posture,
                posture_binding=posture_binding,
                action=f"mcp.session.{method.replace('/', '.').replace('-', '_')}",
                call_id=call_id,
                request_id=request_id,
                server_id=agent_name,
            )

            # Issue a session-level JWT directly (no OPA gate for session messages)
            try:
                issuer = broker._issuer  # type: ignore[attr-defined]
                session_jwt = issuer.issue(
                    user_id=user_id,
                    agent_name=agent_name,
                    posture=posture.value,
                    posture_binding=posture_binding.to_dict(),
                    action=ctx_session.action,
                    call_id=call_id,
                )
            except Exception as exc:
                logger.error(
                    "mcp-runtime: session JWT issuance failed agent=%r: %s", agent_name, exc
                )
                return JSONResponse(
                    status_code=502,
                    content={"error": "SESSION_JWT_ERROR"},
                )

            if is_notification:
                # Notification: forward + return 202 without waiting for a response
                try:
                    async with McpHttpTransport(
                        upstream_url=server_cfg.upstream_url,
                        is_relay=False,
                    ) as transport:
                        # For notifications we still use forward() which issues an HTTP
                        # POST — the bridge returns 202 and we mirror that.
                        upstream_response = await transport.forward(
                            mcp_request_json=body_str,
                            gateway_jwt=session_jwt,
                        )
                except HttpTransportError as exc:
                    logger.warning(
                        "mcp-runtime: notification forward failed agent=%r: %s (non-fatal)",
                        agent_name, exc,
                    )
                    # Non-fatal for notifications — the bridge should return 202
                    # but if the bridge is down we still return 202 to the client
                return Response(status_code=202)

            else:
                # Non-gated request (initialize, tools/list, etc.) — forward with JWT
                try:
                    async with McpHttpTransport(
                        upstream_url=server_cfg.upstream_url,
                        is_relay=False,
                    ) as transport:
                        upstream_response = await transport.forward(
                            mcp_request_json=body_str,
                            gateway_jwt=session_jwt,
                        )
                except HttpTransportError as exc:
                    logger.error(
                        "mcp-runtime: session forward error agent=%r method=%r: %s",
                        agent_name, method, exc,
                    )
                    return JSONResponse(
                        status_code=502,
                        content={"error": "UPSTREAM_UNREACHABLE"},
                    )
                except Exception as exc:
                    logger.error(
                        "mcp-runtime: unexpected session forward error agent=%r method=%r: %s",
                        agent_name, method, exc,
                    )
                    return JSONResponse(
                        status_code=502,
                        content={"error": "UPSTREAM_ERROR"},
                    )

                return Response(
                    content=upstream_response.encode("utf-8"),
                    status_code=200,
                    media_type="application/json",
                )

        else:
            # Unknown method — pass through (forward with a session JWT)
            logger.debug(
                "mcp-runtime: unknown method=%r agent=%r — pass-through", method, agent_name
            )
            try:
                issuer = broker._issuer  # type: ignore[attr-defined]
                passthru_jwt = issuer.issue(
                    user_id=user_id,
                    agent_name=agent_name,
                    posture=posture.value,
                    posture_binding=posture_binding.to_dict(),
                    action=f"mcp.passthrough.{method.replace('/', '.') or 'unknown'}",
                    call_id=call_id,
                )
                async with McpHttpTransport(
                    upstream_url=server_cfg.upstream_url,
                    is_relay=False,
                ) as transport:
                    upstream_response = await transport.forward(
                        mcp_request_json=body_str,
                        gateway_jwt=passthru_jwt,
                    )
                return Response(
                    content=upstream_response.encode("utf-8"),
                    status_code=200,
                    media_type="application/json",
                )
            except Exception as exc:
                logger.error(
                    "mcp-runtime: pass-through error agent=%r method=%r: %s",
                    agent_name, method, exc,
                )
                return JSONResponse(
                    status_code=502,
                    content={"error": "UPSTREAM_ERROR"},
                )

    return mcp_call_router
