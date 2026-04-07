"""
Yashigani Backoffice — Agent registry admin routes.

All routes require an active admin session.
The plaintext PSK token is returned ONCE on register and rotate operations
and is never stored or re-derivable after that point.

After every mutation (register/update/deactivate/token rotate), the combined
RBAC + agent data document is pushed to OPA. Push failure is non-fatal for
the mutation — it is logged but does not roll back the registry change.

Routes:
  GET    /admin/agents                          — list all agents
  POST   /admin/agents                          — register new agent
  GET    /admin/agents/{agent_id}               — get agent detail
  PUT    /admin/agents/{agent_id}               — update agent fields
  DELETE /admin/agents/{agent_id}               — deactivate (soft delete)
  POST   /admin/agents/{agent_id}/token/rotate  — rotate PSK, return new token once
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, HttpUrl

from yashigani.backoffice.middleware import require_admin_session, AdminSession
from yashigani.backoffice.state import backoffice_state

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class AgentRegisterRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    upstream_url: str = Field(min_length=1, max_length=512)
    protocol: str = Field(default="openai", description="Agent protocol: openai or acp")
    groups: list[str] = Field(default_factory=list)
    allowed_caller_groups: list[str] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=list)
    allowed_cidrs: list[str] = Field(
        default_factory=list,
        description="Optional CIDR allowlist. Empty = no IP restriction. E.g. ['10.0.0.0/8', '192.168.1.100/32']",
    )


class AgentUpdateRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    upstream_url: Optional[str] = Field(default=None, min_length=1, max_length=512)
    groups: Optional[list[str]] = None
    allowed_caller_groups: Optional[list[str]] = None
    allowed_paths: Optional[list[str]] = None
    allowed_cidrs: Optional[list[str]] = None


class AgentDeactivateRequest(BaseModel):
    reason: str = Field(default="", max_length=256)


class AgentResponse(BaseModel):
    agent_id: str
    name: str
    upstream_url: str
    status: str
    created_at: str
    last_seen_at: str
    groups: list
    allowed_caller_groups: list
    allowed_paths: list
    allowed_cidrs: list = Field(default_factory=list)
    # v0.9.0 — token rotation metadata (F-09)
    token_last_rotated: str = Field(default="")
    token_rotation_schedule: str = Field(default="")


class AgentRegisterResponse(AgentResponse):
    # Token is only present on creation and rotation — never stored
    token: str = Field(description="Plaintext PSK token. Store immediately — never shown again.")
    quick_start: dict = Field(
        default_factory=dict,
        description="Copy-paste integration snippets for curl, Python, and health check.",
    )


class AgentRotateResponse(BaseModel):
    agent_id: str
    token: str = Field(description="New plaintext PSK token. Store immediately — never shown again.")
    quick_start: dict = Field(default_factory=dict)


class AgentQuickStartResponse(BaseModel):
    agent_id: str
    quick_start: dict = Field(description="Copy-paste integration snippets (token placeholder — use your stored token).")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_registry():
    reg = backoffice_state.agent_registry
    if reg is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Agent registry unavailable",
        )
    return reg


def _to_response(agent: dict) -> AgentResponse:
    return AgentResponse(
        agent_id=agent["agent_id"],
        name=agent["name"],
        upstream_url=agent["upstream_url"],
        status=agent["status"],
        created_at=agent["created_at"],
        last_seen_at=agent["last_seen_at"],
        groups=agent["groups"],
        allowed_caller_groups=agent["allowed_caller_groups"],
        allowed_paths=agent["allowed_paths"],
        allowed_cidrs=agent.get("allowed_cidrs", []),
        token_last_rotated=agent.get("token_last_rotated", ""),
        token_rotation_schedule=agent.get("token_rotation_schedule", ""),
    )


def _build_quick_start(agent_id: str, token: str) -> dict:
    """Build copy-paste integration snippets shown once on agent registration / token rotation."""
    gw = "<your-gateway-url>"
    return {
        "curl": (
            f"curl -X POST https://{gw}/mcp \\\n"
            f"  -H 'Authorization: Bearer {token}' \\\n"
            f"  -H 'Content-Type: application/json' \\\n"
            f"  -d '{{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":1}}'"
        ),
        "python_httpx": (
            f"import httpx\n"
            f"client = httpx.Client(\n"
            f"    base_url='https://{gw}',\n"
            f"    headers={{'Authorization': 'Bearer {token}'}}\n"
            f")\n"
            f"resp = client.post('/mcp', json={{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":1}})\n"
            f"print(resp.json())"
        ),
        "health_check": (
            f"curl https://{gw}/health -H 'Authorization: Bearer {token}'"
        ),
        "note": (
            f"Replace '{gw}' with your actual gateway URL. "
            f"Token shown once — store it securely. Agent ID: {agent_id}"
        ),
    }


def _push_openwebui_model(agent_name: str, upstream_url: str) -> None:
    """
    Register agent as a selectable model in Open WebUI via its REST API.
    Non-fatal: logs on failure. Idempotent — skips if already exists.
    """
    try:
        import json
        import os
        import urllib.request
        import urllib.error

        owui_url = os.getenv("OWUI_API_URL", "http://open-webui:8080")
        owui_secret = os.getenv("OWUI_SECRET_KEY", "yashigani-owui-secret")

        # Generate a JWT for Open WebUI API auth
        import hashlib
        import hmac
        import base64
        import time as _time

        # Open WebUI uses PyJWT with the WEBUI_SECRET_KEY. We craft a minimal
        # HS256 JWT with an admin sub claim to authenticate the API call.
        header = base64.urlsafe_b64encode(json.dumps(
            {"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        payload_data = {
            "id": "00000000-0000-0000-0000-000000000000",
            "sub": "admin",
            "role": "admin",
            "exp": int(_time.time()) + 300,
        }
        payload = base64.urlsafe_b64encode(
            json.dumps(payload_data).encode()).rstrip(b"=").decode()
        sig_input = f"{header}.{payload}".encode()
        sig = base64.urlsafe_b64encode(
            hmac.new(owui_secret.encode(), sig_input, hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        token = f"{header}.{payload}.{sig}"

        model_id = "@" + agent_name
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        # Check if model already exists
        try:
            req = urllib.request.Request(
                f"{owui_url}/api/v1/models/{model_id}",
                headers=headers,
            )
            urllib.request.urlopen(req, timeout=5)
            logger.info("Open WebUI: model %s already exists", model_id)
            return
        except urllib.error.HTTPError as e:
            if e.code != 404:
                logger.warning("Open WebUI: model check failed (%s)", e.code)

        # Create model
        body = json.dumps({
            "id": model_id,
            "name": agent_name + " Agent",
            "base_model_id": os.getenv("OLLAMA_MODEL", "qwen2.5:3b"),
            "meta": {
                "description": f"Yashigani agent: {agent_name} @ {upstream_url}",
                "profile_image_url": "",
                "capabilities": {"usage": True},
            },
            "params": {},
            "is_active": True,
        }).encode()

        req = urllib.request.Request(
            f"{owui_url}/api/v1/models/create",
            data=body,
            headers=headers,
            method="POST",
        )
        urllib.request.urlopen(req, timeout=10)
        logger.info("Open WebUI: registered model %s via API", model_id)
    except Exception as exc:
        logger.warning("_push_openwebui_model failed: %s", exc)


def _push_opa() -> None:
    """
    Push the combined RBAC + agent data to OPA after a registry mutation.
    Non-fatal: logs on failure but never raises.
    """
    try:
        from yashigani.rbac.opa_push import push_rbac_data
        rbac_store = backoffice_state.rbac_store
        if rbac_store is None:
            logger.warning("_push_opa: rbac_store not available — skipping OPA push")
            return
        push_rbac_data(
            store=rbac_store,
            opa_url=backoffice_state.opa_url,
            agent_registry=backoffice_state.agent_registry,
        )
    except Exception as exc:
        logger.error("_push_opa: OPA push failed after agent mutation: %s", exc)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/admin/agents", response_model=list[AgentResponse])
async def list_agents(session: AdminSession = require_admin_session):
    registry = _get_registry()
    return [_to_response(a) for a in registry.list_all()]


@router.post("/admin/agents", response_model=AgentRegisterResponse, status_code=201)
async def register_agent(
    body: AgentRegisterRequest,
    session: AdminSession = require_admin_session,
):
    registry = _get_registry()
    audit = backoffice_state.audit_writer

    agent_id, plaintext_token = registry.register(
        name=body.name,
        upstream_url=body.upstream_url,
        groups=body.groups,
        allowed_caller_groups=body.allowed_caller_groups,
        allowed_paths=body.allowed_paths,
        allowed_cidrs=body.allowed_cidrs,
        protocol=body.protocol,
    )

    agent = registry.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=500, detail="Agent created but not retrievable")

    # Audit
    if audit is not None:
        try:
            from yashigani.audit.schema import AgentRegisteredEvent
            audit.write(AgentRegisteredEvent(
                agent_id=agent_id,
                agent_name=body.name,
                upstream_url=body.upstream_url,
                groups=body.groups,
                allowed_caller_groups=body.allowed_caller_groups,
                allowed_paths=body.allowed_paths,
                admin_account=session.username,
            ))
        except Exception as exc:
            logger.error("Failed to write AgentRegisteredEvent: %s", exc)

    _push_opa()
    _push_openwebui_model(body.name, body.upstream_url)

    return AgentRegisterResponse(
        agent_id=agent_id,
        name=agent["name"],
        upstream_url=agent["upstream_url"],
        status=agent["status"],
        created_at=agent["created_at"],
        last_seen_at=agent["last_seen_at"],
        groups=agent["groups"],
        allowed_caller_groups=agent["allowed_caller_groups"],
        allowed_paths=agent["allowed_paths"],
        allowed_cidrs=agent.get("allowed_cidrs", []),
        token=plaintext_token,
        quick_start=_build_quick_start(agent_id, plaintext_token),
    )


@router.get("/admin/agents/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: str,
    session: AdminSession = require_admin_session,
):
    registry = _get_registry()
    agent = registry.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return _to_response(agent)


@router.put("/admin/agents/{agent_id}", response_model=AgentResponse)
async def update_agent(
    agent_id: str,
    body: AgentUpdateRequest,
    session: AdminSession = require_admin_session,
):
    registry = _get_registry()
    audit = backoffice_state.audit_writer

    # Verify agent exists
    existing = registry.get(agent_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Build update kwargs — only include fields actually provided
    updates = {}
    changed_fields = []
    if body.name is not None:
        updates["name"] = body.name
        changed_fields.append("name")
    if body.upstream_url is not None:
        updates["upstream_url"] = body.upstream_url
        changed_fields.append("upstream_url")
    if body.groups is not None:
        updates["groups"] = body.groups
        changed_fields.append("groups")
    if body.allowed_caller_groups is not None:
        updates["allowed_caller_groups"] = body.allowed_caller_groups
        changed_fields.append("allowed_caller_groups")
    if body.allowed_paths is not None:
        updates["allowed_paths"] = body.allowed_paths
        changed_fields.append("allowed_paths")
    if body.allowed_cidrs is not None:
        updates["allowed_cidrs"] = body.allowed_cidrs
        changed_fields.append("allowed_cidrs")

    if updates:
        registry.update(agent_id, **updates)

    # Audit
    if audit is not None and changed_fields:
        try:
            from yashigani.audit.schema import AgentUpdatedEvent
            audit.write(AgentUpdatedEvent(
                agent_id=agent_id,
                changed_fields=changed_fields,
                admin_account=session.username,
            ))
        except Exception as exc:
            logger.error("Failed to write AgentUpdatedEvent: %s", exc)

    if updates:
        _push_opa()

    updated = registry.get(agent_id)
    return _to_response(updated)


@router.delete("/admin/agents/{agent_id}", status_code=204)
async def deactivate_agent(
    agent_id: str,
    body: AgentDeactivateRequest = None,
    session: AdminSession = require_admin_session,
):
    registry = _get_registry()
    audit = backoffice_state.audit_writer

    existing = registry.get(agent_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if existing.get("status") == "inactive":
        raise HTTPException(status_code=409, detail="Agent already inactive")

    reason = (body.reason if body else "") or ""
    registry.deactivate(agent_id)

    # Audit
    if audit is not None:
        try:
            from yashigani.audit.schema import AgentDeactivatedEvent
            audit.write(AgentDeactivatedEvent(
                agent_id=agent_id,
                admin_account=session.username,
                reason=reason,
            ))
        except Exception as exc:
            logger.error("Failed to write AgentDeactivatedEvent: %s", exc)

    _push_opa()


@router.post("/admin/agents/{agent_id}/token/rotate", response_model=AgentRotateResponse)
async def rotate_agent_token(
    agent_id: str,
    session: AdminSession = require_admin_session,
):
    registry = _get_registry()
    audit = backoffice_state.audit_writer

    existing = registry.get(agent_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    plaintext_token = registry.rotate_token(agent_id)

    # Audit
    if audit is not None:
        try:
            from yashigani.audit.schema import AgentTokenRotatedEvent
            audit.write(AgentTokenRotatedEvent(
                agent_id=agent_id,
                admin_account=session.username,
            ))
        except Exception as exc:
            logger.error("Failed to write AgentTokenRotatedEvent: %s", exc)

    _push_opa()

    return AgentRotateResponse(
        agent_id=agent_id,
        token=plaintext_token,
        quick_start=_build_quick_start(agent_id, plaintext_token),
    )


@router.get("/admin/agents/{agent_id}/quickstart", response_model=AgentQuickStartResponse)
async def get_agent_quickstart(
    agent_id: str,
    session: AdminSession = require_admin_session,
):
    """Return copy-paste integration snippets for the agent detail page.

    The token placeholder ``<your-token>`` is used in place of the actual
    token, which is only available at registration / rotation time.
    """
    registry = _get_registry()
    agent = registry.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return AgentQuickStartResponse(
        agent_id=agent_id,
        quick_start=_build_quick_start(agent_id, "<your-token>"),
    )
