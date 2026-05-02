"""
Yashigani Backoffice — Audit log management routes.
GET    /audit/export                 — stream NDJSON or CSV log export
GET    /audit/masking/scope          — current masking scope config
PUT    /audit/masking/scope          — update masking scope (default + overrides)
POST   /audit/masking/scope/agent    — set per-agent masking override
DELETE /audit/masking/scope/agent/{agent_id}  — remove per-agent override
POST   /audit/masking/scope/user     — set per-user masking override
DELETE /audit/masking/scope/user/{handle}     — remove per-user override
POST   /audit/masking/scope/component — set per-component masking override
DELETE /audit/masking/scope/component/{component} — remove per-component override
GET    /audit/siem                   — list SIEM targets
POST   /audit/siem                   — add a SIEM target
DELETE /audit/siem/{name}            — remove a SIEM target
POST   /audit/siem/{name}/test       — send a test event to a SIEM target
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession
from yashigani.backoffice.state import backoffice_state

router = APIRouter()

_VALID_SIEM_TYPES = {"webhook", "splunk_hec", "elastic_opensearch"}
_VALID_AUTH_HEADERS = {"Authorization", "X-Splunk-HEC-Token", "X-API-Key"}


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class MaskingScopeDefaultRequest(BaseModel):
    mask_all_by_default: bool


class AgentOverrideRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    mask: bool


class UserOverrideRequest(BaseModel):
    user_handle: str = Field(min_length=1, max_length=128)
    mask: bool


class ComponentOverrideRequest(BaseModel):
    component: str = Field(min_length=1, max_length=64)
    mask: bool


class SiemTargetRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_-]+$")
    target_type: str = Field(pattern=r"^(webhook|splunk_hec|elastic_opensearch)$")
    url: str = Field(min_length=8, max_length=512)
    auth_header: str = Field(default="Authorization", max_length=64)
    auth_value: str = Field(min_length=1, max_length=512)
    enabled: bool = True


# ---------------------------------------------------------------------------
# Log export
# ---------------------------------------------------------------------------

@router.get("/export")
async def export_audit_log(
    session: AdminSession,
    output_format: str = Query(default="ndjson", pattern=r"^(ndjson|csv)$"),
    date_from: Optional[str] = Query(default=None, description="ISO 8601 prefix, e.g. 2025-01"),
    date_to: Optional[str] = Query(default=None, description="ISO 8601 prefix, e.g. 2025-03"),
):
    """Stream the audit log as NDJSON or CSV. Never buffers the full file in memory."""
    from yashigani.audit.export import AuditLogExporter

    state = backoffice_state
    exporter = AuditLogExporter(state.audit_writer._config)

    if output_format == "csv":
        media_type = "text/csv"
        filename = "yashigani-audit.csv"

        async def stream():
            async for chunk in exporter.export_csv(date_from=date_from, date_to=date_to):
                yield chunk
    else:
        media_type = "application/x-ndjson"
        filename = "yashigani-audit.ndjson"

        async def stream():
            async for chunk in exporter.export_ndjson(date_from=date_from, date_to=date_to):
                yield chunk

    return StreamingResponse(
        stream(),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Masking scope — global default
# ---------------------------------------------------------------------------

@router.get("/masking/scope")
async def get_masking_scope(session: AdminSession):
    """Return the current masking scope configuration."""
    state = backoffice_state
    scope = state.audit_writer._masking_scope
    return {
        "mask_all_by_default": scope.mask_all_by_default,
        "agent_overrides": scope.agent_overrides,
        "user_overrides": scope.user_overrides,
        "component_overrides": scope.component_overrides,
    }


@router.put("/masking/scope")
async def set_masking_default(body: MaskingScopeDefaultRequest, session: AdminSession):
    """Update the global masking default (mask all vs mask none by default)."""
    state = backoffice_state
    prev = state.audit_writer._masking_scope.mask_all_by_default
    state.audit_writer._masking_scope.mask_all_by_default = body.mask_all_by_default

    state.audit_writer.write(_masking_config_event(
        session.account_id,
        "masking.default",
        str(prev),
        str(body.mask_all_by_default),
    ))
    return {"status": "ok", "mask_all_by_default": body.mask_all_by_default}


# ---------------------------------------------------------------------------
# Masking scope — per-agent
# ---------------------------------------------------------------------------

@router.post("/masking/scope/agent")
async def set_agent_override(body: AgentOverrideRequest, session: AdminSession):
    state = backoffice_state
    state.audit_writer._masking_scope.agent_overrides[body.agent_id] = body.mask
    state.audit_writer.write(_masking_config_event(
        session.account_id,
        f"masking.agent.{body.agent_id}",
        "",
        str(body.mask),
    ))
    return {"status": "ok"}


@router.delete("/masking/scope/agent/{agent_id}")
async def remove_agent_override(agent_id: str, session: AdminSession):
    state = backoffice_state
    removed = state.audit_writer._masking_scope.agent_overrides.pop(agent_id, None)
    if removed is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail={"error": "override_not_found"})
    state.audit_writer.write(_masking_config_event(
        session.account_id, f"masking.agent.{agent_id}", str(removed), "removed"
    ))
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Masking scope — per-user
# ---------------------------------------------------------------------------

@router.post("/masking/scope/user")
async def set_user_override(body: UserOverrideRequest, session: AdminSession):
    state = backoffice_state
    state.audit_writer._masking_scope.user_overrides[body.user_handle] = body.mask
    state.audit_writer.write(_masking_config_event(
        session.account_id,
        f"masking.user.{body.user_handle}",
        "",
        str(body.mask),
    ))
    return {"status": "ok"}


@router.delete("/masking/scope/user/{handle}")
async def remove_user_override(handle: str, session: AdminSession):
    state = backoffice_state
    removed = state.audit_writer._masking_scope.user_overrides.pop(handle, None)
    if removed is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail={"error": "override_not_found"})
    state.audit_writer.write(_masking_config_event(
        session.account_id, f"masking.user.{handle}", str(removed), "removed"
    ))
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Masking scope — per-component
# ---------------------------------------------------------------------------

@router.post("/masking/scope/component")
async def set_component_override(body: ComponentOverrideRequest, session: AdminSession):
    state = backoffice_state
    state.audit_writer._masking_scope.component_overrides[body.component] = body.mask
    state.audit_writer.write(_masking_config_event(
        session.account_id,
        f"masking.component.{body.component}",
        "",
        str(body.mask),
    ))
    return {"status": "ok"}


@router.delete("/masking/scope/component/{component}")
async def remove_component_override(component: str, session: AdminSession):
    state = backoffice_state
    removed = state.audit_writer._masking_scope.component_overrides.pop(component, None)
    if removed is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail={"error": "override_not_found"})
    state.audit_writer.write(_masking_config_event(
        session.account_id, f"masking.component.{component}", str(removed), "removed"
    ))
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# SIEM targets
# ---------------------------------------------------------------------------

@router.get("/siem")
async def list_siem_targets(session: AdminSession):
    state = backoffice_state
    targets = [
        {
            "name": t.name,
            "target_type": t.target_type,
            "url": t.url,
            "auth_header": t.auth_header,
            # auth_value never returned
            "enabled": t.enabled,
        }
        for t in state.audit_writer._siem_targets
    ]
    return {"siem_targets": targets, "total": len(targets)}


@router.post("/siem")
async def add_siem_target(body: SiemTargetRequest, session: AdminSession):
    from yashigani.audit.writer import SiemTarget

    state = backoffice_state

    existing_names = {t.name for t in state.audit_writer._siem_targets}
    if body.name in existing_names:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "siem_target_name_taken"},
        )

    target = SiemTarget(
        name=body.name,
        target_type=body.target_type,
        url=body.url,
        auth_header=body.auth_header,
        auth_value=body.auth_value,
        enabled=body.enabled,
    )
    state.audit_writer.add_siem_target(target)

    state.audit_writer.write(_config_event(
        session.account_id, "siem_target_added", "", body.name
    ))
    return {"status": "ok", "name": body.name}


@router.delete("/siem/{name}")
async def remove_siem_target(name: str, session: AdminSession):
    state = backoffice_state
    targets = state.audit_writer._siem_targets
    idx = next((i for i, t in enumerate(targets) if t.name == name), None)
    if idx is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail={"error": "siem_target_not_found"})

    targets.pop(idx)
    state.audit_writer.write(_config_event(
        session.account_id, "siem_target_removed", name, ""
    ))
    return {"status": "ok"}


@router.post("/siem/{name}/test")
async def test_siem_target(name: str, session: AdminSession):
    """Send a synthetic test event to the named SIEM target."""
    import json, datetime, urllib.request, urllib.error

    state = backoffice_state
    targets = state.audit_writer._siem_targets
    target = next((t for t in targets if t.name == name), None)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail={"error": "siem_target_not_found"})

    test_payload = json.dumps({
        "event_type": "SIEM_CONNECTION_TEST",
        "timestamp": datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
        "source": "yashigani_backoffice",
        "target_name": name,
    })

    body_str, content_type = state.audit_writer._format_for_target(test_payload, target)

    req = urllib.request.Request(
        url=target.url,
        data=body_str.encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": content_type,
            target.auth_header: target.auth_value,
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            http_status = resp.status
    except urllib.error.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "siem_test_failed", "http_status": exc.code, "message": str(exc)},
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "siem_test_failed", "message": str(exc)},
        )

    state.audit_writer.write(_config_event(
        session.account_id, "siem_connection_test", name, f"http_{http_status}"
    ))
    return {"status": "ok", "http_status": http_status}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _config_event(admin_id: str, setting: str, prev: str, new: str):
    from yashigani.audit.schema import ConfigChangedEvent
    return ConfigChangedEvent(
        account_tier="admin",
        admin_account=admin_id,
        setting=setting,
        previous_value=prev,
        new_value=new,
    )


def _masking_config_event(admin_id: str, setting: str, prev: str, new: str):
    from yashigani.audit.schema import MaskingConfigChangedEvent
    return MaskingConfigChangedEvent(
        account_tier="admin",
        admin_account=admin_id,
        change_target=setting,
        target_identifier="",
        previous_value=prev,
        new_value=new,
    )
