"""
Admin API for audit sink configuration.

GET  /admin/audit/sinks         — list all sinks + last write timestamp
GET  /admin/audit/siem          — get current SIEM config
PUT  /admin/audit/siem          — update SIEM config
POST /admin/audit/siem/test     — send a test event
DELETE /admin/audit/sinks/queue — drain the audit queue (admin flush)
"""
from __future__ import annotations

import logging
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, HttpUrl

from yashigani.auth.session import require_admin_session

logger = logging.getLogger(__name__)
audit_sinks_router = APIRouter(tags=["audit-sinks"])


class SiemConfigRequest(BaseModel):
    backend: Literal["none", "splunk", "elasticsearch", "wazuh"]
    endpoint: Optional[str] = None
    token_secret_key: Optional[str] = None  # KMS key name for token/API key
    wazuh_auto_deploy: Optional[bool] = False


class SiemConfigResponse(BaseModel):
    backend: str
    endpoint: Optional[str]
    wazuh_auto_deploy: bool


@audit_sinks_router.get("/admin/audit/sinks")
async def list_sinks(session=Depends(require_admin_session)):
    from yashigani.backoffice.state import backoffice_state
    audit_writer = backoffice_state.audit_writer
    if hasattr(audit_writer, "status"):
        status = await audit_writer.status()
    else:
        status = {"file": {"last_write": None}}
    return {"sinks": status}


@audit_sinks_router.get("/admin/audit/siem", response_model=SiemConfigResponse)
async def get_siem_config(session=Depends(require_admin_session)):
    from yashigani.backoffice.state import backoffice_state
    state = backoffice_state
    return SiemConfigResponse(
        backend=getattr(state, "siem_backend", "none"),
        endpoint=getattr(state, "siem_endpoint", None),
        wazuh_auto_deploy=getattr(state, "siem_wazuh_auto_deploy", False),
    )


@audit_sinks_router.put("/admin/audit/siem")
async def update_siem_config(
    body: SiemConfigRequest,
    session=Depends(require_admin_session),
):
    from yashigani.backoffice.state import backoffice_state

    if body.backend != "none" and not body.endpoint:
        raise HTTPException(status_code=422, detail="endpoint required for non-none backend")

    backoffice_state.siem_backend = body.backend
    backoffice_state.siem_endpoint = body.endpoint
    backoffice_state.siem_wazuh_auto_deploy = body.wazuh_auto_deploy or False

    logger.info(
        "SIEM config updated: backend=%s endpoint=%s auto_deploy=%s",
        body.backend, body.endpoint, body.wazuh_auto_deploy,
    )
    return {"status": "updated", "backend": body.backend}


@audit_sinks_router.post("/admin/audit/siem/test")
async def test_siem(session=Depends(require_admin_session)):
    from yashigani.backoffice.state import backoffice_state
    from yashigani.audit.sinks import SiemSink

    backend = getattr(backoffice_state, "siem_backend", "none")
    endpoint = getattr(backoffice_state, "siem_endpoint", None)

    if backend == "none" or not endpoint:
        raise HTTPException(status_code=400, detail="No SIEM backend configured")

    # Retrieve token from KMS
    token = ""
    kms = backoffice_state.kms_provider
    try:
        token = kms.get_secret(f"{backend}_api_key") or ""
    except Exception:
        pass

    sink = SiemSink(siem_type=backend, endpoint=endpoint, token=token)
    test_event = {
        "event_type": "SIEM_TEST",
        "action": "TEST",
        "tenant_id": "00000000-0000-0000-0000-000000000000",
        "message": "Yashigani SIEM connectivity test",
    }
    await sink.write(test_event)
    return {"status": "test_sent", "backend": backend}
