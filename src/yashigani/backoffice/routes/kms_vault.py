"""Admin API for Vault KMS status and secret listing.

Last updated: 2026-05-03
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException

from yashigani.backoffice.middleware import require_admin_session
from yashigani.common.error_envelope import safe_error_envelope

logger = logging.getLogger(__name__)
kms_vault_router = APIRouter(tags=["kms-vault"])


@kms_vault_router.get("/admin/kms/vault/status")
async def vault_status(session=Depends(require_admin_session)):
    from yashigani.backoffice.state import backoffice_state
    kms = backoffice_state.kms_provider
    if not hasattr(kms, "health"):
        raise HTTPException(status_code=400, detail="Active KMS provider is not Vault")
    return kms.health()


@kms_vault_router.get("/admin/kms/vault/secrets")
async def vault_list_secrets(session=Depends(require_admin_session)):
    from yashigani.backoffice.state import backoffice_state
    kms = backoffice_state.kms_provider
    if not hasattr(kms, "list_secrets"):
        raise HTTPException(status_code=400, detail="Active KMS provider is not Vault")
    try:
        keys = kms.list_secrets()
        return {"keys": keys, "count": len(keys)}
    except Exception as exc:
        payload, _ = safe_error_envelope(exc, public_message="kms vault unavailable", status=500)
        raise HTTPException(status_code=500, detail=payload)
