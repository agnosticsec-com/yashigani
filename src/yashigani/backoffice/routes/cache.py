"""Admin API for response cache configuration.

GET  /admin/cache                  — list all tenant configs
GET  /admin/cache/{tenant_id}      — get config for tenant
PUT  /admin/cache/{tenant_id}      — set config
DELETE /admin/cache/{tenant_id}    — invalidate all entries for tenant
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from yashigani.auth.session import require_admin_session

logger = logging.getLogger(__name__)
cache_router = APIRouter(tags=["cache"])

MAX_TTL = 3600


class CacheConfigRequest(BaseModel):
    enabled: bool = False
    ttl_seconds: int = Field(default=300, ge=1, le=MAX_TTL)


@cache_router.get("/admin/cache")
async def list_cache_configs(session=Depends(require_admin_session)):
    from yashigani.backoffice.state import backoffice_state
    rc = getattr(backoffice_state, "response_cache", None)
    if rc is None:
        return {"tenants": [], "cache_available": False}
    try:
        from yashigani.db.postgres import get_pool
        pool = get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT tenant_id::text, enabled, ttl_seconds FROM cache_config ORDER BY tenant_id"
            )
        return {"tenants": [dict(r) for r in rows], "cache_available": True}
    except Exception as exc:
        return {"tenants": [], "error": str(exc), "cache_available": True}


@cache_router.get("/admin/cache/{tenant_id}")
async def get_cache_config(tenant_id: str, session=Depends(require_admin_session)):
    from yashigani.backoffice.state import backoffice_state
    rc = getattr(backoffice_state, "response_cache", None)
    if rc is None:
        raise HTTPException(status_code=503, detail="Response cache not initialised")
    return rc.get_tenant_config(tenant_id)


@cache_router.put("/admin/cache/{tenant_id}")
async def set_cache_config(tenant_id: str, body: CacheConfigRequest, session=Depends(require_admin_session)):
    from yashigani.backoffice.state import backoffice_state
    rc = getattr(backoffice_state, "response_cache", None)
    if rc is None:
        raise HTTPException(status_code=503, detail="Response cache not initialised")
    rc.set_tenant_config(tenant_id, body.enabled, body.ttl_seconds)
    logger.info("Cache config updated: tenant=%s enabled=%s ttl=%ds", tenant_id, body.enabled, body.ttl_seconds)
    return {"status": "updated", "tenant_id": tenant_id, "enabled": body.enabled, "ttl_seconds": body.ttl_seconds}


@cache_router.delete("/admin/cache/{tenant_id}")
async def invalidate_cache(tenant_id: str, session=Depends(require_admin_session)):
    from yashigani.backoffice.state import backoffice_state
    rc = getattr(backoffice_state, "response_cache", None)
    if rc is None:
        raise HTTPException(status_code=503, detail="Response cache not initialised")
    count = rc.invalidate(tenant_id)
    logger.info("Cache invalidated: tenant=%s keys_deleted=%d", tenant_id, count)
    return {"status": "invalidated", "tenant_id": tenant_id, "keys_deleted": count}
