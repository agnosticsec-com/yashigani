"""
Yashigani Backoffice — Model & Alias management routes.

CRUD for model aliases and model allocation to users/groups/orgs.
  GET     /admin/models                  — List all model aliases
  POST    /admin/models                  — Create a model alias
  DELETE  /admin/models/{alias}          — Delete a model alias
  GET     /admin/models/available        — List models from Ollama
  GET     /admin/models/allocations      — List all model allocations
  POST    /admin/models/allocations      — Allocate a model to user/group/org
  DELETE  /admin/models/allocations/{id} — Remove an allocation
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession
from yashigani.backoffice.state import backoffice_state

logger = logging.getLogger(__name__)

router = APIRouter()


# ── In-memory stores (backed by Redis when available) ──────────────────────

_aliases: dict[str, dict] = {
    "fast": {"alias": "fast", "provider": "ollama", "model": "qwen2.5:3b", "force_local": True},
    "smart": {"alias": "smart", "provider": "anthropic", "model": "claude-sonnet-4-6", "force_local": False},
    "secure": {"alias": "secure", "provider": "ollama", "model": "qwen2.5:3b", "force_local": True},
}

_allocations: list[dict] = []
_alloc_counter = 0


# ── Request / Response models ─────────────────────────────────────────────

class AliasRequest(BaseModel):
    alias: str = Field(min_length=1, max_length=64)
    provider: str = Field(min_length=1, max_length=64)
    model: str = Field(min_length=1, max_length=128)
    force_local: bool = False


class AllocationRequest(BaseModel):
    model_alias: str = Field(min_length=1)
    target_type: str = Field(pattern=r"^(user|group|org)$")
    target_id: str = Field(min_length=1)


# ── Endpoints ─────────────────────────────────────────────────────────────

@router.get("")
async def list_aliases(session: AdminSession):
    return {"aliases": list(_aliases.values())}


@router.post("", status_code=201)
async def create_alias(body: AliasRequest, session: AdminSession):
    if body.alias in _aliases:
        raise HTTPException(status_code=409, detail={"error": "alias_exists"})
    _aliases[body.alias] = {
        "alias": body.alias,
        "provider": body.provider,
        "model": body.model,
        "force_local": body.force_local,
    }
    return {"status": "ok", "alias": body.alias}


@router.delete("/{alias}")
async def delete_alias(alias: str, session: AdminSession):
    if alias not in _aliases:
        raise HTTPException(status_code=404, detail={"error": "alias_not_found"})
    del _aliases[alias]
    return {"status": "ok"}


@router.get("/available")
async def list_available_models(session: AdminSession):
    """List models available from Ollama."""
    pipeline = backoffice_state.inspection_pipeline
    if pipeline is None:
        return {"models": []}
    try:
        import httpx
        ollama_url = getattr(pipeline, '_classifier', None)
        base_url = "http://ollama:11434"
        if ollama_url and hasattr(ollama_url, '_ollama_base_url'):
            base_url = ollama_url._ollama_base_url
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{base_url}/api/tags")
            if resp.status_code == 200:
                data = resp.json()
                return {"models": data.get("models", [])}
    except Exception as exc:
        logger.warning("Failed to list Ollama models: %s", exc)
    return {"models": []}


@router.get("/allocations")
async def list_allocations(session: AdminSession):
    return {"allocations": _allocations}


@router.post("/allocations", status_code=201)
async def create_allocation(body: AllocationRequest, session: AdminSession):
    global _alloc_counter
    if body.model_alias not in _aliases:
        raise HTTPException(status_code=404, detail={"error": "alias_not_found"})
    _alloc_counter += 1
    alloc = {
        "id": str(_alloc_counter),
        "model_alias": body.model_alias,
        "target_type": body.target_type,
        "target_id": body.target_id,
    }
    _allocations.append(alloc)
    return {"status": "ok", "allocation": alloc}


@router.delete("/allocations/{alloc_id}")
async def delete_allocation(alloc_id: str, session: AdminSession):
    global _allocations
    before = len(_allocations)
    _allocations = [a for a in _allocations if a["id"] != alloc_id]
    if len(_allocations) == before:
        raise HTTPException(status_code=404, detail={"error": "allocation_not_found"})
    return {"status": "ok"}
