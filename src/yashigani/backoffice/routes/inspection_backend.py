"""
Yashigani Backoffice — Inspection backend management routes.

Provides hot-swap capability for the active inspection backend
without service restart. All changes are persisted to Redis and
written to the audit log.

Routes:
  GET  /admin/inspection/backend                       — current backend status
  PUT  /admin/inspection/backend                       — hot-swap active backend
  GET  /admin/inspection/backend/{backend_name}/health — health check
  POST /admin/inspection/backend/{backend_name}/test   — test classification

Security constraints:
  - LM Studio is NOT supported in production (YASHIGANI_ENV=production → HTTP 422).
  - API keys are NEVER accepted in request bodies — they come from KMS only.
  - Azure endpoint must use https:// (HTTP 422 otherwise).
  - All config changes write an INSPECTION_BACKEND_CHANGED audit event.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import require_admin_session, AdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.inspection.backend_base import ClassifierBackend, BackendUnavailableError

logger = logging.getLogger(__name__)

router = APIRouter()

_TEST_CONTENT = "Hello, please tell me about the weather."

_SUPPORTED_BACKENDS = frozenset({
    "ollama", "lmstudio", "anthropic", "azure_openai", "gemini",
})

_PRODUCTION_BLOCKED_BACKENDS = frozenset({"lmstudio"})


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class BackendConfigRequest(BaseModel):
    """
    Non-secret backend configuration fields.
    Never include API keys, secrets, or passwords here — those come from KMS.
    """
    base_url: Optional[str] = Field(default=None, description="Base URL for local backends")
    model: Optional[str] = Field(default=None, description="Model name/identifier")
    timeout_seconds: Optional[int] = Field(default=None, ge=1, le=300)
    max_tokens: Optional[int] = Field(default=None, ge=1, le=4096)
    # Azure-specific (non-secret)
    azure_endpoint: Optional[str] = Field(default=None, description="Azure OpenAI endpoint (must be https://)")
    deployment_name: Optional[str] = Field(default=None)
    api_version: Optional[str] = Field(default=None)
    # KMS key reference (name only — never the key value)
    kms_key: Optional[str] = Field(default=None, description="KMS key name for API key retrieval")


class BackendSwapRequest(BaseModel):
    active_backend: str = Field(description="Backend name to activate")
    fallback_chain: Optional[list[str]] = Field(
        default=None,
        description="Ordered fallback backend names. 'fail_closed' terminates the chain.",
    )
    config: Optional[BackendConfigRequest] = Field(
        default=None,
        description="Non-secret backend configuration. API keys come from KMS only.",
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_registry():
    reg = backoffice_state.backend_registry
    if reg is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "backend_registry_not_configured"},
        )
    return reg


def _get_config_store():
    store = backoffice_state.backend_config_store
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "backend_config_store_not_configured"},
        )
    return store


def _is_production() -> bool:
    return os.getenv("YASHIGANI_ENV", "development").lower() == "production"


def _validate_backend_name(name: str) -> None:
    if name not in _SUPPORTED_BACKENDS and name != "fail_closed":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": f"unknown_backend: {name!r}. Supported: {sorted(_SUPPORTED_BACKENDS)}"},
        )


def _validate_production_guard(backend_name: str) -> None:
    if _is_production() and backend_name in _PRODUCTION_BLOCKED_BACKENDS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": f"{backend_name}_not_supported_in_production"},
        )


def _validate_azure_endpoint(endpoint: Optional[str]) -> None:
    if endpoint is not None and not endpoint.startswith("https://"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "azure_endpoint_must_use_https"},
        )


def _build_backend(backend_name: str, config: dict, kms_provider) -> ClassifierBackend:
    """Instantiate a backend from its name and non-secret config dict."""
    from yashigani.inspection.backends.ollama import OllamaBackend

    if backend_name == "ollama":
        return OllamaBackend(
            base_url=config.get("base_url", "http://ollama:11434"),
            model=config.get("model", "qwen2.5:3b"),
            timeout_seconds=int(config.get("timeout_seconds", 30)),
        )
    elif backend_name == "lmstudio":
        from yashigani.inspection.backends.lmstudio import LMStudioBackend
        return LMStudioBackend(
            base_url=config.get("base_url", "http://localhost:1234"),
            model=config.get("model", "qwen2.5-3b-instruct"),
            timeout_seconds=int(config.get("timeout_seconds", 30)),
        )
    elif backend_name == "anthropic":
        from yashigani.inspection.backends.anthropic import AnthropicBackend
        return AnthropicBackend(
            kms_provider=kms_provider,
            kms_key=config.get("kms_key", "anthropic_api_key"),
            model=config.get("model", "claude-haiku-4-5"),
            timeout_seconds=int(config.get("timeout_seconds", 15)),
            max_tokens=int(config.get("max_tokens", 256)),
        )
    elif backend_name == "azure_openai":
        from yashigani.inspection.backends.azure_openai import AzureOpenAIBackend
        azure_endpoint = config.get("azure_endpoint")
        if not azure_endpoint:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"error": "azure_endpoint_required_for_azure_openai_backend"},
            )
        return AzureOpenAIBackend(
            kms_provider=kms_provider,
            azure_endpoint=azure_endpoint,
            deployment_name=config.get("deployment_name", "gpt-4o-mini"),
            api_version=config.get("api_version", "2024-02-01"),
            kms_key=config.get("kms_key", "azure_openai_key"),
            timeout_seconds=int(config.get("timeout_seconds", 15)),
            max_tokens=int(config.get("max_tokens", 256)),
        )
    elif backend_name == "gemini":
        from yashigani.inspection.backends.gemini import GeminiBackend
        return GeminiBackend(
            kms_provider=kms_provider,
            kms_key=config.get("kms_key", "gemini_api_key"),
            model=config.get("model", "gemini-1.5-flash"),
            timeout_seconds=int(config.get("timeout_seconds", 15)),
            max_tokens=int(config.get("max_tokens", 256)),
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": f"unknown_backend: {backend_name!r}"},
        )


def _config_request_to_dict(config: Optional[BackendConfigRequest]) -> dict:
    if config is None:
        return {}
    return {k: v for k, v in config.model_dump().items() if v is not None}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/backend")
async def get_active_backend(session: AdminSession = require_admin_session):
    """Return the active backend name, config (no secrets), fallback chain, and health."""
    registry = _get_registry()

    active_name = registry.get_active_backend_name()
    fallback_chain = registry.get_fallback_chain()
    health = registry.health_status()

    # Load stored config for current active backend (no secrets)
    stored_config = {}
    try:
        config_store = backoffice_state.backend_config_store
        if config_store is not None:
            stored_config = config_store.get_backend_config(active_name)
    except Exception as exc:
        logger.debug("get_active_backend: config store read failed: %s", exc)

    return {
        "active_backend": active_name,
        "fallback_chain": fallback_chain,
        "config": stored_config,
        "health": health,
    }


@router.put("/backend")
async def swap_backend(
    body: BackendSwapRequest,
    session: AdminSession = require_admin_session,
):
    """
    Hot-swap the active inspection backend.
    Validates config, instantiates the new backend, calls BackendRegistry.swap(),
    persists to Redis, and writes an INSPECTION_BACKEND_CHANGED audit event.

    API keys are NOT accepted in this request body — they come from KMS only.
    """
    _validate_backend_name(body.active_backend)
    _validate_production_guard(body.active_backend)

    config_dict = _config_request_to_dict(body.config)

    # Azure endpoint must use https
    _validate_azure_endpoint(config_dict.get("azure_endpoint"))

    registry = _get_registry()
    kms_provider = backoffice_state.kms_provider
    audit = backoffice_state.audit_writer

    previous_backend = registry.get_active_backend_name()

    # Instantiate the new backend
    try:
        new_backend = _build_backend(body.active_backend, config_dict, kms_provider)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("swap_backend: failed to instantiate %s: %s", body.active_backend, exc)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": f"backend_instantiation_failed: {exc}"},
        )

    # Determine fallback chain
    new_chain = body.fallback_chain
    if new_chain is None:
        new_chain = registry.get_fallback_chain()

    # Thread-safe swap
    registry.swap(new_backend, new_chain)

    # Register the new backend in all_backends so fallback works
    with registry._lock:
        registry._all_backends[body.active_backend] = new_backend

    # Persist to Redis
    try:
        config_store = _get_config_store()
        config_store.set_active(body.active_backend)
        config_store.set_fallback_chain(new_chain)
        if config_dict:
            config_store.set_backend_config(body.active_backend, config_dict)
    except Exception as exc:
        logger.error("swap_backend: Redis persist failed: %s", exc)
        # Non-fatal — swap already succeeded in-memory

    # Audit event
    if audit is not None:
        try:
            from yashigani.audit.schema import InspectionBackendChangedEvent
            audit.write(InspectionBackendChangedEvent(
                previous_backend=previous_backend,
                new_backend=body.active_backend,
                admin_account=session.account_id,
            ))
        except Exception as exc:
            logger.error("swap_backend: failed to write audit event: %s", exc)

    return {
        "active_backend": body.active_backend,
        "previous_backend": previous_backend,
        "fallback_chain": new_chain,
        "swapped": True,
    }


@router.get("/backend/{backend_name}/health")
async def get_backend_health(
    backend_name: str,
    session: AdminSession = require_admin_session,
):
    """Ping a specific backend and return its health status."""
    _validate_backend_name(backend_name)

    registry = _get_registry()
    with registry._lock:
        backend = registry._all_backends.get(backend_name)

    if backend is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": f"backend_not_registered: {backend_name!r}"},
        )

    healthy = False
    try:
        healthy = backend.health_check()
    except Exception as exc:
        logger.debug("get_backend_health: health_check raised for %s: %s", backend_name, exc)

    return {
        "backend": backend_name,
        "healthy": healthy,
    }


@router.post("/backend/{backend_name}/test")
async def test_backend(
    backend_name: str,
    session: AdminSession = require_admin_session,
):
    """
    Run a test classification against a registered backend.
    Uses a safe, benign test string — never user-provided content.
    """
    _validate_backend_name(backend_name)

    registry = _get_registry()
    with registry._lock:
        backend = registry._all_backends.get(backend_name)

    if backend is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": f"backend_not_registered: {backend_name!r}"},
        )

    try:
        result = backend.classify(_TEST_CONTENT)
        return {
            "backend": backend_name,
            "label": result.label,
            "confidence": result.confidence,
            "latency_ms": result.latency_ms,
            "test_content": _TEST_CONTENT,
        }
    except BackendUnavailableError as exc:
        return {
            "backend": backend_name,
            "error": str(exc),
            "available": False,
            "test_content": _TEST_CONTENT,
        }
    except Exception as exc:
        logger.error("test_backend: unexpected error for %s: %s", backend_name, exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": f"test_failed: {exc}"},
        )
