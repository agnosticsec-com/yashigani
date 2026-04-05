"""
Yashigani Gateway — OpenAI-compatible API router (/v1/*).

Provides /v1/chat/completions and /v1/models endpoints that Open WebUI
and other OpenAI-compatible clients can use. All requests go through the
full Yashigani pipeline: identity resolution, sensitivity scan, complexity
scoring, budget enforcement, OE routing, and audit.

v1.0: Buffered responses only (Decision 13). Full response collected
before delivery to enable response inspection and token counting.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Optional

from fastapi import APIRouter, Request, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["openai-compat"])


# ── Request/Response Models ──────────────────────────────────────────────


class ChatMessage(BaseModel):
    role: str = Field(description="Role: system, user, assistant")
    content: str = Field(description="Message content")
    name: Optional[str] = None


class ChatCompletionRequest(BaseModel):
    model: str = Field(description="Model name or alias")
    messages: list[ChatMessage]
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    top_p: Optional[float] = None
    stream: bool = False
    # Yashigani extensions
    force_local: Optional[bool] = None
    force_cloud: Optional[bool] = None


class ChatCompletionChoice(BaseModel):
    index: int = 0
    message: ChatMessage
    finish_reason: str = "stop"


class CompletionUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ChatCompletionResponse(BaseModel):
    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: list[ChatCompletionChoice]
    usage: CompletionUsage


class ModelInfo(BaseModel):
    id: str
    object: str = "model"
    created: int = 0
    owned_by: str = "yashigani"


class ModelListResponse(BaseModel):
    object: str = "list"
    data: list[ModelInfo]


# ── State (injected at startup) ─────────────────────────────────────────

class OpenAIRouterState:
    """Mutable state injected by the gateway entrypoint at startup."""

    def __init__(self):
        self.identity_registry = None
        self.sensitivity_classifier = None
        self.complexity_scorer = None
        self.budget_enforcer = None
        self.token_counter = None
        self.audit_writer = None
        self.optimization_engine = None
        self.ollama_url: str = "http://ollama:11434"
        self.default_model: str = "qwen2.5:3b"
        self.available_models: list[dict] = []
        self.agent_registry = None
        self.response_inspection_pipeline = None
        self.ddos_protector = None  # v2.2 — DDoSProtector | None


_state = OpenAIRouterState()


def configure(
    identity_registry=None,
    sensitivity_classifier=None,
    complexity_scorer=None,
    budget_enforcer=None,
    token_counter=None,
    optimization_engine=None,
    audit_writer=None,
    ollama_url: str = "http://ollama:11434",
    default_model: str = "qwen2.5:3b",
    available_models: list[dict] | None = None,
    agent_registry=None,
    response_inspection_pipeline=None,
    ddos_protector=None,  # v2.2 — DDoSProtector | None
) -> None:
    """Configure the OpenAI router with dependencies. Called once at startup."""
    _state.identity_registry = identity_registry
    _state.sensitivity_classifier = sensitivity_classifier
    _state.complexity_scorer = complexity_scorer
    _state.budget_enforcer = budget_enforcer
    _state.token_counter = token_counter
    _state.optimization_engine = optimization_engine
    _state.audit_writer = audit_writer
    _state.ollama_url = ollama_url
    _state.default_model = default_model
    _state.available_models = available_models or []
    _state.agent_registry = agent_registry
    _state.response_inspection_pipeline = response_inspection_pipeline
    _state.ddos_protector = ddos_protector
    logger.info(
        "OpenAI router configured (default_model=%s, response_inspection=%s)",
        default_model,
        "enabled" if response_inspection_pipeline is not None else "disabled",
    )


# ── Endpoints ────────────────────────────────────────────────────────────


@router.post("/chat/completions", response_model=ChatCompletionResponse)
async def chat_completions(body: ChatCompletionRequest, request: Request):
    """
    OpenAI-compatible chat completions endpoint.

    Full pipeline:
    1. Identity resolution (API key or SSO headers)
    2. Sensitivity scan on input
    3. Complexity scoring
    4. Budget check
    5. Route to backend (local Ollama or cloud)
    6. Buffer full response
    7. Response inspection
    8. Token counting + budget recording
    9. Audit event
    10. Return response with budget headers
    """
    request_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
    start_time = time.time()

    # ── 0. DDoS protection — per-IP connection counting (v2.2) ───────────
    if _state.ddos_protector is not None:
        _client_ip = (
            request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or (request.client.host if request.client else "unknown")
        )
        _state.ddos_protector.record(_client_ip, "/v1/chat/completions")
        if not _state.ddos_protector.check(_client_ip, "/v1/chat/completions"):
            logger.warning(
                "DDoS threshold exceeded for ip=%s request_id=%s (openai router)",
                _client_ip,
                request_id,
            )
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "CONNECTION_LIMIT_EXCEEDED",
                    "detail": "Too many requests from this IP address.",
                    "request_id": request_id,
                },
            )

    # ── 1. Identity resolution ────────────────────────────────────────
    identity = _resolve_identity(request)
    identity_id = identity.get("identity_id", "anonymous") if identity else "anonymous"

    # ── 2. Extract prompt text for classification ─────────────────────
    prompt_text = "\n".join(m.content for m in body.messages if m.content)

    # ── 3. Sensitivity scan ───────────────────────────────────────────
    sensitivity_level = "PUBLIC"
    sensitivity_triggers = []
    s_result = None
    if _state.sensitivity_classifier:
        s_result = _state.sensitivity_classifier.classify(prompt_text)
        sensitivity_level = s_result.level.value
        sensitivity_triggers = s_result.triggers
    if s_result is None:
        from yashigani.optimization.sensitivity_classifier import SensitivityLevel, SensitivityResult
        s_result = SensitivityResult(level=SensitivityLevel.PUBLIC)

    # ── 4. Complexity scoring ─────────────────────────────────────────
    complexity_level = "MEDIUM"
    token_estimate = len(prompt_text) // 4
    c_result = None
    if _state.complexity_scorer:
        c_result = _state.complexity_scorer.score(prompt_text, token_estimate)
        complexity_level = c_result.level.value
    if c_result is None:
        from yashigani.optimization.complexity_scorer import ComplexityLevel, ComplexityResult
        c_result = ComplexityResult(level=ComplexityLevel.MEDIUM, token_count=token_estimate, heuristic_score=0.0, reasons=[])

    # ── 5. Budget check ───────────────────────────────────────────────
    budget_signal = "normal"
    budget_pct = 0
    budget_used = 0
    budget_total = 0
    if _state.budget_enforcer and identity:
        from yashigani.billing.budget_enforcer import BudgetState
        budget_state = _state.budget_enforcer.check(
            identity_id, "cloud", budget_total=10000,  # TODO: read from identity's budget allocation
        )
        budget_signal = budget_state.signal.value
        budget_pct = budget_state.pct
        budget_used = budget_state.used
        budget_total = budget_state.total
    else:
        from yashigani.billing.budget_enforcer import BudgetSignal, BudgetState
        budget_state = BudgetState(identity_id=identity_id, provider="cloud", used=0, total=0, signal=BudgetSignal.NORMAL, pct=0)

    # ── 6. Route decision ──────────────────────────────────────────────
    selected_model = body.model or _state.default_model

    # Agent routing: if model starts with @, forward to the agent's upstream
    is_agent_call = selected_model.startswith("@")
    agent_upstream = None
    if is_agent_call and _state.agent_registry:
        agent_name = selected_model[1:]  # strip @
        for agent in _state.agent_registry.list_all():
            if agent.get("name") == agent_name and agent.get("status") == "active":
                agent_upstream = agent.get("upstream_url")
                break

    if _state.optimization_engine and _state.sensitivity_classifier and _state.complexity_scorer and not is_agent_call:
        decision = _state.optimization_engine.route(
            requested_model=selected_model,
            sensitivity=s_result,
            complexity=c_result,
            budget=budget_state,
            force_local=body.force_local or False,
            force_cloud=body.force_cloud or False,
        )
        selected_provider = decision.provider
        selected_model = decision.model
        route_reason = f"{decision.rule}:{decision.reason}"
    else:
        # Fallback: simplified routing if OE not available
        selected_provider = "ollama"
        route_reason = "fallback_local"
        if sensitivity_level in ("CONFIDENTIAL", "RESTRICTED"):
            route_reason = "sensitivity_local"

    # ── 7. Forward to backend (buffered) ──────────────────────────────
    try:
        import httpx

        if is_agent_call and agent_upstream:
            # Route to agent's upstream URL (OpenAI-compatible /v1/chat/completions)
            agent_body = {
                "model": _state.default_model,
                "messages": [{"role": m.role, "content": m.content} for m in body.messages],
                "stream": False,
            }
            if body.temperature is not None:
                agent_body["temperature"] = body.temperature

            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(
                    f"{agent_upstream}/v1/chat/completions",
                    json=agent_body,
                )

            if resp.status_code != 200:
                # Fall back to direct Ollama if agent fails
                logger.warning("Agent %s returned %d, falling back to Ollama", selected_model, resp.status_code)
                agent_upstream = None  # trigger Ollama fallback below
            else:
                agent_resp = resp.json()
                choices = agent_resp.get("choices", [])
                assistant_content = choices[0].get("message", {}).get("content", "") if choices else ""
                backend_body = agent_resp
                route_reason = f"agent:{selected_model[1:]}"

        if not is_agent_call or agent_upstream is None:
            # Standard Ollama routing
            ollama_body = {
                "model": selected_model if not is_agent_call else _state.default_model,
                "messages": [{"role": m.role, "content": m.content} for m in body.messages],
                "stream": False,
            }
            if body.temperature is not None:
                ollama_body["temperature"] = body.temperature

            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(
                    f"{_state.ollama_url}/api/chat",
                    json=ollama_body,
                )

            if resp.status_code != 200:
                raise HTTPException(
                    status_code=resp.status_code,
                    detail=f"Backend error: {resp.text[:200]}",
                )

            backend_body = resp.json()
            assistant_content = backend_body.get("message", {}).get("content", "")

    except httpx.ConnectError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Local model unavailable. Ollama may be starting up.",
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Backend call failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Backend communication error",
        )

    # ── 7b. Response inspection ───────────────────────────────────────
    # Inspect assistant_content as plain text — we care about what the model
    # *said*, not the JSON envelope wrapping it. Using "text/plain" ensures
    # the exempt_content_types list cannot inadvertently skip this check.
    response_verdict = "clean"
    if _state.response_inspection_pipeline is not None and assistant_content:
        try:
            # session_id and agent_id are best-effort from identity; fall back
            # to request_id so the audit event is always correlated.
            resp_session_id = identity.get("identity_id", request_id) if identity else request_id
            resp_agent_id = identity.get("slug", "openai-router") if identity else "openai-router"

            resp_result = _state.response_inspection_pipeline.inspect(
                response_body=assistant_content,
                content_type="text/plain",
                request_id=request_id,
                session_id=resp_session_id,
                agent_id=resp_agent_id,
            )
            if not resp_result.skipped:
                response_verdict = resp_result.verdict.lower()

            if resp_result.verdict == "BLOCKED":
                logger.warning(
                    "Response inspection BLOCKED for request_id=%s confidence=%.2f",
                    request_id,
                    resp_result.confidence,
                )
                # Write audit event for the block
                if _state.audit_writer:
                    try:
                        _state.audit_writer(
                            "RESPONSE_INJECTION_DETECTED",
                            resp_result.audit_fields,
                        )
                    except Exception as _exc:
                        logger.warning("Audit write failed for response block: %s", _exc)
                # Do NOT suppress the response — the content is already generated
                # and withholding it creates a confusing UX (empty assistant turn).
                # The BLOCKED verdict is surfaced via header so downstream
                # systems (e.g. Open WebUI plugins) can act on it.
        except Exception as exc:
            logger.warning("Response inspection raised unexpectedly: %s", exc)

    # ── 8. Token counting + budget recording ─────────────────────────
    input_tokens = backend_body.get("prompt_eval_count", token_estimate)
    output_tokens = backend_body.get("eval_count", len(assistant_content) // 4)
    total_tokens = input_tokens + output_tokens

    # Record token usage in budget system
    if _state.budget_enforcer and selected_provider != "ollama":
        try:
            _state.budget_enforcer.record(
                identity_id=identity_id,
                provider=selected_provider,
                tokens=total_tokens,
            )
        except Exception as exc:
            logger.warning("Budget recording failed: %s", exc)

    # ── 9. Build response ─────────────────────────────────────────────
    elapsed_ms = int((time.time() - start_time) * 1000)

    response = ChatCompletionResponse(
        id=request_id,
        created=int(time.time()),
        model=selected_model,
        choices=[
            ChatCompletionChoice(
                message=ChatMessage(role="assistant", content=assistant_content),
            )
        ],
        usage=CompletionUsage(
            prompt_tokens=input_tokens,
            completion_tokens=output_tokens,
            total_tokens=total_tokens,
        ),
    )

    # ── 10. Return with budget headers ────────────────────────────────
    headers = {
        "X-Yashigani-Request-Id": request_id,
        "X-Yashigani-Routed-Via": selected_provider,
        "X-Yashigani-Route-Reason": route_reason.encode("ascii", "replace").decode("ascii"),
        "X-Yashigani-Model": selected_model,
        "X-Yashigani-Sensitivity": sensitivity_level,
        "X-Yashigani-Complexity": complexity_level,
        "X-Yashigani-Elapsed-Ms": str(elapsed_ms),
        "X-Yashigani-Response-Verdict": response_verdict,
    }
    if budget_total > 0:
        headers["X-Yashigani-Budget-Used"] = str(budget_used)
        headers["X-Yashigani-Budget-Total"] = str(budget_total)
        headers["X-Yashigani-Budget-Pct"] = str(budget_pct)

    return JSONResponse(
        content=response.model_dump(),
        headers=headers,
    )


@router.get("/models", response_model=ModelListResponse)
async def list_models(request: Request):
    """List available models (for Open WebUI model picker)."""
    models = []

    # Add local Ollama models
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{_state.ollama_url}/api/tags")
            if resp.status_code == 200:
                for m in resp.json().get("models", []):
                    models.append(ModelInfo(
                        id=m.get("name", ""),
                        created=0,
                        owned_by="ollama (local)",
                    ))
    except Exception as exc:
        logger.warning("Failed to fetch Ollama models: %s", exc)

    # Add configured service identities as "models" (for @mention invocation)
    if _state.identity_registry:
        from yashigani.identity import IdentityKind
        for svc in _state.identity_registry.list_active(kind=IdentityKind.SERVICE):
            models.append(ModelInfo(
                id=f"@{svc['slug']}",
                created=0,
                owned_by=f"yashigani ({svc['name']})",
            ))

    # Add registered agents as selectable models (for @agent invocation in Open WebUI)
    if _state.agent_registry:
        try:
            for agent in _state.agent_registry.list_all():
                if agent.get("status") == "active":
                    agent_name = agent.get("name", "")
                    models.append(ModelInfo(
                        id=f"@{agent_name}",
                        created=0,
                        owned_by=f"yashigani-agent ({agent_name})",
                    ))
        except Exception as exc:
            logger.warning("Failed to list agents for models: %s", exc)

    # Add any statically configured models
    for m in _state.available_models:
        models.append(ModelInfo(
            id=m.get("id", ""),
            created=0,
            owned_by=m.get("provider", "yashigani"),
        ))

    return ModelListResponse(data=models)


# ── Helpers ──────────────────────────────────────────────────────────────


def _resolve_identity(request: Request) -> Optional[dict]:
    """
    Resolve identity from request.

    Priority:
    1. X-Forwarded-User header (SSO via Caddy)
    2. Authorization: Bearer <api_key>
    """
    if not _state.identity_registry:
        return None

    # SSO headers (from Caddy)
    forwarded_user = request.headers.get("X-Forwarded-User")
    if forwarded_user:
        identity = _state.identity_registry.get_by_slug(forwarded_user)
        if identity:
            return identity

    # API key
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        key = auth[7:]
        if key and key != "yashigani-internal":
            return _state.identity_registry.get_by_api_key(key)

    return None
