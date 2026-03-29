# Yashigani v0.3.0 — Implementation Plan

> **Archived — COMPLETE.** Current release: **v0.7.1** (2026-03-28).

**Version:** 0.3.0
**Plan date:** 2026-03-26
**Author:** Maxine (PM/PO)
**Status:** Draft — awaiting product owner approval before implementation begins
**Security baseline:** OWASP ASVS v5 (continued from v0.2.0)

---

## 1. Executive Summary

v0.3.0 adds two structural capabilities to Yashigani: a routed intra-agent communication layer and a pluggable multi-model inspection backend.

**Intra-Agent Communication** gives registered agents the ability to call each other over the internal Docker network while passing through the same enforcement stack — rate limiting, OPA policy, inspection pipeline, RBAC allow-list — that applies to human traffic. This is not a peer-to-peer sidecar model; every agent-to-agent call transits the gateway, giving the admin full observability and enforcement authority over what agents can do to each other.

**Multi-Model Inspection Backend** removes the hard dependency on Ollama as the sole classifier. A pluggable backend registry allows the admin to configure Ollama, LM Studio, Anthropic Claude, Azure OpenAI, or Google Gemini as the active inspection engine, set a fallback chain, and hot-swap backends without restarting the gateway. All cloud credentials are stored in KMS. Fail-closed semantics are preserved: an unreachable backend produces a `PROMPT_INJECTION_ONLY` classification, never a pass-through.

Neither feature changes the existing enforcement contracts. The gateway remains the single enforcement point. OPA remains the sole policy decision maker. Redis remains the session and rate-limit store. All new state is namespaced to avoid collisions with v0.2.0 data.

---

## 2. Version Goals and Non-Goals

### 2.1 Goals

1. Agent-to-agent calls are routed through the gateway via URL-per-agent path prefix (no port proliferation).
2. Agent identity is established via a pre-shared token issued at registration, injected as an HTTP header by Caddy, and verified by the gateway before inspection.
3. RBAC applies to agent-to-agent calls: the calling agent's group membership is checked against the target agent's allowed caller groups.
4. Rate limiting applies to agent-to-agent calls using the calling agent's existing per-agent bucket.
5. The inspection backend is configurable at runtime via the backoffice without restarting any service.
6. Five backends are supported: Ollama, LM Studio, Anthropic Claude, Azure OpenAI, Gemini.
7. Cloud API keys are stored in KMS only; never in environment variables or config files.
8. Fail-closed: an unreachable backend emits `PROMPT_INJECTION_ONLY`, never `CLEAN`.
9. A fallback chain is configurable: if backend A is unreachable, try B, then C, then fail-closed.
10. All new behaviour is covered by new Prometheus metrics and audit event types.

### 2.2 Non-Goals

- Agent-to-agent calls bypassing the gateway (direct Docker internal calls between agent containers). Not supported; policy cannot be enforced on those paths.
- Running more than one active inspection backend simultaneously (ensemble voting). Deferred; adds cost and latency complexity.
- LLM fine-tuning or custom model training. Out of scope for Yashigani.
- mTLS between the gateway and agent upstreams. Deferred; Docker internal network isolation is the current control. Agent identity is token-based in this version.
- Kubernetes deployment manifests. Docker Compose remains the sole supported deployment target.
- SCIM 2.0 write-back to an external IdP. v0.2.0 scope; not changed here.
- Multi-tenant Yashigani instances with tenant isolation. Deferred.

---

## 3. Feature 1: Intra-Agent Communication

### 3.1 Architecture Decision: Option A vs Option B

#### Option A — Port-per-agent mapping

Each registered agent is assigned a unique port (e.g., agent ID `10` → host port `1010`). Caddy or the gateway listens on those ports and forwards to the correct upstream container.

**Analysis:**

- **Operational complexity.** Every new agent requires a firewall rule update, a new Docker port binding, a Caddyfile change, and a Compose service reload. At 20 agents this is manageable; at 200 it is unworkable. Port assignments must be tracked centrally to avoid collision.
- **Port exhaustion.** Ephemeral port range on Linux starts at 32768. Assigning dedicated ports in the 1000–9000 range caps agent count at roughly 8000 in theory, but practical Docker port binding overhead becomes significant well below that.
- **TLS certificates.** Each port served over TLS requires either a wildcard cert (acceptable) or a per-port SAN in the certificate (impractical). Wildcard certs on non-443 ports require Caddy to terminate TLS on each port, multiplying listener configuration.
- **Security surface.** N agents = N exposed ports on the Docker host (in any non-`internal` network mode). Each open port is an additional lateral movement target if the host is compromised. An attacker who bypasses Caddy on port 1010 reaches the raw gateway listener for agent 10.
- **Caddy compatibility.** Caddy supports per-port listening blocks natively, but dynamic addition of listeners at runtime requires a config reload or API push. The Caddy API supports this, but it is an additional external system interaction that requires admin approval under the HITL protocol.
- **Prometheus labelling.** Port number alone does not produce a human-readable `agent_id` label. Labels must be injected by Caddy or inferred from port mapping at scrape time — adds instrumentation complexity.
- **RBAC enforcement granularity.** Per-port routing gives no structural RBAC advantage over path-based routing; the gateway must still look up the agent mapping in both cases.
- **Verdict on Option A:** High operational cost, growing security surface, poor scalability, runtime Caddy config reload dependency. Not chosen.

#### Option B — URL-per-agent on port 443

All agent-to-agent calls use a single port (443 externally, 8080 gateway internally). Traffic is routed by path prefix: `https://{domain}/agents/{agent_id}/`. The gateway extracts the `agent_id` from the path and routes to the correct upstream.

**Analysis:**

- **Operational complexity.** Zero new ports, zero new firewall rules, zero new Caddy listeners. Registering a new agent adds a record to the agent registry (Redis) only. The gateway's routing table is read from Redis at request time.
- **TLS certificates.** Single wildcard or single-domain cert covers all agents. No change to TLS configuration per agent.
- **Security surface.** One port. Caddy is the sole TLS termination point. Internal traffic is over the Docker bridge. No new host-level exposure per agent.
- **Caddy compatibility.** A single Caddy upstream block `reverse_proxy /agents/* gateway:8080` covers all agent traffic. No per-agent Caddyfile changes required.
- **Compatibility with arbitrary MCP agent implementations.** Any MCP agent that can make an HTTP/HTTPS request to a URL can use a path-prefixed endpoint. Path-based routing is universally supported. Port-based routing requires that the agent's MCP client supports non-standard ports, which some implementations do not.
- **Prometheus labelling.** The path prefix contains the `agent_id` as a structured component. The gateway extracts it and applies it as a label to all metrics for that request. Clean, human-readable.
- **RBAC enforcement granularity.** The path prefix is the natural scope boundary. OPA input can carry `target_agent_id` extracted from the path, and the policy can check `calling_agent.groups` against `target_agent.allowed_caller_groups`.
- **Verdict on Option B:** Minimal operational overhead, single security perimeter, clean Prometheus labelling, universally compatible, scales to thousands of agents without infrastructure changes. Chosen.

### 3.2 Chosen Architecture: URL-per-agent on port 443

```
External caller / agent
        |
        | HTTPS :443  /agents/{target_agent_id}/{path...}
        v
+----------------------+
|   Caddy (TLS edge)   |
|  /agents/* → gateway |
+----------+-----------+
           |
           | HTTP :8080  /agents/{target_agent_id}/{path...}
           v
+----------+-----------+
|   Gateway middleware |
|  1. AgentAuthMiddleware  (verify caller identity token from X-Yashigani-Agent-Token)
|  2. RateLimiter          (calling agent's per-agent bucket)
|  3. InspectionPipeline   (LLM classifier — pluggable in v0.3.0)
|  4. OPA enforce          (RBAC: caller groups → target agent path allow-list)
|  5. AgentRouter          (look up target upstream URL from agent registry)
+----------+-----------+
           |
           | HTTP  to target agent upstream (configured at registration)
           v
   +-------+--------+
   | Target MCP     |
   | agent upstream |
   +----------------+
```

### 3.3 Agent Identity

**Mechanism: pre-shared bearer token (PSK), Caddy-forwarded.**

Rationale for PSK over mTLS at this stage: mTLS between agent containers and the gateway requires per-agent TLS client certificates, a local CA, certificate issuance at registration, and certificate rotation. This is the correct long-term approach and is targeted for v0.4.0. For v0.3.0, a 256-bit random token stored in Redis (agent registry) and issued at registration time provides strong enough identity assertion within the Docker internal network, where the attack surface for token theft is already controlled by Docker bridge isolation.

**Token lifecycle:**

1. Admin registers agent via `POST /admin/agents`. Gateway generates a 256-bit (32-byte) token using `secrets.token_bytes(32)`, hex-encoded to 64 characters.
2. Token is stored in Redis agent registry (see section 12) as a bcrypt hash (cost 12). The plaintext is returned once to the admin and never stored.
3. Calling agent includes the token as `Authorization: Bearer {token}` in its outbound request.
4. Caddy passes the header through unchanged (no stripping, no injection — token is validated by the gateway, not Caddy).
5. `AgentAuthMiddleware` hashes the incoming token and compares against the stored hash. On mismatch: HTTP 401, audit event `AGENT_AUTH_FAILED`, increment `yashigani_agent_auth_failures_total`.
6. On success: `agent_id` is resolved and attached to the request context. Downstream middleware uses `agent_id` from context, not from any user-supplied header.

**Why not header injection by Caddy:** Caddy injecting an `X-Agent-ID` header based on a route match would allow any caller who knows the path prefix to forge agent identity by routing through Caddy on the correct path without presenting a valid token. Token validation must happen at the gateway layer.

### 3.4 Gateway Routing: Agent-to-Agent vs User Traffic

The gateway differentiates agent traffic from user traffic by path prefix only:

- `POST /agents/{target_agent_id}/{remainder...}` — agent-to-agent path. `AgentAuthMiddleware` is active.
- All other paths — user/service traffic. Existing middleware stack unchanged.

The `AgentAuthMiddleware` runs first in the agent path middleware chain, before `RateLimiter`. This prevents unauthenticated requests from consuming rate-limit budget. Order:

```
AgentAuthMiddleware → RateLimiter → InspectionPipeline → OPAEnforce → AgentRouter
```

The `AgentRouter` reads the target agent's upstream URL from the Redis agent registry using `target_agent_id` extracted from the path. If the agent is not registered or is marked inactive, the router returns HTTP 404 before forwarding.

### 3.5 RBAC for Agent-to-Agent Calls

The OPA input document for agent-to-agent requests gains two new fields:

```json
{
  "request": {
    "method": "POST",
    "path": "/agents/42/tools/execute",
    "remainder_path": "/tools/execute"
  },
  "principal": {
    "type": "agent",
    "agent_id": "17",
    "groups": ["automation_agents", "read_only"]
  },
  "target_agent": {
    "agent_id": "42",
    "allowed_caller_groups": ["automation_agents"],
    "allowed_paths": ["/tools/execute", "/tools/list"]
  }
}
```

OPA rule logic (described, not implemented here):

1. Deny if `principal.type == "agent"` and `principal.groups` ∩ `target_agent.allowed_caller_groups` is empty.
2. Deny if `request.remainder_path` does not match any entry in `target_agent.allowed_paths` (prefix match).
3. Allow otherwise.

The RBAC store (Redis db/3) is extended with an agent permissions document pushed to OPA via the existing `opa_push.py` mechanism.

### 3.6 Rate Limiting for Agent-to-Agent Calls

No new rate-limit dimension is introduced. The calling agent's per-agent bucket (keyed by `agent_id` in Redis db/2) is consumed for agent-to-agent calls identically to user calls. This prevents an agent from consuming its entire rate budget through intra-agent calls while also serving user traffic — both count against the same bucket.

The `RateLimiter` reads the `agent_id` from the request context (set by `AgentAuthMiddleware`). No change to rate-limit logic is required beyond ensuring the middleware chain sets context before the rate limiter runs.

### 3.7 New OPA Input Fields

| Field | Type | Description |
|---|---|---|
| `principal.type` | `"agent"` or `"user"` | Differentiates agent-to-agent from user traffic |
| `principal.agent_id` | string | Calling agent ID (resolved from token) |
| `principal.groups` | string[] | RBAC groups the calling agent belongs to |
| `target_agent.agent_id` | string | Target agent ID (extracted from path) |
| `target_agent.allowed_caller_groups` | string[] | Groups permitted to call this agent |
| `target_agent.allowed_paths` | string[] | Path prefixes this agent accepts from callers |

### 3.8 New Audit Event Types

| Event type | Trigger | Key fields |
|---|---|---|
| `AGENT_REGISTERED` | Admin creates a new agent registration | `agent_id`, `agent_name`, `upstream_url`, `admin_account` |
| `AGENT_UPDATED` | Admin modifies agent config (upstream, groups, allowed paths) | `agent_id`, `changed_fields`, `admin_account` |
| `AGENT_DEACTIVATED` | Admin deactivates an agent | `agent_id`, `admin_account`, `reason` |
| `AGENT_TOKEN_ROTATED` | Admin rotates an agent's PSK token | `agent_id`, `admin_account` |
| `AGENT_AUTH_FAILED` | Incoming request with invalid or missing agent token | `agent_id_claimed`, `source_ip`, `path` |
| `AGENT_CALL_ALLOWED` | Agent-to-agent call passed all middleware and was forwarded | `caller_agent_id`, `target_agent_id`, `path`, `pipeline_result` |
| `AGENT_CALL_DENIED_RBAC` | OPA denied agent-to-agent call | `caller_agent_id`, `target_agent_id`, `path`, `opa_reason` |
| `AGENT_CALL_DENIED_INSPECTION` | Inspection pipeline blocked agent-to-agent call | `caller_agent_id`, `target_agent_id`, `classification`, `confidence` |
| `AGENT_NOT_FOUND` | Target agent ID not in registry or inactive | `caller_agent_id`, `target_agent_id_requested`, `path` |

### 3.9 New Prometheus Metrics

See section 6 for the complete metrics catalogue. Agent-specific additions:

- `yashigani_agent_auth_failures_total{agent_id, reason}`
- `yashigani_agent_calls_total{caller_agent_id, target_agent_id, outcome}`
- `yashigani_agent_call_duration_seconds{caller_agent_id, target_agent_id}` (histogram)
- `yashigani_agent_registry_size` (gauge — number of registered, active agents)

### 3.10 New Caddy Configuration Changes

The existing Caddy `reverse_proxy` block in the gateway route gains a path-prefix matcher for agent traffic. No new listeners, no new ports. The Caddyfile change is minimal:

```
# Before (v0.2.0)
handle {
    reverse_proxy gateway:8080
}

# After (v0.3.0)
handle /agents/* {
    reverse_proxy gateway:8080
}
handle {
    reverse_proxy gateway:8080
}
```

Both blocks proxy to the same upstream. The distinction exists so that future Caddy-level controls (e.g., additional rate limiting at the edge, or per-path logging) can be applied to agent traffic independently without modifying the catch-all block.

### 3.11 New Backoffice Admin Routes

All routes are under `/admin/agents/` and require an active admin session.

| Method | Route | Description |
|---|---|---|
| `GET` | `/admin/agents` | List all registered agents (id, name, status, upstream_url, groups, allowed_caller_groups, allowed_paths, created_at, last_seen) |
| `POST` | `/admin/agents` | Register a new agent. Returns `agent_id` and plaintext token (shown once). |
| `GET` | `/admin/agents/{agent_id}` | Get agent details |
| `PUT` | `/admin/agents/{agent_id}` | Update agent config (upstream_url, groups, allowed_caller_groups, allowed_paths, name) |
| `DELETE` | `/admin/agents/{agent_id}` | Deactivate agent (soft delete — marks inactive, retains audit history) |
| `POST` | `/admin/agents/{agent_id}/token/rotate` | Rotate agent PSK token. Returns new plaintext token once. |
| `GET` | `/admin/agents/{agent_id}/calls` | Recent call log for this agent (last 100 events from audit log) |

**Request body for `POST /admin/agents`:**

```json
{
  "name": "data-analysis-agent",
  "upstream_url": "http://data-analysis:9000",
  "groups": ["automation_agents"],
  "allowed_caller_groups": ["orchestrator_agents"],
  "allowed_paths": ["/tools/execute", "/tools/list", "/context/read"]
}
```

**Response for `POST /admin/agents`:**

```json
{
  "agent_id": "agnt_a1b2c3d4",
  "name": "data-analysis-agent",
  "token": "3f8a...e9b2",
  "token_note": "This token will not be shown again. Store it securely.",
  "created_at": "2026-03-26T00:00:00Z"
}
```

### 3.12 New docker-compose.yml Changes

No new services are introduced for agent-to-agent routing. The routing is handled entirely by the gateway process reading from Redis. The only Compose change is documenting the internal network topology. Agent containers (if run in the same Compose stack) are added to the `yashigani_internal` network to allow the gateway to reach their upstream URLs.

A new Compose profile `with-example-agents` can demonstrate the feature with two stub agent containers, but is not part of the production Compose file.

### 3.13 DB Layout Changes

**Redis db/3 — extended for agent registry**

Redis db/3 currently holds RBAC allow-list cache. Agent registry data is added to db/3 under a separate key namespace to avoid collision:

| Key pattern | Type | Content |
|---|---|---|
| `agent:reg:{agent_id}` | Hash | `name`, `upstream_url`, `status` (`active`/`inactive`), `created_at`, `last_seen`, `groups` (JSON array), `allowed_caller_groups` (JSON array), `allowed_paths` (JSON array) |
| `agent:token:{agent_id}` | String | bcrypt hash of the PSK token (cost 12) |
| `agent:index:all` | Set | All registered `agent_id` values |
| `agent:index:active` | Set | Active `agent_id` values only |

Token hash is stored separately from the registry hash to allow the gateway to read agent metadata without touching credential material in a single access pattern.

**No new Redis databases.** db/3 can accommodate both RBAC and agent registry data without conflict via key namespacing. This avoids increasing Redis db count, which would require Compose and config changes.

---

## 4. Feature 2: Multi-Model Inspection Backend

### 4.1 Architecture Overview

The current `InspectionPipeline` holds a direct reference to a `PromptInjectionClassifier`, which is tightly coupled to Ollama. v0.3.0 introduces a `ClassifierBackend` abstract base class and a `BackendRegistry` singleton that the pipeline calls.

```
InspectionPipeline
    |
    v
BackendRegistry
    |
    +-- active_backend (one of below, hot-swappable)
    |
    +-- OllamaBackend        (already implemented logic, refactored)
    +-- LMStudioBackend      (new)
    +-- AnthropicBackend     (new)
    +-- AzureOpenAIBackend   (new)
    +-- GeminiBackend        (new)
    |
    +-- fallback_chain: list[BackendName]  (tried in order on unreachable)
```

The `InspectionPipeline.process()` method calls `BackendRegistry.classify(content)`, which:

1. Tries the active backend.
2. On `BackendUnavailableError`, iterates the fallback chain in order.
3. If all fallbacks fail: returns a synthetic `ClassifierResult(label=LABEL_PROMPT_INJECTION_ONLY, confidence=1.0, ...)` and emits `INSPECTION_BACKEND_FALLBACK_EXHAUSTED` audit event.
4. Emits `INSPECTION_BACKEND_SWITCHED` audit event on each fallback step.

This is fail-closed. An unavailable backend never permits a request to pass.

### 4.2 Backend Specifications

#### 4.2.1 Ollama (existing, refactored)

- **Auth:** None. Ollama runs on the Docker internal network. No credential required.
- **Python approach:** Existing `urllib.request` HTTP client in `classifier.py`, refactored to implement `ClassifierBackend.classify()`. No new dependency.
- **Default model:** `qwen2.5:3b`. Rationale: `qwen3.5:4b` used in v0.1.0/v0.2.0 is replaced by the smaller `qwen2.5:3b` as the default recommendation. `qwen2.5:3b` fits in ~2 GB VRAM, runs on CPU in ~4 GB RAM, and benchmarks show strong classification performance on structured output tasks for its size class. The model name remains operator-configurable.
- **Estimated cost per 1000 classifications:** $0.00 (self-hosted electricity cost only, estimated $0.002–0.01 at typical GPU rates).
- **Fallback:** If Ollama is unreachable or model not loaded: `BackendUnavailableError` raised, registry moves to next fallback.

#### 4.2.2 LM Studio

- **Auth:** None by default (LM Studio local server has no authentication in its current versions). If the operator configures a bearer token in LM Studio's settings, it can be stored in KMS as secret type `lmstudio_api_key` and passed as `Authorization: Bearer {token}`.
- **Python approach:** `httpx` (async-capable HTTP client, already a FastAPI ecosystem dependency). LM Studio exposes an OpenAI-compatible REST API at `http://localhost:1234/v1/chat/completions`. The same request structure as the Ollama implementation applies, adapted for OpenAI message format.
- **Default model:** Operator-defined (LM Studio loads whatever model the user has downloaded). Recommended in documentation: `qwen2.5-3b-instruct` or `phi-3-mini-4k-instruct` for low VRAM. The backend configuration requires a `model` field; no default is assumed.
- **Estimated cost per 1000 classifications:** $0.00 (self-hosted).
- **Note:** LM Studio is a desktop application. It is not appropriate for headless server production deployments. This backend is supported for development/testing workflows where LM Studio is already running on the developer's machine. The backoffice should display a warning when LM Studio is the active backend in a non-development environment.
- **Fallback:** If LM Studio server is unreachable: `BackendUnavailableError`.

#### 4.2.3 Anthropic Claude API

- **Auth:** API key. Stored in KMS as secret type `anthropic_api_key`. Retrieved via `KSMProvider.get_secret("anthropic_api_key")` at backend initialization and cached in memory. Key is never logged.
- **Python approach:** `anthropic` Python SDK (`anthropic>=0.25`). Use `anthropic.Anthropic(api_key=...).messages.create(...)`. The SDK handles retries, connection pooling, and rate-limit backoff.
- **Default model:** `claude-haiku-4-5`. Rationale: fastest and cheapest Anthropic model as of the plan date. Haiku-class models have demonstrated strong structured output compliance in security classification benchmarks. The full model ID is configurable.
- **Estimated cost per 1000 classifications:** At `claude-haiku-4-5` pricing (approximately $0.25/MTok input, $1.25/MTok output as of 2025-08 Anthropic pricing): a typical classification prompt is ~500 input tokens, ~50 output tokens. Cost = (0.5 * $0.25 + 0.05 * $1.25) / 1000 * 1000 = ~$0.19/1000 classifications. Estimate — verify against current Anthropic pricing page.
- **Timeout:** 15 seconds. Classification tasks should complete well under 5 seconds; 15 seconds is a conservative upper bound before declaring unreachable.
- **max_tokens:** 256. The structured JSON output schema is small. Capping tokens prevents billing surprises on runaway model responses.
- **Fallback:** On `anthropic.APIConnectionError`, `anthropic.APITimeoutError`, or any non-200 response: `BackendUnavailableError`.

#### 4.2.4 Azure OpenAI / Microsoft Copilot

- **Auth:** Azure OpenAI API key. Stored in KMS as secret type `azure_openai_key`. Azure Entra (formerly AAD) managed identity is the preferred long-term approach but requires infrastructure plumbing outside Yashigani's current scope. Key-based auth is the v0.3.0 implementation.
- **Python approach:** `openai` Python SDK (`openai>=1.30`) configured with `azure_endpoint`, `api_key`, and `api_version`. The SDK's `AzureOpenAI` client handles Azure-specific request routing.
- **Required config fields:** `azure_endpoint` (e.g., `https://my-resource.openai.azure.com/`), `deployment_name` (the model deployment name in Azure, e.g., `gpt-4o-mini`), `api_version` (e.g., `2024-02-01`).
- **Default model/deployment:** `gpt-4o-mini`. Rationale: cheapest Azure OpenAI deployment suitable for structured classification, strong instruction-following at small token budgets.
- **Estimated cost per 1000 classifications:** At `gpt-4o-mini` Azure pricing (approximately $0.15/MTok input, $0.60/MTok output as of 2025-08): ~500 input tokens, ~50 output tokens. Cost = ~$0.11/1000 classifications. Estimate.
- **Microsoft Copilot Studio custom connector:** Copilot Studio connectors are REST-based and can be wrapped in the same `httpx` client approach as LM Studio. Copilot Studio is noted as an alternative; the primary implementation uses Azure OpenAI directly. If the operator uses Copilot Studio, they configure the base URL and key as a custom backend config.
- **Fallback:** On connection error, timeout, or 5xx: `BackendUnavailableError`.

#### 4.2.5 Google Gemini API

- **Auth:** API key. Stored in KMS as secret type `gemini_api_key`. Google ADC (Application Default Credentials) is the preferred long-term approach; key-based is v0.3.0.
- **Python approach:** `google-generativeai` Python SDK (`google-generativeai>=0.7`). Use `genai.GenerativeModel(model_name=...).generate_content(...)` with `generation_config` set to force JSON output mode.
- **Default model:** `gemini-1.5-flash`. Rationale: lowest latency and lowest cost in the Gemini family as of the plan date. `gemini-1.5-flash` supports JSON mode natively via `response_mime_type="application/json"`, which reduces parse error risk.
- **Estimated cost per 1000 classifications:** At `gemini-1.5-flash` pricing (approximately $0.075/MTok input, $0.30/MTok output as of 2025-08 Google pricing): ~500 input tokens, ~50 output tokens. Cost = ~$0.053/1000 classifications. Estimate.
- **Fallback:** On `google.api_core.exceptions.ServiceUnavailable` or timeout: `BackendUnavailableError`.

### 4.3 Model Comparison Table

See Appendix (section 15) for the full detailed table. Summary:

| Backend | Default Model | p50 Latency | VRAM/RAM (local) | Cost/1k classif. | Structured Output | Security F1 Notes |
|---|---|---|---|---|---|---|
| Ollama | qwen2.5:3b | 800ms–2s | ~2GB VRAM / ~4GB RAM | ~$0.00 | Via format=json | Strong on prompt injection; estimated |
| LM Studio | operator-defined | varies | operator hardware | ~$0.00 | Model-dependent | Depends on loaded model |
| Anthropic Claude | claude-haiku-4-5 | 500ms–1.5s | n/a (cloud) | ~$0.19 | Native JSON mode | Haiku models score well on classification tasks; Anthropic internal eval |
| Azure OpenAI | gpt-4o-mini | 600ms–2s | n/a (cloud) | ~$0.11 | Native JSON mode | GPT-4o-mini strong instruction-following; estimated from OpenAI benchmarks |
| Gemini | gemini-1.5-flash | 400ms–1.2s | n/a (cloud) | ~$0.053 | Native JSON mode | Flash models optimised for speed; Google benchmark data available |

**Recommended default for production:** Ollama with `qwen2.5:3b`. Zero cloud cost, no data leaving the host, predictable latency. Cloud backends are recommended as fallbacks only, not primary backends, unless the operator explicitly accepts data-leaving-host implications.

**Recommended fallback chain (default):** `["ollama", "gemini", "fail_closed"]`. Gemini is the cheapest cloud fallback. "fail_closed" is a sentinel value meaning "emit PROMPT_INJECTION_ONLY, do not attempt further backends."

### 4.4 Admin UX

**New routes under `/admin/inspection/`:**

| Method | Route | Description |
|---|---|---|
| `GET` | `/admin/inspection/backend` | Return active backend name, config (no secrets), fallback chain, and per-backend health status |
| `PUT` | `/admin/inspection/backend` | Set active backend, update config, set fallback chain. Hot-swap: takes effect on next request. |
| `GET` | `/admin/inspection/backend/{backend_name}/health` | Ping a specific backend and return reachability status |
| `POST` | `/admin/inspection/backend/{backend_name}/test` | Send a test classification payload to a specific backend and return the result |

**PUT `/admin/inspection/backend` request body:**

```json
{
  "active_backend": "anthropic",
  "fallback_chain": ["ollama", "gemini", "fail_closed"],
  "backends": {
    "ollama": {
      "base_url": "http://ollama:11434",
      "model": "qwen2.5:3b",
      "timeout_seconds": 30
    },
    "anthropic": {
      "kms_key": "anthropic_api_key",
      "model": "claude-haiku-4-5",
      "timeout_seconds": 15,
      "max_tokens": 256
    },
    "azure_openai": {
      "azure_endpoint": "https://my-resource.openai.azure.com/",
      "deployment_name": "gpt-4o-mini",
      "api_version": "2024-02-01",
      "kms_key": "azure_openai_key",
      "timeout_seconds": 15,
      "max_tokens": 256
    },
    "gemini": {
      "kms_key": "gemini_api_key",
      "model": "gemini-1.5-flash",
      "timeout_seconds": 15,
      "max_tokens": 256
    },
    "lmstudio": {
      "base_url": "http://localhost:1234",
      "model": "qwen2.5-3b-instruct",
      "timeout_seconds": 30,
      "kms_key": null
    }
  }
}
```

**Hot-swap mechanism:** The `BackendRegistry` singleton holds a `threading.Lock`-protected reference to the active backend instance. On `PUT /admin/inspection/backend`, the backoffice service:

1. Validates the new config.
2. Instantiates the new backend (without activating it).
3. Calls `BackendRegistry.swap(new_backend, new_fallback_chain)` under the lock.
4. The next request picks up the new backend with no gap in service.

The FastAPI event loop and the backend registry both run in the same process; the lock prevents a race between a concurrent classify call and the swap operation.

**KMS key resolution:** Cloud backend configs reference KMS keys by name, not by value. The backend's `__init__` calls `KSMProvider.get_secret(kms_key)` and caches the result in an instance variable. On `PUT /admin/inspection/backend`, a new backend instance is created, which re-fetches the secret from KMS. This ensures key rotation is respected without a service restart.

### 4.5 New KMS Secret Types

| Secret key name | Backend | Description |
|---|---|---|
| `anthropic_api_key` | Anthropic Claude | Anthropic API key |
| `azure_openai_key` | Azure OpenAI | Azure OpenAI API key |
| `gemini_api_key` | Gemini | Google AI Studio / Vertex API key |
| `lmstudio_api_key` | LM Studio | Optional bearer token (if LM Studio auth is enabled) |

### 4.6 New Audit Event Types for Feature 2

| Event type | Trigger | Key fields |
|---|---|---|
| `INSPECTION_BACKEND_CHANGED` | Admin swaps active backend | `previous_backend`, `new_backend`, `admin_account` |
| `INSPECTION_BACKEND_UNREACHABLE` | Backend returned error or timed out | `backend_name`, `error_type`, `error_message` |
| `INSPECTION_BACKEND_FALLBACK` | Registry fell back to next backend in chain | `failed_backend`, `next_backend`, `fallback_position` |
| `INSPECTION_BACKEND_FALLBACK_EXHAUSTED` | All backends failed; fail-closed result returned | `backends_tried`, `request_id`, `action_taken` |
| `INSPECTION_BACKEND_CONFIG_CHANGED` | Admin updated backend config (non-secret fields) | `backend_name`, `changed_fields`, `admin_account` |
| `INSPECTION_KMS_KEY_RETRIEVED` | Backend init fetched cloud API key from KMS | `backend_name`, `kms_key_name` (value never logged) |

---

## 5. Security Analysis

### 5.1 ASVS v5 Coverage for New Features

#### V1 — Architecture, Design, and Threat Modelling

- **V1.1 Secure Software Development Lifecycle:** Both features follow the HITL protocol. No code change is deployed without Tiago's explicit approval of this plan document. Threat model entries are added below.
- **V1.2 Authentication:** Agent PSK tokens are 256-bit random, stored as bcrypt hashes. This meets ASVS V2.4 (password storage) requirements as applied to machine credentials. Cloud API keys are KMS-managed, never in environment variables.
- **V1.3 Authorisation:** RBAC is extended to cover agent-to-agent calls. OPA remains the sole enforcement point. No new bypass paths introduced.
- **V1.4 Access Control:** Agent registry read is available to authenticated admins only. Token plaintext is shown once and never stored.

#### V2 — Authentication

- **V2.1 Password Security:** Not directly applicable to agent tokens; covered by 256-bit entropy requirement.
- **V2.4 Credential Storage:** bcrypt with cost 12 for agent tokens. Meets ASVS v5 V2.4 requirements.
- **V2.8 Single or Multi-Factor OTP:** Not applicable to machine-to-machine auth. Documented as N/A.
- **V2.10 Service Authentication:** Agent PSK meets ASVS v5 V2.10 "Secrets used for service authentication shall have sufficient entropy and shall be stored in a secrets manager." KMS stores cloud API keys. Docker internal network isolates Ollama and LM Studio.

#### V3 — Session Management

- No new human sessions. Agent tokens are stateless per-request credentials, not sessions. Not applicable.

#### V4 — Access Control

- **V4.1 General Access Control:** OPA enforces all agent-to-agent decisions. No gateway logic makes allow/deny decisions; it only prepares the OPA input.
- **V4.2 Operation Level Access Control:** `allowed_paths` on target agents restricts which endpoints a calling agent can reach. Path is verified by OPA, not by the gateway router.
- **V4.3 Other Access Control:** Agent registry admin routes require an active admin session. No anonymous access.

#### V7 — Error Handling and Logging

- **V7.1 Log Content:** All new audit event types include `request_id`, `agent_id`, timestamps. No credential values are logged.
- **V7.2 Log Processing:** Audit writer (`AuditLogWriter`) is the sole log sink. No ad-hoc `print()` or `logging.info()` of request bodies in new code.
- **V7.3 Log Protection:** Unchanged from v0.2.0; audit logs are append-only.

#### V8 — Data Protection

- **V8.1 General Data Protection:** Agent PSK plaintext is shown once and not stored. Cloud API keys never appear in logs, HTTP responses, or metrics labels.
- **V8.3 Sensitive Private Data:** Classification payloads (the content being inspected) are not logged to cloud backends. When a cloud backend is active, the content being sent to the external API constitutes a data-leaving-host event. This is a deliberate operator choice; the admin UI warns when a cloud backend is configured as primary.

#### V9 — Communication

- **V9.1 Communication Security:** All external calls to cloud APIs use HTTPS with TLS 1.2+. The `httpx` and SDK clients enforce this by default. Custom `base_url` values in backend config must use `https://`; the backoffice rejects `http://` for cloud backend URLs.
- **V9.2 Server Communication Security:** Ollama and LM Studio communicate over Docker internal network (HTTP acceptable within trust boundary). All external-facing endpoints remain TLS-terminated by Caddy.

#### V10 — Malicious Code

- **V10.2 Malicious Code Search:** Backend implementations do not execute any content from LLM responses beyond parsing the structured JSON classification verdict. The parse layer is strict and schema-validated.

#### V12 — Files and Resources

- Not applicable to these features.

#### V13 — API and Web Service

- **V13.1 Generic Web Service Security:** New backoffice routes use Pydantic models for all request bodies. All fields are validated. No raw SQL or unvalidated inputs.
- **V13.2 RESTful Web Service:** New routes use appropriate HTTP methods (GET/PUT/POST/DELETE). 405 on method mismatch is handled by FastAPI automatically.

### 5.2 Threat Model — New Entries

| Threat ID | Threat | Asset | Likelihood | Impact | Mitigation |
|---|---|---|---|---|---|
| TM-301 | Agent token theft via Docker internal network sniffing | Agent PSK token | Low (Docker bridge isolation) | High (agent impersonation) | mTLS in v0.4.0; current control: Docker internal network |
| TM-302 | Agent calls exhausting rate limit budget of a legitimate agent (denial of service) | Rate limit bucket | Medium (if agent token is compromised) | Medium | Per-agent bucket is global; token rotation immediately cuts off abuser |
| TM-303 | LLM prompt injection via agent-to-agent payload | Inspection pipeline | Medium (agent payloads may be less sanitized than human inputs) | High | Same inspection pipeline applies; fail-closed on detection |
| TM-304 | Cloud backend receives sensitive content from inspected requests | Data confidentiality | Operator-configurable (cloud backend must be explicitly chosen) | High | Admin UI warning; Ollama default; audit event on key retrieval |
| TM-305 | Cloud API key exfiltration via malicious OPA policy | KMS secrets | Low (OPA policies are admin-managed; OPA does not have KMS access) | Critical | KMS keys are not in OPA input; KSMProvider is not accessible from OPA |
| TM-306 | Backend config PUT used to redirect inspection to attacker-controlled server | Inspection integrity | Low (requires compromised admin session) | Critical | Admin session required; `PUT /admin/inspection/backend` is audit-logged; HTTPS enforced for cloud URLs |
| TM-307 | Fallback chain exhaustion attack (deliberately overwhelming all backends) | Availability | Medium | Medium | Fail-closed returns PROMPT_INJECTION_ONLY; rate limiter applies before inspection |
| TM-308 | Agent path traversal via malformed `agent_id` in path | Agent registry | Low (FastAPI path parameter validation) | Medium | `agent_id` validated against `^[a-zA-Z0-9_-]{1,64}$` pattern in route definition |

### 5.3 OWASP LLM Top 10 2025 — New Controls

| Risk | Control in v0.3.0 |
|---|---|
| LLM01 Prompt Injection | Inspection pipeline applies to agent-to-agent payloads. Same classify/sanitize/discard logic. |
| LLM02 Sensitive Information Disclosure | Agent tokens bcrypt-hashed. Cloud API keys KMS-only. Audit events do not log secret values. |
| LLM06 Excessive Agency | Agent RBAC `allowed_paths` restricts what endpoints an agent can invoke on other agents. OPA enforces. |
| LLM09 Misinformation | Classification response schema strictly validated; model output that does not conform to schema defaults to fail-closed. |
| LLM10 Unbounded Consumption | Per-agent rate limiting applies to agent-to-agent calls. `max_tokens` capped on all cloud backend calls. |

---

## 6. New Prometheus Metrics — Complete List

### 6.1 Intra-Agent Communication Metrics

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `yashigani_agent_auth_failures_total` | Counter | `reason` (`missing_token`, `invalid_token`, `agent_inactive`) | Agent authentication failures at gateway |
| `yashigani_agent_calls_total` | Counter | `caller_agent_id`, `target_agent_id`, `outcome` (`allowed`, `denied_rbac`, `denied_inspection`, `not_found`) | Agent-to-agent call dispositions |
| `yashigani_agent_call_duration_seconds` | Histogram | `caller_agent_id`, `target_agent_id` | End-to-end latency for agent-to-agent calls (gateway receipt to upstream response) |
| `yashigani_agent_registry_size` | Gauge | `status` (`active`, `inactive`) | Number of agents in registry by status |

### 6.2 Inspection Backend Metrics

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `yashigani_inspection_backend_requests_total` | Counter | `backend` (`ollama`, `lmstudio`, `anthropic`, `azure_openai`, `gemini`), `outcome` (`success`, `error`, `timeout`, `fallback`) | Classification requests per backend and outcome |
| `yashigani_inspection_backend_latency_seconds` | Histogram | `backend` | Classification latency per backend (p50, p95, p99) |
| `yashigani_inspection_backend_fallbacks_total` | Counter | `failed_backend`, `next_backend` | Number of times registry fell back from one backend to another |
| `yashigani_inspection_backend_exhausted_total` | Counter | (none) | Number of times all fallbacks were exhausted (fail-closed triggered) |
| `yashigani_inspection_active_backend` | Gauge (info) | `backend` | Label-only metric indicating the currently active backend (value always 1) |

### 6.3 Carried Forward from v0.2.0 (No Change)

All metrics defined in v0.2.0 are unchanged. The complete v0.3.0 metrics catalogue is the union of v0.2.0 metrics and the new metrics above.

---

## 7. New Grafana Dashboard Additions

### 7.1 Additions to Existing Dashboards

**Agent Activity Dashboard** (existing in v0.2.0, `agent_activity.json`):

- New panel: "Agent-to-Agent Call Volume" — time series of `yashigani_agent_calls_total` by `caller_agent_id` and `target_agent_id`.
- New panel: "Agent Auth Failures" — bar gauge of `yashigani_agent_auth_failures_total` by `reason`.
- New panel: "Agent Call Latency (p95)" — time series of `histogram_quantile(0.95, yashigani_agent_call_duration_seconds)` by caller/target pair.
- New panel: "Agent Registry Size" — stat panel showing `yashigani_agent_registry_size{status="active"}`.
- New panel: "Agent Call Disposition Breakdown" — pie chart of `yashigani_agent_calls_total` by `outcome`.

**Security Overview Dashboard** (existing in v0.2.0, `security_overview.json`):

- New panel: "Agent Auth Failures (24h)" — stat panel.
- New panel: "Agent Calls Denied by RBAC" — time series from `yashigani_agent_calls_total{outcome="denied_rbac"}`.

### 7.2 New Dashboard: Inspection Backend Health

New dashboard file: `grafana/dashboards/inspection_backend.json`

**Panels:**

- "Active Backend" — stat panel from `yashigani_inspection_active_backend` label.
- "Backend Request Rate" — time series of `rate(yashigani_inspection_backend_requests_total[5m])` by `backend` and `outcome`.
- "Backend Latency (p50 / p95)" — time series of `histogram_quantile` at both quantiles, by `backend`.
- "Backend Error Rate" — time series of `rate(yashigani_inspection_backend_requests_total{outcome=~"error|timeout"}[5m])`.
- "Fallback Events" — time series of `rate(yashigani_inspection_backend_fallbacks_total[5m])` by `failed_backend` / `next_backend`.
- "Fail-Closed Triggers" — stat panel of `yashigani_inspection_backend_exhausted_total` (last 24h increment). Alert threshold: > 0 triggers a Grafana alert.

**Alert rule:** `yashigani_inspection_backend_exhausted_total` increase > 0 in 5 minutes → severity CRITICAL. Rationale: fail-closed means traffic is being blocked. This requires immediate operator investigation.

---

## 8. New OPA Policy Requirements

### 8.1 Agent-to-Agent Policy Document

A new OPA policy file `policy/agents.rego` handles agent-to-agent authorization.

**Required rules:**

1. `agent_call_allowed` — returns true if `input.principal.type == "agent"` AND at least one element of `input.principal.groups` appears in `input.target_agent.allowed_caller_groups` AND `input.request.remainder_path` matches at least one entry in `input.target_agent.allowed_paths` (prefix match).

2. `agent_call_deny_reason` — returns a human-readable string explaining why a call was denied. Used in audit event `AGENT_CALL_DENIED_RBAC.opa_reason` field.

3. Default deny for agent traffic: any request where `input.principal.type == "agent"` that does not match `agent_call_allowed` is denied. The gateway policy must import `agents.rego`.

**Data document extension for OPA bundle push:**

The RBAC data document pushed by `opa_push.py` gains a top-level `agents` key:

```json
{
  "rbac": { ... },
  "agents": {
    "agnt_a1b2c3d4": {
      "allowed_caller_groups": ["orchestrator_agents"],
      "allowed_paths": ["/tools/execute", "/tools/list"]
    }
  }
}
```

The backoffice `opa_push.py` is extended to include agent registry data in the push payload. Agent data is read from Redis db/3 (`agent:reg:{agent_id}` hashes) and serialized into the data document before pushing.

### 8.2 Changes to `policy/yashigani.rego`

The main policy imports `agents.rego` and adds a rule: if `input.principal.type == "agent"`, evaluate `agent_call_allowed` in addition to existing RBAC checks.

---

## 9. New Audit Event Types — Complete List

All new audit events conform to the existing `AuditEvent` base schema defined in `audit/schema.py`. New event types are added as subclasses of `AuditEvent`.

### 9.1 Feature 1 — Intra-Agent Communication

| Event type | Fields (in addition to base `AuditEvent` fields) |
|---|---|
| `AGENT_REGISTERED` | `agent_id: str`, `agent_name: str`, `upstream_url: str`, `groups: list[str]`, `allowed_caller_groups: list[str]`, `allowed_paths: list[str]`, `admin_account: str` |
| `AGENT_UPDATED` | `agent_id: str`, `changed_fields: dict`, `admin_account: str` |
| `AGENT_DEACTIVATED` | `agent_id: str`, `admin_account: str`, `reason: str` |
| `AGENT_TOKEN_ROTATED` | `agent_id: str`, `admin_account: str` |
| `AGENT_AUTH_FAILED` | `agent_id_claimed: str`, `source_ip: str`, `path: str`, `failure_reason: str` (`missing_token`, `invalid_token`, `agent_inactive`) |
| `AGENT_CALL_ALLOWED` | `caller_agent_id: str`, `target_agent_id: str`, `path: str`, `remainder_path: str`, `pipeline_action: str`, `classification: str` |
| `AGENT_CALL_DENIED_RBAC` | `caller_agent_id: str`, `target_agent_id: str`, `path: str`, `opa_reason: str` |
| `AGENT_CALL_DENIED_INSPECTION` | `caller_agent_id: str`, `target_agent_id: str`, `path: str`, `classification: str`, `confidence: float`, `action: str` |
| `AGENT_NOT_FOUND` | `caller_agent_id: str`, `target_agent_id_requested: str`, `path: str` |

### 9.2 Feature 2 — Multi-Model Inspection Backend

| Event type | Fields |
|---|---|
| `INSPECTION_BACKEND_CHANGED` | `previous_backend: str`, `new_backend: str`, `admin_account: str` |
| `INSPECTION_BACKEND_UNREACHABLE` | `backend_name: str`, `error_type: str`, `error_message: str`, `request_id: str` |
| `INSPECTION_BACKEND_FALLBACK` | `failed_backend: str`, `next_backend: str`, `fallback_position: int`, `request_id: str` |
| `INSPECTION_BACKEND_FALLBACK_EXHAUSTED` | `backends_tried: list[str]`, `request_id: str`, `action_taken: str` (`PROMPT_INJECTION_ONLY`) |
| `INSPECTION_BACKEND_CONFIG_CHANGED` | `backend_name: str`, `changed_fields: list[str]`, `admin_account: str` |
| `INSPECTION_KMS_KEY_RETRIEVED` | `backend_name: str`, `kms_key_name: str` |

---

## 10. Backoffice API Changes

### 10.1 New Routes

**Agents (`/admin/agents/`):**

| Method | Route | Auth | Notes |
|---|---|---|---|
| `GET` | `/admin/agents` | Admin session | Pagination: `?limit=50&offset=0` |
| `POST` | `/admin/agents` | Admin session | Returns token once |
| `GET` | `/admin/agents/{agent_id}` | Admin session | |
| `PUT` | `/admin/agents/{agent_id}` | Admin session | Partial update supported |
| `DELETE` | `/admin/agents/{agent_id}` | Admin session | Soft delete only |
| `POST` | `/admin/agents/{agent_id}/token/rotate` | Admin session | Returns new token once |
| `GET` | `/admin/agents/{agent_id}/calls` | Admin session | Last 100 audit events for this agent |

**Inspection Backend (`/admin/inspection/`):**

| Method | Route | Auth | Notes |
|---|---|---|---|
| `GET` | `/admin/inspection/backend` | Admin session | Returns active backend, config (no secrets), fallback chain, health summary |
| `PUT` | `/admin/inspection/backend` | Admin session | Hot-swaps active backend |
| `GET` | `/admin/inspection/backend/{backend_name}/health` | Admin session | Pings specific backend |
| `POST` | `/admin/inspection/backend/{backend_name}/test` | Admin session | Runs test classification |

### 10.2 Updated Routes

**`GET /admin/inspection/status`** (existing):

Updated to return `active_backend` and `fallback_chain` in addition to existing fields. The `ollama_base_url` and `model` fields are retained for backward compatibility but are now also present in the `backends.ollama` sub-object of the response.

**`POST /admin/inspection/model`** (existing):

This route previously accepted a `model` string and updated `pipeline._classifier._model` directly. In v0.3.0 this route is deprecated in favour of `PUT /admin/inspection/backend`. It remains functional for v0.3.0 to avoid breaking changes, but targets the Ollama backend only. A deprecation notice is added to the response: `"deprecated": true, "use_instead": "PUT /admin/inspection/backend"`.

### 10.3 BackofficeState Changes

The `BackofficeState` dataclass gains two new optional fields:

```python
agent_registry: Optional[AgentRegistry] = None       # Redis-backed agent registry
backend_registry: Optional[BackendRegistry] = None   # Pluggable inspection backend registry
```

The `inspection_pipeline` field type is unchanged; `InspectionPipeline` is updated to call `BackendRegistry.classify()` instead of holding a direct `PromptInjectionClassifier` reference. The field therefore continues to hold an `InspectionPipeline` instance.

---

## 11. docker-compose.yml Changes

### 11.1 No New Required Services

All v0.3.0 functionality is implemented in existing services (gateway, backoffice, redis). No new containers are required.

### 11.2 Environment Variable Additions

New environment variables for the gateway and backoffice services:

**Gateway (`gateway` service):**

```yaml
environment:
  YASHIGANI_AGENT_ROUTING_ENABLED: "true"
  YASHIGANI_AGENT_PATH_PREFIX: "/agents"
  YASHIGANI_AGENT_TOKEN_MIN_LENGTH: "64"
```

**Backoffice (`backoffice` service):**

```yaml
environment:
  YASHIGANI_INSPECTION_DEFAULT_BACKEND: "ollama"
  YASHIGANI_INSPECTION_FALLBACK_CHAIN: "ollama,gemini,fail_closed"
  YASHIGANI_INSPECTION_BACKEND_CONFIG_PATH: "/config/inspection_backends.yaml"
```

`YASHIGANI_INSPECTION_BACKEND_CONFIG_PATH` points to a YAML file mounted as a Docker volume. This file holds the per-backend configuration (base URLs, model names, KMS key references, timeouts). Secret values are never in this file; only KMS key names. The file is read at startup and overridden by admin `PUT /admin/inspection/backend` calls (which persist changes back to the file or to Redis — see section 12).

### 11.3 Optional Example Agents Profile

A Compose override file `docker/docker-compose.agents-example.yml` demonstrates two stub agent containers for development testing. It is not part of the production stack and is not referenced from the main `docker-compose.yml`.

### 11.4 Redis Volume Mount

No change to Redis configuration. The existing Redis container configuration already persists data via a named volume. No new volume mounts are required.

---

## 12. Database / Storage Changes

### 12.1 Redis db/3 — Agent Registry Extension

Existing keys in db/3: RBAC allow-list cache (namespace `rbac:*`).

New keys in db/3 (namespace `agent:*`):

| Key | Type | TTL | Content |
|---|---|---|---|
| `agent:reg:{agent_id}` | Hash | None (permanent) | `name`, `upstream_url`, `status`, `created_at`, `last_seen_at`, `groups` (JSON), `allowed_caller_groups` (JSON), `allowed_paths` (JSON) |
| `agent:token:{agent_id}` | String | None (permanent) | bcrypt hash of PSK (cost 12) |
| `agent:index:all` | Set | None | All `agent_id` strings |
| `agent:index:active` | Set | None | Active `agent_id` strings only |

`last_seen_at` is updated on each successful authentication via `HINCRBY` or `HSET` on the registry hash. This allows the admin to see stale agents.

### 12.2 Inspection Backend Config Persistence

Backend configuration (active backend name, per-backend config, fallback chain) is persisted in Redis db/1 (backoffice data) under a new namespace `inspection:backend:*` to survive backoffice restarts:

| Key | Type | Content |
|---|---|---|
| `inspection:backend:active` | String | Active backend name |
| `inspection:backend:fallback_chain` | List | Ordered list of backend names |
| `inspection:backend:config:{backend_name}` | Hash | Per-backend config fields (no secrets) |

On backoffice startup, the `BackendRegistry` reads these keys from Redis. If absent, it falls back to the environment variable defaults (`YASHIGANI_INSPECTION_DEFAULT_BACKEND`, `YASHIGANI_INSPECTION_FALLBACK_CHAIN`) and the config file.

### 12.3 No Schema Migrations Required

Redis is a schema-free store. New keys are additive and do not affect existing keys. No migration scripts are required.

### 12.4 OPA Data Document Extension

The OPA data bundle document pushed by `opa_push.py` gains the `agents` top-level key (see section 8.1). The push operation is additive; existing `rbac` key is unchanged.

---

## 13. Open Questions

The following are genuine blockers requiring resolution before implementation of specific sub-components. Design questions that were answerable within this plan document are already decided above.

1. **LM Studio in production.** LM Studio is a desktop application with no supported headless mode as of the plan date. Should the LM Studio backend be explicitly restricted to `development` profile only (enforced by the backoffice returning HTTP 422 if LM Studio is set as active backend when `YASHIGANI_ENV=production`)? Recommendation: yes, add the guard. Tiago to confirm.

2. **Agent token rotation grace period.** When an admin rotates an agent's PSK token, the old token is immediately invalidated. Any in-flight requests using the old token will receive HTTP 401. A grace period (e.g., 60 seconds where both old and new tokens are valid) would reduce operational disruption during rolling restarts of agent containers. This adds complexity to the token storage schema. Tiago to decide: hard cutover or grace period.

3. **OPA bundle push scope.** Currently `opa_push.py` pushes the entire RBAC data document on each call. With agent registry data included, the document grows proportionally to agent count. At large agent counts (hundreds), full-document pushes may introduce latency. Partial document updates (OPA REST API `PATCH /v1/data/agents`) are supported by OPA. Should v0.3.0 implement partial pushes for the `agents` key, or is full-push acceptable at expected scale? Recommendation: full-push is acceptable up to ~500 agents; defer partial push to v0.4.0. Tiago to confirm scale expectations.

---

## 14. Phase Breakdown

### Phase 1 — Foundation: Agent Registry and Backend Abstraction

**Deliverables:**

1. `AgentRegistry` class (`src/yashigani/agents/registry.py`) — wraps Redis db/3 agent namespace. CRUD operations: register, get, update, deactivate, list, token_hash_verify, token_rotate.
2. `ClassifierBackend` abstract base class (`src/yashigani/inspection/backend_base.py`) — defines `classify(content: str) -> ClassifierResult` and `health_check() -> bool` interface.
3. `OllamaBackend` (`src/yashigani/inspection/backends/ollama.py`) — refactored from existing `PromptInjectionClassifier`. Implements `ClassifierBackend`.
4. `BackendRegistry` (`src/yashigani/inspection/backend_registry.py`) — singleton, holds active backend reference, implements fallback chain logic, fail-closed sentinel.
5. `InspectionPipeline` updated to call `BackendRegistry.classify()` instead of `PromptInjectionClassifier.classify()`. Backward-compatible: if no `BackendRegistry` is injected, falls back to direct `PromptInjectionClassifier` call (deprecation path).
6. All new audit event types for both features added to `audit/schema.py`.
7. Unit tests for `AgentRegistry`, `ClassifierBackend`, `OllamaBackend`, `BackendRegistry` (with mock backends).

**Acceptance gate:** `OllamaBackend` via `BackendRegistry` produces identical classification results to the current `PromptInjectionClassifier` in all existing tests.

### Phase 2 — Agent Authentication and Routing

**Deliverables:**

1. `AgentAuthMiddleware` (`src/yashigani/gateway/agent_auth.py`) — extracts `Authorization: Bearer` token, resolves `agent_id` via `AgentRegistry.token_hash_verify()`, attaches `agent_id` to request state.
2. `AgentRouter` (`src/yashigani/gateway/agent_router.py`) — reads target upstream URL from `AgentRegistry`, proxies the request. Returns 404 if agent not registered or inactive.
3. Gateway `entrypoint.py` updated to mount `AgentAuthMiddleware` and `AgentRouter` under `/agents/` path prefix.
4. Caddy configuration updated with `/agents/*` route block (see section 3.10).
5. New Prometheus metrics for agent auth failures, agent call volume, agent call latency registered in `metrics/` module.
6. Integration test: register a test agent, call it via `/agents/{agent_id}/`, verify forwarding to upstream stub.
7. Integration test: invalid token returns HTTP 401 and emits `AGENT_AUTH_FAILED` audit event.

### Phase 3 — Agent RBAC and OPA Integration

**Deliverables:**

1. `policy/agents.rego` — `agent_call_allowed` rule and `agent_call_deny_reason` rule.
2. `policy/yashigani.rego` updated to import `agents.rego` and evaluate agent rules for agent-type principals.
3. `opa_push.py` extended to include `agents` key in data document.
4. OPA input builder in gateway updated to populate `principal.type`, `principal.agent_id`, `principal.groups`, `target_agent.*` fields for agent-path requests.
5. Backoffice `rbac_router` extended to call `opa_push.py` after any agent registry modification.
6. Integration test: calling agent with valid token but wrong group receives HTTP 403 and emits `AGENT_CALL_DENIED_RBAC`.
7. Integration test: calling agent with valid token and matching group is forwarded.

### Phase 4 — Multi-Model Backends (Local)

**Deliverables:**

1. `LMStudioBackend` (`src/yashigani/inspection/backends/lmstudio.py`) — OpenAI-compatible API, `httpx` client.
2. Unit tests for `LMStudioBackend` with mock server.
3. Backoffice route `GET /admin/inspection/backend` — returns active backend config and health summary.
4. Backoffice route `PUT /admin/inspection/backend` — hot-swap logic with threading lock.
5. Backoffice route `GET /admin/inspection/backend/{name}/health` — pings backend.
6. Backoffice route `POST /admin/inspection/backend/{name}/test` — test classification.
7. `BackendRegistry` persistence to Redis db/1 (read on startup, write on `PUT`).
8. `BackofficeState` updated with `backend_registry` field.
9. Integration test: hot-swap from Ollama to LM Studio (mocked) without restarting gateway.

### Phase 5 — Multi-Model Backends (Cloud)

**Deliverables:**

1. `AnthropicBackend` (`src/yashigani/inspection/backends/anthropic.py`) — `anthropic` SDK.
2. `AzureOpenAIBackend` (`src/yashigani/inspection/backends/azure_openai.py`) — `openai` SDK with `AzureOpenAI` client.
3. `GeminiBackend` (`src/yashigani/inspection/backends/gemini.py`) — `google-generativeai` SDK.
4. KMS secret types `anthropic_api_key`, `azure_openai_key`, `gemini_api_key`, `lmstudio_api_key` documented in KMS README and registered as valid key name patterns in the `KSMProvider` scope validation.
5. Backoffice HTTPS enforcement for cloud backend `base_url` fields.
6. LM Studio production guard (returns HTTP 422 if `YASHIGANI_ENV=production` and LM Studio is set as active backend).
7. Prometheus metrics for backend requests and latency registered and scraped.
8. Unit tests for all three cloud backends with mocked SDK calls.
9. Integration test: fallback chain — Ollama down → Gemini responds → classification succeeds; both backends emit correct audit events.
10. Integration test: all backends down → fail-closed result returned → `INSPECTION_BACKEND_FALLBACK_EXHAUSTED` emitted.

### Phase 6 — Backoffice Agent Admin Routes

**Deliverables:**

1. All agent admin routes (`GET/POST/PUT/DELETE /admin/agents/...`, token rotate, call log).
2. Pydantic request/response models for all new routes.
3. `pyproject.toml` updated with new dependencies: `anthropic>=0.25`, `openai>=1.30`, `google-generativeai>=0.7`, `httpx>=0.27` (if not already present as FastAPI transitive dependency).
4. `docker-compose.yml` updated with new environment variables.
5. `.env.example` updated with all new variables.

### Phase 7 — Observability and Documentation

**Deliverables:**

1. Grafana `inspection_backend.json` dashboard provisioned.
2. Agent Activity dashboard updated with new panels (section 7.1).
3. Security Overview dashboard updated with new panels (section 7.1).
4. Grafana alert rule for `yashigani_inspection_backend_exhausted_total`.
5. Prometheus alert rule for agent auth failure spike: `rate(yashigani_agent_auth_failures_total[5m]) > 10`.
6. `docs/yashigani_v0.3.0_documentation.md` — operator guide covering agent registration workflow, backend configuration, fallback chain setup, and security considerations for cloud backends.
7. Full end-to-end integration test suite covering both features under a Compose-based test environment.
8. `pyproject.toml` version bump to `0.3.0`.

---

## 15. Appendix: Model Comparison Table (Detailed)

| Backend | Default Model | p50 Classify Latency | p95 Classify Latency | VRAM (local) | RAM (local) | Cost/1k classif. | JSON output mode | Security classification notes |
|---|---|---|---|---|---|---|---|---|
| Ollama | qwen2.5:3b | 800ms–2s | 2–5s | ~2 GB | ~4 GB (CPU) | ~$0.00 | Via `format=json` param | Qwen 2.5 3B shows strong structured output compliance at small scale. Security classification F1 not formally benchmarked; estimated based on model card instruction-following scores. Lower confidence than larger models on ambiguous payloads. |
| LM Studio | operator-defined | varies | varies | operator hardware | operator hardware | ~$0.00 | Model-dependent | Performance depends entirely on the model the operator loads. No benchmarks possible without knowing model. Recommend same model family as Ollama for consistency. |
| Anthropic Claude | claude-haiku-4-5 | 500ms–1.5s | 1.5–4s | n/a | n/a | ~$0.19 | Native JSON output mode | Haiku 4.5 is Anthropic's fastest model. Anthropic's internal red-teaming suggests strong prompt injection detection. Structured output via `response_format` is reliable. Latency estimate from Anthropic API documentation and community benchmarks. |
| Azure OpenAI | gpt-4o-mini | 600ms–2s | 2–5s | n/a | n/a | ~$0.11 | Native JSON mode | GPT-4o-mini has strong instruction-following benchmarks (MMLU, IFEval). Azure latency slightly higher than OpenAI direct due to regional routing. Pricing from Azure OpenAI pricing page; estimate for classification token budget. |
| Gemini | gemini-1.5-flash | 400ms–1.2s | 1–3s | n/a | n/a | ~$0.053 | `response_mime_type="application/json"` | Gemini 1.5 Flash is optimised for speed and cost. JSON mode is natively supported. Latency estimates from Google AI Studio documentation. Cheapest cloud option. Lower base model capability than Claude Haiku on complex reasoning tasks; acceptable for structured classification. |

**Notes on estimates:**

- All latency figures are estimates based on publicly available model cards, API documentation, and community benchmark data available as of 2025-08. Production latency will vary based on network conditions, concurrent load, and regional endpoint selection.
- All cost figures are estimates based on publicly available pricing as of 2025-08. Verify against current provider pricing pages before budgeting.
- Local backend latency assumes mid-range consumer GPU (NVIDIA RTX 3080 equivalent) for VRAM figures and Apple M2 Pro for CPU/RAM figures. Significantly lower-end hardware will increase latency; higher-end hardware will decrease it.
- Security classification F1 figures are not formally benchmarked for this specific task across all models. Model selection is based on structured output reliability, instruction-following capability, and speed-cost tradeoffs. A production operator running Yashigani should run their own classification accuracy test using representative prompt injection samples before choosing a cloud backend as primary.

**Recommended production configuration:**

```
active_backend: ollama
fallback_chain: [gemini, fail_closed]
```

Rationale: Ollama as primary keeps all classification on-host with zero cloud cost and zero data-leaving-host risk. Gemini as fallback provides the cheapest cloud option if Ollama becomes temporarily unavailable. Fail-closed as terminal sentinel ensures no request is ever permitted through on complete backend failure.
