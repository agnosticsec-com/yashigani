# Yashigani
---

<html>
<body>
<div>
  <img src="https://github.com/agnosticsec-com/yashigani_img/blob/main/Yashiganymaster.png" alt="Yashigani" style="width:100%">
</div>
</body>
</html>

---
**Yashigani is the security enforcement gateway for MCP servers and agentic AI systems.**
---
*Yashigani — Security enforcement for agentic AI. Every call inspected. Every policy enforced. Every action audited.*
---
---
**Latest Stable Version:** v2.1.0

---
**Release Lines:** v2.x (full stack with Open WebUI, branch: `main`) | v1.x (gateway-only, branch: `release/1.x`)
---
**Document Date:** 2026-04-01
---
**Classification:** ***Public — Product Overview***
---


## Table of Contents

1. [What is Yashigani](#1-what-is-yashigani)
2. [The Problem It Solves](#2-the-problem-it-solves)
3. [Architecture Overview](#3-architecture-overview)
4. [Security Features by Version](#4-security-features-by-version)
5. [Complete Feature List](#5-complete-feature-list)
6. [Feature Matrix by Tier](#6-feature-matrix-by-tier)
7. [Deployment Topologies](#7-deployment-topologies)
8. [Roadmap Context](#8-roadmap-context)

---

## 1. What is Yashigani

Yashigani is a security enforcement gateway purpose-built for Model Context Protocol (MCP) servers and agentic AI systems. It operates as a reverse proxy, sitting between AI agents or human clients and the upstream MCP tool servers that those agents call. Every request passes through Yashigani before reaching a tool; every response is inspected before being returned. Nothing crosses the boundary without being authenticated, authorized, and inspected.

The **Model Context Protocol** is an open standard that allows AI agents — systems driven by large language models — to call external tools: file system operations, database queries, API calls, shell commands, and more. MCP enables genuinely powerful agentic behavior, but it also exposes a new and largely unaddressed attack surface. An LLM that can call tools is an LLM that can be manipulated into exfiltrating credentials, bypassing access controls, or executing unintended actions. The MCP specification itself defines the protocol, not the security envelope around it.

Yashigani fills that gap. It provides the security layer that MCP does not: authentication, fine-grained authorization via Open Policy Agent (OPA), ML-assisted prompt injection detection, credential exfiltration prevention, per-endpoint rate limiting, full audit trails with multi-sink delivery, encrypted secrets management, SSO/SCIM identity integration, enterprise-grade observability, intelligent model routing via the Optimization Engine, and three-tier budget governance. From a single developer running a local model to a large organization deploying hundreds of AI agents across multiple business units, Yashigani is the enforcement point that makes agentic AI deployments safe to operate in production.

---

## 2. The Problem It Solves

Agentic AI systems are not just chat interfaces. They call real tools, read real data, and execute real operations. This creates eight distinct classes of risk that traditional API gateways, network firewalls, and bolt-on AI wrappers were not designed to address. Yashigani solves all eight from a single enforcement point.

### 2.1 Unmonitored AI Access

AI agents and human users call LLMs — cloud and local — without inspection, audit, or policy enforcement. Prompts flow to models unchecked. Responses flow back unexamined. No one knows what was asked, what was answered, or whether any of it violated policy. Security teams have no visibility; compliance teams have no evidence.

**Yashigani's response:** Every prompt and every response passes through Yashigani's bidirectional inspection pipeline before reaching its destination. Inbound payloads are classified by a two-stage pipeline — a FastText ML classifier for low-latency first-pass detection (under 5ms, fully offline), followed by a configurable LLM-based deep inspection backend (Ollama, Anthropic Claude, Google Gemini, Azure OpenAI, or LM Studio). Responses are inspected on the return path with the same rigor. The pipeline is fail-closed: if all inspection backends are unavailable, the request is blocked by a sentinel policy, not passed through. Credential Harvesting Suppression (CHS) detects credential-shaped patterns in both directions. Every transaction produces a structured audit event written simultaneously to multiple sinks — local file, PostgreSQL (with row-level security and AES-256-GCM column encryption), and SIEM platforms (Splunk, Elasticsearch, Wazuh). Nothing passes uninspected. Nothing passes unrecorded.

### 2.2 Identity Sprawl

Enterprise AI deployments accumulate separate identity silos: user stores for the chat interface, agent registries for service accounts, API key tables for integrations, IdP configurations per department. Each silo has its own lifecycle, its own governance gap, and its own audit blind spot. When a security incident occurs, correlating "which entity did what" across disconnected registries is forensic archaeology.

**Yashigani's response:** Yashigani's unified identity model treats every entity — human user, AI agent, service account, API integration — as a first-class identity with a `kind` field. One registry, one governance framework, one audit trail. Humans and agents are subject to the same RBAC policies, the same rate limits, the same budget constraints, and the same audit depth. OPA policy enforcement is identity-aware across all entity types. There is no separate "agent management console" — because there is no separate identity class.

### 2.3 Uncontrolled AI Spend

Cloud LLM costs spiral without visibility or limits. A single team can burn through thousands in a day. A misconfigured agent can loop on expensive models indefinitely. CFOs discover the damage in the monthly invoice. Traditional rate limiting is too coarse — it caps requests, not dollars — and hard rejection breaks user workflows.

**Yashigani's response:** The three-tier budget system enforces spend governance with mathematical guarantees. Organization-level cloud caps set the hard ceiling. Group budgets allocate within that ceiling. Individual budgets constrain each user or agent. When a budget is exhausted at any tier, the system degrades gracefully to local inference via the Optimization Engine — the user's request is still served, just routed to a local model instead of a cloud API. Yashigani never rejects a request due to budget exhaustion. It never stops working. It just stops spending.

### 2.4 Data Leakage to Cloud Providers

Sensitive data — PII, PCI cardholder data, intellectual property, PHI — is sent to cloud LLM APIs without detection or classification. Once transmitted, data may be retained, logged, or used for training. Traditional DLP solutions were not designed for LLM payloads: they do not understand prompt structure, they cannot classify at inference speed, and they cannot enforce routing decisions based on sensitivity.

**Yashigani's response:** The three-layer sensitivity pipeline classifies every prompt before routing. Layer 1: regex pattern matching catches structured sensitive data (credit card numbers, SSNs, API keys). Layer 2: FastText ML classifier detects semantic sensitivity at under 5ms, fully offline. Layer 3: Ollama LLM classification provides deep contextual analysis for ambiguous cases. Data classified as CONFIDENTIAL or RESTRICTED is routed to local models only — this is an immutable rule enforced by the Optimization Engine. No override exists. No admin can bypass it. No configuration can disable it. CHS additionally strips credential-shaped patterns from payloads before any AI inspection backend sees them.

### 2.5 Routing Opacity

When an AI request is routed to a cloud model versus a local model, no one knows why. When a particular model is selected over alternatives, there is no reasoning trail. Debugging cost anomalies, sensitivity violations, or performance issues requires guesswork. Auditors asking "why did this request go to OpenAI instead of staying local?" get no answer.

**Yashigani's response:** The Optimization Engine makes deterministic P1-P9 routing decisions based on four dimensions: sensitivity classification, request complexity, budget state, and model cost. Every routing decision is audited with a full reasoning chain — which factors were evaluated, what scores they produced, which priority level was assigned, and which model was selected. The decision is reproducible: given the same inputs, the same routing decision is made every time. Auditors, security teams, and cost analysts can trace any request from prompt to model selection to response, with complete justification at every step.

### 2.6 Multi-IdP Complexity

Enterprise deployments rarely have a single identity provider. Entra ID for corporate users in one country, a separate Entra ID tenant for another region, Okta for contractors, Google Workspace for a subsidiary acquired last year. Traditional approaches require deploying and maintaining an external identity broker like Keycloak — another service to secure, patch, and scale.

**Yashigani's response:** Yashigani IS the identity broker. Native support for OIDC and SAML v2 federation means multiple identity providers connect directly to the gateway. No external Keycloak instance, no additional infrastructure, no separate identity management surface. Users authenticate through their existing IdP; Yashigani maps the external identity to its unified identity model, applies consistent RBAC policies regardless of IdP origin, and produces a single audit trail across all authentication sources. One fewer service in the stack. One fewer attack surface.

### 2.7 Agent Data Isolation

When multiple users share an AI agent instance — or when a shared model runtime serves concurrent requests — data leaks between users. User A's context contaminates User B's session. Shared container filesystems mean one user's uploaded documents are accessible to another's agent process. This is not a theoretical concern; it is the default behavior of most agent deployment architectures.

**Yashigani's response:** Yashigani enforces container-per-identity isolation. Every user gets their own isolated container instance for agent execution. No shared instances. No shared filesystems. No shared model context. The Pool Manager provisions and manages these containers automatically — users do not need to request isolation, and administrators cannot disable it. This is a security product. Isolation is not a feature toggle; it is an architectural invariant.

### 2.8 Infrastructure Fragility

Containers crash. Models fail to load. Ollama instances run out of memory. Services go down without warning. In most AI deployments, a crashed container means a user is offline until someone notices and manually restarts it. Forensic evidence — logs, container state, filesystem changes — is destroyed on restart. Capacity planning for local model inference is guesswork.

**Yashigani's response:** The Pool Manager replaces broken containers instantly and transparently. Health checks detect failures; replacement containers are provisioned from the warm pool before the user notices the interruption. Ollama instances scale horizontally based on load. When a container fails, Yashigani preserves forensic evidence before cleanup — postmortem logs, container inspect output, and filesystem diffs are captured for root cause analysis. Dead containers are not just restarted; they are investigated. The warm pool ensures that replacement capacity is always available, and horizontal Ollama scaling ensures that local model inference does not become the bottleneck that forces premature cloud routing.

---

## 3. Architecture Overview

Yashigani is structured as a two-plane system: a **data plane** that handles the real-time request path, and a **control plane** (backoffice) that manages configuration, identity, policies, and audit storage.

### 3.1 Request Flow

```
AI Agent / Human (via Open WebUI or API)
        |
        v
[ Caddy TLS Edge ]          <-- ACME / CA-signed / self-signed
        |                       /chat/* → Open WebUI
        |                       /admin/* → Backoffice
        |                       /v1/*, /agents/*, /* → Gateway
        v
[ Identity Broker ]         <-- Multi-IdP: OIDC + SAML v2 (v2.0)
        |                       Unified identity model (kind field)
        v
[ Authentication Layer ]    <-- Session auth, API key, Bearer token,
        |                       TOTP/2FA, OIDC, SAML v2, JWT introspection
        v
[ RBAC / Authorization ]    <-- OPA policy engine, role resolution
        |
        v
[ Sensitivity Pipeline ]    <-- Three layers (all ON by default):
        |                       1. Regex pattern matching
        |                       2. FastText ML classifier (<5ms)
        |                       3. Ollama LLM classification
        |                       + CHS credential detection
        |                       + Payload masking before AI send
        v
[ Optimization Engine ]     <-- Four-dimensional routing (v2.0):
        |                       sensitivity + complexity + budget + cost
        |                       P1-P9 priority matrix
        |                       CONFIDENTIAL/RESTRICTED → always local
        |                       Budget exhaustion → degrade to local
        v
[ Budget Enforcement ]      <-- Three-tier hierarchy (v2.0):
        |                       org cloud cap → group → individual
        |                       budget-redis (noeviction)
        v
[ Rate Limiting ]           <-- Redis fixed-window, per-endpoint
        |
        v
[ OPA Routing Safety Net ]  <-- Second OPA pass on routing decisions
        |                       + LLM policy review (v2.0)
        v
[ Upstream LLM / MCP ]      <-- Cloud API / Ollama / MCP tool server
        |
        v
[ Response Inspection ]     <-- Masking, sanitization, cache check
        |
        v
[ Audit Write ]             <-- File + PostgreSQL + SIEM (async)
        |                       P1-P5 alert severity (v2.0)
        v
AI Agent / Human (response)
```

### 3.2 Components

| Component | Role |
|---|---|
| **Gateway (data plane)** | Reverse proxy, TLS, auth, inspection, rate limiting, routing, Optimization Engine |
| **Backoffice (control plane)** | Admin UI/API, identity management, policy editor, license validation, budget admin |
| **Open WebUI** | Chat interface at /chat/*, internal network only, all LLM calls through gateway (v2.0) |
| **Optimization Engine** | Four-dimensional routing: sensitivity + complexity + budget + cost; P1-P9 priority matrix (v2.0) |
| **Identity Broker** | Multi-IdP identity broker: OIDC + SAML v2; Caddy delegates auth (v2.0) |
| **Pool Manager** | Per-identity container lifecycle: create, route, health, replace, scale, postmortem forensics (v2.0) |
| **OPA Policy Engine** | Declarative, version-controlled authorization for every tool call; routing safety net with LLM policy review (v2.0) |
| **Sensitivity Pipeline** | Three-layer classification: regex + FastText ML + Ollama; all ON by default (v2.0) |
| **Inspection Pipeline** | FastText ML + multi-backend LLM inspection with fail-closed sentinel |
| **Audit Pipeline** | Multi-sink writer: file, PostgreSQL, Splunk, Elasticsearch, Wazuh; P1-P5 alert severity with SIEM integration (v2.0) |
| **PgBouncer** | PostgreSQL connection pooler, prevents connection exhaustion (password from .env since v1.09.5) |
| **Redis** | Rate limiting, response caching, anomaly detection sliding windows |
| **Budget Redis** | Dedicated budget counter store (noeviction policy), prevents counter eviction under memory pressure (v2.0) |
| **Key Management System** | KMS integration: Keeper, AWS KMS, Azure Key Vault, GCP KMS, HashiCorp Vault |
| **Prometheus / Grafana** | Metrics collection and 12 dashboards (9 existing + 3 new: budget, OE, pool manager) (v2.0) |
| **Loki / Promtail** | Log aggregation and shipping |
| **Alertmanager** | 3-channel escalation: Slack/email → PagerDuty |
| **OpenTelemetry / Jaeger** | Distributed tracing across gateway, inspection, and upstream |

### 3.3 Identity and Routing

Yashigani v2.0 introduces a unified identity model: every entity — human or service — is an identity with a `kind` field. There are no separate user and agent stores. The same governance, budget enforcement, RBAC, and audit trail apply to all identities regardless of kind. Humans carry optional IdP federation metadata; services carry optional upstream URL, container configuration, system prompt, and capability declarations. Both are managed through the same Web UI and API.

Incoming bearer tokens identify the calling identity and the Optimization Engine determines routing based on four dimensions: data sensitivity classification, task complexity, remaining budget, and provider cost. The P1-P9 priority matrix governs routing decisions, with P1 (CONFIDENTIAL/RESTRICTED data) as the only immutable rule — such data always stays local. Budget exhaustion triggers graceful degradation to local inference; the system never rejects a request.

---

## 4. Security Features by Version

### Version Progression Summary

| Version | Theme | Key Additions |
|---|---|---|
| **v2.1** | **Admin Dashboard + Alerting + SSO + Persistence** | **Admin Dashboard UI (login page + 9-section admin panel), 12 Alertmanager P1-P5 routing/budget alert rules, Budget Postgres persistence (survives restarts), Pool Manager background health monitor (daemon thread), OPA v1_routing.rego verified operational, OIDC identity broker wired end-to-end (JWT validation, JWKS discovery, group extraction), mandatory 2FA after SSO (anti-replay), Keycloak test IdP, SSO audit trail (SHA-256 email hashing), Podman rootless parity (volume permissions fix, e2e runtime auto-detection), 413 tests (388 unit + 25 e2e)** |
| **v2.0** | **First production-grade release** | **Unified Identity Model (kind field, no separate user/agent stores), Optimization Engine (4D routing: sensitivity + complexity + budget + cost, P1-P9 priority matrix), three-tier Budget System (org cap → group → individual, budget-redis noeviction), Open WebUI integration (/chat/*, internal only), Container Pool Manager (per-identity isolation, self-healing, postmortem forensics, Ollama horizontal scaling), Multi-IdP Identity Broker (OIDC + SAML v2), sensitivity classification pipeline (regex + FastText + Ollama, all ON by default), P1-P5 alert severity with SIEM integration, OPA routing safety net with LLM policy review, 17 core services + 3 optional agent bundles + dynamic per-identity containers, 363 tests (252 + 111 new), 12 Grafana dashboards** |
| v1.09.5 | Agent bundles GA + Podman | Agent bundles (LangGraph, Goose, OpenClaw) work out of the box with PSK auto-registration, first-class Podman support (runtime detection, compose command, auto-apply podman override), DNS fix for Ollama external network access, admin accounts with fun codenames (animal/nature themed), PgBouncer password from .env, Alembic migrations in backoffice image, 18-service full stack verified from clean slate |
| v0.9.4 | Final hardening | Classifier regex fix (security: nested braces in inspection response no longer misclassified as CLEAN), FastAPI lifespan migration, localhost defaults replaced with Docker service names, CI version consistency gate |
| v0.9.3 | Bugfix and hardening (45-issue audit) | Rate limiter bypass fix, OllamaPool stack overflow fix, Vault KMS provider fix, response inspection pipeline activation, ECDSA P-256 license key embedded, all Docker images pinned, WebAuthn migration, integration test suite, 18 bare-exception handlers replaced with logging, CI license key gate, Redis scan_iter, IPv6-safe IP masking |
| v0.9.2 | Installer env var and bash 3.2 compat fixes | Full `.env` writer sets all required vars before compose pull (fixes `UPSTREAM_MCP_URL` error); `update.sh` process substitution replaced with `find | while read` (bash 3.2 compat) |
| v0.9.1 | Installer security hardening — credential bootstrap | Dual admin accounts (random themed usernames) with TOTP 2FA at install, HIBP k-Anonymity breach check on all generated passwords, credential summary at install completion, secrets written to docker/secrets/ chmod 600 |
| v0.9.0 | Post-quantum cryptography + security hardening | ECDSA P-256 licence signing (ML-DSA-65 planned), hybrid TLS X25519+ML-KEM-768 (pending Caddy 2.10), response-path inspection (F-01), WebAuthn/Passkeys (S-01), break-glass dual-control, SHA-384 Merkle audit chain, async SIEM queue, agent PSK auto-rotation, real-time SSE inspection feed, searchable + exportable audit log, installer deployment modes redesign |
| v0.8.4 | Installer patch — macOS + GPU + Podman | Fixed platform detection, GPU detection (Apple Silicon/NVIDIA/AMD), bash 3.2 compat, Podman runtime, Docker Desktop CLI auto-fix, numbered agent bundles, runtime-agnostic compose, interactive fallbacks, `update.sh`, `test-installer.sh` |
| v0.8.0 | Optional agent bundles + agent UX | Opt-in LangGraph / Goose / OpenClaw containers (Compose profiles + Helm toggles), installer agent selection step with disclaimer, `GET /admin/agent-bundles` catalogue API, agent detail quickstart snippet endpoint, rate limit `last_changed` timestamp |
| v0.7.1 | Alert wiring + partition bootstrap | Direct alert dispatch on credential exfil + licence expiry monitor, partition bootstrap migration (2026-05 → 2027-06), full DB health unit test suite |
| v0.7.0 | Operational hardening + OPA Policy Assistant | ECDSA P-256 key active, DB partition automation + monitoring, OPA Policy Assistant (NL → RBAC JSON), MCP quick-start snippets, direct webhook alerting (Slack/Teams/PagerDuty), CIDR IP allowlisting per agent, path matching parity fix, runtime-configurable rate limit thresholds |
| v0.6.2 | Starter tier + three-dimensional limits | 5-tier model adds Starter (OIDC-only), max_end_users + max_admin_seats split, v3 license payload schema |
| v0.6.1 | Tier restructuring + open-source licensing | 4-tier model (Community/Professional/Professional Plus/Enterprise), Apache 2.0 community license, CLA framework |
| v0.6.0 | Universal installer + licensing | Linux/macOS/cloud/VM installer, 3-tier licensing (Community/Professional/Enterprise), ECDSA P-256 license verification, feature gates |
| v0.5.0 | Data plane hardening + observability | PostgreSQL 16 RLS + AES-256-GCM, pg_partman, PgBouncer, JWT introspection (JWKS waterfall), multi-sink audit, OTEL/Jaeger, FastText ML, Vault KMS, Loki, Alertmanager, per-endpoint rate limiting, response caching, Wazuh, anomaly detection, inference logging, container hardening, structured JSON logging |
| v0.4.0 | Cloud-native operations | Kubernetes Helm charts, GitHub Actions CI/CD, KEDA autoscaling, pod disruption budgets, network policies, Trivy scanning, CODEOWNERS |
| v0.3.0 | Enterprise identity + inspection | RBAC via OPA, agent routing, multi-backend inspection (5 providers), OIDC + SAML v2 SSO, SCIM, fail-closed sentinel, response masking, payload masking |
| v0.2.0 | TLS and identity hardening | ACME/CA/self-signed TLS, Prometheus metrics, bcrypt, multi-admin with lockout protection |
| v0.1.0 | Core gateway | MCP proxy, prompt injection (Ollama), CHS, OPA, session/API key auth, audit log, Redis rate limiting, TOTP/2FA, Argon2 |

### v2.1 — Admin Dashboard, Alerting, and Persistence

v2.1 adds the management layer that makes Yashigani self-service. The Admin Dashboard provides a login page and a 9-section admin panel covering identities, budgets, routing, policies, alerts, audit, models, agents, and system health. Operators no longer need curl or API knowledge to manage the platform.

**Admin Dashboard UI** -- A web-based admin panel served behind Caddy authentication. The login page authenticates against the backoffice identity broker. Nine sections provide full visibility and control: identity management, budget configuration and status, routing policy, OPA policy editor, alert configuration, audit log viewer, model alias management, agent registry, and system health overview.

**Alertmanager Rules** -- 12 Alertmanager rules covering P1-P5 severity levels for routing and budget conditions. Rules fire on sensitivity breaches, OPA overrides, classification conflicts, spending anomalies, budget exhaustion, and budget auto-switch events. All rules route through the existing SIEM integration pipeline.

**Budget Postgres Persistence** -- Budget counters are now persisted to PostgreSQL in addition to budget-redis. Budget state survives container restarts and Redis eviction. The persistence layer writes asynchronously to avoid adding latency to the request path.

**Pool Manager Background Health Monitor** -- The Pool Manager now runs a daemon thread that continuously monitors container health. Unhealthy containers are detected and replaced without waiting for a failed request to trigger self-healing.

**OIDC Identity Broker (end-to-end)** -- The identity broker's OIDC flow is now fully operational. `handle_oidc_callback()` delegates to `OIDCProvider.exchange_code()` with real JWT validation, JWKS discovery, and group extraction supporting Entra ID, Okta, Cognito, and Keycloak group claim patterns. SSO routes: `/auth/sso/select` (IdP picker), `/auth/sso/oidc/{idp_id}` (OIDC redirect), `/auth/sso/oidc/{idp_id}/callback` (code exchange + identity resolution). IdPs are configured via `YASHIGANI_IDP_<N>_*` environment variables. CSRF protection via Redis-backed state/nonce tokens with 10-minute TTL (ASVS V3.5.3). SSO audit events use SHA-256 email hashing — raw email never stored.

**Mandatory 2FA After SSO** -- Even after successful IdP authentication, users must complete Yashigani's own TOTP verification. This prevents session hijack and replay attacks — a stolen session cookie is useless without a valid TOTP code. Controlled via `YASHIGANI_SSO_2FA_REQUIRED` (default: `false` for testing, `true` recommended for production).

**Keycloak Test IdP** -- A Docker Compose `test-idp` profile provides a pre-configured Keycloak instance with OIDC and SAML clients, three test users (alice, bob, carol), and group mappers for ID token claims. Start with `docker compose --profile test-idp up -d keycloak`.

**Podman Rootless Parity** -- Full Podman rootless support with correct user namespace configuration. Root-running services (Ollama, Postgres, Redis, Caddy) no longer use `keep-id` which caused volume permission failures. E2E test suite auto-detects runtime (Podman or Docker) via `YASHIGANI_RUNTIME` env var or container probing. Chaos tests handle Podman's restart behavior (explicit restart after kill). 413 tests pass on both Docker and Podman deployments.

**OPA v1_routing.rego Verified Operational** -- The OPA routing safety net policy (v1_routing.rego) has been verified end-to-end in the production configuration. Policy evaluation, LLM validation of policy changes, and SAFE/WARNING/BLOCK verdicts are all confirmed operational.

**Additional v2.1 changes:**
- 413 tests passing (388 unit + 25 e2e)

### v2.0 — First Production-Grade Release

v2.0 is Yashigani's first production-grade release, adding five major subsystems that transform the gateway from a security enforcement proxy into a complete AI operations platform with intelligent routing, budget governance, and unified identity management.

**Unified Identity Model** -- Every entity in the system — human user, AI agent, service account — is now a single identity record with a `kind` field. There are no separate user and agent stores. The same governance, budget enforcement, RBAC rules, and audit trail apply uniformly to all identities. Human identities carry optional IdP federation metadata; service identities carry optional upstream URL, container configuration, system prompt, and capability declarations. Both are managed through the same Web UI and API, under the same rules.

**Optimization Engine** -- The gateway now performs four-dimensional routing on every LLM request, evaluating data sensitivity classification, task complexity, remaining budget, and provider cost to select the optimal backend. A P1-P9 priority matrix governs routing decisions. P1 is immutable: CONFIDENTIAL and RESTRICTED data always stays local — this is enforced by both the Optimization Engine and an OPA routing safety net that performs a second policy pass on every routing decision. Budget exhaustion triggers graceful degradation to local inference; the system always responds and never rejects a request. The OPA routing safety net additionally uses a local LLM to validate OPA policy changes before they are applied, checking for self-lock conditions, contradictions, scope issues, and routing conflicts, returning SAFE/WARNING/BLOCK verdicts.

**Three-Tier Budget System** -- A hierarchical budget model enforces cloud spend governance with mathematical guarantees. The org cloud cap is the hard ceiling. Group budgets are allocated beneath it. Individual budgets are allocated within groups. The sum of individual budgets never exceeds the group budget; the sum of group budgets never exceeds the org cap. Budget counters are stored in a dedicated budget-redis container configured with a noeviction policy to prevent counter loss under memory pressure. Budget state is exposed to clients via `X-Yashigani-Budget-*` response headers.

**Open WebUI Integration** -- Open WebUI is integrated at `/chat/*` behind Caddy, accessible only on the internal Docker network. Open WebUI holds zero LLM credentials — all inference calls (cloud and local) route through the gateway. Caddy delegates authentication to the backoffice, which acts as the identity broker, and forwards trusted headers (`WEBUI_AUTH_TRUSTED_EMAIL_HEADER`) to Open WebUI. Pipelines make LLM and MCP tool calls through the gateway.

**Container Pool Manager** -- The Pool Manager provides per-identity container isolation with a universal container lifecycle: create, route, health check, replace, scale, and postmortem. The operational philosophy is self-healing: broken containers are replaced, not fixed. Before a dead container is killed, postmortem evidence (logs, inspect output, filesystem diff) is preserved for forensic analysis. Ollama scales horizontally under load. The same replace-and-scale pattern applies to all stateless core containers. License tiers gate container limits: Community (1 per service per identity, 3 total), Starter (1/5), Professional (3/15), Professional Plus (5/50), Enterprise (unlimited), Academic (1/3).

**Multi-IdP Identity Broker** -- Yashigani is the identity broker. It supports multiple identity providers natively via OIDC and SAML v2. Caddy delegates all authentication decisions to the backoffice. SCIM provisions users and groups. Group policies govern model and agent access. IdP limits are tier-gated: Community supports local auth only, Starter supports 1 OIDC provider, Professional supports 1 OIDC + 1 SAML, Professional Plus supports 5 IdPs, Enterprise is unlimited, and Academic supports 1 OIDC provider.

**Sensitivity Classification Pipeline** -- Every prompt passes through a three-layer sensitivity classification pipeline, all layers ON by default. Layer 1 (regex) matches patterns for PII, PCI, intellectual property, and PHI. Layer 2 (FastText ML) provides sub-5ms offline classification. Layer 3 (Ollama qwen2.5) performs deep semantic analysis. Administrators can customize patterns per tenant and opt out of the Ollama layer, but cannot disable regex. Classification results feed directly into the Optimization Engine's routing decisions.

**P1-P5 Alert Severity with SIEM Integration** -- Routing decisions are audit events written through the existing audit pipeline to all SIEM sinks. A P1-P5 severity scale triggers on specific conditions: sensitivity breach (P1), OPA override (P1), classification conflict (P2), spending anomaly (P2), budget auto-switch (P3), and others.

**Additional v2.0 changes:**
- 17 core services + 3 optional agent bundles + dynamic per-identity containers (up from 18 services in v1.09.5)
- 363 tests passing (252 original + 111 new)
- 12 Grafana dashboards (9 existing + 3 new: budget, Optimization Engine, Pool Manager)
- Model alias table: DB-driven via admin API, Postgres + Redis cache, CRUD at `/admin/models/aliases`
- Streaming: buffered mode (full response before delivery) for v2.0; response inspection completes before user sees anything; chunk-level streaming deferred to v2.1
- User API keys: 256-bit hex, bcrypt cost 12, max lifetime 1 year, default rotation 90 days, 7-day grace period

### v1.09.5 — Agent Bundles GA and Podman Support

v1.09.5 makes agent bundles and Podman first-class citizens of the deployment experience. The three agent bundles — LangGraph, Goose, and OpenClaw — now work out of the box on a clean install: the installer auto-registers each selected bundle as an agent with a pre-shared key (PSK) token, eliminating the manual agent registration step that previously blocked new operators from reaching a working agent stack. The full stack now comprises 18 services (15 core + 3 agent bundles), all verified working from a clean-slate install.

Podman received first-class support: the installer performs runtime detection, selects the correct compose command (`podman compose` vs `docker compose`), and auto-applies the Podman override file where needed. This extends the v0.8.4 Podman groundwork into a fully automated experience.

A DNS fix resolved a networking issue where the `ollama` and `ollama-init` containers were unable to reach external model registries for model downloads. Both containers are now placed on the external network, restoring model registry access without compromising the internal service network isolation.

Admin account provisioning was enhanced: auto-generated accounts now use fun animal/nature-themed codenames as usernames, with TOTP pre-provisioned at install time. PgBouncer password handling was corrected to read the password from `.env` rather than using a hardcoded or missing value. Alembic database migrations are now included directly in the backoffice Docker image, ensuring schema migrations run automatically on container startup without requiring a separate migration step.

All 18 services have verified health checks from a clean-slate installation using the following command:

```bash
bash install.sh --non-interactive --deploy demo --domain yashigani.local --tls-mode selfsigned --admin-email admin@yashigani.local --agent-bundles langgraph,goose,openclaw
```

### v0.9.4 — Final Hardening Before v2.0

v0.9.4 is the final hardening release before v2.0 development begins. It closes the last known security-relevant bug in the inspection pipeline: the classifier's JSON extraction regex silently misclassified valid injection detections as CLEAN when the LLM response included nested objects in the `detected_payload_spans` field. The regex-based extraction was replaced with a brace-depth counting parser that correctly handles arbitrarily nested JSON. The FastAPI gateway migrated from the deprecated `@app.on_event` pattern to the recommended `lifespan` context manager, eliminating all deprecation warnings. Default service URLs throughout the codebase were standardized to Docker Compose service names (`redis`, `ollama`, `policy`) instead of `localhost`, preventing silent failures in containerized deployments where localhost does not resolve to the expected service. A CI gate was added to verify that `__init__.py` and `pyproject.toml` versions remain in sync. The installer's Prometheus hash generation was fixed for macOS: `passlib` crashes on `bcrypt` 5.x due to a removed API, so the hash generation was replaced with a three-method fallback chain (htpasswd, direct bcrypt module, hashlib PBKDF2) that works reliably on both macOS and Linux.

### v0.9.3 — Full Codebase Audit and Hardening

v0.9.3 was the most comprehensive single-version quality pass in the project's history, addressing all 45 issues found in a full codebase audit. Three critical bugs were closed: an operator precedence error in the rate limiter that allowed unauthenticated sessions to bypass session-level rate limiting; an unbounded recursive call in `OllamaPool.classify()` that caused stack overflow when all Ollama backends were unhealthy simultaneously; and a Vault KMS provider that inherited from a nonexistent base class, preventing instantiation. The `ResponseInspectionPipeline` introduced in v0.9.0 was wired into the gateway but never invoked in the default request path — v0.9.3 activated it, closing the response-path injection vector that v0.9.0 had intended to address. The ECDSA P-256 production public key was embedded in the verifier, making license tier enforcement fully active for the first time since v0.7.0 shipped the key infrastructure. Every Docker image across `docker-compose.yml`, Helm charts, and the agent bundles catalogue was pinned to a specific version, eliminating mutable-tag supply-chain risk. A WebAuthn credentials Alembic migration was created so upgrades from v0.9.0–v0.9.2 apply cleanly. An integration smoke test suite was shipped. Eighteen bare `except Exception: pass` handlers throughout the gateway were replaced with structured debug logging. A CI gate was added to reject builds containing the placeholder license key. Redis `keys()` calls were replaced with `scan_iter()` to eliminate blocking keyspace scans. IPv6 address handling was corrected in session IP masking. All 32 pre-existing stale unit tests were updated to match the current production API signatures, bringing the test suite to 252 tests with 0 failures.

### v0.9.2 — Installer Compatibility Fixes

v0.9.2 fixed two regressions introduced during the v0.9.0 installer redesign. The `.env` writer was incomplete: only the AES key was being written before `docker compose pull` ran, causing `UPSTREAM_MCP_URL` to be undefined in the compose environment and producing a startup error on fresh installs. The function was expanded into a full `.env` writer that sets all required variables — `UPSTREAM_MCP_URL`, `YASHIGANI_TLS_DOMAIN`, `YASHIGANI_ADMIN_EMAIL`, `YASHIGANI_ENV`, and the AES key — before compose is invoked. Demo mode defaults `UPSTREAM_MCP_URL` to `http://localhost:8080/echo`. Additionally, `update.sh` used a process substitution (`< <(find ...)`) that is a bash 4+ feature not available in macOS's default bash 3.2; this was replaced with a `find | while read` pipe that is fully compatible.

### v0.9.1 — Installer Credential Bootstrap

v0.9.1 hardened the credential bootstrap process that v0.9.0's installer redesign had left incomplete. Rather than generating a single admin account and requiring operators to create additional accounts manually, the installer now creates two admin accounts at install time with randomly generated themed usernames — eliminating the single-admin lockout risk from day one. TOTP 2FA is fully provisioned for both accounts during installation: the TOTP secret and `otpauth://` URI are generated, displayed, and immediately ready for import into any authenticator app. All generated passwords are checked against the Have I Been Pwned breach database using SHA-1 k-Anonymity prefix lookup before use; any compromised password is automatically regenerated and rechecked. The same HIBP check was added to the backoffice password-change path, implementing OWASP ASVS V2.1.7. A one-time credential summary block is displayed at the end of install showing all passwords, TOTP secrets, URIs, and the AES key. All credentials are persisted to `docker/secrets/` with permissions 0600.

### v0.9.0 — Post-Quantum Readiness and Security Hardening

v0.9.0 was the largest security-focused release since v0.5.0. ECDSA P-256 licence signing was shipped for offline, air-gapped licence verification with no call-home requirement (ML-DSA-65 post-quantum migration is planned when the Python `cryptography` library ships FIPS 204 support). A hybrid TLS X25519+ML-KEM-768 Caddyfile configuration was included but remains commented pending Caddy 2.10 support. The response-path injection vector was closed: `ResponseInspectionPipeline` applies FastText + LLM fallback classification to upstream responses, blocking tainted tool outputs before they reach the calling agent. WebAuthn/Passkey MFA was added, supporting Face ID, Touch ID, Windows Hello, and hardware security keys (YubiKey) — coexisting with TOTP so operators can choose their preferred second factor. Operations were hardened with break-glass dual-control (hard TTL, Redis-backed, tamper-evident audit trail), a SHA-384 Merkle audit hash chain with daily anchors and a CLI verification tool, and an async SIEM delivery queue with DLQ after 3 retries. Agent PSK auto-rotation via APScheduler and KMS push ensures long-lived tokens are cycled automatically. Real-time operator visibility arrived via a Server-Sent Events inspection feed and searchable/exportable audit logs. The installer was redesigned around three deployment modes: Demo, Production, and Enterprise.

### v0.8.4 — Installer Hardening for macOS, GPU, and Podman

v0.8.4 addressed a cluster of installer failures discovered after v0.8.0 shipped — specifically on macOS with Apple Silicon, Podman, and Docker Desktop environments. Platform detection was fixed by correcting a variable naming mismatch (`DETECTED_*` vs `YSG_*`) that caused the platform summary to report incorrect values. GPU detection was added for Apple Silicon M-series (unified memory, Metal, ANE), NVIDIA, and AMD GPUs with an lspci fallback; Ollama model size recommendations are printed based on detected VRAM. The macOS `df -BG` (GNU-only) flag was replaced with `df -k` and compatible arithmetic. Podman became a first-class supported runtime alongside Docker Engine and Docker Desktop. A Docker Desktop CLI auto-fix was added for environments where Docker Desktop is installed but `docker` is not in PATH. Bash 3.2 compatibility was enforced throughout by replacing all `${var,,}` expansions with `tr`. Agent bundle selection was changed from individual y/n prompts to a numbered menu, eliminating typo-related crashes. A new `update.sh` script handles in-place upgrades with automatic backup, image pull, restart, and rollback on failure. A 7-test automated installer validation suite (`test-installer.sh`) covering 28 checks was added to CI.

### v0.8.0 — Agent Ecosystem Integration

v0.8.0 addressed operator demand for first-class agentic framework support without forcing Yashigani's security boundary to become optional. LangGraph, Goose, and OpenClaw are available as opt-in Docker Compose profiles and Helm toggles — all agent traffic from these containers routes through Yashigani's enforcement layer and is subject to the same inspection, authorization, and audit pipeline as any other agent. A new `GET /admin/agent-bundles` endpoint exposes the bundle catalogue with metadata and a third-party disclaimer for the UI banner. `GET /admin/agents/{id}/quickstart` returns copy-paste curl, Python httpx, and health check snippets on the agent detail page, reducing time-to-first-call for new agent deployments. The rate limit config endpoint was extended with a `last_changed` timestamp, making threshold change history auditable without requiring a full audit log query.

### v0.7.1 — Alert Wiring and Partition Bootstrap

v0.7.1 completed the three remaining code gaps from v0.7.0. The direct webhook alert dispatcher was wired to the two actual trigger points: credential exfil detections in the inspection pipeline now call `dispatcher.dispatch_sync()` immediately on detection, and a new background monitor (`licensing/expiry_monitor.py`) runs daily via APScheduler to fire a warning alert when the active licence is within the configured expiry window (default 14 days). A daily-rate guard prevents alert storms. An Alembic migration (`0003`) pre-creates all `audit_events` and `inference_events` partitions for 2026-05 through 2027-06, ensuring a clean bootstrap without relying on the CronJob to have run first. A full unit test suite for `db/health.py` was added covering all partition check paths including DB error handling.

### v0.7.0 — Operational Hardening and OPA Policy Assistant

v0.7.0 closed three critical pre-production blockers and delivered the headline OPA Policy Assistant feature alongside five operational improvements.

The three blockers were: (1) the ECDSA P-256 public key placeholder in the license verifier was replaced with the real production key, making license tier enforcement active for the first time; (2) database partition automation was introduced — a maintenance script and Kubernetes CronJob pre-create monthly partitions for `audit_events` and `inference_events`, preventing silent write failures at month rollover; (3) a Prometheus gauge (`yashigani_audit_partition_missing`) and Alertmanager alert rule make missing partitions immediately observable.

The **OPA Policy Assistant** allows administrators to describe an access control requirement in plain English; an internal Ollama model (qwen2.5:3b) generates the RBAC data document JSON, which is validated against the schema and presented to the admin for review before anything is applied. Admins approve or reject; the entire flow is written to the audit log. The assistant generates only the data document — it never creates or modifies Rego policy files.

Additional improvements: agent registration now returns a `quick_start` snippet with curl, Python httpx, and health check examples using the live bearer token; direct webhook alerting to Slack, Microsoft Teams, and PagerDuty was added as a lightweight alternative to the full Alertmanager stack (configurable per-event: credential exfil, anomaly threshold, licence expiry); CIDR-based IP allowlisting was introduced per agent — requests from authenticated agents arriving from outside their CIDR list are blocked 403 and audited; a path matching bug (IC-6) that caused OPA's `_path_matches` to allow single-segment wildcards to cross `/` boundaries was fixed with a correct regex-based implementation; and rate limit RPI scale thresholds became runtime-configurable via the backoffice without a gateway restart.

### v0.6.2 — Starter Tier and Three-Dimensional Limits

v0.6.2 completed the licensing model with three changes. First, a Starter tier (OIDC-only SSO, 100 agents) was added to fill the gap between Community and Professional for small teams with an SSO mandate. Second, the single user limit was split into two independent dimensions: `max_end_users` (people using AI tools through the gateway) and `max_admin_seats` (people managing the Yashigani control plane). Third, the license payload was updated to v3 schema with backwards-compat loading for v1/v2 license files.

### v0.6.1 — Tier Restructuring and Open-Source Licensing

v0.6.1 restructured the licensing tiers to reflect real-world deployment segment sizing and formalised the community open-source licensing model. Four tiers replaced the previous three: Community (20 agents, free), Professional (500 agents, 1 org), Professional Plus (2,000 agents, 5 orgs), and Enterprise (unlimited). The community edition adopted the Apache License 2.0, and a Contributor License Agreement (CLA) framework was introduced to allow community contributions to flow into all commercial tiers without copyright or patent encumbrance.

### v0.6.0 — Universal Installer and Licensing

Yashigani became self-distributable. The universal installer auto-detects OS, architecture, and cloud provider, then performs a full production-grade installation on Linux, MacOS, cloud VMs, and bare-metal. Three licensing tiers were introduced: Community (free, no key), Professional (paid, signed key), and Enterprise (paid, signed key with multi-tenancy). License verification uses ECDSA P-256 offline signature validation — no license server call-home required. Feature gates enforce SAML, OIDC, and SCIM access at the tier boundary. Agent and organization limits are enforced per tier.

### v0.5.0 — Data Platform and Full Observability

The most feature-dense release. PostgreSQL 16 with row-level security and AES-256-GCM column encryption via pgcrypto became the primary audit and operational data store. pg_partman and pg_cron automated monthly partition management. PgBouncer was added for connection pooling. JWT introspection implemented a JWKS waterfall supporting three deployment streams (opensource, corporate, SaaS). The audit pipeline became multi-sink: file, PostgreSQL, Splunk, Elasticsearch, and Wazuh simultaneously. OpenTelemetry distributed tracing with OTLP export to Jaeger made end-to-end latency visible. FastText ML added a sub-5ms, fully offline first-pass classifier. Severak KMS's implemented to provided AppRole authentication and KV v2 secrets management. Loki + Promtail consolidated log aggregation. Alertmanager delivered 3-channel escalation. Per-endpoint rate limiting and clean-only response caching (SHA-256 keyed) were introduced. Anomaly detection using Redis ZSET sliding windows caught repeated-small-call enumeration patterns. Inference payloads were logged in AES-encrypted form in Postgres. Container hardening applied seccomp allowlists, AppArmor profiles, UID 1001 non-root execution, tmpfs mounts for `/tmp` and audit buffers, and read-only root filesystem.

### v0.4.0 — Cloud-Native Operations

Kubernetes support arrived via production-ready Helm charts. GitHub Actions CI/CD pipelines automated build, test, and deployment workflows. KEDA-based horizontal autoscaling enabled the gateway to scale replica counts based on real load. Pod disruption budgets and network policies ensured high availability and network isolation in multi-tenant clusters. Trivy container scanning was integrated into the pipeline to catch CVEs before deployment. CODEOWNERS and branch protection enforced code review requirements on security-critical paths.

### v0.3.0 — Enterprise Identity and Inspection

This version transformed Yashigani from a single-organization tool into an enterprise-capable gateway. RBAC via OPA enabled fine-grained, role-based tool authorization. Agent routing with bearer token authentication allowed multi-agent deployments behind a single gateway. The inspection pipeline expanded from Ollama-only to a full multi-backend chain covering Anthropic Claude, Google Gemini, Azure OpenAI, LM Studio, and Ollama — with a fail-closed sentinel ensuring that unavailability of all backends results in request denial, not pass-through. SSO via OIDC and SAML v2, SCIM automated provisioning, response masking, and payload masking before AI inspection rounded out the release.

### v0.2.0 — Transport Security and Operational Robustness

TLS bootstrap was added with full support for ACME certificate provisioning (Let's Encrypt / ACME-compatible CAs), local CA signing, and self-signed certificates for air-gapped environments. Prometheus metrics provided the first visibility into gateway operations. Admin account management was strengthened: bcrypt was added alongside Argon2, multiple admin accounts became supported with minimum-count enforcement (preventing accidental lockout), and admin account lockout protection was implemented to resist brute-force attacks.

### v0.1.0 — Core Security Gateway

The initial release established the core security envelope. Yashigani began as a functional MCP reverse proxy with a meaningful security stack: prompt injection detection using a locally-hosted Ollama model, credential harvesting suppression on all payloads, OPA-based policy enforcement, session and API key authentication, TOTP-based two-factor authentication, Argon2 password hashing, file-based audit logging, and Redis rate limiting. This version made it possible to safely expose MCP servers to agents in a controlled environment.

---

## 5. Complete Feature List

### 5.1 Authentication and Identity

- Username and password authentication (Argon2 and bcrypt hashing)
- TOTP / HOTP two-factor authentication (2FA)
- API key authentication
- Session-based authentication with secure cookie management
- Bearer token authentication for agent routing
- JWT introspection with JWKS waterfall (3 deployment streams: opensource / corporate / SaaS)
- OpenID Connect (OIDC) SSO — Starter and above
- SAML v2 SSO — Professional and above
- SCIM automated user provisioning and deprovisioning — Professional and above
- Multiple admin accounts with minimum-count enforcement
- **Dual admin accounts provisioned at install (v0.9.1, v1.09.5)** — two accounts with fun animal/nature-themed codenames created during installation; TOTP 2FA pre-provisioned for both at install time
- Admin account lockout protection (brute-force resistance)
- **HIBP k-Anonymity breach check on password change (v0.9.1)** — `PasswordBreachedError` raised on known-breached passwords; OWASP ASVS V2.1.7 compliant; fail-open if API unreachable
- **Unified identity model (v2.0)** — every entity (human or service) is an identity with a `kind` field; no separate user/agent stores; same governance, budget, RBAC, and audit for all identity kinds
- **Multi-IdP Identity Broker (v2.0)** — Yashigani IS the identity broker; OIDC + SAML v2 native; Caddy delegates auth to backoffice; SCIM provisions users/groups; IdP limits tier-gated
- **User API keys (v2.0)** — 256-bit hex, bcrypt cost 12, max lifetime 1 year hard limit, default rotation 90 days, 7-day grace period, 14-day warning

### 5.2 Authorization and Policy

- Open Policy Agent (OPA) policy engine
- RBAC (Role-Based Access Control) via OPA
- Per-tool, per-route, per-agent policy enforcement
- URL allowlist enforcement (SSRF prevention)
- Hot-reloadable policies without gateway restarts
- Multi-organization support (Enterprise tier)
- Agent and organization limits enforced per license tier
- **OPA Policy Assistant** — natural language → RBAC JSON suggestion with admin approve/reject flow and full audit trail (v0.7.0)
- **CIDR-based IP allowlisting per agent** — requests from authenticated agents outside their IP allowlist are blocked 403 and audited
- **OPA routing safety net (v2.0)** — second OPA pass on every routing decision; local LLM validates OPA policy changes before applying (checks for self-lock, contradictions, scope issues, routing conflicts); SAFE/WARNING/BLOCK verdicts

### 5.3 Content Inspection and AI Safety

- FastText ML first-pass classifier (offline, under 5ms latency)
- Multi-backend LLM inspection chain:
  - Ollama (local)
  - Anthropic Claude
  - Google Gemini
  - Azure OpenAI
  - LM Studio
- Inspection backend fallback chain with fail-closed sentinel
- Prompt injection detection
- Credential Harvesting Suppression (CHS) on request and response payloads
- Payload masking before AI inspection (secrets not sent to external LLM APIs)
- Response masking and sanitization
- Anomaly detection: repeated-small-call pattern detection (Redis ZSET sliding window)
- Inference payload logging (AES-256-GCM encrypted, stored in Postgres)
- **Sensitivity classification pipeline (v2.0)** — three layers, all ON by default: regex pattern matching (PII, PCI, IP, PHI), FastText ML classifier, Ollama LLM classification; admin can opt out of Ollama but cannot disable regex; results feed into Optimization Engine routing
- **Optimization Engine (v2.0)** — four-dimensional routing (sensitivity + complexity + budget + cost); P1-P9 priority matrix; CONFIDENTIAL/RESTRICTED always local; budget exhaustion degrades to local, never rejects
- **Model alias table (v2.0)** — DB-driven via admin API, Postgres + Redis cache, CRUD at `/admin/models/aliases`

### 5.4 Audit and Compliance

- Structured JSON audit logging
- Multi-sink audit writer (simultaneous delivery):
  - Local file
  - PostgreSQL 16 (RLS + AES-256-GCM column encryption)
  - Splunk
  - Elasticsearch
  - Wazuh SIEM
- PostgreSQL audit tables with row-level security
- Monthly partition management via pg_partman, pg_cron, and Kubernetes CronJob (v0.7.0)
- Partition bootstrap migration pre-creates 14 months of partitions at install time (v0.7.1)
- Full request/response payload capture per audit event
- Inspection verdict recorded per audit event
- OPA policy decision recorded per audit event
- Agent identity recorded per audit event
- Wazuh self-hosted SIEM integration
- Audit events for: IP allowlist violations, rate limit threshold changes, OPA assistant generate/apply/reject (v0.7.0)
- **Routing decisions as audit events (v2.0)** — every OE routing decision written to all SIEM sinks via existing audit pipeline
- **P1-P5 alert severity scale (v2.0)** — sensitivity breach (P1), OPA override (P1), classification conflict (P2), spending anomaly (P2), budget auto-switch (P3); SIEM integration for all severity levels

### 5.5 Rate Limiting and Abuse Prevention

- Per-endpoint rate limiting (Redis fixed-window)
- Response caching for CLEAN-only verdicts (SHA-256 keyed, Redis-backed)
- Anomaly detection for enumeration and bulk extraction patterns
- Admin account lockout on repeated failed authentication
- **Runtime-configurable RPI scale thresholds** — tune medium/high/critical throttle multipliers from the backoffice without a gateway restart; changes audited (v0.7.0)

### 5.6 Budget Governance (v2.0)

- **Three-tier budget hierarchy** — org cloud cap → group budgets → individual budgets; math always enforced
- Sum of individual budgets never exceeds group budget; sum of group budgets never exceeds org cap
- Group-first provisioning: admin sets group budget, offers even distribution across individuals
- User-first provisioning: group budget auto-calculated from sum of individuals
- New user added to group: admin prompted to increase group budget or reduce existing individual budgets
- **Budget-redis** — dedicated Redis container with noeviction policy; prevents counter eviction under memory pressure
- **Budget response headers** — `X-Yashigani-Budget-*` headers expose remaining budget to clients
- Budget exhaustion triggers graceful degradation to local inference; system never rejects

### 5.7 Cryptography and Secrets

- Argon2 password hashing
- bcrypt password hashing
- AES-256-GCM column encryption in PostgreSQL via pgcrypto
- Several KMS supported - Keeper Security, AWS, GCP, Azure and HashiCorp Vault
- ECDSA P-256 offline licence signature verification (v0.9.0) — ML-DSA-65 migration planned when cryptography library ships FIPS 204 support
- Hybrid TLS X25519+ML-KEM-768 Caddyfile config included (pending Caddy 2.10) (v0.9.0)
- TLS bootstrap: ACME (Let's Encrypt / ACME-compatible), CA-signed, self-signed (demo)

### 5.8 Observability and Alerting

- Prometheus metrics (gateway, inspection, rate limiting, policy, database)
- Grafana dashboards
- OpenTelemetry distributed tracing (OTLP export to Jaeger)
- Loki log aggregation + Promtail log shipping
- Alertmanager 3-channel escalation: Slack + email (level 1) → PagerDuty (level 2)
- **Direct webhook alerting** — Slack, Microsoft Teams, PagerDuty as lightweight sinks for P1 events, independent of Alertmanager (v0.7.0)
- **`yashigani_audit_partition_missing` gauge** — fires when an upcoming monthly audit partition is absent; paired Alertmanager alert rule at `severity: critical` (v0.7.0)
- **Licence expiry background monitor** — daily check dispatches warning/critical alert when licence is within configurable day threshold (v0.7.1)
- Structured JSON logging throughout all components
- **12 Grafana dashboards (v2.0)** — 9 existing + 3 new: budget monitoring, Optimization Engine routing, Pool Manager container lifecycle

### 5.9 Infrastructure and Deployment

- Universal installer (Linux, macOS, cloud VM, bare-metal; auto-detects OS, arch, cloud provider, GPU, and container runtime)
- GPU detection at install time: Apple Silicon M-series (unified memory, Metal, ANE), NVIDIA (nvidia-smi, CUDA), AMD (rocm-smi, ROCm), lspci fallback; model recommendations printed based on detected VRAM (v0.8.4)
- Podman support as first-class runtime alongside Docker Engine and Docker Desktop (v0.8.4; runtime detection, compose command selection, and auto-apply podman override in v1.09.5)
- Interactive fallback prompts when OS, runtime, or GPU detection fails (v0.8.4)
- `update.sh` script for updating existing installations with automatic backup, pull, restart, and rollback (v0.8.4)
- Docker Compose single-node deployment
- Kubernetes Helm charts (production-ready)
- KEDA horizontal autoscaling
- Pod disruption budgets (HA)
- Kubernetes network policies
- Multi-replica deployment support
- GitHub Actions CI/CD pipeline
- Trivy container vulnerability scanning
- CODEOWNERS and branch protection enforcement
- Container hardening:
  - seccomp allowlist
  - AppArmor profile
  - UID 1001 non-root execution
  - tmpfs mounts for `/tmp` and audit buffer
  - Read-only root filesystem
- PgBouncer PostgreSQL connection pooling
- **Agent bundle containers** (v0.8.0, GA in v1.09.5) — LangGraph, Goose, OpenClaw as opt-in Docker Compose profiles and Helm toggles; installer auto-registers bundles with PSK tokens (v1.09.5); all agent traffic routes through Yashigani's enforcement layer; images are digest-pinned per release; third-party courtesy integrations (no support obligation)
  - **LangGraph** (port 8000) — multi-agent orchestration framework; shares Postgres (separate DB) and Redis (DB 5)
  - **Goose** (port 3284) — AI developer assistant; uses `goose serve` ACP over HTTP
  - **OpenClaw** (port 18789) — personal AI with 30+ messaging integrations; `OPENCLAW_CONFIG_JSON` routes through gateway
- **Open WebUI integration (v2.0)** — chat interface at `/chat/*`, internal Docker network only (no external port), all LLM calls through gateway, Caddy forwards trusted headers
- **Container Pool Manager (v2.0)** — per-identity container isolation; universal lifecycle: create, route, health check, replace, scale, postmortem; self-healing (replace, don't fix); postmortem forensics (logs, inspect, filesystem diff preserved before kill); Ollama horizontal scaling on load
- **Dynamic per-identity containers (v2.0)** — managed by Pool Manager; license tier gates container limits
- **17 core services + 3 optional agent bundles (v2.0)** — up from 18 in v1.09.5; plus dynamic per-identity containers
- **413 tests passing (v2.1)** — 388 unit + 25 e2e

### 5.10 Licensing and Tiers

- 6-tier licensing model: Community / Academic / Non-Profit / Starter / Professional / Professional Plus / Enterprise
- ECDSA P-256 offline license verification — no call-home, works air-gapped (v0.9.0) — ML-DSA-65 migration planned when cryptography library ships FIPS 204 support
- Three independent limit dimensions: agents, end users, admin seats
- **Container limits per tier (v2.0):** Community (1 per service per identity, 3 total), Starter (1/5), Professional (3/15), Professional Plus (5/50), Enterprise (unlimited), Academic (1/3)
- **Identity limits per tier (v2.0):** Community (20 identities), Starter (100), Professional (500), Professional Plus (2,000), Enterprise (unlimited), Academic (20)
- **IdP limits per tier (v2.0):** Community (local auth only), Starter (1 OIDC), Professional (1 OIDC + 1 SAML), Professional Plus (5 IdPs), Enterprise (unlimited), Academic (1 OIDC)
- Community tier: free, Apache 2.0, 5 agents, 10 end users, 2 admins
- Academic / Non-Profit tier: free (verified institution — see agnosticsec.com/academic)
- Starter, Professional, Professional Plus, Enterprise: signed license key required
- See agnosticsec.com/pricing for current tier limits and pricing
- Apache 2.0 open-source community license with Contributor License Agreement (CLA)

---

## 6. Feature Matrix by Tier

| Feature | Community | Academic / Non-Profit | Starter | Professional | Professional Plus | Enterprise |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Licensing** | | | | | | |
| Free, no license key | Yes | Yes (verified) | — | — | — | — |
| Signed paid license key | — | — | Yes | Yes | Yes | Yes |
| Pricing | Free | Free | See agnosticsec.com/pricing | See agnosticsec.com/pricing | See agnosticsec.com/pricing | Custom |
| Offline licence verification (ECDSA P-256) | Yes | Yes | Yes | Yes | Yes | Yes |
| Max agents / MCP servers | 5 | 50 | 100 | 500 | 2,000 | Unlimited |
| Max end users | 10 | 500 | 250 | 1,000 | 10,000 | Unlimited |
| Max admin seats | 2 | 10 | 25 | 50 | 200 | Unlimited |
| Max organizations / domains | 1 | 1 | 1 | 1 | 5 | Unlimited |
| **Authentication** | | | | | | |
| Username + password (Argon2 / bcrypt) | Yes | Yes | Yes | Yes | Yes | Yes |
| TOTP / 2FA | Yes | Yes | Yes | Yes | Yes | Yes |
| WebAuthn / Passkeys (v0.9.0) | Yes | Yes | Yes | Yes | Yes | Yes |
| API key authentication | Yes | Yes | Yes | Yes | Yes | Yes |
| Session authentication | Yes | Yes | Yes | Yes | Yes | Yes |
| Bearer token (agent routing) | Yes | Yes | Yes | Yes | Yes | Yes |
| JWT introspection / JWKS waterfall | Yes | Yes | Yes | Yes | Yes | Yes |
| OpenID Connect (OIDC) SSO | No | Yes | Yes | Yes | Yes | Yes |
| SAML v2 SSO | No | No | No | Yes | Yes | Yes |
| SCIM automated provisioning | No | No | No | Yes | Yes | Yes |
| Multiple admin accounts | Yes | Yes | Yes | Yes | Yes | Yes |
| Admin lockout protection | Yes | Yes | Yes | Yes | Yes | Yes |
| Unified identity model (v2.0) | Yes | Yes | Yes | Yes | Yes | Yes |
| Multi-IdP Identity Broker (v2.0) | Local only | 1 OIDC | 1 OIDC | 1 OIDC + 1 SAML | 5 IdPs | Unlimited |
| **Authorization** | | | | | | |
| OPA policy engine | Yes | Yes | Yes | Yes | Yes | Yes |
| RBAC via OPA | Yes | Yes | Yes | Yes | Yes | Yes |
| Per-tool / per-route policy | Yes | Yes | Yes | Yes | Yes | Yes |
| Multi-tenant org isolation | No | No | No | No | Partial (5 orgs) | Yes |
| OPA routing safety net + LLM policy review (v2.0) | Yes | Yes | Yes | Yes | Yes | Yes |
| **Content Inspection and Routing** | | | | | | |
| FastText ML classifier (offline, <5ms) | Yes | Yes | Yes | Yes | Yes | Yes |
| Response-path inspection (v0.9.0) | Yes | Yes | Yes | Yes | Yes | Yes |
| Ollama LLM inspection backend | Yes | Yes | Yes | Yes | Yes | Yes |
| Anthropic Claude inspection backend | Yes | Yes | Yes | Yes | Yes | Yes |
| Google Gemini inspection backend | Yes | Yes | Yes | Yes | Yes | Yes |
| Azure OpenAI inspection backend | Yes | Yes | Yes | Yes | Yes | Yes |
| LM Studio inspection backend | Yes | Yes | Yes | Yes | Yes | Yes |
| Fail-closed sentinel | Yes | Yes | Yes | Yes | Yes | Yes |
| Prompt injection detection | Yes | Yes | Yes | Yes | Yes | Yes |
| Credential Harvesting Suppression (CHS) | Yes | Yes | Yes | Yes | Yes | Yes |
| Payload masking before AI inspection | Yes | Yes | Yes | Yes | Yes | Yes |
| Response masking / sanitization | Yes | Yes | Yes | Yes | Yes | Yes |
| Anomaly detection (ZSET sliding window) | Yes | Yes | Yes | Yes | Yes | Yes |
| Inference payload logging (encrypted) | Yes | Yes | Yes | Yes | Yes | Yes |
| Sensitivity classification pipeline (v2.0) | Yes | Yes | Yes | Yes | Yes | Yes |
| Optimization Engine — 4D routing (v2.0) | Yes | Yes | Yes | Yes | Yes | Yes |
| **Budget Governance (v2.0)** | | | | | | |
| Three-tier budget system (org/group/individual) | Yes | Yes | Yes | Yes | Yes | Yes |
| Budget-redis dedicated container | Yes | Yes | Yes | Yes | Yes | Yes |
| Budget response headers | Yes | Yes | Yes | Yes | Yes | Yes |
| **Audit and Compliance** | | | | | | |
| Structured JSON audit log (file) | Yes | Yes | Yes | Yes | Yes | Yes |
| PostgreSQL audit storage (RLS + AES-256-GCM) | Yes | Yes | Yes | Yes | Yes | Yes |
| SHA-384 Merkle audit hash chain (v0.9.0) | Yes | Yes | Yes | Yes | Yes | Yes |
| Audit log search (7 filters, cursor pagination) (v0.9.0) | Yes | Yes | Yes | Yes | Yes | Yes |
| Audit log export (CSV/JSON, 10k rows) (v0.9.0) | Yes | Yes | Yes | Yes | Yes | Yes |
| Splunk SIEM integration | Yes | Yes | Yes | Yes | Yes | Yes |
| Elasticsearch SIEM integration | Yes | Yes | Yes | Yes | Yes | Yes |
| Wazuh SIEM integration | Yes | Yes | Yes | Yes | Yes | Yes |
| Async SIEM delivery queue (v0.9.0) | Yes | Yes | Yes | Yes | Yes | Yes |
| Monthly partition management (pg_partman) | Yes | Yes | Yes | Yes | Yes | Yes |
| P1-P5 alert severity with SIEM integration (v2.0) | Yes | Yes | Yes | Yes | Yes | Yes |
| Routing decisions as audit events (v2.0) | Yes | Yes | Yes | Yes | Yes | Yes |
| **Rate Limiting** | | | | | | |
| Per-endpoint rate limiting (Redis) | Yes | Yes | Yes | Yes | Yes | Yes |
| Response caching (CLEAN-only, SHA-256) | Yes | Yes | Yes | Yes | Yes | Yes |
| **Cryptography and Secrets** | | | | | | |
| TLS (ACME / CA-signed / self-signed) | Yes | Yes | Yes | Yes | Yes | Yes |
| Offline licence verification (v0.9.0) | Yes | Yes | Yes | Yes | Yes | Yes |
| Multi-KMS (Docker, AWS, Azure, GCP, Keeper, Vault) | Yes | Yes | Yes | Yes | Yes | Yes |
| AES-256-GCM column encryption (Postgres) | Yes | Yes | Yes | Yes | Yes | Yes |
| Agent PSK auto-rotation (v0.9.0) | Yes | Yes | Yes | Yes | Yes | Yes |
| **Observability** | | | | | | |
| Prometheus metrics | Yes | Yes | Yes | Yes | Yes | Yes |
| Grafana dashboards | Yes | Yes | Yes | Yes | Yes | Yes |
| Real-time SSE inspection feed (v0.9.0) | Yes | Yes | Yes | Yes | Yes | Yes |
| OpenTelemetry / Jaeger tracing | Yes | Yes | Yes | Yes | Yes | Yes |
| Loki + Promtail log aggregation | Yes | Yes | Yes | Yes | Yes | Yes |
| Alertmanager escalation (Slack/email/PagerDuty) | Yes | Yes | Yes | Yes | Yes | Yes |
| **Deployment** | | | | | | |
| Universal installer | Yes | Yes | Yes | Yes | Yes | Yes |
| Docker Compose | Yes | Yes | Yes | Yes | Yes | Yes |
| Kubernetes Helm charts | Yes | Yes | Yes | Yes | Yes | Yes |
| KEDA autoscaling | Yes | Yes | Yes | Yes | Yes | Yes |
| Multi-replica / HA deployment | Yes | Yes | Yes | Yes | Yes | Yes |
| Container hardening (seccomp, AppArmor, non-root) | Yes | Yes | Yes | Yes | Yes | Yes |
| Trivy container scanning | Yes | Yes | Yes | Yes | Yes | Yes |
| Agent bundles (LangGraph / Goose / OpenClaw) | Yes | Yes | Yes | Yes | Yes | Yes |
| Open WebUI integration (v2.0) | Yes | Yes | Yes | Yes | Yes | Yes |
| Container Pool Manager (v2.0) | 1/identity, 3 total | 1/identity, 3 total | 1/identity, 5 total | 3/identity, 15 total | 5/identity, 50 total | Unlimited |
| 12 Grafana dashboards (v2.0) | Yes | Yes | Yes | Yes | Yes | Yes |
| Apache 2.0 open-source license | Yes | Yes | — | — | — | — |
| CLA-covered contributions | Yes | Yes | — | — | — | — |

---

## 7. Deployment Topologies

### 7.1 Docker Compose — Single Node

The simplest production-capable deployment. The universal installer generates a `docker-compose.yml` with all services pre-configured: gateway, backoffice, Open WebUI, Postgres with PgBouncer, Redis, budget-redis, Ollama with init container, Vault, Prometheus, Grafana, Loki, Promtail, Alertmanager, Jaeger, Caddy, and optional agent bundles. The full stack with all agent bundles enabled comprises 17 core services + 3 optional agent bundles plus dynamic per-identity containers managed by the Pool Manager.

```
docker-compose.yml — 17 core services + 3 optional agent bundles (v2.0):
├── yashigani-gateway       # Core proxy + Optimization Engine, port 8443 (TLS)
├── yashigani-backoffice    # Admin API/UI + identity broker, port 8080 (includes Alembic migrations)
├── open-webui              # Chat interface, port 3000 (internal network only, v2.0)
├── open-webui-init         # First-run setup (v2.0)
├── postgres:16             # Audit + config + identity store
├── pgbouncer               # Connection pooler (password from .env)
├── redis                   # Rate limiting + caching
├── budget-redis            # Budget counters, port 6380 (noeviction policy, v2.0)
├── ollama                  # Local LLM inference (external network for model registry)
├── ollama-init             # Model pull on first start (external network)
├── vault                   # KMS + secrets
├── prometheus              # Metrics scrape
├── grafana                 # 12 dashboards (9 existing + 3 new: budget, OE, pool manager)
├── loki                    # Log aggregation
├── promtail                # Log shipping
├── alertmanager            # Alert routing (P1-P5 severity)
├── jaeger                  # Distributed tracing
├── caddy                   # TLS termination / reverse proxy / auth delegation
│
│   Agent bundles (v1.09.5 — auto-registered with PSK tokens):
├── langgraph               # Multi-agent orchestration, port 8000 (shares Postgres + Redis DB 5)
├── goose                   # AI developer assistant, port 3284 (goose serve ACP over HTTP)
└── openclaw                # Personal AI, port 18789 (30+ messaging integrations)

    Dynamic containers (v2.0 — managed by Pool Manager):
    Per-identity isolated containers, created/destroyed on demand
```

Suitable for: development, staging, small production workloads, air-gapped environments.

**Minimum hardware:** 4 vCPU, 8 GB RAM, 50 GB SSD.
**Recommended hardware:** 8 vCPU, 16 GB RAM, VRAM 8 GB (Ollama), 80 GB SSD.


### 7.2 Kubernetes — High-Availability Multi-Replica

Yashigani ships production-ready Helm charts for Kubernetes. The gateway deployment runs multiple replicas with KEDA-based horizontal autoscaling driven by Prometheus metrics. Pod disruption budgets prevent simultaneous eviction of all gateway replicas during node maintenance. Kubernetes network policies restrict lateral traffic: only the gateway can reach the inspection backends, only the audit writer can reach the database.

```
Namespace: yashigani
├── Deployment: gateway          (replicas: 3+, HPA via KEDA; includes OE)
├── Deployment: backoffice       (replicas: 2; identity broker)
├── Deployment: open-webui       (internal only, v2.0)
├── StatefulSet: postgres        (or external RDS/CloudSQL)
├── Deployment: pgbouncer
├── StatefulSet: redis           (or external ElastiCache)
├── StatefulSet: budget-redis    (noeviction, v2.0)
├── StatefulSet: vault           (or external HCP Vault)
├── Deployment: prometheus
├── Deployment: grafana          (12 dashboards)
├── StatefulSet: loki
├── DaemonSet: promtail
├── Deployment: alertmanager
├── Deployment: jaeger
└── DaemonSet: pool-manager      (per-identity containers, v2.0)
```

Suitable for: production workloads requiring high availability, rolling updates, and auto-scaling.

**Helm install:**
```bash
helm repo add yashigani https://charts.agnosticsec.com
helm install yashigani yashigani/yashigani \
  --namespace yashigani --create-namespace \
  --values values-production.yaml
```

### 7.3 Cloud Managed — AWS / GCP / Azure

The universal installer auto-detects the cloud provider via instance metadata and configures cloud-native service integrations:

| Component | AWS | GCP | Azure |
|---|---|---|---|
| Database | RDS PostgreSQL 16 | Cloud SQL | Azure Database for PostgreSQL |
| Cache | ElastiCache Redis | Memorystore | Azure Cache for Redis |
| Secrets | AWS Secrets Manager | Secret Manager | Azure Key Vault |
| TLS | ACM | Certificate Manager | App Gateway / Front Door |
| Metrics | CloudWatch + Prometheus | Cloud Monitoring | Azure Monitor |
| Load Balancer | ALB / NLB | Cloud Load Balancing | Azure Load Balancer |

Gateway nodes run on EC2 / GCE / Azure VMs or as Kubernetes deployments on EKS / GKE / AKS. All stateful services (Postgres, Redis, Vault) can be replaced with cloud-managed equivalents — the gateway configuration accepts standard connection strings.

### 7.4 Bare-Metal and On-Premises VM

The universal installer supports bare-metal Linux and macOS hosts without container runtimes (though Docker and Kubernetes are the recommended paths). On bare-metal, the installer:

1. Detects OS and architecture (x86_64, arm64)
2. Installs required system packages via the native package manager
3. Configures systemd units for all Yashigani services
4. Bootstraps TLS (self-signed by default, ACME if a public hostname is provided)
5. Initializes PostgreSQL, Redis, and Vault with generated credentials
6. Prints all auto-generated passwords and the admin bootstrap token at install time

Suitable for: regulated industries with no-cloud or no-container requirements, air-gapped environments, on-premises data centers.

**Minimum hardware (production bare-metal):** 8 vCPU, 16 GB RAM, 100 GB NVMe SSD.
**Recommended hardware (production bare-metal):** 12 vCPU, 32 GB RAM, 180 GB NVMe SSD.


---

## 8. Roadmap Context

Yashigani v2.1 is the current production release. v2.1 adds the Admin Dashboard UI (login page + 9-section admin panel), 12 Alertmanager P1-P5 routing/budget alert rules, Budget Postgres persistence (survives restarts), Pool Manager background health monitor (daemon thread), and OPA v1_routing.rego verified operational. The admin panel is the management layer that makes the product fully self-service — no curl or API knowledge needed. v2.1 brings the test count to 388 (363 + 25 e2e).

v2.0 introduced five major subsystems: the Unified Identity Model (every entity is an identity with a `kind` field, no separate stores), the Optimization Engine (four-dimensional routing with P1-P9 priority matrix), the three-tier Budget System (org cap → group → individual, enforced by dedicated budget-redis), Open WebUI integration at `/chat/*` (internal only, all LLM calls through gateway), and the Container Pool Manager (per-identity isolation, self-healing, postmortem forensics, Ollama horizontal scaling). Additional v2.0 additions include the Multi-IdP Identity Broker (OIDC + SAML v2), the three-layer sensitivity classification pipeline (regex + FastText + Ollama, all ON by default), P1-P5 alert severity with SIEM integration, OPA routing safety net with LLM policy review, 17 core services + 3 optional agent bundles plus dynamic per-identity containers, and 12 Grafana dashboards.

**Two release lines are maintained:**
- **v2.x** (branch: `main`) — Full stack: gateway + Open WebUI + Optimization Engine + Budget System + Container Pool Manager
- **v1.x** (branch: `release/1.x`) — Gateway-only: security enforcement proxy without Open WebUI or full-stack subsystems

The progression from v0.1.0 through v2.1 reflects a deliberate security maturity arc: from a minimal viable security proxy to a full enterprise-grade AI operations platform with intelligent routing, budget governance, unified identity management, and an ecosystem of integrated third-party agents. Each version maintained backward compatibility while adding layers of defense. The result is a system where no single component failure — inspection backend unavailability, database outage, KMS unreachability, budget exhaustion — results in an insecure pass-through or silent rejection. Every failure mode has been designed to be fail-closed or gracefully degraded.

### v0.8.0 Delivered

v0.8.0 addressed operator demand for first-class agentic framework support without forcing Yashigani's security boundary to become optional. LangGraph, Goose, and OpenClaw are available as opt-in Docker Compose profiles and Helm toggles — all agent traffic from these containers routes through Yashigani's enforcement layer and is subject to the same inspection, authorization, and audit pipeline as any other agent. A new `GET /admin/agent-bundles` endpoint exposes the bundle catalogue with metadata and a third-party disclaimer for the UI banner. `GET /admin/agents/{id}/quickstart` returns copy-paste curl, Python httpx, and health check snippets on the agent detail page, reducing time-to-first-call for new agent deployments. The rate limit config endpoint was extended with a `last_changed` timestamp, making threshold change history auditable without requiring a full audit log query.

### v0.8.4 Delivered

v0.8.4 addressed a cluster of installer failures discovered after v0.8.0 shipped — specifically on macOS with Apple Silicon, Podman, and Docker Desktop environments. Platform detection was fixed by correcting a variable naming mismatch (`DETECTED_*` vs `YSG_*`) that caused the platform summary to report incorrect values. GPU detection was added for Apple Silicon M-series (unified memory, Metal, ANE), NVIDIA, and AMD GPUs with an lspci fallback; Ollama model size recommendations are printed based on detected VRAM. The macOS `df -BG` (GNU-only) flag was replaced with `df -k` and compatible arithmetic. Podman became a first-class supported runtime alongside Docker Engine and Docker Desktop. A Docker Desktop CLI auto-fix was added for environments where Docker Desktop is installed but `docker` is not in PATH. Bash 3.2 compatibility was enforced throughout by replacing all `${var,,}` expansions with `tr`. Agent bundle selection was changed from individual y/n prompts to a numbered menu, eliminating typo-related crashes. A new `update.sh` script handles in-place upgrades with automatic backup, image pull, restart, and rollback on failure. A 7-test automated installer validation suite (`test-installer.sh`) covering 28 checks was added to CI.

### v0.9.0 Delivered

**Phase 1 — Cryptography and Licensing**
- **ECDSA P-256 licence signing** — production key embedded across `keygen.py`, `sign_license.py`, and `verifier.py`; ML-DSA-65 (FIPS 204) migration planned when the cryptography library ships FIPS 204 support
- **`LicenseFeature` enum** — OIDC, SAML, SCIM feature gates replaced with typed enum (replaces `frozenset[str]`)
- **Academic / Non-Profit tier** — added to `LicenseTier` enum; full tier support in verifier and feature gate logic
- **Community tier limits** — updated to v0.8.4 values (5 agents, 10 users, 2 admins)
- **Hybrid TLS Caddyfile config** — X25519+ML-KEM-768 configuration included (commented — pending Caddy 2.10)

**Phase 2 — Response-Path Inspection (F-01)**
- **`ResponseInspectionPipeline`** — FastText + LLM fallback applied to upstream responses, closing the indirect prompt injection vector
- **Per-agent config** — `fasttext_only` flag and `exempt_content_types` (default: `application/json`) configurable per agent
- **BLOCKED → 502** — tainted upstream responses return 502 to the client; FLAGGED responses forwarded with `X-Yashigani-Response-Verdict` header
- **`response_inspection_verdict`** — added to all audit events; `RESPONSE_INJECTION_DETECTED` event type added

**Phase 3 — Production Hardening**
- **PH-A: Break-glass** — hard TTL (1–72h, default 4h), dual-control approval, Redis-backed activation state, tamper-evident audit events
- **PH-B: Audit hash chain** — SHA-384 Merkle chain with daily anchors, `audit_verify.py` CLI for chain integrity verification, Prometheus gauge for chain health
- **PH-C: Async SIEM queue** — Redis RPUSH/LPOP delivery queue, batched transmission, DLQ after 3 retries, Prometheus gauges for queue depth and DLQ size
- **PH-D: Agent PSK auto-rotation** — APScheduler cron-based rotation, KMS push on rotation, grace period for concurrent token acceptance, `token_last_rotated` field in agent API response

**Phase 6 — WebAuthn / Passkeys (S-01)**
- **`WebAuthnService`** — registration and authentication ceremonies via `py_webauthn`
- **`WebAuthnCredentialRow`** — DB model with `pgp_sym_encrypt` at-rest encryption
- **6 backoffice endpoints** — `/auth/webauthn/register/begin`, `/auth/webauthn/register/complete`, `/auth/webauthn/authenticate/begin`, `/auth/webauthn/authenticate/complete`, `/auth/webauthn/credentials`, `/auth/webauthn/credentials/{id}` (DELETE)
- **TOTP coexistence** — both TOTP and WebAuthn remain available; WebAuthn is preferred when a credential is registered
- **Audit events** — `WEBAUTHN_CREDENTIAL_REGISTERED`, `WEBAUTHN_CREDENTIAL_USED`, `WEBAUTHN_CREDENTIAL_DELETED`

**Phase 7 — Operator Visibility**
- **`EventBus`** — asyncio pub/sub with 512-entry per-subscriber queue; gateway publishes all inspection events
- **SSE real-time inspection feed** — `GET /admin/events/inspection-feed` streams live inspection verdicts with 15-second heartbeat
- **Audit log search** — `GET /admin/audit/search` with 7 filter parameters (event type, agent, user, verdict, date range, cursor) and cursor-based pagination
- **Audit log export** — `GET /admin/audit/export` delivers CSV or JSON with 10,000-row cap and streaming response

**Installer redesign**
- **Three deployment modes** — Demo (1) / Production (2) / Enterprise (3) via `--deploy` flag (replaces `--mode`)
- **AES key provisioning** — auto-generate (default) or BYOK with `--aes-key` flag
- **`--offline` flag** — air-gapped installation support
- **Demo mode** — localhost, self-signed, auto-generate everything, 1–2 prompts maximum

### v0.9.1 Delivered

v0.9.1 hardened the credential bootstrap process that v0.9.0's installer redesign had left incomplete. Rather than generating a single admin account and requiring operators to create additional accounts manually, the installer now creates two admin accounts at install time with randomly generated themed usernames — eliminating the single-admin lockout risk from day one. TOTP 2FA is fully provisioned for both accounts during installation: the TOTP secret and `otpauth://` URI are generated, displayed, and immediately ready for import into any authenticator app. All generated passwords are checked against the Have I Been Pwned breach database using SHA-1 k-Anonymity prefix lookup before use; any compromised password is automatically regenerated and rechecked. The same HIBP check was added to the backoffice password-change path, implementing OWASP ASVS V2.1.7. A one-time credential summary block is displayed at the end of install showing all passwords, TOTP secrets, URIs, and the AES key with a prominent warning that the summary will not be shown again. All credentials are persisted to `docker/secrets/` with permissions 0600; existing secrets survive in-place upgrades.

### v0.9.2 Delivered

v0.9.2 fixed two regressions introduced during the v0.9.0 installer redesign. The `.env` writer was incomplete: only the AES key was being written before `docker compose pull` ran, causing `UPSTREAM_MCP_URL` to be undefined in the compose environment and producing a startup error on fresh installs. The function was expanded into a full `.env` writer that sets all required variables — `UPSTREAM_MCP_URL`, `YASHIGANI_TLS_DOMAIN`, `YASHIGANI_ADMIN_EMAIL`, `YASHIGANI_ENV`, and the AES key — before compose is invoked. Demo mode defaults `UPSTREAM_MCP_URL` to `http://localhost:8080/echo`. Additionally, `update.sh` used a process substitution (`< <(find ...)`) that is a bash 4+ feature not available in macOS's default bash 3.2; this was replaced with a `find | while read` pipe that is fully compatible.

### v0.9.3 Delivered

v0.9.3 was a structured 45-issue audit hardening release — the most comprehensive single-version quality pass in the project's history. Three functional blockers were closed: an authentication bypass in the per-endpoint rate limiting layer; a recursive call path in `OllamaPool` that caused a stack overflow under pool exhaustion; and a Vault KMS provider initialization failure on cold start. The `ResponseInspectionPipeline` introduced in v0.9.0 was wired into the gateway but never invoked in the default request path — v0.9.3 activated it, closing the response-path injection vector that v0.9.0 had intended to address. The ECDSA P-256 production public key was committed, making license tier enforcement fully active for all tiers for the first time since v0.7.0 shipped the key infrastructure. Every image in `docker-compose.yml` and the Helm charts was pinned to a digest, eliminating mutable-tag supply-chain risk. The `WebAuthnCredentialRow` Alembic migration was added so upgrades from v0.9.0–v0.9.2 apply cleanly without manual schema intervention. An end-to-end integration test suite was shipped covering auth, inspection, rate limiting, audit write, and license gate paths. Eighteen `except Exception: pass` bare-exception handlers were replaced with structured logging throughout the gateway and backoffice — previously silent failures became observable. A CI license key gate was added to validate the verifier before any build proceeds. Redis `keys()` calls were replaced with `scan_iter()` to eliminate blocking full-keyspace scans under load. IPv6 address handling was corrected in audit event IP masking and CHS.

### v0.9.4 Delivered

v0.9.4 is the final hardening release before v2.0 development begins. It closes the last known security-relevant bug in the inspection pipeline: the classifier's JSON extraction regex silently misclassified valid injection detections as CLEAN when the LLM response included nested objects in the `detected_payload_spans` field. The regex-based extraction was replaced with a brace-depth counting parser that correctly handles arbitrarily nested JSON.

Additionally, the FastAPI gateway migrated from the deprecated `@app.on_event` pattern to the recommended `lifespan` context manager, eliminating all deprecation warnings. Default service URLs throughout the codebase were standardized to Docker Compose service names (`redis`, `ollama`, `policy`) instead of `localhost`, preventing silent failures in containerized deployments where localhost does not resolve to the expected service. A CI gate was added to verify that `__init__.py` and `pyproject.toml` versions remain in sync, preventing the version drift discovered during v0.9.3 QA.

### v1.09.5 Delivered

v1.09.5 makes the agent bundle experience zero-friction and adds first-class Podman support. Key changes:

- **Agent bundles work out of the box** — the installer auto-registers LangGraph, Goose, and OpenClaw as agents with pre-shared key (PSK) tokens during installation, eliminating manual agent registration. Bundles are selected via `--agent-bundles langgraph,goose,openclaw`.
  - **LangGraph** (port 8000): multi-agent orchestration framework; shares Postgres (separate database) and Redis (DB 5)
  - **Goose** (port 3284): AI developer assistant; runs via `goose serve` ACP over HTTP
  - **OpenClaw** (port 18789): personal AI with 30+ messaging integrations; `OPENCLAW_CONFIG_JSON` routes through the gateway
- **First-class Podman support** — runtime detection identifies Docker Engine, Docker Desktop, or Podman; the correct compose command is selected automatically; the Podman override file is auto-applied when Podman is the active runtime
- **DNS fix for Ollama** — `ollama` and `ollama-init` containers are now on the external network, restoring model registry access for model downloads without compromising internal network isolation
- **Admin codenames** — auto-generated admin accounts use fun animal/nature-themed codenames as usernames, with TOTP pre-provisioned at install time
- **PgBouncer password fix** — PgBouncer now reads its password from `.env` instead of using a hardcoded or missing value
- **Alembic migrations in backoffice image** — database migrations are bundled in the backoffice Docker image and run automatically on container startup
- **18-service full stack verified** — all health checks pass from a clean-slate install (15 core + 3 agent bundles)

Full non-interactive install command:

```bash
bash install.sh --non-interactive --deploy demo --domain yashigani.local --tls-mode selfsigned --admin-email admin@yashigani.local --agent-bundles langgraph,goose,openclaw
```

### v2.0 Delivered

v2.0 is Yashigani's first production-grade release. It adds five major subsystems and transforms the platform from a security enforcement proxy into a complete AI operations platform.

**Unified Identity Model**
- Every entity (human or service) is an identity with a `kind` field — no separate user/agent stores
- Same governance, budget, RBAC, and audit for all identity kinds
- Humans: optional IdP federation metadata
- Services: optional upstream URL, container configuration, system prompt, capabilities
- Both managed through the same Web UI and API

**Optimization Engine**
- Four-dimensional routing: sensitivity + complexity + budget + cost
- P1-P9 priority matrix governs all routing decisions
- P1 is immutable: CONFIDENTIAL/RESTRICTED data always stays local
- Budget exhaustion degrades to local inference, never rejects
- Runs inside the gateway process (not a sidecar)
- Token threshold default: 2,000

**Three-Tier Budget System**
- Org cloud cap → group budgets → individual budgets
- Math always enforced: sum of individuals never exceeds group; sum of groups never exceeds org cap
- Budget-redis: dedicated container (port 6380, noeviction policy)
- Budget state via `X-Yashigani-Budget-*` response headers
- Admin API for budget management

**Open WebUI Integration**
- Chat interface at `/chat/*` behind Caddy
- Internal Docker network only — no external port
- All LLM calls (cloud and local) route through gateway
- Open WebUI holds zero LLM credentials
- Caddy delegates auth to backoffice (identity broker)
- Trusted headers: `WEBUI_AUTH_TRUSTED_EMAIL_HEADER`

**Container Pool Manager**
- Per-identity container isolation
- Universal lifecycle: create, route, health check, replace, scale, postmortem
- Self-healing: replace broken containers, never fix in place
- Postmortem forensics: logs, inspect output, filesystem diff preserved before kill
- Ollama horizontal scaling on load
- License tier container limits: Community (1/3), Starter (1/5), Professional (3/15), Professional Plus (5/50), Enterprise (unlimited), Academic (1/3)

**Multi-IdP Identity Broker**
- Yashigani IS the identity broker
- OIDC + SAML v2 native support
- Caddy delegates all auth to backoffice
- SCIM provisions users and groups
- Group policies govern model and agent access
- IdP limits tier-gated

**Sensitivity Classification Pipeline**
- Three layers, all ON by default: regex + FastText + Ollama
- Regex: PII, PCI, intellectual property, PHI patterns
- FastText: sub-5ms offline ML classification
- Ollama: deep semantic analysis (qwen2.5)
- Admin can opt out of Ollama layer but cannot disable regex
- Results feed directly into OE routing

**OPA Routing Safety Net**
- Second OPA pass on every routing decision
- Local LLM validates policy changes before applying
- Checks for self-lock, contradictions, scope issues, routing conflicts
- SAFE/WARNING/BLOCK verdicts

**P1-P5 Alert Severity**
- Sensitivity breach: P1
- OPA override: P1
- Classification conflict: P2
- Spending anomaly: P2
- Budget auto-switch: P3
- All routing decisions written as audit events to SIEM sinks

**Additional v2.0 changes:**
- 17 core services + 3 optional agent bundles + dynamic per-identity containers
- 363 tests passing (252 original + 111 new)
- 12 Grafana dashboards (9 existing + 3 new: budget, Optimization Engine, Pool Manager)
- Model alias table: DB-driven, Postgres + Redis cache, CRUD at `/admin/models/aliases`
- Streaming: buffered mode for v2.0 (full response before delivery; chunk-level streaming deferred to v2.1)
- User API keys: 256-bit hex, bcrypt cost 12, max lifetime 1 year, default rotation 90 days, 7-day grace period

Organizations evaluating Yashigani for production deployment should begin with the Community tier (5 agents, 10 end users, Apache 2.0). Teams with an SSO mandate but limited scale should consider the Starter tier (OIDC, 100 agents, 250 end users). Professional is the primary production tier for single-org deployments requiring full SSO and SCIM. Professional Plus suits large single-company deployments needing up to 10,000 end users and 5 orgs. Enterprise provides unlimited scale with named support engineers and 24/7 SLA. The universal installer supports in-place tier upgrades via license key injection without data migration or service interruption.

---
### 9. Our commitment to the OSS Community:**
---
Agnostic Security will donate 10% of the Yashigani platform sales profits to the open-source projects that we use, as long as they are registered as non-for-profit organizations.
We might also decide to sponsor other Open-Source projects that we use in some way.
