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
**Latest Stable Version:** v2.23 (main) — Open WebUI is optional via `--with-openwebui`

---
**Single branch:** `main` — all features, all tiers. Open WebUI, Wazuh, Internal CA, and agent bundles are optional compose profiles.
---
**Document Date:** 2026-04-12
---
**Classification:** ***Public — Product Overview***
---


## Table of Contents

1. [What is Yashigani](#1-what-is-yashigani)
2. [The Problem It Solves](#2-the-problem-it-solves)
3. [Pre-flight Checklist](#3-pre-flight-checklist)
4. [Current Release Highlights](#4-current-release-highlights)
5. [How to Deploy](#5-how-to-deploy)
6. [Feature Matrix by Tier](#6-feature-matrix-by-tier)
7. [Compliance](#7-compliance)
8. [Our Commitment to the OSS Community](#8-our-commitment-to-the-oss-community)

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

**Yashigani's response:** The three-layer sensitivity pipeline classifies every prompt before routing. Layer 1: regex pattern matching catches structured sensitive data (credit card numbers, SSNs, API keys). Layer 2: FastText ML classifier detects semantic sensitivity at under 5ms, fully offline. Layer 3: Ollama LLM classification provides deep contextual analysis for ambiguous cases. Data classified as CONFIDENTIAL or RESTRICTED is routed to local models only — this is an immutable rule enforced by the Optimization Engine. No override exists. No admin can bypass it. No configuration can disable it. CHS additionally strips credential-shaped patterns from payloads before any AI inspection backend sees them. The dedicated PII detection module (v2.20) adds 10 entity types (SSN, credit card with Luhn validation, email, phone, IBAN, passport, NHS number, driver's licence, IP address, date of birth) with three enforcement modes: LOG (detect and audit), REDACT (replace with `[REDACTED:TYPE]` before forwarding to cloud), and BLOCK (reject requests containing PII destined for cloud models). PII filtering runs on both request and response paths — bidirectional, on all traffic, by default. Cloud bypass requires explicit admin opt-in.

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

## 4. Current Release Highlights

### v2.23 — Single Branch, API-First Admin, Strict CSP, and Compose Profiles

v2.23 consolidates Yashigani to a single branch. The `release/1.x` branch is eliminated. Open WebUI is now an optional flag (`--with-openwebui`) rather than a separate release line. All features, all tiers, one branch.

**Branch Consolidation** -- The dual-branch model (v2.x on `main`, v1.x on `release/1.x`) is retired. Open WebUI, Wazuh, Internal CA, and agent bundles are optional compose profiles controlled by installer flags. Operators who do not want Open WebUI simply omit `--with-openwebui`. No separate branch to maintain, no backport overhead, no version confusion.

**API-First Admin UI** -- The admin dashboard was refactored from server-rendered Jinja2 templates with inline JavaScript and CSS to a static single-page application (SPA) with all JavaScript and CSS in external files. No inline code remains. This enables strict Content Security Policy headers and eliminates an entire class of XSS vectors. All admin logic lives in backend APIs; the UI is a thin client calling those APIs.

**Strict Content Security Policy** -- All pages served by Yashigani now enforce `script-src 'self'; style-src 'self'` with zero `unsafe-inline` exceptions. Additional hardening: `object-src none`, `base-uri none`, `cross-origin-opener-policy: same-origin`, and a CSP report endpoint for violation monitoring.

**Optional Services via Compose Profiles** -- Services that not every deployment needs are now gated behind compose profiles: `openwebui`, `wazuh`, `internal-ca`, `langflow`, `letta`, `openclaw`. The installer flags (`--with-openwebui`, `--wazuh`, `--with-internal-ca`, `--agent-bundles`) control which profiles are activated. The base stack is leaner; optional services are added without editing compose files.

**Admin Service Management** -- Administrators can enable or disable any optional service directly from the admin panel. No SSH access required. Service state changes are audited.

**Internal CA** -- Smallstep step-ca provides service-to-service mTLS within the Yashigani deployment. Enabled via `--with-internal-ca`. Certificates are automatically provisioned and rotated for inter-service communication.

**Domain-Bound Licensing** -- License keys are now bound to the deployment domain using ECDSA P-256 signatures. A license issued for `example.com` will not activate on `other.com`.

**Additional v2.23 changes:**
- Podman socket detection on macOS (Darwin) via `podman machine inspect`
- Container socket mount is read-only
- `restore.sh` backup recovery script for secrets, `.env`, and Postgres dumps
- Admin-configurable password max age (`YASHIGANI_PASSWORD_MAX_AGE_DAYS`, max 13 months)

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
| Agent bundles (Langflow / Letta / OpenClaw) | Yes | Yes | Yes | Yes | Yes | Yes |
| Open WebUI integration (v2.0) | Yes | Yes | Yes | Yes | Yes | Yes |
| Container Pool Manager (v2.0) | 1/identity, 3 total | 1/identity, 3 total | 1/identity, 5 total | 3/identity, 15 total | 5/identity, 50 total | Unlimited |
| 12 Grafana dashboards (v2.0) | Yes | Yes | Yes | Yes | Yes | Yes |
| Apache 2.0 open-source license | Yes | Yes | — | — | — | — |
| CLA-covered contributions | Yes | Yes | — | — | — | — |

---
### 9. Our commitment to the OSS Community:**
---
Agnostic Security will donate 10% of the Yashigani platform sales profits to the open-source projects that we use, as long as they are registered as non-for-profit organizations.
We might also decide to sponsor other Open-Source projects that we use in some way.
