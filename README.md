# Yashigani
---

<html>
<body>
<div>
  <img src="https://github.com/agnosticsec-com/yashigani/blob/main/theyashigani.png" alt="Yashigani" style="width:50%">
</div>
</body>
</html>



**Yashigani is the security enforcement gateway for MCP servers and agentic AI systems.**

It sits as a reverse proxy between AI agents and MCP tool servers. Every request is authenticated, inspected, policy-checked, and audited before reaching a tool. Every response is inspected before being returned.

```
AI Agent → [Yashigani Gateway] → MCP Tool Server
              ↓
         Authentication · Prompt Injection Detection
         OPA Policy Enforcement · Credential Stripping
         Rate Limiting · Audit Logging · Anomaly Detection
```

Yashigani is **not** a SaaS product — it deploys on the customer's infrastructure, keeping all AI traffic, secrets, and audit data inside their security boundary. This is a hard requirement for regulated industries and the primary reason self-hosted wins in this market.

Yashigani is production-ready at v0.8.0. The full security stack is implemented and deployed:

**Core security layer:**
- ML-assisted prompt injection detection (FastText < 5ms offline + LLM fallback chain)
- Credential Harvesting Suppression — strips secrets from payloads before any AI inspection
- OPA policy engine for per-tool, per-agent, per-route authorization (never cloud-delegated)
- OPA Policy Assistant — natural language → RBAC JSON suggestion with admin approve/reject flow
- RBAC with group-level rate limit overrides and runtime-configurable RPI scale thresholds
- Full multi-sink audit trail: file + PostgreSQL + SIEM (Splunk / Elasticsearch / Wazuh)
- CIDR-based IP allowlisting per registered agent
- Direct P1 alerting to Slack, Microsoft Teams, and PagerDuty (independent of Alertmanager)

**Enterprise identity:**
- TOTP 2FA, SAML v2, OIDC, SCIM automated provisioning
- JWT introspection with JWKS waterfall (three deployment streams)
- Session management (Redis-backed, httpOnly, SameSite, HSTS)

**Operational infrastructure:**
- Universal installer (Linux all major distros, macOS Intel/M-series, AWS/GCP/Azure/DigitalOcean, bare-metal)
- Docker Compose (single-node) and Kubernetes Helm charts
- Six KMS providers: Docker Secrets, Keeper Security KMS, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, HashiCorp Vault
- Full observability: Prometheus, Grafana, OpenTelemetry/Jaeger, Loki, Alertmanager
- PostgreSQL 16 with row-level security, AES-256-GCM column encryption, and automated monthly partition management
- Container hardening: seccomp allowlist, AppArmor, UID 1001 non-root, read-only filesystem

**Agent ecosystem (v0.8.0):**
- Optional LangGraph, Goose, CrewAI, and OpenClaw containers as opt-in courtesy bundles
- All agent traffic routed through Yashigani — every LLM call inspected, audited, and policy-enforced
- One-command activation per agent at install time or via Helm value toggle

**Licensing:**
---
ECDSA P-256 offline verification — no license server, no call-home. Works air-gapped.

***Hardware Requirements:***

---

| Resource | Demo / Dev | Production |
|---|---|---|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8 GB (16 GB with Ollama GPU) |
| Disk | 20 GB | 50+ GB |
| OS | Any (Linux / macOS / VM) | Linux x86_64 or arm64 |

> **Note:** If you enable GPU acceleration for Ollama (recommended for production), the host must have a CUDA-capable NVIDIA GPU (driver 525+) or Apple Silicon with Docker Desktop 4.x+. Expect an additional 4–8 GB VRAM per loaded model.


**Pricing:**
---
Open-core with five tiers:
---
| Tier | Agents | End Users | Admin Seats | Annual Price |
|------|--------|-----------|-------------|-------------|
| Community | 20 | 50 | 10 | Free (Apache 2.0) |
| Starter | 100 | 250 | 25 | TBD |
| Professional | 500 | 1,000 | 50 | TBD |
| Professional Plus | 2,000 | 10,000 | 200 | TBD |
| Enterprise | Unlimited | Unlimited | Unlimited | TBD |

**Our commitment to the Open-Source Projects used:**
---
Agnistic security will donate 10% of the Yashigani platform sales profits to the open-source projects that we use, as long as they registered as non-for-profit organizations.
We might also decide to sponsor other Open-Source projects that we use in some way.
