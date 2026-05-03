<!-- last-updated: 2026-04-28T19:45:00+00:00 -->

# Changelog

All notable changes to Yashigani are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For full release narratives, design rationale, and per-feature detail, see [`README.md`](README.md) section 4 (Security Features by Version).

---

## [Unreleased] — v2.23.1 (in development)

Active branch: `v2.23.1-mtls`. Theme: **Core-Plane mTLS + Two-Tier PKI + Release Hardening**.

### Added
- Core-plane mTLS default-on across gateway, backoffice, postgres, pgbouncer, redis, opa
- Two-tier internal PKI (root → intermediate → per-service leaves) with SPIFFE-style URI SANs
- Automatic certificate issuance + rotation (admin-API + install.sh subcommands + Helm CronJob)
- Centralised SSRF allowlist helper for outbound HTTP (`yashigani.net.http_client`)
- Per-endpoint body-size limits (ASVS 4.3.1)
- Log-injection sanitisation across audit and application logs (ASVS 16.6.1)
- Algorithm allowlist on license ECDSA verifier (ES256 / SECP256R1 only)
- `/.well-known/security.txt` per RFC 9116
- Symbol-bearing generated passwords with category guarantees (`A-Za-z0-9!*,-._~`)
- AppArmor mmap permission for shared libraries (e.g. `libpython3.12.so`)

### Changed
- seccomp + AppArmor profiles default-on for all runtimes (Linux + macOS where applicable)
- Fail-closed on missing HMAC and Open WebUI secrets (no silent dev-mode fallback)
- Session rotation on password change invalidates all prior sessions (ASVS V7.4.2)
- 401 vs 404 uniformised on unauthenticated admin endpoints (no information disclosure)
- Caddy header hygiene: `Server` stripped, stale `alt-svc` removed
- TOTP enrolment split into separate provision/confirm endpoints
- Agent tier-limit returns 402 Payment Required (was 500 Internal Server Error)
- AGENT_REGISTERED events now persisted to the audit log (previously in-memory only)

### Fixed
- `YSG_RUNTIME` stale-env bleed across install invocations
- PKI trust-store mounts aligned per library compatibility (libssl-direct services use root anchor; partial-chain-capable services use intermediate; root private key never enters a workload container)

### Security
- PCI-compliant password expiry profile (≤90 days) selectable via `YASHIGANI_PASSWORD_MAX_AGE_DAYS=pci`
- Auth-throttle admin self-visibility — authenticated admins see own + all throttled/blocked IPs at `/admin → Security → Blocked IPs` (backed by `/auth/blocked-ips`). Unauthenticated locked-out operator path (RFC 6585 `Retry-After` on login) deferred to v2.23.2.
- **YSG-RISK-001 (CWE-89, HIGH)** — replaced SQL f-string interpolation in `scripts/partition_maintenance.py` with safe identifier quoting (`_quote_ident()`, allowlist `[a-zA-Z_][a-zA-Z0-9_]*`). Date literals in the `PARTITION OF … FOR VALUES FROM … TO …` DDL clause are formatted via `date.isoformat()` (deterministic `YYYY-MM-DD`); asyncpg / PostgreSQL do not accept bind parameters in DDL parser positions. The date values are derived from Python `date` arithmetic, never from user input. ACS v3 dogfood scan finding `acs-v3-sql-string-concat-exec`. Closing commits `75536a5` (identifier quoting) + `af114f7` (DDL date-literal exception; Lu re-audit YCS-20260502-v2.23.1-CWE89-reaudit-001 PASS).
- **YSG-RISK-002 (CWE-89, MEDIUM)** — replaced `op.execute(f"DROP TABLE IF EXISTS {name}")` in Alembic migration `0003_prepartition_audit_2026_2027.py` with `op.drop_table()` native API. Closing commit `9d867be`.
- **YSG-RISK-003 (CWE-601, MEDIUM)** — OIDC discovery validator now rejects `authorization_endpoint`, `token_endpoint`, and `jwks_uri` whose scheme is not `https` or whose host does not match the registered `discovery_url` host. Closes the post-admin-compromise open-redirect class (TA-3 insider). Closing commit `c5839e4`.
- **YSG-RISK-004 (CWE-400, MEDIUM)** — Docker Compose `mem_limit` and `cpus` now set on every service across `docker-compose.yml` (21 services) + `docker-compose.wazuh.yml` (3 services). Defaults documented in `docker/.env.example`; env-overridable via `YASHIGANI_<SERVICE>_MEM_LIMIT` / `YASHIGANI_<SERVICE>_CPU_LIMIT`. Closing commit `0143fb4`.
- **YSG-RISK-005 (CWE-400, MEDIUM)** — Helm chart `resources.limits.{memory,cpu}` AND `resources.requests.{memory,cpu}` set on every container in the chart; surfaced as tunables in `values.yaml`. Requests = 50% of limits to satisfy the K8s scheduler. Closing commit `6c35d28`.
- **YSG-RISK-006 (CWE-668, MEDIUM)** — OpenClaw host port binding moved from `0.0.0.0:18789` to `127.0.0.1:18789`. OpenClaw remains reachable from the gateway over the internal Docker bridge by service name; the host-side binding is loopback-only. OTEL collector `0.0.0.0:*` listeners confirmed bridge-only (no host `ports:` mapping). Closing commit `33f7318`.
- **YSG-RISK-007 (CWE-918, HIGH worst-case)** — SSRF allowlists added at every flagged call site:
  - **7-A** `agents.py:218,245` — `OWUI_API_URL` validated against `YASHIGANI_OWUI_HOSTNAMES` allowlist (default `open-webui,127.0.0.1,localhost`). Commit `84aab78`.
  - **7-B** `oidc.py:160,169` — discovery URL validated against `YASHIGANI_OIDC_DISCOVERY_HOSTS` allowlist; `jwks_uri` host MUST equal `discovery_url` host (case-insensitive) and MUST be `https`; re-asserted in `_get_jwks()` as defence-in-depth. Commit `64ec325`.
  - **7-C** `audit/writer.py:285` + `backoffice/routes/audit.py:326` — Pydantic v2 `field_validator` on `SiemTargetRequest.url` enforces `https` scheme and rejects RFC 1918 / loopback / link-local / multicast hosts at register-time AND test-fire-time. `YASHIGANI_TEST_MODE=1` skips DNS resolution but keeps the HTTPS requirement. Commit `1209055`.

### Deferred (accepted-risk, carried to v2.23.2 P1)
- **YSG-RISK-008 (CWE-732/CWE-250, LOW-MEDIUM batch)** — container-hardening absent-key gaps (no `read_only: true` in compose, no `readOnlyRootFilesystem: true` in Helm `securityContext`, no `security_opt: ["no-new-privileges:true"]`). Tiago accepted the deferral on 2026-04-28 with the rationale that adding YAML keys without OPA/Conftest/Kyverno admission control would be half-measure hardening; v2.23.2 P1 will ship both YAML keys AND admission policies together as proper end-to-end enforcement.

---

## [v2.22.3] — 2026-04-12

Theme: OPA on /v1, Agent Personas, Fail2ban, IP Access Control, OWASP Compliance Review.

### Added
- OPA policy enforcement on **all** `/v1/chat/completions` traffic (request + response paths, fail-closed)
- Agent personas with chaining: **Lala** (Langflow), **Julietta** (Letta), **Scout** (OpenClaw); `@Scout` → `@Julietta` → `@qwen` syntax; `@Help` chaining guide
- Fail2ban-style auth throttle: per-IP (3 failures) + global (5 failures), ×5 escalation (30s → 625m), permanent IP block after maximum
- IP allowlist + blocklist (IPv4 / IPv6 / CIDR, admin manageable; blocklist precedence)
- Content relay detection (agent-to-agent content laundering)
- Crypto inventory API (`/admin/crypto/inventory`) + admin UI with JSON export
- `__Host-` cookie prefix on session cookies (enforces Secure, Path=/, no Domain)
- Self-service password reset (TOTP-verified, no admin involvement)
- Wazuh SIEM full stack (`--wazuh`): manager + indexer + dashboard
- Grafana + Prometheus admin access at `/admin/grafana/` and `/admin/prometheus/` via Caddy forward_auth
- Monitoring tab in admin UI (Grafana / Prometheus / Wazuh links)
- OWASP compliance review (ASVS v5 all 17 chapters + API Security + Agentic AI / LLM Top 10) with per-control PASS / PARTIAL / FAIL / N/A verdicts and file:line evidence
- Risk register (5×5 quantitative-analysis matrix)
- Audit log viewer (search, filter, CSV export)
- Dashboard auto-refresh (15s), session-timeout warning (10 min), first-run onboarding checklist
- Podman SDK (`podman-py`) for container-per-user isolation

### Changed
- PKCE on all OIDC flows (`code_verifier` / `code_challenge`)
- `acr` / `amr` validation on ID tokens (auth-strength enforcement)
- Constant-time TOTP comparison (`hmac.compare_digest`)
- Context-specific password word list (blocks "yashigani", "admin", "password", etc.)
- Postgres migrations now run on startup (`pg_partman` / `pg_cron` optional)

### Removed
- **Goose** agent (ACP integration too slow on CPU; replaced by Letta/Julietta)

### Security
- Login branding (Agnostic Security footer)

## [v2.22.0] – [v2.22.2] — 2026-04-12

Patch sequence completing the v2.22.x feature set listed under v2.22.3.

---

## [v2.20] (untagged release line, 2026-04 series)

Theme: Security Hardening, PII Detection, and Compliance.

### Added
- License anti-tampering (v4 counter-signature schema; binary-patch-detecting self-integrity check at startup)
- PII detection module (`yashigani.pii`) — 10 entity types (SSN, credit card with Luhn validation, email, phone, IBAN, passport, NHS number, driver's licence, IP address, date of birth) — three modes: LOG / REDACT / BLOCK — bidirectional (request + response paths) — cloud bypass requires explicit admin opt-in
- Response-path inspection wired to all `/v1/*` routes (`ResponseInspectionPipeline` activation)
- WAF and DDoS protection: hardened Caddy timeouts and body limits + per-IP `DDoSProtector` (Redis-backed, 429 + `Retry-After`); `Caddyfile.waf` reference for Coraza WAF plugin
- Streaming chunk-level inspection (`StreamingInspector`) for `/v1/*` SSE responses
- HMAC-SHA256 per-tenant email hashing in SSO audit events (closes cross-tenant correlation risk)
- Ollama model digest pinning (validates SHA-256 on subsequent starts; alerts on mismatch)
- Open WebUI "Powered by Open WebUI" attribution (commercial-use compliance)
- 9-framework compliance mapping document; 2 STRIDE threat models (product: 17 threats; solution: 38 threats)
- Helm chart fixes (`helm lint` clean) + Kubernetes network policies covering all v2.0 / v2.1 services

### Changed
- Container hardening: explicit `security_opt`, `cap_drop`, `read_only` directives in compose; embedded seccomp profile at `docker/seccomp/yashigani.json`
- FastText classifier model baked into Docker image (no outbound dependency for inspection at startup)
- Model aliases: write-through to Redis on every CRUD operation; Redis read path with Postgres source-of-truth

### Security
- SBOM (CycloneDX 1.5) per image
- Cosign keyless image signing (Sigstore, GitHub Actions OIDC)
- 548 tests (523 unit + 25 e2e)

---

## [v2.1.0] — 2026-04-02

Theme: Admin Dashboard + Alerting + SSO + Persistence.

### Added
- Admin Dashboard UI (login page + 9-section admin panel)
- 12 Alertmanager rules covering P1-P5 severity for routing and budget conditions
- Budget Postgres persistence (counters survive container restarts and Redis eviction)
- Pool Manager background health monitor (daemon thread)
- OIDC identity broker — full end-to-end (`handle_oidc_callback()`, JWKS discovery, group extraction for Entra ID / Okta / Cognito / Keycloak)
- Mandatory 2FA after SSO (TOTP required even after IdP success)
- Keycloak test IdP (`test-idp` compose profile with three users: alice, bob, carol)

### Changed
- SSO email hashing standardised (SHA-256, raw email never stored)
- CSRF protection on OIDC flows via Redis-backed state/nonce tokens (10-minute TTL, ASVS V3.5.3)
- Podman rootless parity: corrected user namespace; `keep-id` removed from root-running services; e2e auto-detects runtime

### Security
- 413 tests (388 unit + 25 e2e)

---

## [v2.0.0] — 2026-04-02

Theme: First production-grade release. Five major subsystems transform Yashigani into a complete AI operations platform.

### Added
- **Unified Identity Model** — every entity (human or service) is a single identity record with a `kind` field; same governance, RBAC, budget, and audit for all kinds
- **Optimization Engine** — four-dimensional routing (sensitivity + complexity + budget + cost) with P1-P9 priority matrix; CONFIDENTIAL/RESTRICTED data always stays local (immutable)
- **Three-Tier Budget System** — org cloud cap → group → individual; budget-redis (noeviction policy); `X-Yashigani-Budget-*` response headers
- **Open WebUI Integration** — chat interface at `/chat/*` (internal Docker network only); all LLM calls route through gateway; Open WebUI holds zero LLM credentials
- **Container Pool Manager** — per-identity container isolation with universal lifecycle (create / route / health / replace / scale / postmortem); self-healing (replace, don't fix); forensic preservation before kill
- **Multi-IdP Identity Broker** — OIDC + SAML v2 native; Caddy delegates auth to backoffice; SCIM provisions users and groups
- **Sensitivity Classification Pipeline** — three layers ON by default: regex + FastText (sub-5ms offline) + Ollama (qwen2.5)
- **OPA Routing Safety Net** — second OPA pass on every routing decision; local-LLM policy validation with SAFE / WARNING / BLOCK verdicts
- **P1-P5 Alert Severity** — sensitivity breach (P1), OPA override (P1), classification conflict (P2), spending anomaly (P2), budget auto-switch (P3); SIEM integration for all
- 12 Grafana dashboards (9 existing + 3 new: budget, Optimization Engine, Pool Manager)

### Changed
- Open WebUI auth delegation via Caddy `WEBUI_AUTH_TRUSTED_EMAIL_HEADER`
- License tier container limits introduced

### Security
- 363 tests (252 original + 111 new)

---

## [v1.22.x] — 2026-04-12 (deprecated, end-of-life)

Final v1.x release line. **Branch `release/1.x` retired in v2.23.0** in favour of single-branch model where Open WebUI is `--with-openwebui` flag. Existing v1.x deployments should migrate to v2.x.

Tag history: `v1.22.0`, `v1.22.1`, `v1.22.2`, `v1.22.3`.

## [v1.10.x] — 2026-04-02 (deprecated, end-of-life)

Tag history: `v1.10.0`, `v1.10.1`.

## [v1.09.5] — 2026-04-01 (deprecated, end-of-life)

Theme: Agent bundles GA + first-class Podman support.

### Added
- Agent bundles auto-registered with PSK tokens at install time (`--agent-bundles`)
- First-class Podman runtime detection (compose command + override file)
- Animal/nature-themed admin codenames; TOTP pre-provisioned at install
- Alembic migrations bundled in backoffice Docker image

### Fixed
- DNS routing for `ollama` and `ollama-init` (external network for model registry access)
- PgBouncer reads password from `.env`

---

## [v0.9.4] — 2026-03-31

Theme: Final hardening before v2.0.

### Fixed
- Inspection classifier brace-depth parser replaces regex JSON extractor (fixes silent CLEAN misclassification of nested objects)

### Changed
- FastAPI gateway migrated to `lifespan` context manager (deprecates `@app.on_event`)
- Default service URLs use Docker Compose service names (`redis`, `ollama`, `policy`)

### Added
- CI gate enforcing `__init__.py` ↔ `pyproject.toml` version sync

## [v0.9.3] (untagged)

45-issue audit hardening release.

### Fixed
- Rate limiter operator-precedence bug (unauthenticated session bypass)
- `OllamaPool.classify()` recursive call → stack overflow under pool exhaustion
- Vault KMS provider initialisation failure on cold start
- 18× bare `except Exception: pass` handlers replaced with structured logging
- Redis `keys()` → `scan_iter()` (eliminates blocking keyspace scans)
- IPv6 address handling in session IP masking and CHS

### Added
- `ResponseInspectionPipeline` activated on default request path
- ECDSA P-256 production public key embedded in verifier
- Every Docker image digest-pinned across compose + Helm
- WebAuthn credentials Alembic migration
- End-to-end integration smoke test suite
- CI gate rejecting builds with placeholder license keys
- 252 tests (0 failures)

## [v0.9.2] (untagged)

### Fixed
- `.env` writer now sets all required vars before `docker compose pull` (fixes `UPSTREAM_MCP_URL` undefined on fresh installs)
- `update.sh` process substitution replaced with `find | while read` (bash 3.2 compat)

## [v0.9.1] (untagged)

### Added
- Two admin accounts at install time (eliminates single-admin lockout)
- TOTP 2FA fully provisioned at install with `otpauth://` URIs
- HIBP k-Anonymity breach check on all generated passwords
- HIBP check on backoffice password-change path (ASVS V2.1.7)
- One-time credential summary at install completion
- All credentials persisted to `docker/secrets/` with 0600 perms

## [v0.9.0] (untagged)

Theme: Post-quantum readiness and security hardening.

### Added
- ECDSA P-256 license signing (offline, air-gapped, no call-home)
- Hybrid TLS X25519+ML-KEM-768 Caddyfile config (commented, pending Caddy 2.10)
- Response-path inspection (`ResponseInspectionPipeline`)
- WebAuthn / Passkeys (Touch ID, Face ID, Windows Hello, YubiKey) coexisting with TOTP
- Break-glass dual-control (hard TTL, Redis-backed, tamper-evident audit trail)
- SHA-384 Merkle audit hash chain with daily anchors + `audit_verify.py` CLI
- Async SIEM delivery queue (Redis RPUSH/LPOP, batched, DLQ after 3 retries)
- Agent PSK auto-rotation via APScheduler with KMS push
- Real-time SSE inspection feed (`/admin/events/inspection-feed`)
- Searchable / exportable audit log (`/admin/audit/search`, `/admin/audit/export`)

### Changed
- Installer redesigned around three deployment modes: Demo / Production / Enterprise
- AES key provisioning: auto-generate by default, `--aes-key` BYOK option
- `--offline` flag for air-gapped installation

---

## [v0.8.4] (untagged)

### Fixed
- Platform-detection variable mismatch (`DETECTED_*` vs `YSG_*`)
- macOS `df -BG` (GNU-only) replaced with `df -k`
- Bash 3.2 compatibility throughout (`${var,,}` → `tr`)

### Added
- GPU detection (Apple Silicon / NVIDIA / AMD with lspci fallback)
- First-class Podman runtime support
- Docker Desktop CLI auto-fix (when Docker Desktop installed but `docker` not on PATH)
- `update.sh` script for in-place upgrades (backup → pull → restart → rollback on failure)
- 7-test installer validation suite (`test-installer.sh`, 28 checks)

## [v0.8.0] (untagged)

Theme: Optional agent bundles.

### Added
- Opt-in compose profiles + Helm toggles for LangGraph, Goose, OpenClaw
- `GET /admin/agent-bundles` catalogue API
- `GET /admin/agents/{id}/quickstart` snippet endpoint (curl / httpx / health)
- Rate-limit config endpoint extended with `last_changed` timestamp

## [v0.7.1] (untagged)

### Added
- Direct webhook alert dispatch on credential exfil detection
- Background license-expiry monitor (APScheduler, daily, configurable threshold)
- Alembic migration `0003` pre-creates all `audit_events` and `inference_events` partitions for 2026-05 → 2027-06
- Full unit-test suite for `db/health.py`

## [v0.7.0] (untagged)

Theme: Operational hardening + OPA Policy Assistant.

### Added
- ECDSA P-256 production public key replaces placeholder
- Database partition automation (maintenance script + Kubernetes CronJob)
- Prometheus gauge `yashigani_audit_partition_missing` with paired Alertmanager rule
- **OPA Policy Assistant** — natural language → RBAC JSON suggestion with admin approve/reject + full audit trail (uses Ollama qwen2.5:3b)
- Agent registration `quick_start` snippet (curl / httpx / health)
- Direct webhook alerting (Slack / Microsoft Teams / PagerDuty) as Alertmanager-independent sink
- CIDR-based IP allowlisting per agent
- Runtime-configurable rate-limit thresholds via backoffice (no gateway restart)

### Fixed
- OPA `_path_matches` regex bug (single-segment wildcards crossing `/` boundaries)

## [v0.6.2] (untagged)

### Added
- **Starter** tier (OIDC-only, 100 agents)
- Three-dimensional limits: `max_end_users` + `max_admin_seats` (split from single user limit)
- v3 license payload schema (with v1/v2 backwards-compat loading)

## [v0.6.1] (untagged)

### Changed
- Tier model restructured: Community / Professional / Professional Plus / Enterprise (replaces previous 3-tier scheme)
- Apache 2.0 community licence
- Contributor License Agreement (CLA) framework

## [v0.6.0] (untagged)

Theme: Universal installer + licensing.

### Added
- Universal installer (Linux, macOS, cloud VM, bare-metal — auto-detects OS, arch, cloud, GPU, runtime)
- Three licence tiers: Community (free, no key), Professional (paid, signed key), Enterprise (paid, signed key, multi-tenancy)
- ECDSA P-256 offline licence verification (no call-home)
- Feature gates: SAML, OIDC, SCIM tier-bounded

## [v0.5.0] (untagged)

Theme: Data-platform and full observability.

### Added
- PostgreSQL 16 with row-level security and `pgcrypto` AES-256-GCM column encryption (audit + operational store)
- `pg_partman` and `pg_cron` for monthly partition management
- PgBouncer connection pooling
- JWT introspection with JWKS waterfall (open-source / corporate / SaaS)
- Multi-sink audit pipeline (file + PostgreSQL + Splunk + Elasticsearch + Wazuh, simultaneous)
- OpenTelemetry distributed tracing with OTLP export to Jaeger
- FastText ML first-pass classifier (sub-5ms offline)
- HashiCorp Vault KMS integration (AppRole auth, KV v2 secrets)
- Loki + Promtail log aggregation
- Alertmanager 3-channel escalation (Slack / email → PagerDuty)
- Per-endpoint rate limiting (Redis fixed-window) + response caching (CLEAN-only, SHA-256 keyed)
- Redis ZSET sliding-window anomaly detection (enumeration / bulk-extraction patterns)
- Inference payload AES-encrypted logging in Postgres
- Container hardening (seccomp allowlist, AppArmor, UID 1001 non-root, tmpfs `/tmp`, read-only root)
- Structured JSON logging throughout

## [v0.4.0] (untagged)

Theme: Cloud-native operations.

### Added
- Production-ready Helm charts
- GitHub Actions CI/CD pipelines
- KEDA horizontal autoscaling
- Pod disruption budgets and Kubernetes network policies
- Trivy container scanning in CI
- CODEOWNERS + branch protection on security-critical paths

## [v0.3.0] (untagged)

Theme: Enterprise identity + multi-backend inspection.

### Added
- RBAC via OPA
- Agent routing with bearer token auth
- Multi-backend inspection: Anthropic Claude, Google Gemini, Azure OpenAI, LM Studio, Ollama
- Fail-closed sentinel (denies on all-backend unavailability)
- OIDC + SAML v2 SSO, SCIM provisioning
- Response masking + payload masking (pre-AI inspection)

## [v0.2.0] (untagged)

Theme: Transport security and admin hardening.

### Added
- TLS bootstrap: ACME (Let's Encrypt / ACME-compatible), CA-signed, self-signed
- Prometheus metrics
- bcrypt alongside Argon2 for password hashing
- Multiple admin accounts with minimum-count enforcement (anti-lockout)
- Admin lockout protection (brute-force resistance)

## [v0.1.0] (untagged)

Initial release. Core MCP gateway with prompt-injection detection, CHS, OPA, session/API-key auth, Argon2 hashing, TOTP/2FA, file-based audit log, Redis rate limiting.

---

## Notes on tag history

- `v0.9.4` (2026-03-31), `v1.09.5` (2026-04-01), `v1.10.x` + `v2.0.0` + `v2.1.0` (2026-04-02), `v1.22.x` + `v2.22.x` (2026-04-12) reflect parallel-branch parity for the v1.x line that has now been retired.
- The single-branch model (Open WebUI as `--with-openwebui` flag) shipped in v2.23.0; `release/1.x` is end-of-life.
- v2.20, v2.1, v2.0, and earlier carry untagged CHANGELOG entries reflecting the per-version content from `README.md` §4.
