# Yashigani v0.5.0 — Implementation Plan

**Date:** 2026-03-27
**Author:** Maxine (PM/PO — Lead Architect)
**Status:** COMPLETE — 2026-03-27
**Predecessor:** v0.4.0 (CI/CD + Helm + Scaling + Failover — 59 files, 3016 lines)

---

## 1. Executive Summary

- v0.5.0 is the **data-plane hardening and observability completeness** release. It adds PostgreSQL as the
  authoritative durable store, layered with per-tenant RLS and AES-256-GCM column encryption via pgcrypto,
  replacing the Redis-only persistence model for all compliance-critical data.
- **Anomaly detection goes online**: every inference call is hashed, sized, classified, and checked against
  a sliding-window repeated-small-call detector. Non-compliant call patterns emit audit events and Prometheus
  counters before the payload ever leaves the gateway.
- **ML-first content filtering**: FastText offline binary classifier handles ≥ 70% of classifications in
  < 5 ms. The existing LLM backends are demoted to a second-pass for uncertain cases (confidence 0.4–0.8),
  cutting Ollama load significantly on high-traffic tenants.
- **Full observability stack**: Loki + Promtail for log aggregation, OpenTelemetry + Jaeger for distributed
  tracing, and Alertmanager for alert routing (PagerDuty/Slack) ship in the same release. Every service
  emits structured JSON logs with a consistent schema.
- **Secrets architecture matures**: HashiCorp Vault joins the KMS provider roster. All new infra services
  (Postgres, PgBouncer, Alertmanager, Loki, Vault) auto-generate 36-char passwords at bootstrap, consistent
  with the established policy.
- **Per-endpoint rate limiting and response caching** close the last two gaps in the API control surface.
  Endpoint rate limits are configurable at runtime via the backoffice; caching is disabled by default and
  gated on CLEAN classification.
- **JWT introspection** with JWKS caching eliminates the need for opaque token round-trips. Fail-closed is
  the default. Container seccomp + AppArmor profiles complete the ASVS Level 3 container hardening arc
  started in v0.4.0.
- All 13 feature areas (A–M) are phased across 12 implementation phases. No external API calls are
  authorized without explicit Tiago GO per the HITL protocol. ASVS v5 and OWASP LLM Top 10 2025 control
  mappings are in Section 12.

---

## 2. Repo Layout Diff

```
yashigani/
├── .github/                                        [UNCHANGED]
├── config/
│   ├── prometheus.yml                              [MODIFIED] — add new scrape targets
│   ├── prometheus_alerts.yml                       [MODIFIED] — add 5 new alert rules
│   ├── alertmanager.yml                            [NEW] — routes + receivers config
│   ├── loki/
│   │   └── loki.yml                               [NEW]
│   ├── promtail/
│   │   └── promtail.yml                           [NEW]
│   ├── otel/
│   │   └── otel-collector.yml                     [NEW]
│   ├── grafana/
│   │   ├── provisioning/
│   │   │   ├── datasources/
│   │   │   │   ├── prometheus.yml                 [UNCHANGED]
│   │   │   │   ├── loki.yml                       [NEW]
│   │   │   │   └── jaeger.yml                     [NEW]
│   │   │   └── dashboards/
│   │   │       └── dashboards.yml                 [MODIFIED] — add new dashboard paths
│   │   └── dashboards/
│   │       ├── gateway.json                       [MODIFIED] — add cache + JWT + endpoint RL panels
│   │       ├── audit.json                         [MODIFIED] — add repeated-small-calls panel
│   │       ├── logs.json                          [NEW] — Loki log stream panels
│   │       ├── tracing.json                       [NEW] — Jaeger trace panels
│   │       └── anomaly.json                       [NEW] — FastText + anomaly detection
│   └── logging.json                               [NEW] — Python structured logging config
├── docker/
│   ├── docker-compose.yml                         [MODIFIED] — add 8 new services
│   ├── Dockerfile.gateway                         [MODIFIED] — tmpfs mounts, seccomp label
│   ├── Dockerfile.backoffice                      [MODIFIED] — same
│   ├── seccomp/
│   │   └── yashigani-gateway.json                [NEW] — custom seccomp allowlist
│   ├── apparmor/
│   │   └── yashigani-gateway                     [NEW] — AppArmor deny rules
│   └── pgbouncer/
│       └── pgbouncer.ini                          [NEW] — PgBouncer transaction mode config
├── helm/
│   ├── charts/
│   │   ├── gateway/                               [MODIFIED] — seccomp + apparmor securityContext
│   │   ├── backoffice/                            [MODIFIED] — same
│   │   ├── postgres/                              [NEW] — StatefulSet, PVC, init job
│   │   ├── pgbouncer/                             [NEW]
│   │   ├── alertmanager/                          [NEW]
│   │   ├── loki/                                  [NEW]
│   │   ├── otel-collector/                        [NEW]
│   │   ├── jaeger/                                [NEW]
│   │   └── vault/                                 [NEW] — optional, dev-mode only
│   └── yashigani/
│       ├── Chart.yaml                             [MODIFIED] — version bump to 0.5.0
│       └── values.yaml                            [MODIFIED] — new service blocks
├── models/
│   └── fasttext_classifier.bin                   [NEW] — downloaded by init container
├── policy/                                        [UNCHANGED]
├── scripts/
│   ├── generate_training_data.py                 [NEW] — FastText training data generator
│   └── bootstrap_postgres.py                     [NEW] — one-shot DB init + password gen
├── src/
│   └── yashigani/
│       ├── audit/
│       │   ├── schema.py                          [UNCHANGED]
│       │   ├── writer.py                          [MODIFIED] — become MultiSinkAuditWriter
│       │   └── sinks.py                           [NEW] — FileSink, PostgresSink, SiemSink
│       ├── backoffice/
│       │   ├── app.py                             [MODIFIED] — add new routers
│       │   └── routes/
│       │       ├── cache.py                       [NEW] — /admin/cache/*
│       │       ├── jwt_config.py                  [NEW] — /admin/jwt/*
│       │       ├── audit_sinks.py                 [NEW] — /admin/audit/sinks
│       │       └── kms_vault.py                   [NEW] — /admin/kms/vault/status
│       ├── db/
│       │   ├── __init__.py                        [NEW]
│       │   ├── postgres.py                        [NEW] — asyncpg pool + PgBouncer DSN
│       │   ├── models.py                          [NEW] — table definitions + RLS helpers
│       │   └── migrations/
│       │       ├── env.py                         [NEW] — Alembic env
│       │       ├── script.py.mako                 [NEW] — migration template
│       │       └── versions/
│       │           └── 0001_initial_schema.py     [NEW] — full DDL migration
│       ├── gateway/
│       │   ├── proxy.py                           [MODIFIED] — JWT, endpoint RL, cache, OTEL, PG write
│       │   ├── jwt_inspector.py                   [NEW] — JWKS fetch + JWT validation
│       │   ├── endpoint_ratelimit.py              [NEW] — per-endpoint RL logic
│       │   └── response_cache.py                  [NEW] — Redis response cache
│       ├── inference/
│       │   ├── payload_logger.py                  [NEW] — async Postgres payload log writer
│       │   └── anomaly.py                         [NEW] — sliding-window small-call detector
│       ├── inspection/
│       │   └── backends/
│       │       └── fasttext_backend.py            [NEW] — FastText first-pass classifier
│       ├── kms/
│       │   └── providers/
│       │       └── vault.py                       [NEW] — Vault AppRole KMS provider
│       ├── metrics/
│       │   └── registry.py                        [MODIFIED] — add 15 new metrics
│       └── tracing/
│           ├── __init__.py                        [NEW]
│           └── otel.py                            [NEW] — OTLP tracer setup
├── alembic.ini                                    [NEW]
└── pyproject.toml                                 [MODIFIED] — add asyncpg, alembic, fasttext, otel deps
```

---

## 3. Phase Breakdown

---

### Phase 1 — PostgreSQL Foundation
**Goal:** Bring up Postgres 16 + PgBouncer; generate password; run Alembic initial migration; verify RLS.
**Effort:** 2 days
**Dependencies:** None (foundational)

#### Files Created/Modified

| Path | Action |
|------|--------|
| `src/yashigani/db/__init__.py` | CREATE |
| `src/yashigani/db/postgres.py` | CREATE |
| `src/yashigani/db/models.py` | CREATE |
| `src/yashigani/db/migrations/env.py` | CREATE |
| `src/yashigani/db/migrations/script.py.mako` | CREATE |
| `src/yashigani/db/migrations/versions/0001_initial_schema.py` | CREATE |
| `alembic.ini` | CREATE |
| `docker/docker-compose.yml` | MODIFY — add postgres + pgbouncer services |
| `docker/pgbouncer/pgbouncer.ini` | CREATE |
| `scripts/bootstrap_postgres.py` | CREATE |
| `pyproject.toml` | MODIFY — add asyncpg>=0.29, alembic>=1.13 |

#### Key Decisions

- **asyncpg not psycopg2**: asyncpg is a native async Postgres driver with 2–3x throughput vs psycopg2
  for async FastAPI workloads. It does not support DBAPI2; all queries use asyncpg's native protocol.
- **PgBouncer transaction mode**: transaction mode is the only mode compatible with asyncpg's prepared
  statement cache and connection pooling. Session mode would break `SET app.tenant_id` between requests.
  The `app.tenant_id` session variable must be set at the start of every transaction, not at connection
  open time.
- **pgcrypto for column encryption**: pgcrypto runs server-side — encrypted blobs are stored and the key
  material never leaves the DB connection. Application-layer encryption would require fetching plaintext
  over the connection for every read; pgcrypto allows `pgp_sym_encrypt` / `pgp_sym_decrypt` inline in SQL.
- **Alembic, not raw DDL scripts**: Alembic gives a migration history that CI can run `alembic upgrade head`
  against idempotently. Raw scripts require manual sequencing.
- **Password**: 36-char auto-generated at bootstrap via `secrets.token_urlsafe(27)`, printed once to stdout
  of the `bootstrap_postgres` init container. Matches established policy for all infra services.

#### Cross-Phase Dependencies

Phases 2 (inference logging), 10 (audit sinks), and 12 (ML classification) all require Phase 1 to
have a live pool connection in the gateway process. Phase 1 must be complete before any of them.

---

### Phase 2 — Inference Payload Logging + Anomaly Detection
**Goal:** Log every inference call to Postgres `inference_events`; detect repeated small calls.
**Effort:** 1.5 days
**Dependencies:** Phase 1

#### Files Created/Modified

| Path | Action |
|------|--------|
| `src/yashigani/inference/payload_logger.py` | CREATE |
| `src/yashigani/inference/anomaly.py` | CREATE |
| `src/yashigani/gateway/proxy.py` | MODIFY — call payload_logger + anomaly detector post-inspection |
| `src/yashigani/metrics/registry.py` | MODIFY — add `yashigani_repeated_small_calls_total` |
| `src/yashigani/backoffice/routes/inspection.py` | MODIFY — add anomaly threshold GET/PUT endpoints |
| `config/grafana/dashboards/anomaly.json` | CREATE |

#### Key Decisions

- **Async fire-and-forget write**: `payload_logger.py` enqueues writes to an `asyncio.Queue` and a
  background task drains it in batches of 50. This keeps the gateway request path latency unaffected
  by Postgres I/O. The queue depth is the `InferencePayloadLogLag` Prometheus gauge.
- **SHA-256 hash, not raw payload, in the non-encrypted column**: the `payload_hash` column is indexed
  and used for deduplication and anomaly correlation. The actual payload content goes into the
  AES-encrypted `payload_content` column.
- **Sliding window via Redis ZSET**: the small-call detector uses `ZADD` + `ZREMRANGEBYSCORE` +
  `ZCARD` on a sorted set keyed by `(tenant_id, session_id)`. Redis is the right store for this:
  it is ephemeral and does not require durability. Postgres would be overkill and slower.

---

### Phase 3 — Alertmanager + Alert Rules
**Goal:** Ship Alertmanager; wire all 5 new alert rules; configure PagerDuty + Slack receivers.
**Effort:** 1 day
**Dependencies:** Phase 1 (for DBConnectionPoolExhausted rule)

#### Files Created/Modified

| Path | Action |
|------|--------|
| `config/alertmanager.yml` | CREATE |
| `config/prometheus_alerts.yml` | MODIFY — add 5 rules |
| `docker/docker-compose.yml` | MODIFY — add alertmanager service |
| `helm/charts/alertmanager/` | CREATE — sub-chart |
| `config/grafana/dashboards/gateway.json` | MODIFY — link to alertmanager |

#### Key Decisions

- **Alertmanager not Grafana alerting**: Alertmanager is already in the Prometheus ecosystem and
  integrates natively with the existing Prometheus stack. Grafana alerting would add a second
  alert evaluation engine with different semantics.
- **PagerDuty + Slack routing**: critical alerts use both channels (PagerDuty for paging, Slack for
  visibility); warnings go Slack-only. This is documented in the receiver config in Section 9.

---

### Phase 4 — Container Hardening (seccomp + AppArmor + tmpfs)
**Goal:** Custom seccomp profile; AppArmor profile; tmpfs mounts for writable dirs; Helm wiring.
**Effort:** 1 day
**Dependencies:** v0.4.0 read-only root filesystem (already done)

#### Files Created/Modified

| Path | Action |
|------|--------|
| `docker/seccomp/yashigani-gateway.json` | CREATE |
| `docker/apparmor/yashigani-gateway` | CREATE |
| `docker/docker-compose.yml` | MODIFY — add security_opt + tmpfs |
| `docker/Dockerfile.gateway` | MODIFY — document writable dirs |
| `docker/Dockerfile.backoffice` | MODIFY — document writable dirs |
| `helm/charts/gateway/templates/deployment.yaml` | MODIFY — seccompProfile + appArmorProfile |
| `helm/charts/backoffice/templates/deployment.yaml` | MODIFY — same |

#### Key Decisions

- **Syscall allowlist (not denylist)**: the seccomp profile explicitly allows only the syscalls needed
  for Python + asyncio. Everything else is denied. This is stricter than a denylist and aligns with
  ASVS V14.3.
- **tmpfs for `/tmp` and `/data/audit` write buffer**: the gateway writes temporary buffers to `/tmp`
  and the audit queue flush writes to `/data/audit`. Both directories need write access despite
  `readOnlyRootFilesystem: true`. tmpfs mounts are ephemeral (lost on restart) and never persist
  sensitive data to the overlay filesystem.
- **UID 1001 verified**: both Dockerfiles already set `USER yashigani` (UID 1001). This phase
  adds `runAsUser: 1001` + `runAsNonRoot: true` explicitly to all Helm securityContexts.

---

### Phase 5 — Per-Endpoint Rate Limiting
**Goal:** Add per-endpoint RL logic; admin GET/PUT endpoints; exempt health/metrics routes.
**Effort:** 1 day
**Dependencies:** None (builds on existing Redis RL infrastructure)

#### Files Created/Modified

| Path | Action |
|------|--------|
| `src/yashigani/gateway/endpoint_ratelimit.py` | CREATE |
| `src/yashigani/gateway/proxy.py` | MODIFY — call endpoint RL check before session RL |
| `src/yashigani/backoffice/routes/ratelimit.py` | MODIFY — add /admin/ratelimit/endpoints |
| `src/yashigani/backoffice/app.py` | MODIFY — mount new endpoints |

#### Key Decisions

- **Redis key pattern `rl:ep:{endpoint_hash}:{window_bucket}`**: the endpoint hash is SHA-256 of the
  normalized path template (e.g., `/agents/{agent_id}` not the literal path). The window bucket is
  `int(time.time() / window_seconds)`. This is a fixed-window counter — simpler than sliding window
  and sufficient for per-endpoint abuse detection.
- **Health/metrics exemption list is hard-coded**: `/healthz`, `/readyz`, `/internal/metrics` bypass
  all rate limiting. These endpoints must always respond for container orchestrators.

---

### Phase 6 — Response Caching
**Goal:** Redis response cache with CLEAN-only gate; admin toggle; Prometheus metrics.
**Effort:** 1 day
**Dependencies:** Phase 2 (classification result must be CLEAN before caching)

#### Files Created/Modified

| Path | Action |
|------|--------|
| `src/yashigani/gateway/response_cache.py` | CREATE |
| `src/yashigani/gateway/proxy.py` | MODIFY — check cache before forward; populate after |
| `src/yashigani/backoffice/routes/cache.py` | CREATE |
| `src/yashigani/backoffice/app.py` | MODIFY — mount cache router |
| `src/yashigani/metrics/registry.py` | MODIFY — add 3 cache metrics |

#### Key Decisions

- **Cache disabled by default**: opt-in per tenant. Caching MCP responses can mask upstream errors
  and interfere with stateful MCP session semantics. Operators must explicitly enable it.
- **Cache key = SHA-256(tenant_id + normalized_body)**: normalizing the body (sorted JSON keys,
  stripped whitespace) increases cache hit rate for semantically identical requests. The normalization
  is best-effort; binary or non-JSON bodies skip caching.
- **Max TTL 3600s enforced server-side**: regardless of admin config, the Redis `SETEX` call caps
  TTL at 3600s. This prevents stale compliance-sensitive responses persisting indefinitely.

---

### Phase 7 — JWT Introspection
**Goal:** Inspect `Authorization: Bearer` JWTs; validate claims; JWKS cache; admin config.
**Effort:** 1.5 days
**Dependencies:** None

#### Files Created/Modified

| Path | Action |
|------|--------|
| `src/yashigani/gateway/jwt_inspector.py` | CREATE |
| `src/yashigani/gateway/proxy.py` | MODIFY — call JWT inspector in `_extract_identity` |
| `src/yashigani/backoffice/routes/jwt_config.py` | CREATE |
| `src/yashigani/backoffice/app.py` | MODIFY — mount jwt_config router |
| `pyproject.toml` | MODIFY — add PyJWT>=2.8 (no cryptography extra needed; we do RS256 via jwcrypto) |

#### Key Decisions

- **PyJWT not python-jose**: python-jose has had repeated CVEs (CVE-2022-29217). PyJWT >= 2.8 with
  explicit algorithm allow-listing is the safe choice.
- **JWKS in-memory + Redis two-level cache**: in-memory cache (TTL 5 min) avoids Redis RTT on every
  request. Redis cache (TTL 5 min) is the fallback for multi-instance deployments where in-memory
  caches are not shared.
- **Fail-closed default**: if the JWKS endpoint is unreachable and the Redis cache is cold, the
  gateway returns 401. Fail-open is available as a config option but must be explicitly set.
- **No `alg: none` allowed**: the JWT inspector rejects tokens with `alg: none` unconditionally,
  even if the JWKS URL is not configured.

---

### Phase 8 — Structured Logging + Loki
**Goal:** Standardize JSON log schema; ship Loki + Promtail; Grafana Logs dashboard.
**Effort:** 1 day
**Dependencies:** None

#### Files Created/Modified

| Path | Action |
|------|--------|
| `config/logging.json` | CREATE |
| `config/loki/loki.yml` | CREATE |
| `config/promtail/promtail.yml` | CREATE |
| `config/grafana/provisioning/datasources/loki.yml` | CREATE |
| `config/grafana/dashboards/logs.json` | CREATE |
| `docker/docker-compose.yml` | MODIFY — add loki + promtail services |
| `helm/charts/loki/` | CREATE |

#### Key Decisions

- **Promtail Docker log driver** (not sidecar): in Docker Compose deployments, Promtail reads
  Docker socket log files via the `__path__` label. This avoids a sidecar per service. In Kubernetes,
  the Helm chart switches to a DaemonSet Promtail.
- **Loki in single-binary mode**: for the Docker Compose dev/staging stack, Loki runs in
  single-binary mode. Production Kubernetes deployments should use the Loki Helm chart with
  distributed mode. The plan scopes single-binary only.
- **Log rotation**: `logging.json` configures `RotatingFileHandler` with `maxBytes=104857600`
  (100 MB) and `backupCount=5`. This is already partially implemented via `YASHIGANI_AUDIT_MAX_FILE_SIZE_MB`;
  Phase 8 standardizes it across all services via the shared `logging.json` config.

---

### Phase 9 — OpenTelemetry Tracing
**Goal:** OTLP spans for all gateway operations; Jaeger UI; `X-Trace-Id` header; trace metrics.
**Effort:** 1.5 days
**Dependencies:** Phase 1 (Postgres span), Phase 2 (inference span)

#### Files Created/Modified

| Path | Action |
|------|--------|
| `src/yashigani/tracing/__init__.py` | CREATE |
| `src/yashigani/tracing/otel.py` | CREATE |
| `src/yashigani/gateway/proxy.py` | MODIFY — wrap spans around OPA, inspection, forward, Redis, PG |
| `src/yashigani/backoffice/app.py` | MODIFY — add OTEL middleware |
| `config/otel/otel-collector.yml` | CREATE |
| `config/grafana/provisioning/datasources/jaeger.yml` | CREATE |
| `config/grafana/dashboards/tracing.json` | CREATE |
| `docker/docker-compose.yml` | MODIFY — add otel-collector + jaeger services |
| `helm/charts/otel-collector/` | CREATE |
| `helm/charts/jaeger/` | CREATE |
| `pyproject.toml` | MODIFY — add opentelemetry-sdk>=1.24, opentelemetry-exporter-otlp>=1.24 |

#### Key Decisions

- **OTLP via gRPC not HTTP**: gRPC OTLP is more efficient for high-volume span export and supports
  bidirectional streaming. The otel-collector receives on `0.0.0.0:4317` (gRPC) and forwards to
  Jaeger's OTLP receiver.
- **`X-Trace-Id` from W3C traceparent**: the response header is populated from the W3C `traceparent`
  header trace ID field, not a Yashigani-proprietary format. This allows third-party tools to
  correlate traces.
- **Sampling at 100% in dev, configurable in prod**: the otel-collector applies a tail-sampling
  processor. Default: sample 100% of error traces, 10% of success traces in production.

---

### Phase 10 — Audit Multi-Sink Writer
**Goal:** Audit events go to File + Postgres simultaneously; optional Splunk/Elasticsearch SIEM.
**Effort:** 1 day
**Dependencies:** Phase 1

#### Files Created/Modified

| Path | Action |
|------|--------|
| `src/yashigani/audit/sinks.py` | CREATE |
| `src/yashigani/audit/writer.py` | MODIFY — become MultiSinkAuditWriter |
| `src/yashigani/backoffice/routes/audit_sinks.py` | CREATE |
| `src/yashigani/backoffice/app.py` | MODIFY — mount audit_sinks router |

#### Key Decisions

- **Write to FileSink synchronously, PostgresSink async**: file writes must be synchronous to
  guarantee the audit trail is never lost even if the Postgres connection is down. The PostgresSink
  uses the same asyncio queue pattern as the inference payload logger.
- **SiemSink is optional and fail-open**: SIEM forwarding failures must not block audit writes.
  The SiemSink catches all exceptions and increments a `yashigani_siem_forward_errors_total` counter.

---

### Phase 11 — HashiCorp Vault KMS Provider
**Goal:** Vault AppRole provider; Docker Compose dev service; admin status endpoint.
**Effort:** 1 day
**Dependencies:** None

#### Files Created/Modified

| Path | Action |
|------|--------|
| `src/yashigani/kms/providers/vault.py` | CREATE |
| `src/yashigani/backoffice/routes/kms_vault.py` | CREATE |
| `src/yashigani/backoffice/app.py` | MODIFY — mount vault status router |
| `docker/docker-compose.yml` | MODIFY — add optional vault service |
| `helm/charts/vault/` | CREATE |
| `pyproject.toml` | MODIFY — add hvac>=2.1 as optional `vault` extra |

#### Key Decisions

- **AppRole auth only**: Kubernetes auth and Token auth are more powerful but AppRole is the
  correct choice for container workloads without a Kubernetes service account. It requires only
  a `role_id` and `secret_id` mounted as Docker secrets.
- **KV v2 only**: KV v1 has no secret versioning. All Vault secrets are stored under the `kv/`
  mount with metadata versioning enabled.
- **Dev mode Vault in Docker Compose**: Vault in dev mode stores everything in memory and is
  not suitable for production. The compose service has a clear label and the README must warn
  operators.

---

### Phase 12 — FastText ML Content Filtering
**Goal:** FastText first-pass classifier; LLM second-pass for uncertain range; init container.
**Effort:** 2 days
**Dependencies:** Phase 9 (tracing spans)

#### Files Created/Modified

| Path | Action |
|------|--------|
| `src/yashigani/inspection/backends/fasttext_backend.py` | CREATE |
| `scripts/generate_training_data.py` | CREATE |
| `docker/docker-compose.yml` | MODIFY — fasttext-init service to download model |
| `src/yashigani/metrics/registry.py` | MODIFY — add FastText metrics |
| `pyproject.toml` | MODIFY — add fasttext>=0.9.2 |

#### Key Decisions

- **fasttext not transformers**: the HuggingFace `transformers` library adds 2–4 GB to the image
  and has 50–200 ms inference latency. fasttext produces a 10–100 MB model with < 5 ms inference.
  For a binary CLEAN/UNSAFE classifier, fasttext is the right tool.
- **Confidence threshold 0.4–0.8 for LLM second-pass**: FastText confidence below 0.4 is
  considered ambiguous (→ LLM second-pass); above 0.8 is considered certain (→ direct decision).
  The 0.4–0.8 band is configurable via backoffice.
- **Model downloaded by init container, not baked into image**: the binary model file is 50–100 MB.
  Baking it into the image increases image size and complicates model updates. The init container
  downloads from a configurable URL (default: internal S3/GCS bucket, never a public endpoint
  without operator configuration).

---

## 4. Full PostgreSQL Schema (DDL)

```sql
-- ============================================================
-- Extensions
-- ============================================================
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================
-- Encryption helper
-- The AES key is stored in a Postgres parameter, injected at
-- connection time from the application's KMS provider.
-- Never hard-code key material in DDL.
-- ============================================================
-- Key reference: current_setting('app.aes_key')
-- Usage: pgp_sym_encrypt(plaintext, current_setting('app.aes_key'))
--        pgp_sym_decrypt(ciphertext::bytea, current_setting('app.aes_key'))

-- ============================================================
-- tenants
-- Root table. Not per-tenant; scoped to the platform.
-- ============================================================
CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_active       BOOLEAN NOT NULL DEFAULT true
);

-- ============================================================
-- tenant_context
-- Per-tenant configuration blob.
-- ============================================================
CREATE TABLE tenant_context (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    config_key      TEXT NOT NULL,
    config_value    TEXT NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, config_key)
);

ALTER TABLE tenant_context ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_context
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- ============================================================
-- rbac_groups
-- ============================================================
CREATE TABLE rbac_groups (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT,
    rate_limit_rps  INTEGER,
    rate_limit_burst INTEGER,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

ALTER TABLE rbac_groups ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON rbac_groups
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- ============================================================
-- rbac_members
-- ============================================================
CREATE TABLE rbac_members (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    group_id        UUID NOT NULL REFERENCES rbac_groups(id) ON DELETE CASCADE,
    -- AES-256-GCM encryption on email (PII)
    email_encrypted BYTEA NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, group_id, email_encrypted)
);

ALTER TABLE rbac_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON rbac_members
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- Insert example (application inserts encrypted value):
-- INSERT INTO rbac_members (tenant_id, group_id, email_encrypted)
-- VALUES ($1, $2, pgp_sym_encrypt($3, current_setting('app.aes_key')));

-- ============================================================
-- agent_registry
-- ============================================================
CREATE TABLE agent_registry (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_name      TEXT NOT NULL,
    upstream_url    TEXT NOT NULL,
    token_hash      TEXT NOT NULL,    -- SHA-256 hex of the agent bearer token
    rate_limit_rps  INTEGER NOT NULL DEFAULT 10,
    rate_limit_burst INTEGER NOT NULL DEFAULT 5,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, agent_name)
);

ALTER TABLE agent_registry ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent_registry
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- ============================================================
-- audit_events
-- Append-only. No UPDATE or DELETE permitted for app user.
-- Retention enforced via pg_partman partitioning by month.
-- ============================================================
CREATE TABLE audit_events (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    event_type      TEXT NOT NULL,
    request_id      UUID,
    session_id      TEXT,
    agent_id        TEXT,
    action          TEXT NOT NULL,
    reason          TEXT,
    upstream_status INTEGER,
    elapsed_ms      INTEGER,
    confidence_score DOUBLE PRECISION,
    client_ip_hash  TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
) PARTITION BY RANGE (created_at);

-- Monthly partitions (example; pg_partman manages creation automatically)
CREATE TABLE audit_events_2026_03
    PARTITION OF audit_events
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_events
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- Indexes
CREATE INDEX idx_audit_events_tenant_created ON audit_events (tenant_id, created_at DESC);
CREATE INDEX idx_audit_events_request_id ON audit_events (request_id);

-- ============================================================
-- inference_events
-- Every inference call. Payload content is AES-encrypted.
-- ============================================================
CREATE TABLE inference_events (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id),
    session_id              TEXT NOT NULL,
    agent_id                TEXT NOT NULL,
    payload_hash            TEXT NOT NULL,          -- SHA-256 hex, NOT encrypted (indexed)
    payload_length          INTEGER NOT NULL,
    response_length         INTEGER,
    -- AES-256-GCM encrypted columns
    payload_content         BYTEA,                  -- pgp_sym_encrypt(content, key)
    response_content        BYTEA,                  -- pgp_sym_encrypt(content, key)
    classification_label    TEXT NOT NULL,
    classification_confidence DOUBLE PRECISION NOT NULL,
    backend_used            TEXT NOT NULL,
    latency_ms              INTEGER NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
) PARTITION BY RANGE (created_at);

CREATE TABLE inference_events_2026_03
    PARTITION OF inference_events
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

ALTER TABLE inference_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON inference_events
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

CREATE INDEX idx_inference_events_tenant_session ON inference_events (tenant_id, session_id, created_at DESC);
CREATE INDEX idx_inference_events_payload_hash ON inference_events (payload_hash);

-- ============================================================
-- anomaly_thresholds
-- Per-tenant configurable thresholds for anomaly detection.
-- ============================================================
CREATE TABLE anomaly_thresholds (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    window_seconds  INTEGER NOT NULL DEFAULT 60,
    call_count_n    INTEGER NOT NULL DEFAULT 10,
    payload_threshold_bytes INTEGER NOT NULL DEFAULT 256,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id)
);

ALTER TABLE anomaly_thresholds ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON anomaly_thresholds
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- ============================================================
-- jwt_config
-- Per-tenant JWT introspection configuration.
-- ============================================================
CREATE TABLE jwt_config (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    jwks_url        TEXT NOT NULL,
    issuer          TEXT NOT NULL,
    audience        TEXT NOT NULL,
    fail_closed     BOOLEAN NOT NULL DEFAULT true,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id)
);

ALTER TABLE jwt_config ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON jwt_config
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- ============================================================
-- cache_config
-- Per-tenant response cache configuration.
-- ============================================================
CREATE TABLE cache_config (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    enabled         BOOLEAN NOT NULL DEFAULT false,
    ttl_seconds     INTEGER NOT NULL DEFAULT 300,
    max_size_mb     INTEGER NOT NULL DEFAULT 64,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id)
);

ALTER TABLE cache_config ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON cache_config
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- ============================================================
-- endpoint_ratelimit_overrides
-- Per-endpoint rate limit overrides (admin-set).
-- ============================================================
CREATE TABLE endpoint_ratelimit_overrides (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    endpoint_hash   TEXT NOT NULL,    -- SHA-256 of normalized path template
    endpoint_label  TEXT NOT NULL,    -- human-readable path template
    rps             INTEGER NOT NULL,
    burst           INTEGER NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, endpoint_hash)
);

ALTER TABLE endpoint_ratelimit_overrides ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON endpoint_ratelimit_overrides
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- ============================================================
-- Application role (least privilege)
-- ============================================================
CREATE ROLE yashigani_app LOGIN PASSWORD 'PLACEHOLDER_REPLACED_BY_BOOTSTRAP';
GRANT CONNECT ON DATABASE yashigani TO yashigani_app;
GRANT USAGE ON SCHEMA public TO yashigani_app;
GRANT SELECT, INSERT ON audit_events TO yashigani_app;
GRANT SELECT, INSERT ON inference_events TO yashigani_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO yashigani_app;
REVOKE DELETE ON audit_events FROM yashigani_app;
REVOKE DELETE ON inference_events FROM yashigani_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE ON TABLES TO yashigani_app;
```

---

## 5. Gateway Code Specification

### 5.1 `src/yashigani/db/postgres.py`

```python
"""
Postgres connection pool via asyncpg + PgBouncer.

Design:
- Single asyncpg pool per process, shared across all coroutines.
- PgBouncer is the actual Postgres connection manager (transaction mode).
  asyncpg connects to PgBouncer (port 5432), not Postgres directly.
- app.tenant_id and app.aes_key are SET at the start of every transaction.
  This is safe in PgBouncer transaction mode because the SET is within the
  transaction boundary.
- All queries use asyncpg's $1/$2 parameterized syntax. No f-strings in SQL.
"""
from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

import asyncpg
from asyncpg import Pool, Connection

logger = logging.getLogger(__name__)

_pool: Pool | None = None
_AES_KEY_ENV = "YASHIGANI_DB_AES_KEY"


async def create_pool() -> Pool:
    """
    Called once at application startup.
    DSN points to PgBouncer, not Postgres directly.
    """
    dsn = os.environ["YASHIGANI_DB_DSN"]   # e.g. postgresql://yashigani_app:PWD@pgbouncer:5432/yashigani
    global _pool
    _pool = await asyncpg.create_pool(
        dsn=dsn,
        min_size=2,
        max_size=10,               # PgBouncer caps at 20 per service; leave headroom
        max_inactive_connection_lifetime=300,
        command_timeout=10,
        init=_init_connection,
    )
    logger.info("Postgres pool created (PgBouncer DSN)")
    return _pool


async def _init_connection(conn: Connection) -> None:
    """
    Called by asyncpg for every new physical connection.
    Prepares commonly used statements.
    Note: SET commands in init run on the raw connection, not a transaction,
    so they persist for the connection lifetime in asyncpg.
    The per-request SET inside the transaction overrides this.
    """
    await conn.execute("SET application_name = 'yashigani-gateway'")


async def close_pool() -> None:
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


@asynccontextmanager
async def tenant_transaction(
    tenant_id: str,
) -> AsyncIterator[Connection]:
    """
    Acquire a connection, open a transaction, and SET the tenant context.
    Yields the connection for use within the transaction.
    RLS policies evaluate current_setting('app.tenant_id') on every row access.
    The AES key is also injected here so pgcrypto functions can reference it.

    Usage:
        async with tenant_transaction(tenant_id) as conn:
            await conn.fetchrow(
                "SELECT id FROM tenants WHERE id = $1",
                uuid.UUID(tenant_id),
            )
    """
    assert _pool is not None, "DB pool not initialized — call create_pool() at startup"
    aes_key = os.environ.get(_AES_KEY_ENV, "")
    async with _pool.acquire() as conn:
        async with conn.transaction():
            # SET LOCAL is scoped to the current transaction — correct for PgBouncer
            await conn.execute(
                "SELECT set_config('app.tenant_id', $1, true),"
                "       set_config('app.aes_key', $2, true)",
                tenant_id,
                aes_key,
            )
            yield conn


def get_pool() -> Pool:
    assert _pool is not None
    return _pool
```

### 5.2 `src/yashigani/db/models.py`

```python
"""
Table column definitions and typed row helpers.

Not an ORM. asyncpg returns asyncpg.Record objects; these dataclasses
provide typed wrappers for the most frequently accessed rows.

Why no ORM: SQLAlchemy async adds significant complexity (session management,
lazy loading footguns). For a security-critical gateway, explicit SQL with
$N parameters is auditable and deterministic.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class TenantRow:
    id: uuid.UUID
    name: str
    is_active: bool
    created_at: datetime


@dataclass(frozen=True)
class AgentRegistryRow:
    id: uuid.UUID
    tenant_id: uuid.UUID
    agent_name: str
    upstream_url: str
    token_hash: str
    rate_limit_rps: int
    rate_limit_burst: int
    is_active: bool


@dataclass(frozen=True)
class InferenceEventRow:
    tenant_id: uuid.UUID
    session_id: str
    agent_id: str
    payload_hash: str
    payload_length: int
    response_length: Optional[int]
    classification_label: str
    classification_confidence: float
    backend_used: str
    latency_ms: int


@dataclass(frozen=True)
class AuditEventRow:
    tenant_id: uuid.UUID
    event_type: str
    request_id: Optional[uuid.UUID]
    session_id: Optional[str]
    agent_id: Optional[str]
    action: str
    reason: Optional[str]
    upstream_status: Optional[int]
    elapsed_ms: Optional[int]
    confidence_score: Optional[float]
    client_ip_hash: Optional[str]


# ---------------------------------------------------------------------------
# Query helpers — all use $N parameterization, no string interpolation
# ---------------------------------------------------------------------------

INSERT_INFERENCE_EVENT = """
INSERT INTO inference_events (
    tenant_id, session_id, agent_id, payload_hash, payload_length,
    response_length, payload_content, response_content,
    classification_label, classification_confidence,
    backend_used, latency_ms
) VALUES (
    $1, $2, $3, $4, $5, $6,
    pgp_sym_encrypt($7, current_setting('app.aes_key')),
    pgp_sym_encrypt($8, current_setting('app.aes_key')),
    $9, $10, $11, $12
)
"""

INSERT_AUDIT_EVENT = """
INSERT INTO audit_events (
    tenant_id, event_type, request_id, session_id, agent_id,
    action, reason, upstream_status, elapsed_ms,
    confidence_score, client_ip_hash
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
"""

SELECT_AGENT_BY_TOKEN_HASH = """
SELECT id, tenant_id, agent_name, upstream_url, token_hash,
       rate_limit_rps, rate_limit_burst, is_active
FROM   agent_registry
WHERE  tenant_id = $1
AND    token_hash = $2
AND    is_active = true
"""
```

### 5.3 `src/yashigani/db/migrations/` (Alembic structure)

```
db/migrations/
├── env.py           — loads YASHIGANI_DB_DSN; runs migrations via asyncpg sync wrapper
├── script.py.mako   — standard Alembic template
└── versions/
    └── 0001_initial_schema.py
        revision = "0001"
        down_revision = None
        # upgrade(): runs the full DDL block from Section 4 via op.execute()
        # downgrade(): DROP TABLE cascade in reverse dependency order
```

`alembic.ini` at repo root:
```ini
[alembic]
script_location = src/yashigani/db/migrations
sqlalchemy.url = %(YASHIGANI_DB_DSN)s
```

CI runs `alembic upgrade head` after `docker compose up -d postgres pgbouncer` in the integration
test stage.

### 5.4 Gateway `proxy.py` modifications

The following modifications are additive to the existing `proxy.py`. Existing logic is not removed.

```python
# In _extract_identity() — append JWT inspection after existing logic:

async def _extract_identity_v2(request: Request, state: dict) -> tuple[str, str, str]:
    """
    Extended identity extraction with JWT introspection.
    Falls back to existing cookie/API-key logic if no JWT is present.
    """
    session_id, agent_id, user_id = _extract_identity(request)

    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer ") and _is_jwt(auth_header[7:]):
        jwt_inspector = state.get("jwt_inspector")
        if jwt_inspector is not None:
            result = await jwt_inspector.inspect(auth_header[7:], request)
            if not result.valid:
                # Return sentinel that the caller checks for 401
                return session_id, agent_id, "__JWT_INVALID__"
            if result.sub and user_id == "unknown":
                user_id = result.sub
            # Refresh session_id to be JWT-derived for consistent RL keying
            session_id = hashlib.sha256(result.sub.encode()).hexdigest()[:16]

    return session_id, agent_id, user_id


def _is_jwt(token: str) -> bool:
    """A token is a JWT if it has exactly 3 base64url-separated parts."""
    return token.count(".") == 2


# In _handle_request() — add after identity extraction, before rate limiting:

    # JWT identity check — must happen before rate limiting (RL keys on session_id)
    if user_id == "__JWT_INVALID__":
        return Response(
            status_code=401,
            headers={
                "WWW-Authenticate": 'Bearer error="invalid_token"',
                "X-Yashigani-Request-Id": request_id,
            },
        )

    # Endpoint rate limit — before session RL
    ep_rl = state.get("endpoint_rate_limiter")
    if ep_rl is not None and not _is_exempt_path(path):
        ep_result = ep_rl.check(path, user_id)
        if not ep_result.allowed:
            return JSONResponse(status_code=429, content={"error": "ENDPOINT_RATE_LIMIT_EXCEEDED"})

    # After OPA check, before forward — check response cache:
    cache = state.get("response_cache")
    if cache is not None and request.method == "POST":
        cached = await cache.get(tenant_id, forwarded_body)
        if cached is not None:
            # Cache hit — return immediately, no upstream call
            return cached

    # After forward — populate cache if result is CLEAN:
    if cache is not None and inspection_result.action == "FORWARDED":
        await cache.set(tenant_id, forwarded_body, upstream_response)

    # Emit X-Trace-Id on every response:
    response.headers["X-Trace-Id"] = current_trace_id()

    # Set app.tenant_id for Postgres writes:
    # tenant_id is derived from the authenticated session's tenant binding
    # (looked up from Redis session store or JWT claim)
```

### 5.5 `src/yashigani/audit/sinks.py`

```python
"""
Multi-sink audit writer.

Sinks:
  FileSink      — synchronous RotatingFileHandler (already implemented, refactored here)
  PostgresSink  — async batch writer to audit_events table via asyncpg
  SiemSink      — optional async forwarding to Splunk HEC or Elasticsearch bulk API

Architecture:
  MultiSinkAuditWriter.write(event) is synchronous (called from sync gateway context).
  The FileSink writes synchronously.
  The PostgresSink and SiemSink enqueue to asyncio.Queue and drain in a background task.
  If the queue is full (> 1000 items), the write is dropped and a counter is incremented.
  This design ensures audit writes never block the gateway request path.
"""
from __future__ import annotations

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


class AuditSink(ABC):
    name: str

    @abstractmethod
    async def write(self, event: dict) -> None: ...

    @abstractmethod
    async def last_write_ts(self) -> datetime | None: ...


class FileSink(AuditSink):
    name = "file"

    def __init__(self, writer):  # existing AuditWriter instance
        self._writer = writer
        self._last_write: datetime | None = None

    async def write(self, event: dict) -> None:
        # Delegate to existing synchronous file writer
        self._writer._write_raw(json.dumps(event))
        self._last_write = datetime.now(timezone.utc)

    async def last_write_ts(self) -> datetime | None:
        return self._last_write


class PostgresSink(AuditSink):
    name = "postgres"
    MAX_QUEUE_DEPTH = 1000

    def __init__(self, pool_getter):
        self._pool_getter = pool_getter   # callable returning asyncpg Pool
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=self.MAX_QUEUE_DEPTH)
        self._last_write: datetime | None = None
        self._task: asyncio.Task | None = None

    def start(self):
        self._task = asyncio.create_task(self._drain_loop())

    async def _drain_loop(self):
        BATCH_SIZE = 50
        DRAIN_INTERVAL = 2.0  # seconds
        while True:
            batch = []
            try:
                # Collect up to BATCH_SIZE events, wait up to DRAIN_INTERVAL
                deadline = asyncio.get_event_loop().time() + DRAIN_INTERVAL
                while len(batch) < BATCH_SIZE:
                    timeout = max(0, deadline - asyncio.get_event_loop().time())
                    try:
                        item = await asyncio.wait_for(self._queue.get(), timeout=timeout)
                        batch.append(item)
                    except asyncio.TimeoutError:
                        break
                if batch:
                    await self._flush_batch(batch)
            except Exception as exc:
                logger.error("PostgresSink drain error: %s", exc)
                await asyncio.sleep(5)

    async def _flush_batch(self, batch: list[dict]):
        from yashigani.db.postgres import get_pool
        from yashigani.db.models import INSERT_AUDIT_EVENT
        pool = get_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                for event in batch:
                    await conn.execute(
                        INSERT_AUDIT_EVENT,
                        event["tenant_id"],
                        event["event_type"],
                        event.get("request_id"),
                        event.get("session_id"),
                        event.get("agent_id"),
                        event["action"],
                        event.get("reason"),
                        event.get("upstream_status"),
                        event.get("elapsed_ms"),
                        event.get("confidence_score"),
                        event.get("client_ip_hash"),
                    )
        self._last_write = datetime.now(timezone.utc)

    async def write(self, event: dict) -> None:
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            from yashigani.metrics.registry import audit_queue_overflow_total
            audit_queue_overflow_total.inc()
            logger.warning("PostgresSink queue full — audit event dropped")

    async def last_write_ts(self) -> datetime | None:
        return self._last_write


class SiemSink(AuditSink):
    """
    Optional SIEM forwarding. Fail-open: errors are logged and counted,
    never propagated to the caller.
    Supports: Splunk HEC, Elasticsearch bulk API.
    """
    name = "siem"

    def __init__(self, siem_type: str, endpoint: str, token: str):
        self._siem_type = siem_type   # "splunk" | "elasticsearch"
        self._endpoint = endpoint
        self._token = token
        self._last_write: datetime | None = None

    async def write(self, event: dict) -> None:
        import httpx
        try:
            if self._siem_type == "splunk":
                await self._send_splunk(event)
            elif self._siem_type == "elasticsearch":
                await self._send_elasticsearch(event)
            self._last_write = datetime.now(timezone.utc)
        except Exception as exc:
            try:
                from yashigani.metrics.registry import siem_forward_errors_total
                siem_forward_errors_total.labels(siem=self._siem_type).inc()
            except Exception:
                pass
            logger.warning("SiemSink forward error (%s): %s", self._siem_type, exc)

    async def _send_splunk(self, event: dict) -> None:
        import httpx
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(
                self._endpoint,
                json={"event": event, "sourcetype": "yashigani_audit"},
                headers={"Authorization": f"Splunk {self._token}"},
            )

    async def _send_elasticsearch(self, event: dict) -> None:
        import httpx
        async with httpx.AsyncClient(timeout=5.0) as client:
            # Elasticsearch bulk API: newline-delimited JSON
            meta = json.dumps({"index": {"_index": "yashigani-audit"}})
            body = f"{meta}\n{json.dumps(event)}\n"
            await client.post(
                self._endpoint + "/_bulk",
                content=body,
                headers={
                    "Content-Type": "application/x-ndjson",
                    "Authorization": f"ApiKey {self._token}",
                },
            )

    async def last_write_ts(self) -> datetime | None:
        return self._last_write


class MultiSinkAuditWriter:
    """
    Drop-in replacement for the existing AuditWriter.
    write() is synchronous — compatible with existing call sites.
    Each event is serialized and dispatched to all sinks.
    FileSink writes synchronously; other sinks enqueue asynchronously.
    """

    def __init__(self, sinks: list[AuditSink]):
        self._sinks = sinks

    def write(self, event) -> None:
        """
        Accept a Pydantic audit event (existing schema) and dispatch to all sinks.
        """
        try:
            event_dict = event.model_dump() if hasattr(event, "model_dump") else dict(event)
            for sink in self._sinks:
                try:
                    # FileSink.write is a coroutine but we call it in a fire-and-forget
                    # wrapper using the running event loop
                    import asyncio
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        asyncio.ensure_future(sink.write(event_dict))
                    else:
                        loop.run_until_complete(sink.write(event_dict))
                except Exception as exc:
                    logger.error("Sink %s write error: %s", sink.name, exc)
        except Exception as exc:
            logger.error("MultiSinkAuditWriter serialization error: %s", exc)
```

---

## 6. New Services Table

| Service | Image | Internal Port | Purpose | Auto-gen Secret |
|---------|-------|---------------|---------|-----------------|
| `postgres` | `postgres:16-alpine` | 5432 | Primary durable store (tenants, audit, inference, RBAC, agents) | Yes — 36-char `POSTGRES_PASSWORD` |
| `pgbouncer` | `bitnami/pgbouncer:1.22` | 5432 | Connection pooler (transaction mode, max 20 conn/service) | No — inherits Postgres password |
| `alertmanager` | `prom/alertmanager:latest` | 9093 | Alert routing (PagerDuty + Slack) | Yes — 36-char admin password |
| `loki` | `grafana/loki:3.0` | 3100 | Log aggregation backend | No — internal only |
| `promtail` | `grafana/promtail:3.0` | 9080 | Log shipper (Docker → Loki) | No — internal only |
| `otel-collector` | `otel/opentelemetry-collector-contrib:0.100` | 4317 (gRPC), 4318 (HTTP) | OTLP trace receiver + Jaeger exporter | No — internal only |
| `jaeger` | `jaegertracing/all-in-one:1.57` | 16686 (UI), 4317 (OTLP) | Distributed trace UI | Yes — 36-char UI admin password |
| `vault` | `hashicorp/vault:1.16` | 8200 | Dev-mode KMS provider (NOT for production) | Yes — 36-char root token printed at init |
| `fasttext-init` | `yashigani/gateway:latest` | — | One-shot: downloads `fasttext_classifier.bin` from configured URL | No |

---

## 7. New Prometheus Metrics Table

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `yashigani_repeated_small_calls_total` | Counter | `tenant_id` | Cumulative REPEATED_SMALL_CALLS anomaly events fired |
| `yashigani_inference_payload_log_queue_depth` | Gauge | — | Current depth of the async inference payload write queue |
| `yashigani_cache_hits_total` | Counter | `tenant_id` | Cache hits on response cache |
| `yashigani_cache_misses_total` | Counter | `tenant_id` | Cache misses |
| `yashigani_cache_evictions_total` | Counter | `tenant_id` | Cache keys evicted (TTL + manual) |
| `yashigani_jwt_validations_total` | Counter | `result` (valid/invalid/expired/fetch_error) | JWT introspection outcomes |
| `yashigani_jwks_cache_hits_total` | Counter | `layer` (memory/redis) | JWKS cache hit by layer |
| `yashigani_fasttext_classifications_total` | Counter | `result` (clean/unsafe/uncertain) | FastText first-pass outcomes |
| `yashigani_fasttext_latency_ms` | Histogram | — | FastText inference latency |
| `yashigani_trace_spans_total` | Counter | `span_name`, `status` | OTLP spans emitted |
| `yashigani_db_pool_acquired_total` | Counter | `service` | Postgres pool acquisitions |
| `yashigani_db_pool_waittime_seconds` | Histogram | — | Time waiting for a pool connection |
| `yashigani_audit_queue_overflow_total` | Counter | — | Audit events dropped due to full queue |
| `yashigani_siem_forward_errors_total` | Counter | `siem` (splunk/elasticsearch) | SIEM forwarding failures |
| `yashigani_endpoint_ratelimit_violations_total` | Counter | `endpoint_hash` | Per-endpoint RL violations |

---

## 8. New Grafana Dashboards Table

| Dashboard | Panels Count | Key Panels |
|-----------|--------------|------------|
| `gateway.json` (modified) | +6 panels | Cache hit ratio, JWT validation outcomes, endpoint RL violations, response latency P99 by endpoint |
| `anomaly.json` (new) | 8 panels | Repeated small calls rate per tenant, inference payload length distribution, anomaly events timeline, queue depth gauge |
| `logs.json` (new) | 6 panels | Log stream per service, error log rate by service, log volume heatmap, log latency filter panel |
| `tracing.json` (new) | 5 panels | Span latency P50/P95/P99 by span name, error span rate, trace volume, Jaeger embed link |
| `audit.json` (modified) | +3 panels | PostgresSink write lag, FileSink rotation events, SIEM forward error rate |

---

## 9. Alertmanager Configuration

```yaml
# config/alertmanager.yml
global:
  resolve_timeout: 5m
  smtp_require_tls: true
  # PagerDuty and Slack keys injected at runtime from secrets volume
  pagerduty_url: https://events.pagerduty.com/v2/enqueue

route:
  group_by: [alertname, tenant_id]
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  receiver: slack-warning
  routes:
    - match:
        severity: critical
      receiver: critical-combined
      continue: false
    - match:
        severity: warning
      receiver: slack-warning
      continue: false

receivers:

  - name: slack-warning
    slack_configs:
      - api_url_file: /run/secrets/slack_webhook_url
        channel: "#yashigani-alerts"
        send_resolved: true
        title: '[{{ .Status | toUpper }}] {{ .GroupLabels.alertname }}'
        text: |
          {{ range .Alerts }}
          *Alert:* {{ .Annotations.summary }}
          *Description:* {{ .Annotations.description }}
          *Severity:* {{ .Labels.severity }}
          {{ if .Labels.tenant_id }}*Tenant:* {{ .Labels.tenant_id }}{{ end }}
          {{ end }}
        color: '{{ if eq .Status "firing" }}warning{{ else }}good{{ end }}'

  - name: critical-combined
    slack_configs:
      - api_url_file: /run/secrets/slack_webhook_url
        channel: "#yashigani-oncall"
        send_resolved: true
        title: '[CRITICAL] {{ .GroupLabels.alertname }}'
        text: |
          {{ range .Alerts }}
          *Alert:* {{ .Annotations.summary }}
          *Description:* {{ .Annotations.description }}
          {{ if .Labels.tenant_id }}*Tenant:* {{ .Labels.tenant_id }}{{ end }}
          *Runbook:* {{ .Annotations.runbook_url }}
          {{ end }}
        color: danger
    pagerduty_configs:
      - routing_key_file: /run/secrets/pagerduty_integration_key
        description: '{{ .GroupLabels.alertname }}: {{ (index .Alerts 0).Annotations.summary }}'
        severity: critical
        details:
          alert_count: '{{ len .Alerts }}'
          tenant_ids: '{{ range .Alerts }}{{ .Labels.tenant_id }} {{ end }}'

inhibit_rules:
  # If a 5xx spike is firing, suppress the 4xx spike alert (they often co-occur)
  - source_match:
      alertname: GatewayError5xxSpike
    target_match:
      alertname: GatewayError4xxSpike
    equal: [instance]
```

```yaml
# config/prometheus_alerts.yml — additions to existing file
groups:
  - name: yashigani_gateway
    rules:
      - alert: GatewayError4xxSpike
        expr: rate(yashigani_gateway_upstream_status_total{status_code=~"4.."}[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High 4xx error rate on gateway"
          description: "4xx rate is {{ $value | humanize }}/s over 5m (threshold: 10/s)"
          runbook_url: "https://wiki.internal/yashigani/runbooks/4xx-spike"

      - alert: GatewayError5xxSpike
        expr: rate(yashigani_gateway_upstream_status_total{status_code=~"5.."}[5m]) > 5
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Critical 5xx error rate on gateway"
          description: "5xx rate is {{ $value | humanize }}/s over 5m (threshold: 5/s)"
          runbook_url: "https://wiki.internal/yashigani/runbooks/5xx-spike"

      - alert: DBConnectionPoolExhausted
        expr: pgbouncer_pools_cl_active / pgbouncer_pools_pool_size > 0.9
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "PgBouncer connection pool near exhaustion"
          description: "Pool utilization is {{ $value | humanizePercentage }} (threshold: 90%)"
          runbook_url: "https://wiki.internal/yashigani/runbooks/db-pool"

      - alert: InferencePayloadLogLag
        expr: yashigani_inference_payload_log_queue_depth > 1000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Inference audit write queue is backing up"
          description: "Queue depth: {{ $value }} (threshold: 1000)"
          runbook_url: "https://wiki.internal/yashigani/runbooks/audit-lag"

      - alert: RepeatedSmallCallsSpike
        expr: rate(yashigani_repeated_small_calls_total[1m]) > 5
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Repeated small call anomaly spike detected"
          description: "Rate: {{ $value | humanize }}/min per tenant (threshold: 5/min)"
          runbook_url: "https://wiki.internal/yashigani/runbooks/small-calls"
```

---

## 10. Docker Compose Additions

The following services are appended to the existing `docker-compose.yml`. The `x-common-env` anchor
is already defined; services reference it via `<<: *common-env`.

```yaml
  # ---------------------------------------------------------------------------
  # PostgreSQL 16 — primary durable store
  # Password auto-generated at bootstrap; see scripts/bootstrap_postgres.py
  # ---------------------------------------------------------------------------
  postgres:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: yashigani
      POSTGRES_USER: yashigani_app
      POSTGRES_PASSWORD_FILE: /run/secrets/postgres_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - secrets_volume:/run/secrets:ro
    secrets:
      - postgres_password
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U yashigani_app -d yashigani"]
      interval: 10s
      timeout: 5s
      retries: 5
    security_opt:
      - no-new-privileges:true
    networks:
      - internal

  # ---------------------------------------------------------------------------
  # PgBouncer — transaction-mode connection pooler
  # ---------------------------------------------------------------------------
  pgbouncer:
    image: bitnami/pgbouncer:1.22
    restart: unless-stopped
    environment:
      POSTGRESQL_HOST: postgres
      POSTGRESQL_PORT: "5432"
      POSTGRESQL_DATABASE: yashigani
      POSTGRESQL_USERNAME: yashigani_app
      POSTGRESQL_PASSWORD_FILE: /run/secrets/postgres_password
      PGBOUNCER_AUTH_TYPE: scram-sha-256
      PGBOUNCER_POOL_MODE: transaction
      PGBOUNCER_MAX_CLIENT_CONN: "100"
      PGBOUNCER_DEFAULT_POOL_SIZE: "20"
      PGBOUNCER_STATS_USERS: yashigani_app
    volumes:
      - secrets_volume:/run/secrets:ro
      - ./pgbouncer/pgbouncer.ini:/bitnami/pgbouncer/conf/pgbouncer.ini:ro
    secrets:
      - postgres_password
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - internal

  # ---------------------------------------------------------------------------
  # Alertmanager — alert routing
  # ---------------------------------------------------------------------------
  alertmanager:
    image: prom/alertmanager:latest
    restart: unless-stopped
    command:
      - "--config.file=/etc/alertmanager/alertmanager.yml"
      - "--storage.path=/alertmanager"
    volumes:
      - ../config/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro
      - alertmanager_data:/alertmanager
      - secrets_volume:/run/secrets:ro
    secrets:
      - slack_webhook_url
      - pagerduty_integration_key
    depends_on:
      - prometheus
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:9093/-/healthy"]
      interval: 15s
      timeout: 5s
      retries: 3
    networks:
      - internal

  # ---------------------------------------------------------------------------
  # Loki — log aggregation
  # ---------------------------------------------------------------------------
  loki:
    image: grafana/loki:3.0.0
    restart: unless-stopped
    command: -config.file=/etc/loki/loki.yml
    volumes:
      - ../config/loki/loki.yml:/etc/loki/loki.yml:ro
      - loki_data:/loki
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:3100/ready | grep -q ready"]
      interval: 15s
      timeout: 5s
      retries: 5
    networks:
      - internal

  # ---------------------------------------------------------------------------
  # Promtail — log shipper (Docker logs → Loki)
  # ---------------------------------------------------------------------------
  promtail:
    image: grafana/promtail:3.0.0
    restart: unless-stopped
    command: -config.file=/etc/promtail/promtail.yml
    volumes:
      - ../config/promtail/promtail.yml:/etc/promtail/promtail.yml:ro
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    depends_on:
      - loki
    networks:
      - internal

  # ---------------------------------------------------------------------------
  # OpenTelemetry Collector — OTLP receiver, Jaeger exporter
  # ---------------------------------------------------------------------------
  otel-collector:
    image: otel/opentelemetry-collector-contrib:0.100.0
    restart: unless-stopped
    command: ["--config=/etc/otel/otel-collector.yml"]
    volumes:
      - ../config/otel/otel-collector.yml:/etc/otel/otel-collector.yml:ro
    ports:
      - "4317:4317"    # gRPC OTLP — internal only in production (remove host binding)
    depends_on:
      - jaeger
    networks:
      - internal

  # ---------------------------------------------------------------------------
  # Jaeger — distributed trace UI
  # ---------------------------------------------------------------------------
  jaeger:
    image: jaegertracing/all-in-one:1.57
    restart: unless-stopped
    environment:
      COLLECTOR_OTLP_ENABLED: "true"
    volumes:
      - jaeger_data:/tmp
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:14269/"]
      interval: 15s
      timeout: 5s
      retries: 3
    networks:
      - internal

  # ---------------------------------------------------------------------------
  # Vault — dev-mode KMS provider (NOT FOR PRODUCTION)
  # ---------------------------------------------------------------------------
  vault:
    image: hashicorp/vault:1.16
    restart: unless-stopped
    cap_add:
      - IPC_LOCK
    environment:
      VAULT_DEV_ROOT_TOKEN_ID_FILE: /run/secrets/vault_root_token
      VAULT_DEV_LISTEN_ADDRESS: "0.0.0.0:8200"
    volumes:
      - secrets_volume:/run/secrets:ro
    secrets:
      - vault_root_token
    healthcheck:
      test: ["CMD", "vault", "status"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - internal
    profiles:
      - vault    # opt-in: docker compose --profile vault up

  # ---------------------------------------------------------------------------
  # FastText model init — one-shot download
  # ---------------------------------------------------------------------------
  fasttext-init:
    image: yashigani/gateway:${YASHIGANI_VERSION:-latest}
    restart: "no"
    entrypoint: ["/bin/sh", "-c"]
    command:
      - |
        MODEL_URL="${FASTTEXT_MODEL_URL:?set FASTTEXT_MODEL_URL}"
        MODEL_PATH="/models/fasttext_classifier.bin"
        if [ ! -f "$MODEL_PATH" ]; then
          echo "Downloading FastText model from $MODEL_URL..."
          wget -q -O "$MODEL_PATH" "$MODEL_URL"
          echo "FastText model downloaded: $(wc -c < $MODEL_PATH) bytes"
        else
          echo "FastText model already present — skipping download"
        fi
    volumes:
      - models_data:/models
    networks:
      - internal

# New volumes (append to existing volumes section):
# postgres_data, alertmanager_data, loki_data, jaeger_data, models_data
```

---

## 11. Open Questions

1. ~~**JWKS URL per-tenant vs. platform-wide**~~ **RESOLVED 2026-03-27:** Ship **both** — this
   decision maps directly to the three Yashigani product streams now confirmed:

   | Stream | JWT scope | JWKS resolution |
   |--------|-----------|-----------------|
   | **Open Source** | Single deployment, single org | Platform-wide `YASHIGANI_JWKS_URL` env var; `jwt_config` has one row (`tenant_id = platform`) |
   | **Corporate** | Self-hosted, multiple internal IdPs per business unit | Per-tenant `jwks_url` in `jwt_config`; fallback to platform-wide if tenant row absent |
   | **SaaS** | Fully multi-tenant; each customer brings their own IdP | Per-tenant `jwks_url` mandatory; platform-wide JWKS used only for admin/service accounts |

   **Implementation design (Phase 7 update):**
   - `jwt_config` table gains a `scope` column: `'platform' | 'tenant'`
   - JWKS resolution order in `JWTIntrospector.resolve_jwks(tenant_id)`:
     1. Look up `jwt_config WHERE tenant_id = $1 AND scope = 'tenant'` — use if found
     2. Fall back to `jwt_config WHERE scope = 'platform'` — use if found
     3. Fall back to `YASHIGANI_JWKS_URL` env var — use if set
     4. If nothing: return configured fail behavior (fail-closed by default)
   - `YASHIGANI_DEPLOYMENT_STREAM` env var (`opensource | corporate | saas`) controls which
     backoffice UI flows are exposed:
     - `opensource`: hide per-tenant JWKS UI, show only platform JWKS setting
     - `corporate`: show both platform and per-tenant JWKS UI
     - `saas`: enforce per-tenant JWKS (platform-wide alone is blocked via validation)
   - Admin panel: `GET/PUT /admin/jwt/config` gains a `scope` field and stream-aware validation
   - The `tenant_id` column on all tables uses `'00000000-0000-0000-0000-000000000000'` as the
     sentinel UUID for platform-scoped rows (avoids NULL complications with RLS)
   - Forking note: the `opensource` stream ships without the SaaS tenant-management routes
     compiled in — controlled via `YASHIGANI_DEPLOYMENT_STREAM` feature flag, not separate
     code branches, to keep the codebase unified

2. ~~**FastText model hosting**~~ **RESOLVED 2026-03-27:** Option (c) — bundle the FastText
   classifier model directly into the gateway image (~100 MB size increase). No `fasttext-init`
   init container. The model is copied via `COPY models/fasttext_classifier.bin /app/models/`
   in `docker/Dockerfile.gateway`. CI verifies the SHA-256 digest. Multi-arch (amd64/arm64)
   builds carry the same binary (FastText models are architecture-independent). The `fasttext-init`
   service is removed from all compose files and Helm charts.

3. ~~**PagerDuty integration key**~~ **RESOLVED 2026-03-27:** Alerting notifications are
   configurable in the admin panel with three escalation options in order:
   1. **Email** — primary; configured at install time or via `Admin → Alerts → Notifications`
   2. **Phone/SMS** — secondary; Twilio-backed, admin sets E.164 number in admin panel
   3. **PagerDuty** — tertiary; admin pastes integration key in `Admin → Alerts → PagerDuty`
   Alertmanager `critical-combined` receiver chains all three; each is optional and independently
   toggled. If a channel is unconfigured, Alertmanager skips it. Auto-generated channel secrets
   (Twilio auth token, PagerDuty key) stored in KMS, printed at install when provided.

4. ~~**Postgres partition management**~~ **RESOLVED 2026-03-27:** Include `pg_partman` extension
   in the Postgres image. The init SQL installs it (`CREATE EXTENSION IF NOT EXISTS pg_partman`)
   and registers `inference_payloads` and `audit_events` under `partman.create_parent()` with
   `monthly` interval. A `pg_cron` job calls `partman.run_maintenance()` nightly. No APScheduler
   involvement — partition lifecycle is fully managed inside Postgres.

5. ~~**Splunk/Elasticsearch SIEM endpoint**~~ **RESOLVED 2026-03-27:** The admin panel exposes
   a SIEM integration selector under `Admin → Audit → SIEM Integration` with four modes:

   | Mode | Description |
   |------|-------------|
   | **None** | Default. Audit events to file + Postgres only. |
   | **Splunk** | Admin enters HEC URL + token; stored in KMS. |
   | **Elasticsearch** | Admin enters endpoint URL + API key; stored in KMS. |
   | **Wazuh (self-hosted)** | Two sub-modes: *auto-deploy* (Yashigani adds `wazuh` compose service, generates and prints credentials at install) or *connect to existing* (admin enters Wazuh indexer URL + credentials). |

   Implementation notes:
   - `SiemSink` gains a `backend` parameter: `"splunk" | "elasticsearch" | "wazuh" | None`
   - Wazuh mode reuses the Elasticsearch bulk API format (Wazuh indexer = OpenSearch) — minimal
     extra code path
   - Auto-deploy mode adds `docker/docker-compose.wazuh.yml` as an opt-in compose override,
     exactly like the Podman override pattern from v0.4.0
   - Wazuh manager + indexer + dashboard are three containers; auto-deploy generates a 36-char
     random password for the Wazuh admin account and prints it at install (same policy as all
     other system credentials)
   - `SiemSink` is fail-open: SIEM forwarding failures are counted in
     `yashigani_siem_forward_errors_total` and never propagate to the audit write path

---

## 12. Security Controls Checklist

| Feature | ASVS v5 Control | OWASP LLM Top 10 2025 | Notes |
|---------|-----------------|----------------------|-------|
| A. PostgreSQL RLS | V3.5 (Contextual data access), V8.2 (Sensitive data at rest) | LLM06: Excessive Agency | Per-tenant isolation enforced at DB layer; application cannot bypass RLS |
| A. AES-256-GCM column encryption | V8.2.1 (Encryption at rest for PII), V8.3.7 (Strong cipher) | LLM06 | pgcrypto AES-256 via `pgp_sym_encrypt`; key injected via KMS, never in DDL |
| A. Prepared statements only | V5.3.4 (SQL injection prevention) | — | asyncpg's `$N` parameterization; no string-concatenated SQL allowed anywhere |
| A. PgBouncer + connection pooling | V1.14 (Resource limits) | — | Transaction mode prevents session variable leakage across tenants |
| A. Alembic migrations | V14.2 (Dependency management) | — | Migration history in version control; no manual DDL drift |
| B. Inference payload logging | V8.1.3 (Audit log integrity), V7.1 (Logging completeness) | LLM02: Insecure Output Handling | Hash + length logged in clear; content AES-encrypted; SHA-256 links both |
| B. Repeated small-call detection | V13.4 (DoS protection) | LLM04: Model Denial of Service | Sliding window in Redis; configurable per-tenant thresholds |
| C. Alertmanager | V7.4.1 (Alert on security events) | — | Critical alerts page via PagerDuty; all alert configs in version-controlled YAML |
| C. 4xx/5xx spike alerts | V7.4 (Error logging and alerting) | LLM04 | Rate-based alerting with distinct warning/critical thresholds |
| D. seccomp profile (syscall allowlist) | V14.3.1 (OS hardening) | — | Deny ptrace, mount, module loading — prevents privilege escalation via syscall |
| D. AppArmor profile | V14.3.2 (Mandatory access control) | — | Deny raw network and /proc writes — limits post-exploit lateral movement |
| D. tmpfs for writable dirs | V14.3 (Unintended data disclosure) | — | Ephemeral writes never hit overlay filesystem |
| D. UID 1001 non-root enforcement | V14.3.3 (Least privilege process) | — | `runAsNonRoot: true` + `runAsUser: 1001` in all Helm securityContexts |
| E. Per-endpoint rate limiting | V13.4.1 (Rate limiting per resource) | LLM04: Model Denial of Service | Endpoint-level RL prevents targeted resource exhaustion |
| E. Health/metrics RL exemption | V11.1 (Service availability) | — | Orchestrators must always reach health probes |
| F. Response caching (CLEAN-only) | V13.2.6 (Caching controls) | LLM02 | Non-CLEAN responses are never cached; prevents tainted response reuse |
| F. Cache invalidation endpoint | V13.2 (RESTful web service security) | — | Admin-authenticated DELETE endpoint; no tenant can invalidate another's cache |
| G. JWT introspection | V3.5 (Token-based sessions), V3.5.3 (JWT validation) | LLM09: Misinformation | exp/iss/aud validated; alg:none rejected unconditionally |
| G. JWKS cache | V3.5.1 (Token revocation) | — | 5-min TTL balances freshness vs. JWKS server DoS |
| G. Fail-closed default | V3.5.2 (Secure defaults) | — | Unknown JWKS = 401; operator must explicitly opt into fail-open |
| H. Structured JSON logging | V7.1 (Logging content), V7.1.3 (Sensitive data in logs) | LLM06 | Schema enforced; no raw payload content in logs — only hash and length |
| H. Loki log aggregation | V7.3 (Log protection) | — | Logs centralized; shipped over internal network only |
| I. OpenTelemetry tracing | V7.2 (Log processing), V7.4 (Alert on security events) | LLM07: System Prompt Leakage | Trace IDs link audit events to request spans; span content never includes raw payload |
| I. X-Trace-Id header | V7.2.1 (Log correlation) | — | W3C traceparent format; enables cross-system correlation |
| J. Vault KMS provider | V6.4 (Secret management), V6.4.1 (Secret store) | — | AppRole auth; KV v2 versioning; dev-mode clearly labeled |
| K. FastText first-pass | V14.2 (Dependency management) | LLM01: Prompt Injection, LLM02 | Offline model — no external API call for classification; < 5 ms latency |
| K. LLM second-pass for uncertain | V14.6 (AI/ML validation) | LLM01 | Confidence-gated second-pass prevents both false positives and false negatives |
| L. MultiSinkAuditWriter | V7.3.1 (Audit log availability), V7.3.3 (Audit log integrity) | — | Dual-write (file + Postgres) ensures audit trail survives single-sink failure |
| L. SIEM forwarding fail-open | V7.3.2 (Audit log protection) | — | SIEM failures never suppress the primary file+Postgres audit trail |
| All | OWASP ASVS Level 3 | OWASP LLM Top 10 2025 | All features validated against Level 3 requirements before deployment gate |

---

*Plan complete. All 13 feature areas (A–M) are phased. No agents instantiated. No external
communications authorized. Awaiting Tiago GO before implementation begins.*
