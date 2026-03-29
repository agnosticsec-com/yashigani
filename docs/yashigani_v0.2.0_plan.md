# Yashigani v0.2.0 — Implementation Plan

> **Archived — COMPLETE.** Current release: **v0.7.1** (2026-03-28).

**Version:** 0.2.0
**Plan date:** 2026-03-26
**Author:** Maxine (PM/PO)
**Status:** Draft — awaiting product owner approval before implementation begins
**Security baseline:** OWASP ASVS v5 (upgrade from v4 applied in this iteration)

---

## 1. Executive Summary

v0.2.0 transforms Yashigani from a functional security proxy into a production-hardened, enterprise-deployable platform. The five capability additions and one compliance upgrade in this iteration address the three most critical gaps in v0.1.0: lack of transport security ownership, no rate limiting or DoS protection, and no role-based authorization at the data plane.

**What v0.2.0 delivers:**

- **TLS everywhere, operator-selectable mode.** A Caddy reverse proxy layer handles TLS termination for both the gateway and the backoffice. Three modes — Let's Encrypt ACME, CA-signed, and self-signed — are selected via a single environment variable. The application layer is unchanged; TLS is infrastructure.

- **Adaptive rate limiting.** An L7 rate limiter sits in the gateway middleware stack before the inspection pipeline. Limits are multi-dimensional (global, per-IP, per-agent, per-session, per-RBAC-role) and self-adjust based on the Resource Pressure Index already computed by the existing `ResourceMonitor`. Token bucket semantics differentiate burst from sustained rate.

- **GPU metrics.** The `ResourceMonitor` gains a GPU tier via provider-agnostic detection (NVML for NVIDIA, ROCm sysfs for AMD, fallback-safe for CPU-only). GPU pressure is incorporated into the RPI formula with a new weight. Ollama GPU utilisation is read via the `/api/ps` endpoint combined with NVML.

- **Full observability stack.** A `yashigani/metrics/` module wraps `prometheus_client`. Every security-relevant event already audited in v0.1.0 gains a corresponding Prometheus metric. Prometheus and Grafana join the Compose stack. Four pre-built Grafana dashboards ship with the product.

- **RBAC at the data plane.** Two provisioning modes — SCIM 2.0 sync from an external IdP and an admin-managed allow-list — feed group/user → resource mappings into OPA as a data document pushed via the OPA REST bundle API. OPA remains the single enforcement point.

- **OWASP ASVS v5 baseline.** Every module is audited against v5 requirements. The OWASP LLM Top 10 2025 and OWASP Agentic AI Security framework controls are mapped and implemented where gaps exist.

**What changes from v0.1.0:**

- The gateway and backoffice no longer bind directly to host ports in production. Caddy binds 443/80 and proxies internally.
- The backoffice binding changes from `127.0.0.1:8443` to an internal Caddy upstream, enabling remote admin access over authenticated TLS without exposing the raw ASGI port.
- The OPA policy bundle (`policy/yashigani.rego`) is replaced with a multi-file bundle that includes RBAC enforcement rules and receives live data pushes from the backoffice RBAC service.
- `ResourceMonitor` in `chs/resource_monitor.py` gains GPU fields and an updated RPI formula; its `ResourceMetrics` dataclass is extended.
- `BackofficeState` gains fields for the rate limiter, RBAC service, GPU monitor, and metrics registry.
- Redis gains two new logical databases: `/2` for rate limit counters, `/3` for RBAC allow-list cache.
- Five new Python packages become core dependencies: `prometheus-client`, `pynvml`, `caddy` (via Docker image, not Python), `limits` (token bucket), `scim2-filter-parser`.

---

## 2. Scope and Goals

### 2.1 Feature Goals and Acceptance Criteria

#### TLS Layer

**Goal:** All external-facing communication is encrypted in transit. No service accepts plaintext HTTP in production. TLS mode is operator-selectable without code changes.

**Acceptance criteria:**
1. `curl -s http://gateway-host/` redirects to HTTPS (HTTP 301) in all modes.
2. `curl -sk https://gateway-host/healthz` returns HTTP 200 in self-signed mode.
3. TLS 1.0 and TLS 1.1 connections are rejected. TLS 1.2 connections succeed. TLS 1.3 is negotiated when client supports it.
4. `curl -sI https://gateway-host/healthz` shows `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` in response headers.
5. In Let's Encrypt mode, certificate auto-renews without service restart; renewal is confirmed by checking certificate expiry with `openssl s_client`.
6. In CA-signed mode, providing a valid CA cert and key in the Caddy secrets directory results in successful TLS handshake verified by a client trusting that CA.
7. Backoffice is reachable at `https://admin.example.com` (or configured hostname) over TLS. Raw port 8443 is not exposed on the Docker host in production mode.
8. `testssl.sh` against the gateway endpoint rates TLS configuration at grade A or above.

#### Adaptive Rate Limiting

**Goal:** The gateway and backoffice cannot be taken down or materially degraded by L7 request floods from any single source or in aggregate. Limits are configurable and auto-tune under resource pressure.

**Acceptance criteria:**
1. Sending 200 requests per second from a single IP for 10 seconds to the gateway produces HTTP 429 responses on requests exceeding the per-IP limit, with a `Retry-After` header present.
2. The rate limiter reads the current RPI from `ResourceMonitor` and applies the correct multiplier: at RPI > 0.8, effective rate is 40% of configured; at RPI 0.6–0.8, 70%; at RPI < 0.3, 100%.
3. Admin `GET /admin/rate-limits` returns current effective limits and the current multiplier.
4. Admin `POST /admin/rate-limits` accepts new base limits and they take effect within one poll interval.
5. Every rate-limit violation produces an audit event of type `RATE_LIMIT_EXCEEDED`.
6. Rate limit state keys in Redis expire correctly; a Redis flush returns the limiter to a clean state.
7. Per-RBAC-role limits override per-IP limits when the session carries a known role.

#### GPU Metrics

**Goal:** The ResourceMonitor accurately reports GPU utilisation and memory for the Ollama container and any other GPU-using service. GPU pressure feeds into the RPI.

**Acceptance criteria:**
1. On a host with an NVIDIA GPU, `GET /dashboard/resources` returns a `gpu` field containing `utilisation_pct`, `memory_used_bytes`, `memory_total_bytes`, `provider`.
2. On a CPU-only host, the same endpoint returns `gpu: {"provider": "none", "utilisation_pct": 0.0}` without error.
3. With GPU utilisation at 90%, the RPI is higher than with GPU utilisation at 10% (all other variables equal).
4. Prometheus metrics `yashigani_gpu_utilisation_pct` and `yashigani_gpu_memory_used_bytes` are scraped successfully by Prometheus.
5. Ollama GPU stats via `/api/ps` are included when Ollama reports an active model.

#### Observability Stack

**Goal:** All security-relevant events, resource metrics, and pipeline performance data are queryable in Prometheus and visualised in Grafana with no manual configuration required after deployment.

**Acceptance criteria:**
1. `curl http://localhost:9090/api/v1/targets` shows all four Yashigani scrape targets as `"health":"up"`.
2. Grafana at `http://localhost:3000` is accessible after `docker compose up`. All four dashboards are present and populated with data after 5 minutes of traffic.
3. All metrics in the catalogue (Section 4.4) are present in Prometheus at `http://localhost:9090/metrics` after the gateway processes one request.
4. Firing a simulated `CREDENTIAL_EXFIL` detection results in a Grafana alert notification within 60 seconds.
5. The `yashigani_gateway_requests_total` counter increments by exactly 1 per proxied request.
6. Per-agent labels are present on all gateway metrics.

#### RBAC

**Goal:** Access to MCP servers, API paths, and agent endpoints is controlled by group membership. OPA enforces all decisions. Allow-list can be managed in the backoffice without editing Rego files.

**Acceptance criteria:**
1. With RBAC mode `allow_list`, an agent belonging to group `analysts` that is not mapped to path `/v1/tools/execute` receives HTTP 403 from the gateway.
2. The same agent mapped to that path receives HTTP 200.
3. With RBAC mode `scim`, adding a group in the IdP and triggering a sync results in the group appearing in `GET /admin/rbac/groups` within the sync interval.
4. `POST /admin/rbac/policy/push` pushes the current RBAC data document to OPA and returns `{"status": "ok"}`.
5. Every RBAC policy change (add/remove group, add/remove mapping) produces an audit event of type `RBAC_POLICY_CHANGED`.
6. An OPA policy violation for a mapped agent produces an audit event of type `RBAC_ACCESS_DENIED`.
7. Per-role rate limits are applied correctly when an agent's group has a configured rate limit override.

#### ASVS v5 Baseline

**Goal:** Every applicable ASVS v5 requirement is implemented or documented as a deferred risk with justification. The OWASP LLM Top 10 2025 and Agentic AI Security controls are fully mapped.

**Acceptance criteria:**
1. A gap analysis table covering all ASVS v5 chapters V1–V14 is produced and all critical/high gaps are resolved in code before v0.2.0 ships.
2. The LLM Top 10 2025 mapping shows a control for each of the 10 risks.
3. No ASVS v5 requirement rated Critical remains unaddressed without written justification signed off by the product owner.

### 2.2 Explicit Out of Scope for v0.2.0

- Multi-tenant Yashigani (multiple upstream MCP servers behind a single Yashigani instance with tenant isolation). Planned v0.3.0.
- Web Application Firewall (WAF) integration. L7 rate limiting covers DoS; WAF is a separate concern.
- mTLS between Yashigani internal services. Internal network isolation via Docker bridge with `internal: true` is the current control. mTLS between internal services is v0.3.0.
- SCIM 2.0 write-back (provisioning users in the IdP from Yashigani). v0.2.0 SCIM is read-only inbound sync.
- Grafana user provisioning or SSO integration with Grafana. Grafana ships with admin/admin in dev mode; production operators configure their own auth.
- Custom Rego rule editing via the backoffice UI. Operators edit Rego files directly in v0.2.0.
- High-availability Redis (Sentinel or Cluster). Single Redis instance only.
- Kubernetes deployment manifests. Docker Compose remains the sole supported deployment target.

---

## 3. Architecture Changes

### 3.1 v0.1.0 Architecture (Reference)

```
Internet ──▶ Docker host :8080 ──▶ gateway (ASGI, plain HTTP internally)
             Docker host :8443 ──▶ backoffice (ASGI, plain HTTP internally, localhost only)
```

The v0.1.0 gateway sends `Strict-Transport-Security` headers but has no TLS itself. The comment in `docker-compose.yml` says "TLS termination handled by reverse proxy / ingress" — that proxy did not exist in the shipped stack.

### 3.2 v0.2.0 Architecture Overview

```
Internet
    │
    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Caddy (TLS edge proxy)                           │
│  :443 → gateway upstream (http://gateway:8080)                      │
│  :443 → backoffice upstream (http://backoffice:8443)               │
│          (routed by hostname or path prefix)                        │
│  :80  → permanent redirect to :443                                  │
│  Modes: acme | ca_signed | self_signed (YASHIGANI_TLS_MODE)         │
└────────────────────────┬────────────────────────────────────────────┘
                         │ internal Docker network
         ┌───────────────┼───────────────────────┐
         ▼               ▼                       ▼
  ┌─────────────┐ ┌─────────────┐        ┌─────────────────┐
  │   gateway   │ │  backoffice │        │   prometheus    │
  │   :8080     │ │   :8443     │        │   :9090         │
  │             │ │             │        │ scrapes: gateway│
  │  middleware │ │  admin UI   │        │ backoffice, opa  │
  │  stack:     │ │             │        │ redis, ollama   │
  │  1. RateLimit│ │             │        └────────┬────────┘
  │  2. Inspect │ │             │                 │
  │  3. OPA     │ │             │        ┌────────▼────────┐
  └──────┬──────┘ └──────┬──────┘        │    grafana      │
         │               │               │    :3000        │
         │               │               │ 4 dashboards    │
         └───────────────┴───────────────┴────────┬────────┘
                         │ internal                │
              ┌──────────┼──────────┐              │
              ▼          ▼          ▼              │
           redis        OPA      ollama        alert mgr
           :6379       :8181    :11434            │
           db/0 sessions                          ▼
           db/1 admin sessions            Admin notifications
           db/2 rate limit counters       (email/webhook/PagerDuty)
           db/3 RBAC allow-list cache
```

### 3.3 New Services

| Service | Image | Port | Purpose |
|---|---|---|---|
| `caddy` | `caddy:2-alpine` | 80, 443 | TLS termination, HTTP→HTTPS redirect, reverse proxy |
| `prometheus` | `prom/prometheus:v2.52` | 9090 | Metrics scraping and storage |
| `grafana` | `grafana/grafana:10.4` | 3000 | Dashboards and alerting |

### 3.4 New Python Modules

| Module path | Purpose |
|---|---|
| `yashigani/metrics/__init__.py` | Prometheus registry and metric definitions |
| `yashigani/metrics/gateway_metrics.py` | Gateway request counters, histograms, labels |
| `yashigani/metrics/inspection_metrics.py` | Classification latency, detection rates |
| `yashigani/metrics/auth_metrics.py` | Auth event counters for backoffice |
| `yashigani/metrics/system_metrics.py` | CPU, memory, GPU gauges |
| `yashigani/metrics/rate_limit_metrics.py` | Rate limiter state gauges |
| `yashigani/ratelimit/__init__.py` | Rate limiter public API |
| `yashigani/ratelimit/limiter.py` | AdaptiveRateLimiter: token bucket + RPI adjustment |
| `yashigani/ratelimit/storage.py` | Redis key schema and atomic counter operations |
| `yashigani/ratelimit/config.py` | RateLimitConfig dataclass and defaults |
| `yashigani/rbac/__init__.py` | RBAC public API |
| `yashigani/rbac/model.py` | RBACGroup, RBACMapping, ResourcePattern dataclasses |
| `yashigani/rbac/store.py` | In-memory + Redis-cached allow-list store |
| `yashigani/rbac/scim.py` | SCIM 2.0 inbound sync endpoint and parser |
| `yashigani/rbac/opa_push.py` | Pushes RBAC data document to OPA REST API |
| `yashigani/chs/gpu_monitor.py` | GPUMonitor: NVML/ROCm/fallback provider |
| `docker/Caddyfile` | Caddy configuration for all three TLS modes |
| `docker/caddy/acme/Caddyfile` | Let's Encrypt mode Caddy config |
| `docker/caddy/ca_signed/Caddyfile` | CA-signed mode Caddy config |
| `docker/caddy/self_signed/Caddyfile` | Self-signed mode Caddy config |
| `policy/rbac.rego` | OPA RBAC enforcement rules |
| `policy/data/rbac_data.json` | Seed RBAC data document (empty groups, replaced by push) |
| `grafana/dashboards/security_overview.json` | Security Overview dashboard |
| `grafana/dashboards/system_health.json` | System Health dashboard |
| `grafana/dashboards/agent_activity.json` | Agent Activity dashboard |
| `grafana/dashboards/rate_limit_status.json` | Rate Limit Status dashboard |
| `grafana/provisioning/datasources/prometheus.yaml` | Grafana datasource provisioning |
| `grafana/provisioning/dashboards/yashigani.yaml` | Grafana dashboard provisioning |
| `prometheus/prometheus.yml` | Prometheus scrape configuration |

### 3.5 Modified Files

| File | What changes |
|---|---|
| `src/yashigani/__init__.py` | Version bump to `0.2.0`; add `rbac`, `ratelimit`, `metrics` to module docstring |
| `src/yashigani/chs/resource_monitor.py` | `ResourceMetrics` gains GPU fields; RPI formula updated; `GPUMonitor` integration |
| `src/yashigani/gateway/proxy.py` | Rate limiter middleware added before inspection pipeline; per-agent Prometheus labels on every request; `agent_id` and `session_id` added to OPA input |
| `src/yashigani/backoffice/state.py` | Add `rate_limiter`, `rbac_store`, `gpu_monitor`, `metrics_registry` fields |
| `src/yashigani/backoffice/app.py` | Register new routers: `rate_limits_router`, `rbac_router`, `metrics_router`, `scim_router` |
| `src/yashigani/backoffice/routes/dashboard.py` | Add GPU metrics to `/dashboard/resources`; add rate limiter summary |
| `src/yashigani/audit/schema.py` | New event types: `RATE_LIMIT_EXCEEDED`, `RBAC_POLICY_CHANGED`, `RBAC_ACCESS_DENIED`, `OPA_PUSH_FAILED`, `GPU_PRESSURE_CRITICAL` |
| `docker/docker-compose.yml` | Add `caddy`, `prometheus`, `grafana` services; expose Caddy on 80/443; remove direct host port bindings for gateway and backoffice in production profile; add Redis db/2 and db/3 configuration |
| `.env.example` | Add TLS, rate limit, RBAC, and observability variables |
| `policy/yashigani.rego` | Import RBAC rules from `rbac.rego`; update OPA input schema to include `groups` |
| `pyproject.toml` | Add `prometheus-client>=0.20`, `limits>=3.12`, `pynvml>=11.5` to core dependencies; add `scim2-filter-parser>=2.0` |

---

## 4. Feature Specifications

### 4.1 TLS Layer

#### 4.1.1 Caddy as the TLS Edge — Justification

Caddy is chosen over Nginx for the following reasons:

1. **Native ACME support.** Caddy implements ACME natively without certbot as a sidecar. Certificate acquisition, storage, and renewal are zero-configuration for Let's Encrypt mode.
2. **Automatic HTTPS redirect.** Caddy enables HTTP→HTTPS redirect by default without additional configuration.
3. **Modern TLS defaults out of the box.** Caddy defaults to TLS 1.2 minimum, TLS 1.3 preferred, and a restricted cipher suite that aligns with Mozilla's "Intermediate" profile without explicit configuration.
4. **OCSP stapling built-in.** No nginx `ssl_stapling` directives needed.
5. **Single binary, Alpine image.** `caddy:2-alpine` is 45 MB, smaller than the Nginx equivalent with certbot.
6. **Operator-readable Caddyfile syntax.** Significantly easier to audit than an equivalent Nginx configuration with certbot hooks.

The tradeoff against Nginx is that Caddy has a smaller community and less operator familiarity in some enterprises. This is mitigated by providing ready-made Caddyfiles for all three modes.

#### 4.1.2 Three TLS Modes

Mode is selected via `YASHIGANI_TLS_MODE` environment variable. Valid values: `acme`, `ca_signed`, `self_signed`. No default — the variable is required. If absent, Caddy startup fails with a clear error message.

**Mode: `acme` (Let's Encrypt)**

For internet-facing production deployments. Requires:
- `YASHIGANI_TLS_DOMAIN` — the public FQDN (e.g., `gateway.example.com`). Required.
- `YASHIGANI_TLS_ACME_EMAIL` — email for Let's Encrypt registration. Required.
- Port 80 reachable from the internet (HTTP-01 challenge) OR DNS credentials configured for DNS-01 challenge.

Caddy stores certificates in the named Docker volume `caddy_data` at `/data/caddy`. Renewal is automatic; Caddy checks expiry every 12 hours and renews at 30 days before expiry.

**Mode: `ca_signed`**

For enterprise or on-premises deployments with an internal CA. Requires:
- `YASHIGANI_TLS_CERT_FILE` — path inside the Caddy container to the PEM certificate file (mounted via Docker volume).
- `YASHIGANI_TLS_KEY_FILE` — path inside the Caddy container to the PEM private key file.

These files are mounted from Docker secrets or a host bind mount. The Caddyfile references them directly. Renewal is the operator's responsibility; Caddy will log a warning when a static certificate expires within 14 days (via the Caddy event log).

**Mode: `self_signed`**

For local development and demo only. Caddy generates a self-signed certificate automatically. No additional configuration required. The Caddyfile includes a comment block visible in `docker compose logs caddy` warning that self-signed mode is not suitable for production and that clients will receive TLS trust errors unless they import the Caddy root CA.

In self-signed mode, the Caddy-generated root CA certificate is exported to the `caddy_data` volume at `/data/caddy/pki/authorities/local/root.crt` for optional import by clients.

#### 4.1.3 Caddyfile Specifications

**acme/Caddyfile:**

```
{
    email {$YASHIGANI_TLS_ACME_EMAIL}
    admin off
}

{$YASHIGANI_TLS_DOMAIN} {
    reverse_proxy /metrics* prometheus:9090
    reverse_proxy /grafana* grafana:3000
    reverse_proxy /admin*   backoffice:8443
    reverse_proxy /*        gateway:8080

    tls {
        protocols tls1.2 tls1.3
        ciphers TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 \
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   \
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 \
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   \
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305  \
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
    }

    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "no-referrer"
        Content-Security-Policy "default-src 'self'"
        -Server
    }

    encode gzip
    log {
        output file /var/log/caddy/access.log
        format json
    }
}

http://{$YASHIGANI_TLS_DOMAIN} {
    redir https://{$YASHIGANI_TLS_DOMAIN}{uri} 301
}
```

**ca_signed/Caddyfile:** Identical to `acme/Caddyfile` except the `tls` block becomes:

```
    tls {$YASHIGANI_TLS_CERT_FILE} {$YASHIGANI_TLS_KEY_FILE} {
        protocols tls1.2 tls1.3
        ciphers ...
    }
```

**self_signed/Caddyfile:** Uses `tls internal` block with Caddy's built-in CA:

```
{
    local_certs
    admin off
}

localhost, 127.0.0.1 {
    tls internal {
        on_demand
    }
    reverse_proxy /admin*  backoffice:8443
    reverse_proxy /*       gateway:8080
    ...
}
```

#### 4.1.4 Certificate Storage and Renewal

| Mode | Storage | Renewal |
|---|---|---|
| `acme` | `caddy_data` Docker named volume at `/data/caddy` | Automatic by Caddy (30-day pre-expiry window) |
| `ca_signed` | Operator-managed. Mounted as Docker secrets or volume bind. | Operator responsibility. Caddy logs warning at 14 days pre-expiry. |
| `self_signed` | `caddy_data` Docker named volume. Regenerated on `docker compose down -v`. | Automatic regeneration. |

#### 4.1.5 HSTS, OCSP Stapling, Cipher Policy

**HSTS:** `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` — two years, all subdomains, preload-eligible. Applied via Caddy `header` directive.

**OCSP Stapling:** Caddy enables OCSP stapling automatically for certificates issued by a CA that publishes an OCSP responder. In `acme` mode, Let's Encrypt certificates are stapled automatically. In `ca_signed` mode, stapling occurs if the CA certificate chain includes an OCSP URI in the AIA extension. In `self_signed` mode, no OCSP stapling (self-signed CAs have no OCSP responder).

**Minimum TLS version:** TLS 1.2. Connections negotiating TLS 1.0 or 1.1 are rejected at the TLS handshake.

**Cipher suites (TLS 1.2):** Only ECDHE key exchange, AES-GCM or ChaCha20-Poly1305 AEAD ciphers. No RSA key exchange. No CBC mode. Specifically:
- `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`
- `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`

**TLS 1.3:** All TLS 1.3 cipher suites are permitted (they are all AEAD; there is no insecure TLS 1.3 cipher).

**Curves:** X25519 preferred, P-256, P-384.

#### 4.1.5a Single-FQDN Routing Decision (Product Owner Confirmed — 2026-03-26)

**Decision:** Single FQDN, path-based routing is the confirmed architecture for v0.2.0 (Q1, Option A). The `/admin/*` path prefix routes to the backoffice upstream. A single TLS certificate covers the entire deployment. One Caddyfile route is required per mode.

This decision supersedes the Option C recommendation in Section 12. Option C flexibility is deferred to v0.3.0 as a non-breaking enhancement. All Caddyfiles are authored accordingly: the ACME, CA-signed, and self-signed variants each use a single server block with path-based routing.

---

#### 4.1.6 Backoffice Binding Change

In v0.1.0: `BACKOFFICE_PORT=127.0.0.1:8443` — backoffice is localhost-only, not accessible remotely.

In v0.2.0: The backoffice ASGI process continues to bind to `0.0.0.0:8443` inside the container (internal Docker network only, not exposed on host). Caddy routes `/admin/*` requests to `backoffice:8443` over the internal Docker network. Remote admin access is via `https://admin.example.com/admin/...` through Caddy, which enforces TLS. The raw port `8443` is not published in the Compose `ports` section in production mode.

The `BACKOFFICE_PORT` environment variable is removed from the production Compose service definition. A `BACKOFFICE_HOST_PORT` variable is added, defaulting to empty (not exposed). Operators who need direct access for debugging can set `BACKOFFICE_HOST_PORT=127.0.0.1:8443`.

#### 4.1.7 ASVS v5 TLS Requirements Mapped

| ASVS v5 Requirement | Implementation |
|---|---|
| V9.1.1 — TLS required for all communications containing sensitive data | Caddy enforces TLS at the edge. HTTP redirects to HTTPS (301). |
| V9.1.2 — TLS 1.2 or higher only | `protocols tls1.2 tls1.3` in Caddyfile. |
| V9.1.3 — Only strong cipher suites (forward secrecy required) | ECDHE-only cipher list, no RSA key exchange, no CBC. |
| V9.2.1 — Certificate validity checked | Caddy validates Let's Encrypt cert chain. CA-signed mode: operator responsibility documented. |
| V9.2.2 — HSTS enforced | `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` |
| V9.2.3 — OCSP stapling or must-staple | OCSP stapling automatic in Caddy for ACME/CA-signed modes. |
| V9.3.1 — Admin interfaces accessible only over authenticated TLS | Backoffice behind Caddy TLS; admin session required for all `/admin/*` routes. |

---

### 4.2 Adaptive Rate Limiting

#### 4.2.1 Architecture

The rate limiter is implemented as an ASGI middleware class injected into the gateway's FastAPI application. It runs before the inspection pipeline, ensuring that rejected requests consume zero inspection resources.

```
Inbound request
       │
       ▼
┌─────────────────────────────┐
│  RateLimitMiddleware        │
│  (gateway middleware stack) │
│                             │
│  1. Extract dimensions:     │
│     - client IP             │
│     - agent_id header       │
│     - session_id cookie     │
│     - RBAC role (if known)  │
│                             │
│  2. Read current RPI from   │
│     ResourceMonitor         │
│     → compute multiplier    │
│                             │
│  3. Check all applicable    │
│     token buckets in Redis  │
│     (atomic Lua script)     │
│                             │
│  4a. All buckets OK →       │
│      call_next(request)     │
│                             │
│  4b. Any bucket exhausted   │
│      → HTTP 429             │
│        Retry-After header   │
│        audit event          │
└─────────────────────────────┘
```

The backoffice also gets a rate limiter middleware instance, scoped to admin authentication endpoints only (`/auth/login`, `/auth/totp`). This prevents brute-force enumeration at the network level in addition to the existing per-account lockout in `LocalAuthService`.

#### 4.2.2 Rate Limit Dimensions

Five independent token buckets are checked per request. All five must pass. If any is exhausted, the request is rejected with HTTP 429. The `Retry-After` header value is the ceil of the earliest bucket refill time across all exhausted buckets.

| Dimension | Key pattern | Description |
|---|---|---|
| Global | `rl:global` | Total request rate across all sources. Protects against distributed floods. |
| Per-IP | `rl:ip:{client_ip_hash}` | Per source IP. Client IP is SHA-256 hashed to avoid storing raw IPs in Redis (GDPR). |
| Per-agent | `rl:agent:{agent_id}` | Per `X-Yashigani-Agent-Id` header value. Protects against a single misbehaving agent. |
| Per-session | `rl:session:{session_id_prefix}` | Per session token (first 16 chars used as key to avoid full token in Redis key). |
| Per-role | `rl:role:{role_name}` | Applied when the session carries a known RBAC role. Overrides per-IP limit when present. If no role is known, this bucket is skipped. |

The IP hash uses the first-seen IP from the `X-Forwarded-For` chain (already handled in `_get_client_ip`). The raw IP is never stored; only `SHA-256(ip)[:16]` is used as the Redis key suffix.

#### 4.2.3 Adaptive Algorithm: RPI-Based Multiplier

The `AdaptiveRateLimiter` reads `ResourceMonitor.metrics.pressure_index` on every request (the value is cached in-process and updated by the background poll thread — no Redis round-trip for the RPI read).

The effective rate for any bucket is:

```
effective_rate = configured_base_rate * adaptive_multiplier(rpi)
```

The multiplier function:

```python
def adaptive_multiplier(rpi: float) -> float:
    if rpi > 0.80:
        return 0.40   # Critical pressure: 40% of base rate
    if rpi > 0.60:
        return 0.70   # High pressure: 70% of base rate
    if rpi > 0.30:
        return 0.90   # Medium pressure: 90% of base rate
    return 1.00       # Low pressure: full rate
```

**Multiplier justification:** At critical RPI (>0.80), the system is near memory and CPU exhaustion. Reducing allowed traffic to 40% of base protects the inspection pipeline and OPA from starvation. The 70% multiplier at high pressure is a proportional reduction to give the system room to recover. The 90% at medium pressure has negligible user impact but prevents the system from being pushed from medium into high pressure by sustained traffic. At low pressure (<0.30), no reduction is applied.

The effective rate is recomputed on each token bucket refill. The bucket does not retroactively remove tokens already issued under a lower-pressure configuration.

#### 4.2.4 Token Bucket Algorithm

The token bucket is implemented using a Redis Lua script for atomicity. This avoids race conditions when multiple gateway instances run against the same Redis.

Each bucket has:
- `capacity` — maximum tokens (burst allowance)
- `rate` — tokens added per second (sustained rate)
- `tokens` — current token count (float stored as string in Redis)
- `last_refill` — Unix timestamp of last refill (float)

The Lua script (executed atomically via `EVAL`):

```lua
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])  -- always 1 for a single request

local data = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens = tonumber(data[1]) or capacity
local last_refill = tonumber(data[2]) or now

-- Refill tokens based on elapsed time
local elapsed = now - last_refill
local new_tokens = math.min(capacity, tokens + elapsed * rate)

-- Check if request can be served
if new_tokens < cost then
    -- Not enough tokens — return remaining tokens and time to next token
    redis.call('HSET', key, 'tokens', new_tokens, 'last_refill', now)
    redis.call('EXPIRE', key, 3600)
    local wait = (cost - new_tokens) / rate
    return {0, math.ceil(wait)}
end

-- Consume tokens
new_tokens = new_tokens - cost
redis.call('HSET', key, 'tokens', new_tokens, 'last_refill', now)
redis.call('EXPIRE', key, 3600)
return {1, 0}
```

Return value: `{1, 0}` means allowed. `{0, N}` means denied, retry after N seconds.

**Burst vs sustained semantics:** `capacity` is the burst allowance — the maximum spike a client can make before being rate-limited. `rate` is the tokens-per-second refill — this is the sustained rate. Example: `capacity=50, rate=10` allows a burst of 50 requests followed by a steady state of 10 requests/second. This maps to human-readable admin configuration:

```
burst_requests: 50       # burst allowance
requests_per_second: 10  # sustained rate
```

#### 4.2.5 Redis Key Schema

All rate limit keys live in Redis database `/2`.

| Key | Type | TTL | Fields |
|---|---|---|---|
| `rl:global` | Hash | 3600s rolling | `tokens`, `last_refill` |
| `rl:ip:{sha256_prefix}` | Hash | 3600s rolling | `tokens`, `last_refill` |
| `rl:agent:{agent_id}` | Hash | 3600s rolling | `tokens`, `last_refill` |
| `rl:session:{session_id_prefix}` | Hash | 3600s rolling | `tokens`, `last_refill` |
| `rl:role:{role_name}` | Hash | 3600s rolling | `tokens`, `last_refill` |
| `rl:config` | Hash | no TTL | `global_capacity`, `global_rate`, `ip_capacity`, `ip_rate`, `agent_capacity`, `agent_rate`, `session_capacity`, `session_rate` |

The config key is written by the backoffice when an admin updates rate limits. The limiter reads it at startup and caches it in memory. The background poll thread (same as ResourceMonitor's) re-reads the config key every 60 seconds to pick up changes without restart.

#### 4.2.6 Admin-Configurable Defaults

Defaults are safe for a moderate-traffic production deployment. Operators should tune based on observed traffic patterns.

| Limit | Default capacity (burst) | Default rate (req/s sustained) | Description |
|---|---|---|---|
| Global | 5000 | 500 | Total across all sources |
| Per-IP | 200 | 20 | Per source IP (SHA-256 keyed) |
| Per-agent | 500 | 50 | Per agent ID |
| Per-session | 300 | 30 | Per session handle |
| Per-role (default) | 400 | 40 | Default for any named role without explicit override |

These defaults allow a burst of traffic typical of an agent pipeline startup while preventing sustained flood from any single source. They are stored in Redis `rl:config` so they persist across gateway restarts.

#### 4.2.7 Backoffice API Endpoints for Rate Limit Management

All require an authenticated admin session (AdminSession dependency).

| Method | Path | Description |
|---|---|---|
| `GET` | `/admin/rate-limits` | Return current effective limits, current RPI, and adaptive multiplier |
| `POST` | `/admin/rate-limits` | Update base rate limits for one or more dimensions |
| `DELETE` | `/admin/rate-limits/reset` | Flush all rate limit counters from Redis (emergency reset) |
| `GET` | `/admin/rate-limits/status` | Per-dimension current token counts and bucket state |
| `GET` | `/admin/rate-limits/roles` | List per-role rate limit overrides |
| `POST` | `/admin/rate-limits/roles` | Add or update a per-role rate limit override |
| `DELETE` | `/admin/rate-limits/roles/{role_name}` | Remove per-role rate limit override |

#### 4.2.8 Audit Events for Rate Limit Violations

Every HTTP 429 response emits a `RATE_LIMIT_EXCEEDED` audit event (defined in Section 9). The event includes:
- `dimension` — which bucket was exhausted (global/ip/agent/session/role)
- `client_ip_hash` — SHA-256 prefix of client IP
- `agent_id` — from request header
- `session_id_prefix` — first 8 chars of session token
- `effective_limit` — the actual limit after RPI multiplier applied
- `rpi_at_time` — the RPI value used for the multiplier

The event is written to the volume audit log only. It is not forwarded to SIEM unless the SIEM target is configured to receive `RATE_LIMIT_EXCEEDED` events (configurable per SIEM target in v0.2.0).

#### 4.2.9 HTTP 429 Response Format

```json
{
  "error": "RATE_LIMITED",
  "request_id": "<uuid>",
  "retry_after_seconds": 12,
  "dimension": "per_ip"
}
```

Headers:
- `Retry-After: 12` (integer seconds)
- `X-Yashigani-Request-Id: <uuid>`
- `X-RateLimit-Limit: 200` (the configured capacity for the exhausted dimension)
- `X-RateLimit-Remaining: 0`
- `X-RateLimit-Reset: <unix_timestamp>` (when the bucket will have at least 1 token)

#### 4.2.10 DDoS Considerations

SYN flood (L3/L4) is handled at the network layer by the host OS or upstream network infrastructure. Yashigani handles L7 (HTTP) rate limiting only. Operators deploying in cloud environments should enable cloud provider L4 DDoS protection (AWS Shield, Cloudflare, etc.) separately.

For L7 amplification: the rate limiter checks happen before body reads complete for large requests. The size check (`max_request_body_bytes = 4 MB`) in the existing gateway (`proxy.py` line 139) continues to apply and is the first check, before the rate limiter.

Request processing order in v0.2.0:
1. Size check (existing, 4 MB ceiling)
2. Rate limit check (new, HTTP 429 fast path)
3. Identity extraction (existing)
4. Inspection pipeline (existing)
5. OPA check (existing)
6. Upstream forward (existing)

#### 4.2.11 Integration with Existing ResourceMonitor

The `AdaptiveRateLimiter` receives a reference to the `ResourceMonitor` instance at construction. It calls `resource_monitor.metrics.pressure_index` on each request. This is a read from the in-process `_metrics` field under an RLock — effectively free in terms of latency. No additional polling thread is created.

The `ResourceMonitor` already runs its background thread. The rate limiter consumes its output only. The limiter registers an `on_critical` callback with the ResourceMonitor: when RPI crosses the 0.80 threshold, it emits a `GPU_PRESSURE_CRITICAL` or `RESOURCE_PRESSURE_CRITICAL` audit event and immediately drops the effective rate to 40% without waiting for the next request to trigger a recalculation.

### 4.3 GPU Metrics

#### 4.3.1 Detection Strategy

The `GPUMonitor` class uses a provider chain with graceful fallback. Each provider is attempted in order at startup. The first one that succeeds becomes the active provider for the process lifetime. The monitor does not retry a failed provider mid-run.

**Provider chain:**

1. **NVML (pynvml) — NVIDIA GPUs.** Attempts `pynvml.nvmlInit()`. If successful and at least one device is found, NVML is the active provider. Reads `nvmlDeviceGetUtilizationRates`, `nvmlDeviceGetMemoryInfo`. Each call is wrapped in a try/except; a failed read returns the last known good value, not an error.

2. **ROCm sysfs — AMD GPUs.** If pynvml fails or no NVIDIA devices are found, checks for AMD GPU sysfs paths at `/sys/class/drm/card*/device/gpu_busy_percent` and `/sys/class/drm/card*/device/mem_info_vram_used`. If present and readable, ROCm sysfs is the active provider.

3. **Metal Performance Shaders sysfs — Apple Silicon.** On macOS (detected via `platform.system() == 'Darwin'`), attempts to read GPU stats from `powermetrics` subprocess output (requires `sudo`). If unavailable (container environments will not have `sudo`), falls back gracefully.

4. **Ollama /api/ps endpoint.** Regardless of the GPU provider above, `GPUMonitor` also polls the Ollama API at `{OLLAMA_BASE_URL}/api/ps`. The response includes per-model GPU utilisation when a model is loaded. This is additive — it provides application-level GPU context (which model is consuming GPU) on top of the hardware-level metrics from the provider chain.

5. **None / unavailable.** If all providers fail, the GPU monitor returns `GPUMetrics` with `provider="none"`, all utilisation values 0.0, and logs a single warning at startup. No repeated errors. The system operates normally; GPU pressure simply does not contribute to the RPI.

This design means the same Docker image runs on NVIDIA hosts, AMD hosts, and CPU-only hosts without modification.

#### 4.3.2 GPUMetrics Dataclass

```python
@dataclass
class GPUMetrics:
    provider: str               # "nvml" | "rocm_sysfs" | "ollama_ps" | "none"
    device_count: int           # number of GPU devices detected
    utilisation_pct: float      # 0.0–100.0, average across all devices
    memory_used_bytes: int      # bytes
    memory_total_bytes: int     # bytes
    memory_pressure: float      # memory_used_bytes / memory_total_bytes, 0.0–1.0
    ollama_model: str           # name of model currently loaded in Ollama, "" if none
    ollama_gpu_utilisation_pct: float  # per Ollama /api/ps, 0.0–100.0, 0.0 if not available
    sampled_at: datetime        # UTC timestamp of last successful read
```

This dataclass is separate from `ResourceMetrics`. The `ResourceMetrics` dataclass is extended to include a `gpu: Optional[GPUMetrics]` field.

#### 4.3.3 Updated RPI Formula

**v0.1.0 formula (in `_read_cgroup_v2` and `_read_docker_stats`):**

```python
index = min(1.0, 0.7 * memory_pressure + 0.3 * cpu_throttle)
```

**v0.2.0 formula:**

```python
def compute_rpi(
    memory_pressure: float,
    cpu_throttle: float,
    gpu_memory_pressure: float,
    gpu_utilisation_normalised: float,
) -> float:
    """
    Weights:
      memory:           0.50  (primary — OOM is the most catastrophic failure mode)
      cpu_throttle:     0.25  (secondary — throttle means pipeline latency increases)
      gpu_memory:       0.15  (tertiary — GPU OOM kills Ollama inference)
      gpu_utilisation:  0.10  (quaternary — high GPU util increases inspection latency)
    Total: 1.00
    """
    return min(1.0,
        0.50 * memory_pressure +
        0.25 * cpu_throttle +
        0.15 * gpu_memory_pressure +
        0.10 * (gpu_utilisation_normalised / 100.0)
    )
```

**Weight justification:**
- Memory (0.50): Container OOM kills the process. Memory pressure is the most direct indicator of imminent failure. Weight is kept dominant.
- CPU throttle (0.25): Reduced from 0.30 to make room for GPU terms. CPU throttle causes inspection latency but not outright failure.
- GPU memory pressure (0.15): Ollama crashes with CUDA out-of-memory if GPU memory is exhausted. This is a hard failure for the inspection pipeline.
- GPU utilisation (0.10): High GPU utilisation correlates with inference latency increases. Lower weight because 100% GPU utilisation does not necessarily cause failure.

When GPU metrics are unavailable (`provider="none"`), `gpu_memory_pressure=0.0` and `gpu_utilisation_normalised=0.0` are used. The formula reduces to `0.50 * mem + 0.25 * cpu`, which maintains the relative weighting of the v0.1.0 formula (70/30 scaled to 50/25 with the remainder unused).

#### 4.3.4 Updated TTL Tier Table

The tier thresholds are unchanged (0.3/0.6/0.8). The new GPU terms mean a host with a heavily loaded GPU can now push the RPI into a higher tier even if CPU and memory are comfortable.

| RPI Range | Tier | CHS TTL | Rate Limit Multiplier | Notes |
|---|---|---|---|---|
| 0.00–0.30 | Low | 1800s (30 min) | 1.00 (100%) | All resources comfortable |
| 0.30–0.60 | Medium | 900s (15 min) | 0.90 (90%) | Normal operating pressure |
| 0.60–0.80 | High | 300s (5 min) | 0.70 (70%) | Elevated — likely GPU or memory pressure |
| 0.80–1.00 | Critical | 120s (2 min) | 0.40 (40%) | Near-failure — reduce all loads |

#### 4.3.5 Prometheus Metrics from GPU Monitor

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `yashigani_gpu_utilisation_pct` | Gauge | `device`, `provider` | GPU compute utilisation 0–100 |
| `yashigani_gpu_memory_used_bytes` | Gauge | `device`, `provider` | GPU VRAM used in bytes |
| `yashigani_gpu_memory_total_bytes` | Gauge | `device`, `provider` | GPU VRAM total in bytes |
| `yashigani_gpu_memory_pressure` | Gauge | `device`, `provider` | GPU memory pressure 0.0–1.0 |
| `yashigani_ollama_gpu_utilisation_pct` | Gauge | `model` | Ollama per-model GPU utilisation from /api/ps |
| `yashigani_rpi` | Gauge | `source` | Current Resource Pressure Index 0.0–1.0 |

#### 4.3.6 Ollama GPU Stats via /api/ps

The Ollama `/api/ps` endpoint returns JSON with a `models` array. Each model entry includes `size_vram` (VRAM in bytes used by that model). The GPU monitor derives GPU utilisation per model by polling `/api/ps` at the same interval as the hardware GPU poll (default 30s). The resulting `ollama_model` and `ollama_gpu_utilisation_pct` fields in `GPUMetrics` reflect the currently-loaded model.

If multiple models are loaded simultaneously, only the first is recorded in `GPUMetrics`. All are exported as individual `yashigani_ollama_gpu_utilisation_pct{model=...}` Prometheus gauge values.

---

### 4.4 Observability (Prometheus + Grafana)

#### 4.4.1 New Module: yashigani/metrics/

The `yashigani/metrics/` package wraps `prometheus_client`. A single `CollectorRegistry` is created at import time. All metric objects are module-level singletons — this is the standard `prometheus_client` pattern and avoids duplicate registration errors.

Each sub-module defines its metrics and exports an `instrument_*` helper function that wires the metric updates into the corresponding Yashigani component. This keeps the metrics module decoupled: the `gateway/proxy.py` imports `from yashigani.metrics.gateway_metrics import instrument_gateway_request` and calls it; it does not import `prometheus_client` directly.

A `/metrics` HTTP endpoint is added to both the gateway and the backoffice FastAPI apps. This endpoint is protected: on the gateway, it is blocked by the OPA policy (the existing `path_blocked` rule for `/metrics` already exists in v0.1.0 and continues to block external access). On the backoffice, it requires an admin session. Prometheus scrapes the `/metrics` endpoint via the internal Docker network, bypassing Caddy, so authentication is handled by network isolation rather than HTTP auth on the Prometheus scrape.

#### 4.4.2 Complete Metrics Catalogue

**Gateway metrics (`yashigani/metrics/gateway_metrics.py`)**

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `yashigani_gateway_requests_total` | Counter | `method`, `agent_id`, `action` | Total requests processed. `action` = FORWARDED / DISCARDED / DENIED / BLOCKED / RATE_LIMITED |
| `yashigani_gateway_request_duration_seconds` | Histogram | `method`, `agent_id`, `action` | End-to-end request latency. Buckets: 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0 |
| `yashigani_gateway_upstream_status_total` | Counter | `status_code`, `agent_id` | Upstream HTTP status codes returned |
| `yashigani_gateway_body_size_bytes` | Histogram | `agent_id` | Request body size in bytes. Buckets: 256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304 |
| `yashigani_gateway_opa_denials_total` | Counter | `agent_id`, `path_pattern` | OPA policy deny events |
| `yashigani_gateway_opa_errors_total` | Counter | none | OPA unreachable / error events (fail-closed triggers) |
| `yashigani_gateway_active_connections` | Gauge | none | Current in-flight requests (incremented on entry, decremented on exit) |

**Inspection pipeline metrics (`yashigani/metrics/inspection_metrics.py`)**

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `yashigani_inspection_classifications_total` | Counter | `classification`, `action`, `agent_id` | Pipeline output counts by classification and action |
| `yashigani_inspection_classification_duration_seconds` | Histogram | `model` | Time from pipeline entry to classifier response. Buckets: 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0 |
| `yashigani_inspection_confidence_score` | Histogram | `classification` | Distribution of classifier confidence scores. Buckets: 0.5, 0.6, 0.7, 0.75, 0.80, 0.85, 0.90, 0.95, 0.99, 1.0 |
| `yashigani_inspection_sanitization_total` | Counter | `outcome` | Sanitization attempts. `outcome` = success / failed |
| `yashigani_inspection_credential_exfil_total` | Counter | `action`, `agent_id` | CREDENTIAL_EXFIL detections by action taken |
| `yashigani_inspection_prompt_injection_total` | Counter | `agent_id` | PROMPT_INJECTION_ONLY detections |

**Auth metrics (`yashigani/metrics/auth_metrics.py`)**

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `yashigani_auth_login_attempts_total` | Counter | `tier`, `outcome` | Login attempts. `tier` = admin/user, `outcome` = success/failure |
| `yashigani_auth_totp_failures_total` | Counter | `tier` | TOTP verification failures |
| `yashigani_auth_account_lockouts_total` | Counter | `tier` | Account lockout events |
| `yashigani_auth_session_creations_total` | Counter | `tier` | New sessions created |
| `yashigani_auth_session_invalidations_total` | Counter | `tier`, `reason` | Sessions invalidated. `reason` = logout/timeout/password_change/new_login |
| `yashigani_ksm_rotation_total` | Counter | `provider`, `outcome` | KSM rotation outcomes |

**System metrics (`yashigani/metrics/system_metrics.py`)**

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `yashigani_memory_pressure` | Gauge | `source` | Memory pressure 0.0–1.0 from cgroup v2 or Docker API |
| `yashigani_cpu_throttle_ratio` | Gauge | `source` | CPU throttle ratio 0.0–1.0 |
| `yashigani_rpi` | Gauge | `source` | Resource Pressure Index 0.0–1.0 |
| `yashigani_gpu_utilisation_pct` | Gauge | `device`, `provider` | GPU utilisation 0–100 |
| `yashigani_gpu_memory_used_bytes` | Gauge | `device`, `provider` | GPU VRAM used |
| `yashigani_gpu_memory_total_bytes` | Gauge | `device`, `provider` | GPU VRAM total |
| `yashigani_ollama_gpu_utilisation_pct` | Gauge | `model` | Ollama per-model GPU utilisation |

**Rate limiter metrics (`yashigani/metrics/rate_limit_metrics.py`)**

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `yashigani_rate_limit_exceeded_total` | Counter | `dimension` | Requests rejected by rate limiter. `dimension` = global/ip/agent/session/role |
| `yashigani_rate_limit_tokens_remaining` | Gauge | `dimension` | Token count for the global and per-role buckets (per-IP/session/agent not individually exported — too high cardinality) |
| `yashigani_rate_limit_adaptive_multiplier` | Gauge | none | Current adaptive multiplier 0.0–1.0 |

**KSM / CHS metrics**

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `yashigani_ksm_rotation_duration_seconds` | Histogram | `provider` | KSM rotation operation duration. Buckets: 0.5, 1, 2, 5, 10, 30 |
| `yashigani_chs_handles_active` | Gauge | none | Number of active CHS credential handles |
| `yashigani_chs_handle_ttl_seconds` | Gauge | none | Current TTL tier in seconds (120/300/900/1800) |

**RBAC metrics**

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `yashigani_rbac_access_denied_total` | Counter | `agent_id`, `resource_pattern` | RBAC-driven OPA denials |
| `yashigani_rbac_policy_push_total` | Counter | `outcome` | OPA data push attempts. `outcome` = success/failure |
| `yashigani_rbac_groups_total` | Gauge | `mode` | Number of RBAC groups configured. `mode` = allow_list/scim |

#### 4.4.3 Prometheus Scrape Configuration

File: `prometheus/prometheus.yml`

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    deployment: ${YASHIGANI_ENV:-development}

rule_files:
  - /etc/prometheus/rules/*.yml

alerting:
  alertmanagers:
    - static_configs:
        - targets: []  # Add alertmanager address here for production

scrape_configs:
  - job_name: yashigani_gateway
    static_configs:
      - targets: ['gateway:8080']
    metrics_path: /metrics
    scrape_interval: 15s

  - job_name: yashigani_backoffice
    static_configs:
      - targets: ['backoffice:8443']
    metrics_path: /metrics
    scrape_interval: 30s

  - job_name: opa
    static_configs:
      - targets: ['policy:8181']
    metrics_path: /metrics
    scrape_interval: 30s

  - job_name: redis
    static_configs:
      - targets: ['redis-exporter:9121']
    scrape_interval: 30s

  - job_name: ollama
    static_configs:
      - targets: ['ollama:11434']
    metrics_path: /metrics
    scrape_interval: 30s
```

Note: Redis does not expose Prometheus metrics natively. A `redis_exporter` (oliver006/redis_exporter) container is added to the Compose stack to bridge Redis INFO output to Prometheus.

#### 4.4.4 Grafana Dashboard Specifications

All dashboards use the Prometheus datasource named `yashigani-prometheus` provisioned at startup.

**Dashboard 1: Security Overview**

Purpose: Real-time visibility into all security events. Primary dashboard for on-call security engineers.

Panels:
1. **Detection Rate (time series)** — `rate(yashigani_inspection_classifications_total{classification!="CLEAN"}[5m])` grouped by `classification`. Y-axis: detections/sec.
2. **Block Rate (stat)** — `sum(rate(yashigani_gateway_requests_total{action="DISCARDED"}[5m])) / sum(rate(yashigani_gateway_requests_total[5m]))`. Shows % of requests blocked.
3. **CREDENTIAL_EXFIL Events (time series)** — `rate(yashigani_inspection_credential_exfil_total[5m])` grouped by `action`. Red/orange colour theme.
4. **OPA Denials (time series)** — `rate(yashigani_gateway_opa_denials_total[5m])` grouped by `path_pattern`.
5. **RBAC Access Denials (time series)** — `rate(yashigani_rbac_access_denied_total[5m])` grouped by `resource_pattern`.
6. **Confidence Score Distribution (heatmap)** — `yashigani_inspection_confidence_score_bucket` across all classifications.
7. **KSM Rotation Status (stat)** — Last rotation outcome. Green if last rotation succeeded, red if failed.
8. **Active Admin Sessions (stat)** — `yashigani_auth_session_creations_total{tier="admin"}` minus invalidations. Shows current admin presence.
9. **Auth Failures (time series)** — `rate(yashigani_auth_login_attempts_total{outcome="failure"}[5m])` grouped by `tier`. Spike indicates brute-force attempt.
10. **Account Lockouts (stat panel, last 1h)** — `increase(yashigani_auth_account_lockouts_total[1h])`.

**Dashboard 2: System Health**

Purpose: Infrastructure health for DevOps. Shows whether the platform is healthy enough to process traffic.

Panels:
1. **Resource Pressure Index (time series)** — `yashigani_rpi`. Colour thresholds: green < 0.3, yellow < 0.6, orange < 0.8, red >= 0.8.
2. **Memory Pressure (gauge)** — `yashigani_memory_pressure`. 0–1 gauge with threshold bands.
3. **CPU Throttle Ratio (gauge)** — `yashigani_cpu_throttle_ratio`.
4. **GPU Utilisation (time series)** — `yashigani_gpu_utilisation_pct` grouped by `device`. Hidden with "No GPU" annotation when all values are 0.
5. **GPU Memory Pressure (gauge)** — `yashigani_gpu_memory_used_bytes / yashigani_gpu_memory_total_bytes`.
6. **Ollama Active Model (stat)** — `yashigani_ollama_gpu_utilisation_pct` max value, label shows model name.
7. **CHS Handle TTL Tier (stat)** — Current TTL tier from `yashigani_chs_handle_ttl_seconds`. Coloured by tier.
8. **Active Gateway Connections (time series)** — `yashigani_gateway_active_connections`.
9. **Redis Memory (time series)** — From `redis_exporter`: `redis_memory_used_bytes`.
10. **OPA Health (stat)** — Derived from `yashigani_gateway_opa_errors_total` rate — green if 0, red if > 0.
11. **Inspection Pipeline Latency p50/p95/p99 (time series)** — Quantiles from `yashigani_inspection_classification_duration_seconds`.
12. **Gateway Request Latency p50/p95/p99 (time series)** — Quantiles from `yashigani_gateway_request_duration_seconds`.

**Dashboard 3: Agent Activity**

Purpose: Per-agent visibility into traffic volume, detection rate, and block rate. Used by security engineers investigating a specific agent.

Panels:
1. **Top Agents by Request Volume (bar chart)** — `topk(10, sum by(agent_id)(rate(yashigani_gateway_requests_total[5m])))`.
2. **Top Agents by Detection Rate (bar chart)** — `topk(10, sum by(agent_id)(rate(yashigani_inspection_classifications_total{classification!="CLEAN"}[5m])))`.
3. **Per-Agent Request Rate (time series)** — `sum by(agent_id)(rate(yashigani_gateway_requests_total[5m]))`. Variable dropdown to filter by agent.
4. **Per-Agent Detection Timeline (time series)** — `sum by(agent_id, classification)(rate(yashigani_inspection_classifications_total[5m]))` filtered by selected agent variable.
5. **Per-Agent Block Rate (time series)** — `rate(yashigani_gateway_requests_total{action="DISCARDED", agent_id="$agent_id"}[5m])`.
6. **Per-Agent OPA Denials (time series)** — `rate(yashigani_gateway_opa_denials_total{agent_id="$agent_id"}[5m])`.
7. **Per-Agent Latency Percentiles (time series)** — p50/p95 from `yashigani_gateway_request_duration_seconds{agent_id="$agent_id"}`.
8. **Per-Agent RBAC Denials (time series)** — `rate(yashigani_rbac_access_denied_total{agent_id="$agent_id"}[5m])`.
9. **Agent Body Size Distribution (heatmap)** — `yashigani_gateway_body_size_bytes_bucket{agent_id="$agent_id"}`.
10. **Rate Limit Events per Agent (time series)** — `rate(yashigani_rate_limit_exceeded_total{dimension="agent"}[5m])` — note: this shows aggregate agent-dimension violations, not per-agent (cardinality guard).

**Dashboard 4: Rate Limit Status**

Purpose: Operational visibility into rate limiter behaviour. Used when investigating DoS events or tuning limits.

Panels:
1. **Rate Limit Violations by Dimension (time series)** — `rate(yashigani_rate_limit_exceeded_total[1m])` grouped by `dimension`.
2. **Current Adaptive Multiplier (stat)** — `yashigani_rate_limit_adaptive_multiplier`. Colour: green=1.0, yellow<0.9, orange<0.7, red<0.5.
3. **Global Token Bucket Level (gauge)** — `yashigani_rate_limit_tokens_remaining{dimension="global"}`.
4. **Violations Heatmap (heatmap)** — `yashigani_rate_limit_exceeded_total` over time.
5. **RPI vs Multiplier (dual-axis time series)** — `yashigani_rpi` (left axis) and `yashigani_rate_limit_adaptive_multiplier` (right axis). Shows the causal relationship.
6. **429 Response Rate (time series)** — `rate(yashigani_gateway_requests_total{action="RATE_LIMITED"}[1m])`.
7. **Effective Rate Limit Table (table)** — Static panel showing configured base limits and current effective limits (base * multiplier) for all dimensions.
8. **Per-Role Limit Violations (bar chart)** — `sum by(dimension)(increase(yashigani_rate_limit_exceeded_total{dimension=~"role.*"}[1h]))`.

#### 4.4.5 Alert Rules

Alert rules file: `prometheus/rules/yashigani_alerts.yml`

```yaml
groups:
  - name: yashigani_security
    rules:
      - alert: CredentialExfiltrationDetected
        expr: rate(yashigani_inspection_credential_exfil_total[5m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "CREDENTIAL_EXFIL detection active"
          description: "At least one credential exfiltration attempt detected in the last 5 minutes."

      - alert: OPADenialSpike
        expr: rate(yashigani_gateway_opa_denials_total[5m]) > 5
        for: 2m
        labels:
          severity: high
        annotations:
          summary: "OPA denial rate elevated"
          description: "More than 5 OPA denials/second sustained for 2 minutes."

      - alert: OPAUnreachable
        expr: rate(yashigani_gateway_opa_errors_total[2m]) > 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "OPA unreachable — gateway in fail-closed state"
          description: "All requests denied due to OPA connection failure."

      - alert: KSMRotationFailure
        expr: increase(yashigani_ksm_rotation_total{outcome="failure"}[1h]) > 0
        for: 0m
        labels:
          severity: high
        annotations:
          summary: "KSM secret rotation failed"
          description: "At least one KSM rotation failure in the last hour."

      - alert: ResourcePressureCritical
        expr: yashigani_rpi > 0.8
        for: 5m
        labels:
          severity: high
        annotations:
          summary: "Resource Pressure Index critical"
          description: "RPI has been above 0.8 for 5 minutes. Rate limiting active at 40%."

      - alert: RateLimitDDoSPattern
        expr: rate(yashigani_rate_limit_exceeded_total{dimension="global"}[1m]) > 50
        for: 1m
        labels:
          severity: high
        annotations:
          summary: "Possible DDoS — global rate limit threshold exceeded at high rate"
          description: "More than 50 global rate-limit rejections per second for 1 minute."

      - alert: RBACPolicyPushFailure
        expr: increase(yashigani_rbac_policy_push_total{outcome="failure"}[15m]) > 2
        for: 0m
        labels:
          severity: high
        annotations:
          summary: "RBAC policy push to OPA failing"
          description: "OPA data push has failed more than twice in 15 minutes. RBAC data may be stale."
```

Alert routing is via Grafana's built-in alerting (Grafana 10+ unified alerting). Each alert is routed to a contact point. The contact points (email, Slack webhook, PagerDuty) are provisioned via `grafana/provisioning/alerting/contact_points.yaml` with values drawn from environment variables (`GRAFANA_ALERT_EMAIL`, `GRAFANA_ALERT_WEBHOOK_URL`). If these variables are absent, alerting is configured but contact points are empty (alerts fire but do not route anywhere — operator must configure).

**Product Owner Decision — 2026-03-26 (Q6):** The admin email address (required at bootstrap — see Section 4.5 note on Q6) is auto-registered as the default Grafana alert contact point during bootstrap. This guarantees at least one contact point is always configured. The `/dashboard/health` endpoint cannot transition to `degraded` due to missing contact points, because bootstrap ensures at least one exists. Operators may add additional contact points via environment variables without removing the bootstrapped default.

**Product Owner Decision — 2026-03-26 (Q4):** The `/metrics-federate` path is routed through Caddy behind admin authentication, supporting external Prometheus federation and Thanos deployments. This replaces the original Option A recommendation (internal-only). The Caddy route for `/metrics-federate` proxies to `prometheus:9090/federate` and applies the same admin session authentication as `/admin/*` routes. Operators who do not require federation do not need to configure anything; the route is present but gated.

#### 4.4.6 New docker-compose Services

```yaml
  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    environment:
      YASHIGANI_TLS_MODE: ${YASHIGANI_TLS_MODE:?set YASHIGANI_TLS_MODE}
      YASHIGANI_TLS_DOMAIN: ${YASHIGANI_TLS_DOMAIN:-localhost}
      YASHIGANI_TLS_ACME_EMAIL: ${YASHIGANI_TLS_ACME_EMAIL:-}
      YASHIGANI_TLS_CERT_FILE: ${YASHIGANI_TLS_CERT_FILE:-}
      YASHIGANI_TLS_KEY_FILE: ${YASHIGANI_TLS_KEY_FILE:-}
    volumes:
      - ../docker/caddy/${YASHIGANI_TLS_MODE:-self_signed}/Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    depends_on:
      - gateway
      - backoffice
    networks:
      - internal
      - external

  prometheus:
    image: prom/prometheus:v2.52.0
    restart: unless-stopped
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=30d'
      - '--storage.tsdb.retention.size=10GB'
      - '--web.enable-lifecycle'
    volumes:
      - ../prometheus:/etc/prometheus:ro
      - prometheus_data:/prometheus
    networks:
      - internal
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:9090/-/healthy"]
      interval: 15s
      timeout: 5s
      retries: 3

  grafana:
    image: grafana/grafana:10.4.2
    restart: unless-stopped
    environment:
      GF_SECURITY_ADMIN_PASSWORD: ${GRAFANA_ADMIN_PASSWORD:?set GRAFANA_ADMIN_PASSWORD}
      GF_SECURITY_ADMIN_USER: ${GRAFANA_ADMIN_USER:-admin}
      GF_USERS_ALLOW_SIGN_UP: "false"
      GF_SERVER_ROOT_URL: ${GRAFANA_ROOT_URL:-http://localhost:3000}
      GF_ALERTING_ENABLED: "true"
      GF_UNIFIED_ALERTING_ENABLED: "true"
    volumes:
      - ../grafana/provisioning:/etc/grafana/provisioning:ro
      - ../grafana/dashboards:/var/lib/grafana/dashboards:ro
      - grafana_data:/var/lib/grafana
    networks:
      - internal
    depends_on:
      - prometheus

  redis-exporter:
    image: oliver006/redis_exporter:v1.61.0-alpine
    restart: unless-stopped
    environment:
      REDIS_ADDR: redis://redis:6379
      REDIS_PASSWORD: ${REDIS_PASSWORD}
    networks:
      - internal
    depends_on:
      redis:
        condition: service_healthy
```

#### 4.4.7 Retention and Storage Sizing

Prometheus is configured with `--storage.tsdb.retention.time=30d` and `--storage.tsdb.retention.size=10GB`. At the metric cardinality defined above (approximately 80 active time series), Prometheus memory usage is approximately 50–100 MB. Disk usage at default scrape interval (15s) is approximately 150 MB/day → 4.5 GB/month, well within the 10 GB cap. Operators may increase retention to 90 days by setting `PROMETHEUS_RETENTION_DAYS=90d`.

Grafana state (dashboards, alert state, user sessions) is stored in the `grafana_data` named volume. Estimated size: < 500 MB at this scale.

---

### 4.5 RBAC

#### 4.5.1 Two Provisioning Modes

Mode is selected via `YASHIGANI_RBAC_MODE`. Valid values: `allow_list`, `scim`. Defaults to `allow_list` if absent.

Both modes feed data into OPA. The data format is identical regardless of mode — the mode affects only how that data is populated.

#### 4.5.2 SCIM 2.0 Mode

**Endpoint base:** `/scim/v2` — registered as a new FastAPI router on the backoffice.

**Supported resources:**
- `Users` — individual user/agent identities
- `Groups` — group memberships

**Supported SCIM operations:**

| Method | Path | Description |
|---|---|---|
| `GET` | `/scim/v2/Users` | List users (paginated, filter support) |
| `GET` | `/scim/v2/Users/{id}` | Get single user |
| `POST` | `/scim/v2/Users` | Create user (IdP push) |
| `PUT` | `/scim/v2/Users/{id}` | Replace user (IdP push) |
| `PATCH` | `/scim/v2/Users/{id}` | Partial update user |
| `DELETE` | `/scim/v2/Users/{id}` | Delete user |
| `GET` | `/scim/v2/Groups` | List groups |
| `GET` | `/scim/v2/Groups/{id}` | Get single group |
| `POST` | `/scim/v2/Groups` | Create group |
| `PUT` | `/scim/v2/Groups/{id}` | Replace group |
| `PATCH` | `/scim/v2/Groups/{id}` | Add/remove group members |
| `DELETE` | `/scim/v2/Groups/{id}` | Delete group |

**Authentication for SCIM endpoint:** Bearer token. A SCIM bearer token is provisioned by the admin via `POST /admin/rbac/scim-token`. The token is stored as a KSM secret (key: `yashigani/scim/bearer_token`). The SCIM endpoint requires this token in the `Authorization: Bearer <token>` header. No session cookie is accepted for SCIM requests.

**Supported IdPs:** Any IdP that supports SCIM 2.0 outbound provisioning. Tested configurations: Okta, Azure AD (Microsoft Entra), Google Workspace. The SCIM endpoint is IdP-agnostic as long as the IdP conforms to RFC 7644.

**Sync frequency:** IdP-driven (push model). The SCIM endpoint is called by the IdP on change events. There is no Yashigani-initiated pull. For IdPs that support scheduled sync (e.g., Okta can sync every 1h), the interval is configured in the IdP.

**Conflict resolution:** Last-write-wins for user attributes. For group membership: PATCH operations with `op=add` and `op=remove` are applied atomically. A full `PUT` on a group replaces the member list entirely. Soft deletes: SCIM `DELETE` marks the user/group as inactive but retains the record for audit purposes. The OPA data document only includes active users and groups.

**SCIM schema extensions:** Yashigani adds a custom SCIM schema extension `urn:ietf:params:scim:schemas:extension:yashigani:2.0:User` with one additional attribute: `agentId` (string). This maps the Yashigani `X-Yashigani-Agent-Id` header to an IdP user. If this extension is not populated, the user's `userName` attribute is used as the agent_id match.

#### 4.5.3 Allow-List Mode

The allow-list is the default mode. It is managed entirely within the Yashigani backoffice. No external IdP is required.

**Data model:**

```python
@dataclass
class ResourcePattern:
    pattern_type: str       # "mcp_server" | "api_path" | "agent_id" | "ml_model"
    pattern: str            # exact match or glob pattern (e.g. "/v1/tools/*")
    description: str        # human-readable description

@dataclass
class RBACGroup:
    group_id: str           # UUID
    name: str               # e.g. "analysts", "ml-operators"
    description: str
    member_agent_ids: list[str]    # agent IDs (X-Yashigani-Agent-Id values)
    member_user_ids: list[str]     # user IDs (X-Yashigani-User-Id values)
    rate_limit_override: Optional[RateLimitConfig]  # None = use default
    created_at: str         # ISO 8601
    updated_at: str

@dataclass
class RBACMapping:
    mapping_id: str         # UUID
    group_id: str
    resource: ResourcePattern
    allowed_methods: list[str]   # ["GET", "POST"] or ["*"] for all
    created_at: str
    created_by: str         # admin account ID
```

**Resource taxonomy — what can be protected:**

| Resource type | Pattern example | Match semantics |
|---|---|---|
| `mcp_server` | `my-mcp-server` | Matches `Host` header or upstream server name |
| `api_path` | `/v1/tools/*` | Glob path match against `input.path` in OPA |
| `agent_id` | `agent-prod-01` | Exact match against `input.agent_id` |
| `ml_model` | `gpt-4o` | Matches model name in request body (extracted by inspection pipeline) |

Glob matching uses Python `fnmatch` semantics: `*` matches any sequence of characters except `/`. `**` matches across path separators.

**Storage:** Allow-list data is persisted in Redis database `/3` as JSON-serialised dataclasses. Keys:
- `rbac:groups` — Hash of `group_id → JSON(RBACGroup)`
- `rbac:mappings` — Hash of `mapping_id → JSON(RBACMapping)`
- `rbac:version` — String, monotonically increasing integer, incremented on every write

The backoffice holds an in-memory cache of the current allow-list. The `rbac:version` key is checked every 30 seconds; if the version has changed, the cache is invalidated and reloaded from Redis.

**Import/export:** `GET /admin/rbac/export` returns the full allow-list as a JSON document. `POST /admin/rbac/import` accepts the same document, validates it, and replaces the current allow-list atomically. Import requires a second admin confirmation (re-TOTP-verify) to prevent accidental data loss.

#### 4.5.4 OPA Integration

**Integration method: REST push via OPA bundle API.**

On every allow-list change (or SCIM sync event), the backoffice RBAC service calls `PUT /v1/data/yashigani/rbac` on the OPA REST API with the current RBAC data document. This pushes a live data update without requiring an OPA restart or bundle server.

**Why REST push over file-based data document or bundle server:**
- File-based: requires volume remount on change — incompatible with dynamic allow-list management.
- Bundle server: requires an additional HTTPS endpoint, certificate management, and polling latency. Adds infrastructure for a problem REST push solves directly.
- REST push: OPA natively supports `PUT /v1/data/{path}` to update data documents at runtime. Changes take effect on the next policy evaluation. Atomic from OPA's perspective.

**OPA data document structure pushed by Yashigani:**

```json
{
  "groups": {
    "analysts": {
      "member_agent_ids": ["agent-001", "agent-002"],
      "member_user_ids": ["user-alice", "user-bob"],
      "rate_limit_override": null
    },
    "ml-operators": {
      "member_agent_ids": ["agent-ml-01"],
      "member_user_ids": [],
      "rate_limit_override": {"burst": 1000, "rate": 100}
    }
  },
  "mappings": [
    {
      "group": "analysts",
      "resource_pattern": "/v1/tools/*",
      "pattern_type": "api_path",
      "allowed_methods": ["GET", "POST"]
    },
    {
      "group": "ml-operators",
      "resource_pattern": "/v1/models/*",
      "pattern_type": "api_path",
      "allowed_methods": ["*"]
    }
  ],
  "version": 42
}
```

**Gateway OPA input extension:** The gateway's OPA input document (in `proxy.py _opa_check`) is extended to include:

```python
input_doc = {
    "method": request.method,
    "path": path,
    "session_id": session_id,
    "agent_id": agent_id,
    "user_id": user_id,
    "groups": groups_for_identity(session_id, agent_id),  # resolved by local cache
    "headers": {...},
}
```

The `groups_for_identity` function is a fast in-process lookup against the RBAC store's memory cache. It does not hit Redis on every request.

#### 4.5.5 OPA RBAC Policy Rules (policy/rbac.rego)

```rego
package yashigani.rbac

import future.keywords.if
import future.keywords.in
import future.keywords.every

# ---------------------------------------------------------------------------
# RBAC allow: request is allowed if there is a matching group mapping
# ---------------------------------------------------------------------------

# A request is RBAC-allowed if the caller belongs to a group that has
# a mapping granting access to the requested path with the requested method.
rbac_allow if {
    some group_name, group_data in data.yashigani.rbac.groups
    caller_in_group(group_name, group_data)
    mapping_grants_access(group_name, input.path, input.method)
}

# Product Owner Decision 2026-03-26 (Q3, Option B confirmed):
# DENY BY DEFAULT when no RBAC groups are configured. Zero-trust posture.
# The permissive "count == 0" branch has been REMOVED. This is a fixed security
# posture — there is no configurable override. Operators must configure at least
# one group and mapping before any agent traffic is permitted.
# The startup bootstrap procedure must push a valid RBAC data document to OPA
# before the gateway opens for traffic.

# ---------------------------------------------------------------------------
# Caller group membership resolution
# ---------------------------------------------------------------------------

caller_in_group(group_name, group_data) if {
    input.agent_id in group_data.member_agent_ids
}

caller_in_group(group_name, group_data) if {
    input.user_id in group_data.member_user_ids
}

caller_in_group(group_name, group_data) if {
    some grp in input.groups
    grp == group_name
}

# ---------------------------------------------------------------------------
# Mapping access resolution
# ---------------------------------------------------------------------------

mapping_grants_access(group_name, path, method) if {
    some mapping in data.yashigani.rbac.mappings
    mapping.group == group_name
    path_matches(path, mapping.resource_pattern, mapping.pattern_type)
    method_allowed(method, mapping.allowed_methods)
}

# ---------------------------------------------------------------------------
# Path matching
# ---------------------------------------------------------------------------

path_matches(path, pattern, "api_path") if {
    glob.match(pattern, ["/"], path)
}

path_matches(path, pattern, "agent_id") if {
    # For agent_id pattern type, the match is on input.agent_id, not path
    input.agent_id == pattern
}

path_matches(path, pattern, "mcp_server") if {
    # For mcp_server, match is on the upstream server name from request context
    # The gateway injects X-Yashigani-Upstream header before OPA call
    input.headers["x-yashigani-upstream"] == pattern
}

# Exact match fallback
path_matches(path, pattern, _) if {
    path == pattern
}

# ---------------------------------------------------------------------------
# Method matching
# ---------------------------------------------------------------------------

method_allowed(method, allowed) if {
    "*" in allowed
}

method_allowed(method, allowed) if {
    method in allowed
}
```

The `rbac_allow` rule is imported into the main `yashigani.rego` and included in the `allow` decision:

```rego
# In policy/yashigani.rego — updated allow rule:
allow if {
    input.session_id != ""
    input.session_id != "anonymous"
    input.agent_id != ""
    input.agent_id != "unknown"
    input.method in allowed_methods
    not path_blocked
    data.yashigani.rbac.rbac_allow  # RBAC gate
}
```

Wait — the import across packages must use data document references. The correct pattern is to call via `data.yashigani.rbac.rbac_allow` which references the rule computed in the `rbac` package. The OPA bundle must include both files under the `/policies` volume.

#### 4.5.6 Backoffice RBAC Routes

All require admin session.

| Method | Path | Description |
|---|---|---|
| `GET` | `/admin/rbac/mode` | Get current RBAC mode (allow_list/scim) |
| `POST` | `/admin/rbac/mode` | Set RBAC mode |
| `GET` | `/admin/rbac/groups` | List all groups |
| `POST` | `/admin/rbac/groups` | Create group |
| `GET` | `/admin/rbac/groups/{group_id}` | Get group details |
| `PUT` | `/admin/rbac/groups/{group_id}` | Replace group |
| `PATCH` | `/admin/rbac/groups/{group_id}` | Add/remove members |
| `DELETE` | `/admin/rbac/groups/{group_id}` | Delete group |
| `GET` | `/admin/rbac/mappings` | List all resource mappings |
| `POST` | `/admin/rbac/mappings` | Create mapping |
| `GET` | `/admin/rbac/mappings/{mapping_id}` | Get mapping |
| `DELETE` | `/admin/rbac/mappings/{mapping_id}` | Delete mapping |
| `POST` | `/admin/rbac/policy/push` | Push current RBAC data to OPA immediately |
| `GET` | `/admin/rbac/export` | Export full allow-list as JSON |
| `POST` | `/admin/rbac/import` | Import full allow-list (replaces existing, TOTP re-verify required) |
| `POST` | `/admin/rbac/scim-token` | Rotate SCIM bearer token (SCIM mode only) |
| `GET` | `/scim/v2/ServiceProviderConfig` | SCIM service provider configuration (unauthenticated) |
| `GET` | `/scim/v2/Schemas` | SCIM schema listing |
| `GET/POST/PUT/PATCH/DELETE` | `/scim/v2/Users[/{id}]` | SCIM User resource CRUD |
| `GET/POST/PUT/PATCH/DELETE` | `/scim/v2/Groups[/{id}]` | SCIM Group resource CRUD |

#### 4.5.7 RBAC Audit Events

| Event type | Trigger | Key fields |
|---|---|---|
| `RBAC_POLICY_CHANGED` | Any group or mapping create/update/delete | `admin_account`, `change_type` (create/update/delete), `resource_type` (group/mapping), `resource_id`, `summary` |
| `RBAC_ACCESS_DENIED` | OPA denies due to RBAC (detected by gateway from OPA response) | `agent_id`, `user_id`, `session_id`, `path`, `method`, `reason` = rbac_deny |
| `OPA_PUSH_FAILED` | PUT to OPA data endpoint fails | `opa_url`, `http_status`, `error`, `retry_count` |
| `RBAC_SCIM_SYNC` | SCIM push received and processed | `operation`, `resource_type`, `resource_id`, `outcome` |
| `RBAC_IMPORT_EXECUTED` | Full allow-list import via `/admin/rbac/import` | `admin_account`, `groups_imported`, `mappings_imported`, `previous_version`, `new_version` |

---

### 4.6 ASVS v5 Upgrade

#### 4.6.1 ASVS v4 → v5 Gap Analysis by Chapter

ASVS v5 was released in 2025. Key structural changes from v4: V1 (Architecture) is merged into other chapters; V13 (API) is significantly expanded; V14 (Configuration) is renamed; new V15 (Cryptography) chapter introduced with stronger key management requirements. The chapter numbering in v5 shifts in places.

| Chapter | v5 Reference | v0.1.0 Status | v5 New/Changed Requirement | v0.2.0 Action |
|---|---|---|---|---|
| V1 — Architecture, Design, Threat Modeling | V1.1–V1.14 | Partially met. No formal TM document. | v5 requires formal threat model updated on each significant change. | Add Section 11 (Threat Model Updates) to this plan. Maintain living threat model document. |
| V2 — Authentication | V2.1–V2.9 | Met for local auth. Argon2id, TOTP RFC 6238, lockout, TOTP replay prevention. | v5 adds requirement for phishing-resistant authentication for privileged interfaces. TOTP is phishable. | **Gap:** TOTP is phishable. v0.2.0 mitigations: (1) enforce strict SameSite=Strict cookies, (2) add CSRF token on all admin POST endpoints, (3) implement TOTP exponential backoff — 1st failure=1s delay, 2nd=2s, 3rd=4s, 4th=8s, 5th+=30-minute hard lockout. This backoff sequence is documented as a compensating control against real-time TOTP relay attacks. FIDO2/passkey deferred to v0.3.0 for full phishing-resistance compliance. |
| V3 — Session Management | V3.1–V3.9 | Met. 256-bit tokens, idle/absolute timeouts, HttpOnly/Secure/SameSite=Strict, no concurrent sessions, Redis-backed. | v5 requires session binding to TLS channel (token binding). Not widely supported. | **Partial gap:** Token binding is not implemented. Documented as deferred; TLS + SameSite=Strict provides comparable protection in practice. |
| V4 — Access Control | V4.1–V4.3 | Met via OPA (fail-closed, always local). RBAC stubs only in v0.1.0. | v5 requires RBAC enforcement documented and tested, not just stubbed. | **Gap closed in v0.2.0:** RBAC implemented (Section 4.5). OPA remains single enforcement point. |
| V5 — Validation, Sanitization, Encoding | V5.1–V5.5 | Partially met. Input size check (4 MB), inspection pipeline for AI content, CHS masking. HTTP parameter binding not explicitly validated. | v5 tightens schema validation requirements for all API inputs. | **Gap:** Add Pydantic model validation for all gateway request path/query parameters. Already done in backoffice (Pydantic models on all POST bodies). Extend to gateway. |
| V6 — Stored Cryptography | V6.1–V6.4 | Argon2id for passwords. TOTP secrets stored in-memory (plaintext in AccountRecord). AuditEvent fields not encrypted at rest. | v5 introduces V6 (formerly part of V2/V8) as standalone chapter. Requires encryption of sensitive data at rest beyond passwords. | **Gap:** TOTP secrets stored in memory without encryption. Production deployments should encrypt `AccountRecord.totp_secret` via KSM. Add KSM-backed encryption for TOTP secrets in `local_auth.py`. Mark as v0.2.0 implementation. |
| V7 — Error Handling and Logging | V7.1–V7.5 | Met. Generic error handler in backoffice. Audit log writes for all security events. No stack traces in API responses. | v5 requires log integrity protection (tamper detection). | **Gap:** Audit log file has no tamper detection. Add HMAC chaining to audit log entries (each entry includes HMAC of previous entry). New field `chain_hmac` on `AuditEvent`. |
| V8 — Data Protection | V8.1–V8.4 | Partially met. IP masking in sessions. Content hash instead of raw query in audit. | v5 expands data minimisation requirements. Requires explicit data inventory. | Extend audit event field masking to cover all PII fields. Document data inventory in deployment guide. |
| V9 — Communication Security | V9.1–V9.3 | Not met in v0.1.0 (TLS not implemented). | v5 requires TLS 1.2+ for all communications. | **Gap closed in v0.2.0:** Caddy TLS layer (Section 4.1). |
| V10 — Malicious Code | V10.1–V10.5 | Partially met. Dependency pinning not enforced. No SBOM. | v5 adds requirement for verified dependency integrity and SBOM. | Add `pip-audit` to CI/CD. Add `pyproject.toml` hash-pinned lockfile requirement to build docs. Generate SBOM via `cyclonedx-bom`. Deferred to CI/CD setup (not a runtime code change). |
| V11 — Business Logic | V11.1–V11.8 | Partially met. Admin account minimums. Force password change on first login. | v5 adds requirements for rate limiting on business logic operations (not just authentication). | **Gap closed in v0.2.0:** Adaptive rate limiter (Section 4.2). |
| V12 — Files and Resources | V12.1–V12.6 | Met. Body size limit (4 MB). Path traversal protection in KSM Docker provider. | v5 tightens file type validation for any upload endpoint. | No upload endpoints in Yashigani. RBAC import endpoint validates JSON schema before processing. Verified compliant. |
| V13 — API and Web Service | V13.1–V13.7 | Partially met. OpenAPI/Swagger disabled. No CORS on backoffice. | v5 significantly expands API security requirements. Adds requirements for rate limiting on all API endpoints, schema validation, and consumer authentication. | **Gaps closed in v0.2.0:** Rate limiting on all endpoints; Pydantic schema validation on all request bodies (extension from backoffice to gateway); RBAC on data plane. |
| V14 — Configuration | V14.1–V14.9 | Partially met. Security headers present. Docs URLs disabled. Secrets via Docker secrets or KSM. | v5 renames to "Secure Build and Deployment." Adds requirements for secret rotation verification and deployment integrity. | Rate limit config stored in Redis (not hardcoded). TLS config externalised. Extends `.env.example` with all new variables. |
| V15 — Cryptography (new in v5) | V15.1–V15.8 | Not explicitly addressed. | New chapter. Requires documented cryptographic inventory, algorithm agility, minimum key lengths. | Add cryptographic inventory to security controls reference. All algorithms in use: Argon2id (passwords), HMAC-SHA256 (audit chain, TOTP), AES-256-GCM (KSM at-rest encryption), TLS ECDHE (transport). All meet v5 minimums. |

#### 4.6.2 OWASP LLM Top 10 2025 Control Mapping

| LLM Risk | Description | Yashigani Control in v0.2.0 |
|---|---|---|
| LLM01: Prompt Injection | Malicious input manipulates LLM behaviour | `InspectionPipeline` with `PromptInjectionClassifier` (PROMPT_INJECTION_ONLY detection, always discard). CHS pre-masking ensures credentials are not part of the classified content. |
| LLM02: Sensitive Information Disclosure | LLM leaks training data or context | `CredentialMasker` strips credential patterns before content reaches the classifier. `CREDENTIAL_EXFIL` classification triggers sanitization or discard. Audit event for every detection. |
| LLM03: Supply Chain | Compromised model files or training data | Ollama model is pulled by content hash in `ollama-init`. Model is local-only — no cloud inference. Digest verification added to `ollama-init` script in v0.2.0 (pull with `--insecure` removed; SHA verification via Ollama manifest). |
| LLM04: Data and Model Poisoning | Manipulated training or fine-tuning data | Out of scope for Yashigani's proxy role. Yashigani does not perform training or fine-tuning. Documented as operator responsibility. |
| LLM05: Improper Output Handling | LLM output triggers downstream injection | Response from upstream MCP server passes through Yashigani on the return path. v0.2.0 adds optional response inspection (configurable, disabled by default — response inspection is expensive). Pipeline already supports bidirectional inspection; this is a config switch. |
| LLM06: Excessive Agency | LLM takes unauthorised actions | OPA policy enforcement on every forwarded request. RBAC limits which MCP server paths each agent can call. Rate limiter prevents runaway agent loops from causing DoS. |
| LLM07: System Prompt Leakage | System prompt extracted via crafted input | System prompts traverse the gateway as request content. The `CredentialMasker` and `InspectionPipeline` apply to all content. Admin can configure custom masking patterns for system prompt markers. |
| LLM08: Vector and Embedding Weaknesses | Poisoned retrieval results | Out of scope for Yashigani's proxy role at v0.2.0. Documented as operator responsibility for RAG pipeline operators. |
| LLM09: Misinformation | LLM generates false information | Out of scope. Yashigani does not evaluate semantic truthfulness. |
| LLM10: Unbounded Consumption | Excessive resource usage by LLM agents | Adaptive rate limiter (Section 4.2) with per-agent limits. GPU metrics (Section 4.3) feed into RPI, which reduces rate limits under GPU load. CHS TTL shortening under pressure reduces credential exposure window. |

#### 4.6.3 OWASP Agentic AI Security Framework Controls

| Control Category | Framework Requirement | Yashigani Implementation |
|---|---|---|
| Identity and Authentication | Agents must have verifiable identities | `X-Yashigani-Agent-Id` header is the agent identity claim. RBAC maps agent IDs to groups. OPA rejects requests with `agent_id == "unknown"`. v0.2.0 adds RBAC enforcement per agent ID. |
| Least Privilege | Agents should have minimal required permissions | RBAC (Section 4.5) scopes each agent to specific MCP server paths and methods. No agent can call any path by default when RBAC is configured with an explicit allow-list. |
| Audit and Traceability | All agent actions must be logged | `AuditLogWriter` writes a `GATEWAY_REQUEST` event for every request. `request_id` is injected as `X-Yashigani-Request-Id` into the upstream request, enabling end-to-end trace. |
| Content Integrity | Agent content must be inspected for manipulation | `InspectionPipeline` processes all agent requests. `CredentialMasker` runs before classifier. Sanitization before forwarding on CREDENTIAL_EXFIL with high confidence. |
| Rate and Resource Control | Agents must not exhaust shared resources | Adaptive rate limiter with per-agent bucket (Section 4.2). GPU metrics integrated into RPI (Section 4.3), which gates the rate limit multiplier. |
| Secrets Management | Agent credentials must not traverse inspection layers | CHS opaque handles prevent raw credentials from appearing in inspected content. Masking patterns in `CredentialMasker` provide a secondary layer. |
| Policy Enforcement | Agent behaviour must comply with organisational policy | OPA is the single enforcement point. Policy is always local (never cloud-delegated). RBAC data is pushed to OPA, not hard-coded in Rego. Fail-closed on any OPA error. |
| Anomaly Detection | Unusual agent behaviour should trigger alerts | Grafana Agent Activity dashboard (Section 4.4.4) visualises per-agent detection rates and spikes. Prometheus alerts on elevated OPA denial rates and CREDENTIAL_EXFIL detections. |
| Human Oversight | Critical decisions must be reviewed by humans | HITL protocol: CREDENTIAL_EXFIL above threshold → sanitize and forward; below threshold → discard and alert admin. Admin is alerted for every CRITICAL detection. Rate limit violations are audited. |
| Data Minimisation | Agent data should not be retained beyond necessity | Raw query content is never logged (audit invariant). Content hash only. Session tokens masked to first 8 chars in audit. IP last-octet masked in session store. |

#### 4.6.4 Specific Code Changes Required for ASVS v5 Compliance

| Module | Change | ASVS v5 Reference |
|---|---|---|
| `auth/local_auth.py` | Encrypt `AccountRecord.totp_secret` at rest using KSM `get_secret`/`set_secret`. Add `totp_secret_handle: str` field alongside (or replacing) plaintext `totp_secret`. | V6.2 — Sensitive data encrypted at rest |
| `audit/schema.py` | Add `chain_hmac: str` field to `AuditEvent`. Each event's HMAC is computed over `HMAC-SHA256(previous_chain_hmac + event_data)`. First event uses a deployment-specific HMAC key from KSM. | V7.3 — Log integrity protection |
| `audit/writer.py` | Compute and write `chain_hmac` on every event write. Store `last_chain_hmac` in Redis db/1 (backoffice) under key `audit:chain:last_hmac`. | V7.3 |
| `gateway/proxy.py` | Add Pydantic model for path/query validation on gateway requests (reject requests with invalid UTF-8 paths or overly long query strings > 8 KB). | V5.2 — Input validation |
| `backoffice/routes/*.py` | Add CSRF token validation on all state-mutating POST/PUT/PATCH/DELETE endpoints. CSRF token generated at session creation, stored in session, validated from `X-CSRF-Token` header. | V4.2.3 — CSRF protection |
| `gateway/proxy.py` | Inject `X-Yashigani-Upstream` header into OPA input to support MCP server-level RBAC matching. | V4.1 — RBAC enforcement completeness |
| `chs/resource_monitor.py` | GPU metrics integration (Section 4.3) — updated RPI formula. | V11.1 — Resource control |

---

## 5. New Modules and Files

| File path | Description |
|---|---|
| `src/yashigani/metrics/__init__.py` | Prometheus `CollectorRegistry` singleton; exports shared registry |
| `src/yashigani/metrics/gateway_metrics.py` | Gateway counters, histograms, `instrument_gateway_request()` function |
| `src/yashigani/metrics/inspection_metrics.py` | Inspection pipeline classification and latency metrics |
| `src/yashigani/metrics/auth_metrics.py` | Login, TOTP, session, KSM rotation counters |
| `src/yashigani/metrics/system_metrics.py` | CPU/memory/GPU gauges, RPI gauge |
| `src/yashigani/metrics/rate_limit_metrics.py` | Rate limit violation counters, token gauge, multiplier gauge |
| `src/yashigani/ratelimit/__init__.py` | Public API: `AdaptiveRateLimiter`, `RateLimitConfig` |
| `src/yashigani/ratelimit/limiter.py` | Token bucket logic, RPI multiplier, Redis Lua script execution |
| `src/yashigani/ratelimit/storage.py` | Redis key schema constants, atomic bucket operations |
| `src/yashigani/ratelimit/config.py` | `RateLimitConfig` dataclass with defaults and validation |
| `src/yashigani/rbac/__init__.py` | Public API: `RBACStore`, `RBACGroup`, `RBACMapping` |
| `src/yashigani/rbac/model.py` | `RBACGroup`, `RBACMapping`, `ResourcePattern` dataclasses |
| `src/yashigani/rbac/store.py` | Redis-backed allow-list store with in-memory cache |
| `src/yashigani/rbac/scim.py` | SCIM 2.0 router, resource CRUD, bearer token validation |
| `src/yashigani/rbac/opa_push.py` | `push_rbac_to_opa()`: builds data document, calls OPA REST API |
| `src/yashigani/chs/gpu_monitor.py` | `GPUMonitor` class, `GPUMetrics` dataclass, provider chain |
| `src/yashigani/backoffice/routes/rate_limits.py` | Admin rate limit management routes |
| `src/yashigani/backoffice/routes/rbac.py` | Admin RBAC allow-list management routes |
| `src/yashigani/backoffice/routes/scim.py` | SCIM 2.0 endpoint router |
| `src/yashigani/backoffice/routes/metrics.py` | `/metrics` endpoint for Prometheus scrape (admin-protected) |
| `docker/caddy/acme/Caddyfile` | Caddy config for Let's Encrypt mode |
| `docker/caddy/ca_signed/Caddyfile` | Caddy config for CA-signed certificate mode |
| `docker/caddy/self_signed/Caddyfile` | Caddy config for self-signed (local/dev) mode |
| `prometheus/prometheus.yml` | Prometheus scrape and alerting configuration |
| `prometheus/rules/yashigani_alerts.yml` | Prometheus alert rules |
| `grafana/provisioning/datasources/prometheus.yaml` | Grafana datasource provisioning (auto-loads on startup) |
| `grafana/provisioning/dashboards/yashigani.yaml` | Grafana dashboard provisioning config |
| `grafana/dashboards/security_overview.json` | Security Overview dashboard definition |
| `grafana/dashboards/system_health.json` | System Health dashboard definition |
| `grafana/dashboards/agent_activity.json` | Agent Activity dashboard definition |
| `grafana/dashboards/rate_limit_status.json` | Rate Limit Status dashboard definition |
| `policy/rbac.rego` | OPA RBAC policy rules (`package yashigani.rbac`) |
| `policy/data/rbac_data.json` | Seed RBAC data document pushed to OPA on startup |

---

## 6. Modified Files

| File | Changes | Reason |
|---|---|---|
| `src/yashigani/__init__.py` | Version → `0.2.0`; add `rbac`, `ratelimit`, `metrics` to module docstring | Version tracking and discoverability |
| `src/yashigani/chs/resource_monitor.py` | Add `gpu: Optional[GPUMetrics]` to `ResourceMetrics`; update `_read_cgroup_v2` and `_read_docker_stats` to call `GPUMonitor`; update RPI formula to 4-term weighted sum; pass `on_critical` to rate limiter callback chain | GPU metrics integration, updated RPI |
| `src/yashigani/gateway/proxy.py` | Add `RateLimitMiddleware` before inspection pipeline; add Prometheus instrumentation via `instrument_gateway_request`; extend OPA input with `groups` and `X-Yashigani-Upstream`; add Pydantic path/query validation; add `/metrics` route | Rate limiting, observability, RBAC, ASVS v5 |
| `src/yashigani/backoffice/state.py` | Add `rate_limiter: Optional[AdaptiveRateLimiter]`, `rbac_store: Optional[RBACStore]`, `gpu_monitor: Optional[GPUMonitor]`, `metrics_registry` | New subsystem references for DI |
| `src/yashigani/backoffice/app.py` | Register `rate_limits_router`, `rbac_router`, `scim_router`, `metrics_router`; add rate limit middleware for `/auth/*` routes | New features |
| `src/yashigani/backoffice/routes/dashboard.py` | Add GPU metrics block to `/dashboard/resources`; add rate limiter summary (current multiplier, violations last 1h) to `/dashboard/health` | GPU observability, rate limiter health |
| `src/yashigani/auth/local_auth.py` | Add `totp_secret_handle` field to `AccountRecord`; modify `provision_totp` to store secret via KSM if available; add CSRF token generation and validation helpers | ASVS v5 V6.2 (encrypt sensitive data at rest) |
| `src/yashigani/audit/schema.py` | Add `chain_hmac: str` field to `AuditEvent`; add new `EventType` values: `RATE_LIMIT_EXCEEDED`, `RBAC_POLICY_CHANGED`, `RBAC_ACCESS_DENIED`, `OPA_PUSH_FAILED`, `GPU_PRESSURE_CRITICAL`, `RBAC_SCIM_SYNC`, `RBAC_IMPORT_EXECUTED`; add corresponding event dataclasses | ASVS v5 log integrity, new event types |
| `src/yashigani/audit/writer.py` | Compute `chain_hmac` on write; load/store last HMAC from Redis; write HMAC key from KSM on first write | ASVS v5 V7.3 |
| `docker/docker-compose.yml` | Add `caddy`, `prometheus`, `grafana`, `redis-exporter` services; add `caddy_data`, `caddy_config`, `prometheus_data`, `grafana_data` named volumes; remove direct host port bindings for `gateway` and `backoffice`; add Redis db/2 and db/3 via command args; add `YASHIGANI_TLS_MODE` and new env vars | TLS, observability, rate limiting |
| `.env.example` | Add: `YASHIGANI_TLS_MODE`, `YASHIGANI_TLS_DOMAIN`, `YASHIGANI_TLS_ACME_EMAIL`, `YASHIGANI_TLS_CERT_FILE`, `YASHIGANI_TLS_KEY_FILE`, `YASHIGANI_RBAC_MODE`, `GRAFANA_ADMIN_PASSWORD`, `GRAFANA_ADMIN_USER`, `GRAFANA_ROOT_URL`, `PROMETHEUS_RETENTION_DAYS`, `BACKOFFICE_HOST_PORT` | New feature configuration |
| `policy/yashigani.rego` | Import `data.yashigani.rbac.rbac_allow` in `allow` rule; update `allow` rule to include RBAC gate; add `X-Yashigani-Upstream` to allowed input fields | RBAC enforcement |
| `pyproject.toml` | Add `prometheus-client>=0.20`, `limits>=3.12`, `pynvml>=11.5`, `scim2-filter-parser>=2.0` to `dependencies`; add `grafana` and `prometheus` Docker image references to dev dependency comments | New runtime dependencies |

---

## 7. New Dependencies

### 7.1 Python Packages (core dependencies)

| Package | Minimum version | Feature | Justification |
|---|---|---|---|
| `prometheus-client` | 0.20.0 | Observability | Official Prometheus Python client. Provides Counter, Gauge, Histogram, Summary primitives and HTTP `/metrics` exposition. |
| `limits` | 3.12.0 | Rate Limiting | Token bucket and sliding window algorithms with Redis backend. Used as the atomic counter layer under the custom `AdaptiveRateLimiter`. |
| `pynvml` | 11.5.0 | GPU Metrics | NVIDIA Management Library Python bindings. Provides `nvmlDeviceGetUtilizationRates` and `nvmlDeviceGetMemoryInfo`. Optional at runtime — `GPUMonitor` catches `ImportError` gracefully. |
| `scim2-filter-parser` | 2.0.0 | RBAC/SCIM | Parses SCIM 2.0 filter expressions for `GET /scim/v2/Users?filter=...` queries. |

### 7.2 Python Packages (optional extras)

| Package | Minimum version | Extra key | Justification |
|---|---|---|---|
| `pynvml` | 11.5.0 | `gpu` | Only needed on NVIDIA GPU hosts. Install with `pip install 'yashigani[gpu]'`. |

### 7.3 Docker Images (new)

| Image | Version | Service | Notes |
|---|---|---|---|
| `caddy:2-alpine` | 2.7 | `caddy` | TLS edge proxy. Pin to minor version for predictability. |
| `prom/prometheus` | v2.52.0 | `prometheus` | Metrics collection. Pin exact version. |
| `grafana/grafana` | 10.4.2 | `grafana` | Dashboards and alerting. Pin exact version. |
| `oliver006/redis_exporter` | v1.61.0-alpine | `redis-exporter` | Redis → Prometheus bridge. |

### 7.4 New Infrastructure Services

| Service | Purpose | Network exposure |
|---|---|---|
| Caddy | TLS termination, HTTP→HTTPS redirect, reverse proxy to gateway and backoffice | External (ports 80, 443) |
| Prometheus | Metrics scraping and TSDB storage | Internal only (port 9090 on internal network; not exposed on host) |
| Grafana | Dashboard visualisation and alerting | Internal only in default config; expose via `GRAFANA_HOST_PORT` env var for external access |
| redis-exporter | Redis metrics bridge | Internal only |

---

## 8. Backoffice API Changes

All new endpoints require an authenticated admin session (`AdminSession` dependency) unless noted otherwise.

| Method | Path | Description | Request body | Response | Guards |
|---|---|---|---|---|---|
| `GET` | `/admin/rate-limits` | Current effective limits and RPI multiplier | — | `{global: {capacity, rate, effective_rate}, ip: {...}, agent: {...}, session: {...}, rpi: float, multiplier: float}` | AdminSession |
| `POST` | `/admin/rate-limits` | Update base limits | `{dimension: str, capacity: int, rate: float}` | `{status: "ok", applied: {...}}` | AdminSession |
| `DELETE` | `/admin/rate-limits/reset` | Flush all rate limit Redis keys | — | `{status: "ok", keys_deleted: int}` | AdminSession + TOTP re-verify |
| `GET` | `/admin/rate-limits/status` | Live bucket state for all global/role dimensions | — | `{buckets: [{dimension, tokens_remaining, capacity, rate}]}` | AdminSession |
| `GET` | `/admin/rate-limits/roles` | List per-role overrides | — | `{roles: [{role_name, capacity, rate}]}` | AdminSession |
| `POST` | `/admin/rate-limits/roles` | Add/update role override | `{role_name: str, capacity: int, rate: float}` | `{status: "ok"}` | AdminSession |
| `DELETE` | `/admin/rate-limits/roles/{role_name}` | Remove role override | — | `{status: "ok"}` | AdminSession |
| `GET` | `/admin/rbac/mode` | Get RBAC mode | — | `{mode: "allow_list" | "scim"}` | AdminSession |
| `POST` | `/admin/rbac/mode` | Set RBAC mode | `{mode: str}` | `{status: "ok", mode: str}` | AdminSession |
| `GET` | `/admin/rbac/groups` | List all groups | — | `{groups: [RBACGroup], total: int}` | AdminSession |
| `POST` | `/admin/rbac/groups` | Create group | `{name: str, description: str, member_agent_ids: list, member_user_ids: list}` | `{group_id: str, status: "ok"}` | AdminSession |
| `GET` | `/admin/rbac/groups/{group_id}` | Get group | — | `RBACGroup` | AdminSession |
| `PUT` | `/admin/rbac/groups/{group_id}` | Replace group | Full `RBACGroup` body (except `group_id`, `created_at`) | `{status: "ok"}` | AdminSession |
| `PATCH` | `/admin/rbac/groups/{group_id}` | Add/remove members | `{op: "add"|"remove", member_type: "agent"|"user", ids: list}` | `{status: "ok", members_added: int, members_removed: int}` | AdminSession |
| `DELETE` | `/admin/rbac/groups/{group_id}` | Delete group | — | `{status: "ok"}` | AdminSession |
| `GET` | `/admin/rbac/mappings` | List all mappings | — | `{mappings: [RBACMapping], total: int}` | AdminSession |
| `POST` | `/admin/rbac/mappings` | Create mapping | `{group_id: str, resource: ResourcePattern, allowed_methods: list}` | `{mapping_id: str, status: "ok"}` | AdminSession |
| `GET` | `/admin/rbac/mappings/{mapping_id}` | Get mapping | — | `RBACMapping` | AdminSession |
| `DELETE` | `/admin/rbac/mappings/{mapping_id}` | Delete mapping | — | `{status: "ok"}` | AdminSession |
| `POST` | `/admin/rbac/policy/push` | Push RBAC data to OPA | — | `{status: "ok", version: int, opa_response_ms: int}` | AdminSession |
| `GET` | `/admin/rbac/export` | Export full allow-list | — | JSON document (see Section 4.5.3) | AdminSession |
| `POST` | `/admin/rbac/import` | Import full allow-list | JSON document + `{totp_code: str}` | `{status: "ok", groups_imported: int, mappings_imported: int}` | AdminSession + TOTP re-verify |
| `POST` | `/admin/rbac/scim-token` | Rotate SCIM bearer token | — | `{status: "ok", token: str}` (token shown once) | AdminSession + TOTP re-verify |
| `GET` | `/metrics` (gateway) | Prometheus metrics scrape endpoint | — | `text/plain; version=0.0.4` Prometheus exposition format | Network isolation (internal only; OPA blocks external access) |
| `GET` | `/metrics` (backoffice) | Prometheus metrics scrape endpoint | — | `text/plain; version=0.0.4` | AdminSession OR scrape IP allowlist |
| `GET` | `/scim/v2/ServiceProviderConfig` | SCIM service provider config | — | SCIM ServiceProviderConfig JSON | None (unauthenticated) |
| `GET` | `/scim/v2/Schemas` | SCIM schema definitions | — | SCIM Schemas JSON | None (unauthenticated) |
| `GET` | `/scim/v2/Users` | List users (SCIM) | — | SCIM ListResponse | SCIM Bearer token |
| `POST` | `/scim/v2/Users` | Create user (SCIM) | SCIM User JSON | SCIM User JSON (201) | SCIM Bearer token |
| `GET` | `/scim/v2/Users/{id}` | Get user (SCIM) | — | SCIM User JSON | SCIM Bearer token |
| `PUT` | `/scim/v2/Users/{id}` | Replace user (SCIM) | SCIM User JSON | SCIM User JSON | SCIM Bearer token |
| `PATCH` | `/scim/v2/Users/{id}` | Partial update user (SCIM) | SCIM PatchOp JSON | SCIM User JSON | SCIM Bearer token |
| `DELETE` | `/scim/v2/Users/{id}` | Delete user (SCIM) | — | 204 No Content | SCIM Bearer token |
| `GET` | `/scim/v2/Groups` | List groups (SCIM) | — | SCIM ListResponse | SCIM Bearer token |
| `POST` | `/scim/v2/Groups` | Create group (SCIM) | SCIM Group JSON | SCIM Group JSON (201) | SCIM Bearer token |
| `GET` | `/scim/v2/Groups/{id}` | Get group (SCIM) | — | SCIM Group JSON | SCIM Bearer token |
| `PUT` | `/scim/v2/Groups/{id}` | Replace group (SCIM) | SCIM Group JSON | SCIM Group JSON | SCIM Bearer token |
| `PATCH` | `/scim/v2/Groups/{id}` | Partial update group (SCIM) | SCIM PatchOp JSON | SCIM Group JSON | SCIM Bearer token |
| `DELETE` | `/scim/v2/Groups/{id}` | Delete group (SCIM) | — | 204 No Content | SCIM Bearer token |

---

## 9. Audit Schema Additions

New `EventType` values and corresponding dataclasses added to `audit/schema.py`:

```python
class EventType(str, Enum):
    # ... existing values ...
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    RBAC_POLICY_CHANGED = "RBAC_POLICY_CHANGED"
    RBAC_ACCESS_DENIED = "RBAC_ACCESS_DENIED"
    OPA_PUSH_FAILED = "OPA_PUSH_FAILED"
    GPU_PRESSURE_CRITICAL = "GPU_PRESSURE_CRITICAL"
    RBAC_SCIM_SYNC = "RBAC_SCIM_SYNC"
    RBAC_IMPORT_EXECUTED = "RBAC_IMPORT_EXECUTED"
```

**New event dataclasses:**

```python
@dataclass
class RateLimitExceededEvent(AuditEvent):
    event_type: str = EventType.RATE_LIMIT_EXCEEDED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    dimension: str = ""                  # global | ip | agent | session | role
    client_ip_hash: str = ""             # SHA-256[:16] of client IP
    agent_id: str = ""
    session_id_prefix: str = ""          # first 8 chars
    effective_limit: float = 0.0         # base * multiplier at time of rejection
    rpi_at_time: float = 0.0
    retry_after_seconds: int = 0


@dataclass
class RbacPolicyChangedEvent(AuditEvent):
    event_type: str = EventType.RBAC_POLICY_CHANGED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    admin_account: str = ""
    change_type: str = ""                # create | update | delete
    resource_type: str = ""              # group | mapping
    resource_id: str = ""
    summary: str = ""                    # human-readable change description


@dataclass
class RbacAccessDeniedEvent(AuditEvent):
    event_type: str = EventType.RBAC_ACCESS_DENIED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    agent_id: str = ""
    user_id: str = ""
    session_id: str = ""
    path: str = ""
    method: str = ""
    reason: str = "rbac_deny"


@dataclass
class OpaPushFailedEvent(AuditEvent):
    event_type: str = EventType.OPA_PUSH_FAILED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    opa_url: str = ""
    http_status: Optional[int] = None
    error: str = ""
    retry_count: int = 0


@dataclass
class GpuPressureCriticalEvent(AuditEvent):
    event_type: str = EventType.GPU_PRESSURE_CRITICAL
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    gpu_utilisation_pct: float = 0.0
    gpu_memory_pressure: float = 0.0
    rpi: float = 0.0
    rate_limit_multiplier_applied: float = 0.0


@dataclass
class RbacScimSyncEvent(AuditEvent):
    event_type: str = EventType.RBAC_SCIM_SYNC
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    operation: str = ""                  # create | update | delete
    resource_type: str = ""              # User | Group
    resource_id: str = ""
    outcome: str = ""                    # success | failure
    error: Optional[str] = None


@dataclass
class RbacImportExecutedEvent(AuditEvent):
    event_type: str = EventType.RBAC_IMPORT_EXECUTED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    admin_account: str = ""
    groups_imported: int = 0
    mappings_imported: int = 0
    previous_version: int = 0
    new_version: int = 0
```

All new events inherit `chain_hmac: str` from the updated `AuditEvent` base class (ASVS v5 V7.3 requirement).

---

## 10. Implementation Phases

### Phase 1: TLS + Security Baseline (Foundation)

**Goal:** All traffic is encrypted. ASVS v5 critical gaps are closed before any new feature traffic flows over the system.

**Duration estimate:** 8–10 engineering days.

**Files to create:**
- `docker/caddy/acme/Caddyfile`
- `docker/caddy/ca_signed/Caddyfile`
- `docker/caddy/self_signed/Caddyfile`

**Files to modify:**
- `docker/docker-compose.yml` — Add Caddy service; update port bindings
- `.env.example` — Add TLS variables
- `src/yashigani/auth/local_auth.py` — TOTP secret KSM encryption, CSRF token helpers
- `src/yashigani/audit/schema.py` — Add `chain_hmac` field, new event types (all)
- `src/yashigani/audit/writer.py` — HMAC chain computation
- `src/yashigani/__init__.py` — Version bump to `0.2.0`

**Acceptance tests:**
1. `testssl.sh https://localhost` grades A or above in self-signed mode.
2. HTTP connection to port 80 returns HTTP 301.
3. TLS 1.1 connection attempt is rejected.
4. Two sequential audit events: `event_N.chain_hmac == HMAC(event_{N-1}.chain_hmac + event_N_data)` verified by a test utility.
5. Admin POST endpoints without `X-CSRF-Token` header return HTTP 403.

**Dependencies between phases:** Phase 1 must complete before Phase 2 begins. Rate limiter and RBAC operate over TLS. Observability stack routes through Caddy.

---

### Phase 2: Observability + GPU Metrics

**Goal:** Full metrics pipeline operational. Every security event emits a Prometheus metric. Grafana dashboards populated. GPU metrics visible.

**Duration estimate:** 8–10 engineering days.

**Files to create:**
- `src/yashigani/metrics/__init__.py`
- `src/yashigani/metrics/gateway_metrics.py`
- `src/yashigani/metrics/inspection_metrics.py`
- `src/yashigani/metrics/auth_metrics.py`
- `src/yashigani/metrics/system_metrics.py`
- `src/yashigani/metrics/rate_limit_metrics.py`
- `src/yashigani/chs/gpu_monitor.py`
- `prometheus/prometheus.yml`
- `prometheus/rules/yashigani_alerts.yml`
- `grafana/provisioning/datasources/prometheus.yaml`
- `grafana/provisioning/dashboards/yashigani.yaml`
- `grafana/dashboards/security_overview.json`
- `grafana/dashboards/system_health.json`
- `grafana/dashboards/agent_activity.json`
- `grafana/dashboards/rate_limit_status.json`

**Files to modify:**
- `src/yashigani/chs/resource_monitor.py` — GPU integration, updated RPI formula
- `src/yashigani/gateway/proxy.py` — Prometheus instrumentation
- `src/yashigani/backoffice/app.py` — Register `/metrics` route
- `src/yashigani/backoffice/routes/dashboard.py` — GPU metrics in `/dashboard/resources`
- `src/yashigani/backoffice/state.py` — Add `gpu_monitor`, `metrics_registry`
- `docker/docker-compose.yml` — Add Prometheus, Grafana, redis-exporter services
- `pyproject.toml` — Add `prometheus-client>=0.20`, `pynvml>=11.5`

**Acceptance tests:**
1. `curl http://prometheus:9090/api/v1/targets | jq '.data.activeTargets[] | select(.health=="up")' | wc -l` returns 4 (gateway, backoffice, opa, redis-exporter).
2. After 10 gateway requests, `yashigani_gateway_requests_total` equals 10 in Prometheus.
3. All four Grafana dashboards load without "No data" panels (after 5 minutes of traffic).
4. On an NVIDIA host: `yashigani_gpu_utilisation_pct` has a non-zero value. On CPU-only: value is 0.0 and no error in logs.
5. Firing a simulated CREDENTIAL_EXFIL event: Grafana alert `CredentialExfiltrationDetected` fires within 60 seconds.

**Dependencies:** Phase 1 complete. Prometheus and Grafana route through Caddy for external access.

---

### Phase 3: Adaptive Rate Limiting

**Goal:** Gateway is protected against L7 DoS. Rate limits are configurable and self-tune under resource pressure.

**Duration estimate:** 6–8 engineering days.

**Files to create:**
- `src/yashigani/ratelimit/__init__.py`
- `src/yashigani/ratelimit/limiter.py`
- `src/yashigani/ratelimit/storage.py`
- `src/yashigani/ratelimit/config.py`
- `src/yashigani/backoffice/routes/rate_limits.py`

**Files to modify:**
- `src/yashigani/gateway/proxy.py` — Add `RateLimitMiddleware`
- `src/yashigani/backoffice/app.py` — Register `rate_limits_router`
- `src/yashigani/backoffice/state.py` — Add `rate_limiter`
- `src/yashigani/audit/schema.py` — `RateLimitExceededEvent` (already added in Phase 1 schema changes)
- `docker/docker-compose.yml` — Add Redis db/2 config
- `pyproject.toml` — Add `limits>=3.12`

**Acceptance tests:**
1. Send 300 requests in 1 second from a single IP (burst > `ip_capacity=200`). Requests 201–300 return HTTP 429 with `Retry-After` header.
2. `GET /admin/rate-limits` shows current effective limits and correct RPI multiplier.
3. Simulate RPI = 0.85: confirm effective per-IP rate = `0.40 * 20 = 8 req/s`.
4. Flush Redis db/2. Rate limit counters reset. Subsequent requests not throttled.
5. Audit log contains `RATE_LIMIT_EXCEEDED` event for each HTTP 429 response.
6. Per-RBAC-role override: set role `analysts` to `capacity=1000`. Agent with `groups=["analysts"]` gets 1000-token bucket, not the default 200.

**Dependencies:** Phase 2 complete (metrics emitted from rate limiter require Phase 2 metrics module). Redis must be running (already in Phase 1).

---

### Phase 4: RBAC

**Goal:** Data plane access is controlled by group membership. Allow-list manageable in backoffice. SCIM 2.0 sync operational. OPA enforces all decisions.

**Duration estimate:** 10–12 engineering days.

**Files to create:**
- `src/yashigani/rbac/__init__.py`
- `src/yashigani/rbac/model.py`
- `src/yashigani/rbac/store.py`
- `src/yashigani/rbac/scim.py`
- `src/yashigani/rbac/opa_push.py`
- `src/yashigani/backoffice/routes/rbac.py`
- `src/yashigani/backoffice/routes/scim.py`
- `policy/rbac.rego`
- `policy/data/rbac_data.json`

**Files to modify:**
- `src/yashigani/gateway/proxy.py` — Add `groups` to OPA input; add `X-Yashigani-Upstream` header injection
- `src/yashigani/backoffice/app.py` — Register `rbac_router`, `scim_router`
- `src/yashigani/backoffice/state.py` — Add `rbac_store`
- `src/yashigani/ratelimit/limiter.py` — Integrate per-role limit overrides from RBAC store
- `docker/docker-compose.yml` — Add Redis db/3 config
- `policy/yashigani.rego` — Add RBAC gate to `allow` rule
- `pyproject.toml` — Add `scim2-filter-parser>=2.0`

**Acceptance tests:**
1. Empty allow-list: all authenticated agents are **denied** by RBAC (deny-by-default posture confirmed 2026-03-26). The `count(groups) == 0` permissive branch has been removed from `rbac.rego`. Test must verify HTTP 403 when no groups are configured.
2. Non-empty allow-list, agent not in any group: request returns HTTP 403. Audit event `RBAC_ACCESS_DENIED` written.
3. Agent in group `analysts` mapped to `/v1/*` with `GET`: `GET /v1/tools` passes; `DELETE /v1/tools` returns HTTP 403.
4. `POST /admin/rbac/policy/push` returns `{status: "ok"}` and the OPA data document at `GET /v1/data/yashigani/rbac` reflects the pushed state.
5. SCIM `POST /scim/v2/Groups` with valid bearer token creates a group visible in `GET /admin/rbac/groups`.
6. SCIM `DELETE /scim/v2/Groups/{id}` soft-deletes the group. OPA data push after delete removes the group from OPA. Agents previously in that group are now denied.
7. `GET /admin/rbac/export` returns valid JSON importable via `POST /admin/rbac/import`.

**Dependencies:** Phase 1 (TLS) and Phase 3 (rate limiter, per-role override integration) complete before Phase 4 ships. Phase 2 (metrics) must be complete for RBAC metrics to be exported.

---

## 11. Security Threat Model Updates

### 11.1 TLS Layer

**New attack surface introduced:**
- Caddy process becomes a new trust boundary. Compromise of Caddy means all TLS traffic can be intercepted.
- ACME challenge endpoint (port 80) is exposed to the internet in `acme` mode.
- Certificate private key stored in `caddy_data` volume.

**Mitigations:**
- Caddy runs as a non-root user inside the `caddy:2-alpine` image.
- `admin off` in all Caddyfiles disables the Caddy admin API endpoint (prevents runtime config manipulation).
- `caddy_data` volume is owned by the Caddy container user; not accessible from other containers.
- ACME HTTP-01 challenge only serves `.well-known/acme-challenge/` paths — all other HTTP requests are immediately redirected to HTTPS.
- Operator documentation recommends DNS-01 challenge for environments where port 80 must not be exposed.

**Residual risks:**
- ACME provider (Let's Encrypt) compromise or outage. Mitigated by: static certificates fall back cleanly; certificate validity is 90 days giving time to respond.
- Private key exfiltration from the Docker host. Not fully mitigated at the application layer — this is a host security control.

### 11.2 Adaptive Rate Limiting

**New attack surface introduced:**
- Redis database `/2` becomes a target — an attacker who can write to Redis can zero all rate limit counters, disabling rate limiting.
- The Lua script executes on the Redis server; a crafted Lua script could be a Redis injection vector (mitigated: only the pre-defined script is executed; no user-supplied Lua).
- Rate limit bypass via IP spoofing in `X-Forwarded-For` header.

**Mitigations:**
- Redis requires authentication (`REDIS_PASSWORD`). Redis is on the internal Docker network only.
- Lua script is pre-loaded by the rate limiter at startup and referenced by SHA1 (`EVALSHA`); the script bytes are not re-sent per request.
- `X-Forwarded-For` is trusted only when Caddy is in the chain. In Compose deployments, Caddy sets the `X-Forwarded-For` header authoritatively after stripping any client-provided value. The gateway's `_get_client_ip` already reads the first value from the chain — when Caddy is present, this is the real client IP as seen by Caddy.
- Rate limit bucket keys use `SHA-256(ip)[:16]` — no raw IPs in Redis keys.

**Residual risks:**
- Distributed DoS from a large botnet may exhaust per-IP limits across many IPs without triggering the global limit if the global limit is set too high. Safe defaults in Section 4.2.6 are conservative. Operators should tune for their traffic profile.
- Rate limiting is at L7 only. SYN flood is not mitigated by Yashigani.

### 11.3 GPU Metrics

**New attack surface introduced:**
- `pynvml` makes NVML calls; a vulnerability in the NVML driver or `pynvml` binding could be exploited if the container has GPU device access.
- Ollama `/api/ps` is polled from the gateway container — this is an additional internal HTTP call that could fail or be manipulated if Ollama is compromised.

**Mitigations:**
- GPU monitor runs read-only NVML calls only (`nvmlDeviceGetUtilizationRates`, `nvmlDeviceGetMemoryInfo`). No write or configuration operations.
- `pynvml` import is wrapped in `try/except ImportError`. Failure is silent and graceful.
- Ollama `/api/ps` is on the internal Docker network. Response is validated for expected JSON structure before parsing.

**Residual risks:**
- NVML driver vulnerabilities. Mitigated by keeping the host NVIDIA driver patched. Not a Yashigani control.

### 11.4 Observability Stack

**New attack surface introduced:**
- Prometheus stores potentially sensitive operational data (detection rates, agent IDs as label values, auth failure counts). If the Prometheus TSDB is exposed or exfiltrated, an attacker learns the detection cadence and agent topology.
- Grafana admin interface is a new authentication surface.
- `/metrics` endpoint on the gateway exposes operational data.

**Mitigations:**
- Prometheus is on the internal Docker network only. Not exposed on host ports by default.
- Grafana is on the internal network by default. Exposed only if `GRAFANA_HOST_PORT` is set.
- `GRAFANA_ADMIN_PASSWORD` is required at startup (no default).
- Gateway `/metrics` endpoint is blocked by OPA policy for any external caller (`path_blocked` rule on `/metrics` already exists in v0.1.0).
- Agent IDs in Prometheus labels are treated as identifiers, not secrets. Labels should not contain credential material — this is enforced by the `CredentialMasker` running before any agent_id is logged.

**Residual risks:**
- Grafana alert contact points (email, Slack webhook) are stored in Grafana provisioning config files. These files must be protected with appropriate file permissions. Recommendation: use environment variables for webhook URLs and never commit them to version control.

### 11.5 RBAC

**New attack surface introduced:**
- SCIM 2.0 endpoint is a new external-facing API that can create users and groups.
- OPA data push endpoint (`PUT /v1/data/yashigani/rbac`) — if accessible, an attacker could push a permissive RBAC data document, granting themselves access.
- RBAC store in Redis db/3 — compromise of Redis allows manipulation of allow-list data.
- RBAC bypass: if the `groups_for_identity` lookup in the gateway fails (e.g., Redis unavailable), the RBAC data fed to OPA would be empty, triggering the `count(groups) == 0` permissive branch.

**Mitigations:**
- SCIM endpoint requires a Bearer token issued by the admin. Token is stored in KSM; never in `.env`.
- OPA data endpoint is on the internal Docker network only. No external access. The backoffice is the only service that calls it.
- Redis authentication required. Internal network only.
- **RBAC bypass via empty groups:** This is the most significant risk. Mitigation: the `groups_for_identity` function caches the last known good RBAC state in-process. If Redis is unavailable, the last cached state is used (fail-last-known, not fail-open). If the cache is empty (first startup before first OPA push), the gateway starts in `deny-all-unauthenticated` mode. A startup health check verifies that RBAC data is in OPA before the gateway begins accepting traffic.
- RBAC import requires TOTP re-verification. This prevents a session-hijacked admin from bulk-replacing the allow-list.

**Residual risks:**
- The permissive branch (`count(groups) == 0`) has been **removed** per the Product Owner decision on 2026-03-26 (Q3, Option B). The OPA rule is now fail-closed: no RBAC groups configured means deny all. The bootstrap procedure must configure at least one group before opening traffic. This is a zero-trust posture with no configurable override.

---

## 12. Product Owner Decisions — Closed Questions

All open questions from the draft plan are closed. Each entry below records the confirmed decision, the implementation notes required to execute it, and supersedes the previous recommendation where they differ.

---

### Q1: Backoffice Remote Access Hostname — CLOSED

**Decision confirmed:** Option A — Single FQDN, path-based routing.

**Rationale:** Simpler operator experience. `/admin/*` routes to the backoffice upstream. The gateway receives all other traffic. One TLS certificate covers the entire deployment. One Caddyfile route block per mode.

**Implementation notes:**
- All three Caddyfile variants (`acme`, `ca_signed`, `self_signed`) use a single server block.
- The `/admin/*` matcher must be declared before the catch-all `/*` matcher in the Caddyfile (Caddy evaluates matchers top-down).
- The `YASHIGANI_TLS_ADMIN_DOMAIN` variable from Option C is not implemented in v0.2.0.
- Two-FQDN support (Option B/C) may be added as a non-breaking v0.3.0 enhancement without changing the default.
- The existing Section 4.1 Caddyfile examples already reflect this layout and require no changes.

---

### Q2: Response Inspection (LLM05) — CLOSED

**Decision confirmed:** Option A — Response inspection added in v0.2.0, opt-in via `YASHIGANI_INSPECT_RESPONSES=true`, disabled by default.

**Rationale:** Closes OWASP LLM05 Improper Output Handling. The classifier already supports bidirectional content. Opt-in default prevents unexpected performance impact on existing deployments.

**Implementation notes:**
- Add `YASHIGANI_INSPECT_RESPONSES` boolean env var (default `false`) to `BackofficeState` configuration and `.env.example`.
- In `gateway/proxy.py`, after receiving the upstream response and before streaming it to the caller, conditionally run `inspection_pipeline.process(response_body_str)` when the flag is enabled.
- Response inspection uses the same `InspectionPipeline` instance. Classification results are treated as follows: CLEAN → forward; CREDENTIAL_EXFIL → sanitize (mask) before forwarding; PROMPT_INJECTION_ONLY → discard and return HTTP 502 with `X-Yashigani-Block-Reason: response_injection`.
- Add `yashigani_inspection_response_classifications_total` counter (labels: `classification`, `action`, `agent_id`) to `inspection_metrics.py`.
- Audit event `RESPONSE_INSPECTION_BLOCK` added to `audit/schema.py` for response-path discards.
- LLM05 control mapping in Section 4.6.2 updated to "fully met" when `YASHIGANI_INSPECT_RESPONSES=true`. When disabled, status remains "partially met (inbound only)."
- Performance note: response inspection adds one Ollama classifier call per response. At high traffic volumes this doubles classifier load. Operators should monitor `yashigani_inspection_classification_duration_seconds` before enabling in production.

---

### Q3: RBAC Empty Allow-List Semantics — CLOSED

**Decision confirmed:** Option B — Deny by default when no RBAC groups are configured. This overrides the plan's Option C recommendation.

**Rationale:** Zero-trust posture. An empty allow-list must never be silently permissive. OPA rule is written fail-closed. There is no configurable override — this is a fixed security architecture decision for Yashigani.

**Implementation notes:**
- The `rbac_allow if { count(data.yashigani.rbac.groups) == 0 }` permissive branch is permanently removed from `policy/rbac.rego`.
- The `YASHIGANI_RBAC_EMPTY_POLICY` environment variable from Option C is not implemented and must not be added in v0.2.0 or any future version without a new Product Owner decision.
- The bootstrap procedure (`auth/bootstrap.py` or equivalent) must push a valid, non-empty RBAC data document to OPA before the gateway health check transitions to `healthy`. A gateway in a state where no RBAC groups are configured must not report itself as healthy.
- Startup sequence: OPA receives the initial `rbac_data.json` seed document → backoffice RBAC store loads → OPA push executes → gateway opens for traffic.
- Phase 4 acceptance test #1 is updated: empty allow-list must produce HTTP 403, not HTTP 200.
- This is a **breaking change from the plan's original recommended default**. Any existing test fixtures or documentation that assumed empty-allow-list = allow must be updated.

---

### Q4: Prometheus External Exposure — CLOSED

**Decision confirmed:** Option B — `/metrics-federate` routed through Caddy behind admin authentication.

**Rationale:** Supports external Prometheus federation and Thanos deployments without requiring operators to expose raw host ports. Admin authentication gate prevents unauthenticated metric scraping.

**Implementation notes:**
- Add a `/metrics-federate` matcher to all three Caddyfile variants. The route proxies to `prometheus:9090/federate` and applies the same admin session cookie validation used by `/admin/*`.
- Caddy `forward_auth` directive (or equivalent) is used to validate the admin session against the backoffice `/auth/validate` endpoint before proxying the Prometheus federate response.
- The Prometheus `--web.enable-lifecycle` and federation endpoints must remain enabled in the Prometheus command args.
- The `PROMETHEUS_HOST_PORT` env var is retained for local debugging but is not the recommended federation path.
- Add to `.env.example`: `# Set YASHIGANI_METRICS_FEDERATE_ENABLED=true to expose /metrics-federate via Caddy (admin auth required)`.
- Alert rule `PrometheusExternalAccessUnauthenticated` is added: fires if any request to `/metrics-federate` returns HTTP 200 without an `Authorization` or `Cookie` header present (Caddy access log rule).

---

### Q5: TOTP Phishing Gap — CLOSED

**Decision confirmed:** New Option C (not in original list) — Defer FIDO2 to v0.3.0. Implement TOTP exponential backoff in v0.2.0 as the compensating control.

**Rationale:** FIDO2 deferred to v0.3.0 as originally recommended. The additional compensating control (exponential backoff) materially reduces real-time relay attack feasibility beyond what CSRF + SameSite=Strict alone provides.

**Backoff schedule:**

| Failure count | Delay before next attempt |
|---|---|
| 1st failure | 1 second |
| 2nd failure | 2 seconds |
| 3rd failure | 4 seconds |
| 4th failure | 8 seconds |
| 5th and beyond | 30-minute hard lockout (existing behaviour) |

**Implementation notes:**
- Backoff state is stored in Redis db/1 (admin session store) under key `auth:totp_backoff:{account_id}` as a hash: `{failures: int, next_allowed_at: float (unix timestamp)}`.
- The backoff check runs at the start of the TOTP verification handler in `auth/local_auth.py`, before the TOTP code is evaluated. If `now < next_allowed_at`, return HTTP 429 with `Retry-After` header.
- On successful TOTP verification, the backoff key is deleted.
- The existing 30-minute hard lockout (5th failure) is unchanged. The backoff adds friction before lockout, not a replacement for it.
- This compensating control is documented in the ASVS v5 V2 gap table (Section 4.6.1) as: "Mitigated-with-compensating-control. Real-time relay attack window narrowed by exponential backoff. Full phishing-resistance via FIDO2 deferred to v0.3.0."
- Add `yashigani_auth_totp_backoff_active` gauge (labels: `tier`) to `auth_metrics.py` — set to 1 when an account is in a backoff window, 0 when clear.
- FIDO2 target: v0.3.0. Required before claiming full ASVS v5 V2 compliance in any external audit.

---

### Q6: Alert Routing Configuration — CLOSED

**Decision confirmed:** New Option D (not in original list) — Admin username must be a valid email address. That email is auto-registered as the default Grafana alert contact point at bootstrap.

**Rationale:** This is a breaking change from v0.1.0 (which allowed `^[a-z0-9_-]+$` usernames). Requiring an email address is a stronger identity requirement aligned with ASVS v5 V2, and solving the "no contact points configured" problem via bootstrap eliminates the need for a separate degraded-health check.

**Implementation notes:**
- **Breaking change from v0.1.0:** The admin username validation regex changes from `^[a-z0-9_-]+$` to a valid email address regex (RFC 5322 simplified). Existing v0.1.0 deployments with non-email usernames must migrate the admin account username before upgrading to v0.2.0. The upgrade guide must document this migration.
- Validation is enforced in `auth/local_auth.py` `create_account()` and in the bootstrap script. Accounts with non-email usernames are rejected at creation time.
- During bootstrap, after the admin account is created, the bootstrap script calls the Grafana provisioning API to register an email contact point using the admin email address. This is a one-time operation; subsequent bootstraps are idempotent (check if contact point exists before creating).
- The bootstrapped contact point is named `yashigani-admin-default` in Grafana. Operators may add additional contact points. The bootstrapped one must not be deletable via the standard operator flow (protected contact point).
- Because bootstrap guarantees at least one contact point, the `/dashboard/health` endpoint cannot report `degraded` due to missing contact points. The Q6 Option C degraded-state check is not implemented.
- Add `ADMIN_EMAIL` to the bootstrap environment variable documentation (replaces `ADMIN_USERNAME`). The `.env.example` `YASHIGANI_ADMIN_USERNAME` variable is renamed to `YASHIGANI_ADMIN_EMAIL`.
- The Grafana alert routing for `CredentialExfiltrationDetected` (severity: critical) and `OPAUnreachable` (severity: critical) default to the `yashigani-admin-default` contact point.

---

### Global Credential Generation Rule (All Phases — Permanent)

**Rule:** Every new infrastructure service added to the stack (Grafana, Prometheus, Redis, any future service) must have a 36-character cryptographically random password auto-generated using the same method as `auth/password.py generate_password()`. This rule applies to v0.2.0 and all future versions.

**Implementation notes:**
- All generated credentials are printed to stdout during first-run bootstrap in a clearly delimited block (e.g., `=== YASHIGANI BOOTSTRAP CREDENTIALS — STORE SECURELY ===` ... `=== END CREDENTIALS ===`). Credentials are not re-displayed on subsequent startups.
- Credentials are stored as Docker Secrets or via the KSM abstraction. Plain-text env var defaults (e.g., `GRAFANA_ADMIN_PASSWORD=changeme`) are prohibited in production compose files.
- The `.env.example` file must list all credential variables with placeholder `<generated-at-bootstrap>` as the value, not a default password.
- Services affected in v0.2.0: Grafana admin password (`GRAFANA_ADMIN_PASSWORD`), Prometheus web password (if `--web.config.file` is used), Redis password (`REDIS_PASSWORD` — already required in v0.1.0, confirm generation method matches `generate_password()`).
- The bootstrap script must validate that no credential variable is set to a known weak default (e.g., `admin`, `password`, `changeme`). If detected, bootstrap must halt with an error.
- This rule is permanent. Any PR that introduces a new service with a hardcoded or weak default credential must be rejected in review.

---

## 13. Product Owner Decisions Log

**Log date:** 2026-03-26
**Authority:** Tiago (CEO / Product Owner)
**Recorded by:** Maxine (PM/PO)

This section is a permanent audit record. All entries are append-only. No entry may be modified after recording.

| Decision ID | Question | Decision | Overrides Recommendation | Date |
|---|---|---|---|---|
| PO-2026-03-26-Q1 | Backoffice hostname routing | Option A: Single FQDN, path-based routing. `/admin/*` → backoffice. Single certificate. One Caddyfile route. | Yes (plan recommended Option C) | 2026-03-26 |
| PO-2026-03-26-Q2 | Response inspection (LLM05) | Option A: Add response inspection in v0.2.0. Opt-in via `YASHIGANI_INSPECT_RESPONSES=true`. Disabled by default. Covers OWASP LLM05. | No (matches recommendation) | 2026-03-26 |
| PO-2026-03-26-Q3 | RBAC empty allow-list semantics | Option B: Deny by default. Zero-trust posture. OPA rule fail-closed. No configurable override. Fixed security architecture decision. | Yes (plan recommended Option C with allow default) | 2026-03-26 |
| PO-2026-03-26-Q4 | Prometheus external exposure | Option B: `/metrics-federate` routed through Caddy behind admin authentication. Supports external Prometheus federation and Thanos. | Yes (plan recommended Option A / internal only) | 2026-03-26 |
| PO-2026-03-26-Q5 | TOTP phishing gap | New Option C (not in original list): Defer FIDO2 to v0.3.0. Implement TOTP exponential backoff in v0.2.0 (1s/2s/4s/8s/30-min lockout). Documented as mitigated-with-compensating-control against real-time relay attacks. | Partial (deferred to v0.3.0 matches, but adds backoff compensating control not in original options) | 2026-03-26 |
| PO-2026-03-26-Q6 | Alert routing configuration | New Option D (not in original list): Admin username must be a valid email address (breaking change from v0.1.0 `^[a-z0-9_-]+$` pattern). Admin email auto-registered as default Grafana contact point at bootstrap. Health check cannot reach degraded due to missing contact points. | Yes (plan recommended Option C / degraded health check) | 2026-03-26 |
| PO-2026-03-26-GLOBAL | Credential generation for all infrastructure services | All new infrastructure services must use 36-character cryptographically random passwords via `auth/password.py generate_password()`. Generated at first-run bootstrap, printed to stdout in a delimited block, stored as Docker Secrets or KSM. Never as plain env var defaults in production. Permanent rule — applies to all future versions. | N/A (new rule, not previously specified) | 2026-03-26 |

### Security Impact Summary

| Decision | OWASP ASVS v5 Impact | OWASP LLM Top 10 2025 Impact | Risk Delta |
|---|---|---|---|
| Q1 Single FQDN | Neutral (single cert is ASVS V9-compliant) | None | Neutral |
| Q2 Response inspection | Closes LLM05 gap when enabled | LLM05 fully met (opt-in) | Positive — reduces residual risk |
| Q3 Deny-by-default RBAC | Strengthens V4 (Access Control) beyond plan recommendation | LLM06 (Excessive Agency) further constrained | Positive — zero-trust hardening |
| Q4 `/metrics-federate` auth | V9.3.1 (admin interfaces over authenticated TLS) maintained | None | Neutral with guard |
| Q5 TOTP backoff | V2 partial gap — compensating control documented | None | Positive — relay attack window narrowed |
| Q6 Email username + bootstrap contact point | V7.4 (log review) gap closed via guaranteed alert routing | None | Positive — alert delivery assured |
| Global credential rule | V6 (Stored Cryptography) and V14 (Secure Deployment) strengthened | None | Positive — eliminates weak defaults |

---

*End of Yashigani v0.2.0 Implementation Plan*
*Document version: 1.1 — 2026-03-26 (Product Owner decisions applied)*
*Next review: Before Phase 1 kickoff*
