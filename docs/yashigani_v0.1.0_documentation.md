# Yashigani v0.1.0 — Technical Documentation

> **Archived.** This document describes the initial v0.1.0 release. Current release: **v0.7.1** (2026-03-28).

**Version:** 0.1.0
**License:** Proprietary
**Python requirement:** >= 3.12
**Audience:** Security engineers and DevOps teams deploying Yashigani in production or staging environments.

---

## Table of Contents

1. [Product Overview](#1-product-overview)
2. [Architecture](#2-architecture)
3. [Deployment](#3-deployment)
4. [KSM Configuration](#4-ksm-configuration)
5. [KSM Secret Rotation](#5-ksm-secret-rotation)
6. [Gateway](#6-gateway)
7. [Backoffice Admin Portal](#7-backoffice-admin-portal)
8. [Admin Account Management](#8-admin-account-management)
9. [User and Operator Account Management](#9-user-and-operator-account-management)
10. [Audit Log](#10-audit-log)
11. [Inspection Pipeline Configuration](#11-inspection-pipeline-configuration)
12. [Credential Handle Service (CHS)](#12-credential-handle-service-chs)
13. [SSO Integration](#13-sso-integration)
14. [Security Controls Reference](#14-security-controls-reference)
15. [Troubleshooting](#15-troubleshooting)

---

## 1. Product Overview

Yashigani is a security enforcement gateway for MCP (Model Context Protocol) servers and agentic AI systems. It sits inline between AI agents and the MCP servers they communicate with, applying prompt injection detection, credential exfiltration prevention, secrets management, and policy enforcement before any request reaches the upstream service.

**Problem statement.** AI agents operating against MCP servers represent an expanded attack surface: they can be vector for prompt injection attacks that attempt to leak credentials, override system instructions, or exfiltrate authentication material. Standard API gateways have no awareness of AI-specific threat patterns. Yashigani closes this gap.

**Core capabilities:**
- Reverse proxy with request inspection pipeline (prompt injection classification via local LLM)
- Credential Handle Service (CHS): opaque handles for raw credentials so secrets never traverse the inspection layer
- Policy enforcement via Open Policy Agent (OPA), always local, never cloud-delegated
- Key Secrets Manager (KSM) abstraction with five providers: Docker Secrets, Keeper, AWS, Azure, GCP
- Automated secret rotation with cron scheduling and retry logic
- Hybrid audit log: volume sink (always active) plus optional multi-SIEM forwarding
- Admin control plane (backoffice) with local auth: Argon2id passwords, RFC 6238 TOTP, Redis-backed sessions
- SSO integration: OIDC and SAMLv2, with mandatory TOTP provisioning for first-time SSO users

**Deployment targets:** Docker Compose (primary). Both services ship as multi-stage Python 3.12 container images. The gateway and backoffice are independent ASGI processes; they share a Redis instance and an audit log volume.

---

## 2. Architecture

### 2.1 Traffic Flow Diagram

```
                         ┌─────────────────────────────────────────────────┐
                         │                  GATEWAY (port 8080)            │
                         │                                                  │
  AI Agent  ──────────▶  │  1. Size check (max 4 MB)                       │
  (session                │  2. Identity extraction                         │
   cookie or              │     (yashigani_session cookie OR                │
   API key)               │      SHA-256(Authorization header)[:16])        │
                         │                                                  │
                         │  3. CHS pre-mask                                │
                         │     CredentialMasker applied to body            │
                         │     before classifier sees content              │
                         │                │                                │
                         │  4. Inspection pipeline                          │
                         │     PromptInjectionClassifier                    │
                         │     (Ollama / local LLM only)                   │
                         │         │                                        │
                         │         ├─ CLEAN ──────────────────────────────▶│
                         │         ├─ CREDENTIAL_EXFIL (CRITICAL)         │
                         │         │    confidence >= threshold:           │
                         │         │      sanitize → forward              │
                         │         │    confidence < threshold:            │
                         │         │      discard → return user_alert      │
                         │         └─ PROMPT_INJECTION_ONLY (HIGH)         │
                         │              always discard → return user_alert  │
                         │                                                  │
                         │  5. OPA policy check                             │
                         │     POST http://policy:8181/v1/data/yashigani/allow│
                         │     fail-closed on any OPA error                │
                         │         │                                        │
                         │         ├─ allow=true ──────────────────────────▶│
                         │         └─ allow=false → HTTP 403 POLICY_DENIED │
                         │                                                  │
                         │  6. Forward to upstream MCP server              │
                         │     X-Yashigani-Request-Id injected             │
                         │     X-Forwarded-For injected                    │
                         │     Hop-by-hop headers stripped                 │
                         │                                                  │
                         │  7. Audit event written for every request       │
                         └─────────────────────────────────────────────────┘
                                          │
                               Upstream MCP Server
                               (UPSTREAM_MCP_URL)


     ┌─────────────────────────────────────────────────────────────────────────┐
     │                      BACKOFFICE (port 8443)                            │
     │   Admin control plane — localhost only (never exposed externally)      │
     │   Auth: username + password (Argon2id) + TOTP (RFC 6238)              │
     │   Routes: /auth, /dashboard, /admin/accounts, /admin/users,           │
     │           /admin/kms, /admin/audit, /admin/inspection                 │
     └─────────────────────────────────────────────────────────────────────────┘

     ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌────────────┐
     │     OPA      │   │    Redis     │   │    Ollama    │   │    KSM     │
     │  port 8181   │   │  port 6379   │   │ port 11434   │   │ (provider) │
     │  (internal)  │   │  (internal)  │   │  (internal)  │   │            │
     └──────────────┘   └──────────────┘   └──────────────┘   └────────────┘
```

### 2.2 Component Map

| Component | Service | Port | Network |
|---|---|---|---|
| Gateway (data plane) | `gateway` | 8080 | internal + external |
| Backoffice (admin control plane) | `backoffice` | 8443 | internal only |
| OPA policy engine | `policy` | 8181 | internal only |
| Redis session + TOTP store | `redis` | 6379 | internal only |
| Ollama LLM inference | `ollama` | 11434 | internal only |

### 2.3 Network Isolation

The Docker Compose stack defines two networks:

- `internal` (bridge, `internal: true`): All services communicate on this network. No direct internet access.
- `external` (bridge): The gateway service only. Allows outbound connections to the upstream MCP server.

The backoffice is on the `internal` network exclusively. It is bound to `127.0.0.1:8443` by default via the `BACKOFFICE_PORT` variable, ensuring it cannot be reached from outside the host without explicit network configuration.

### 2.4 Redis Database Allocation

| Database | Service | Purpose |
|---|---|---|
| `/0` | gateway | Session store (gateway sessions) |
| `/1` | backoffice | Session store (admin sessions) |

---

## 3. Deployment

### 3.1 Docker Compose Quickstart

**Prerequisites:**
- Docker >= 24.0 with Compose v2
- Sufficient disk for the Ollama model (`qwen2.5:3b` is approximately 2 GB)

**Step 1. Clone the repository and enter the `docker/` directory context.**

```bash
cd yashigani
```

**Step 2. Copy the environment file and fill in required values.**

```bash
cp .env.example .env
```

Edit `.env`. At minimum, set:
- `UPSTREAM_MCP_URL` — URL of the MCP server Yashigani will proxy to
- `REDIS_PASSWORD` — Redis authentication password (change from default)

**Step 3. Create the secrets directory and populate the initial admin password.**

```bash
mkdir -p docker/secrets
# Write the initial admin password (minimum 36 characters)
echo "YourVeryLongInitialPassword1234!@#$%" > docker/secrets/admin_initial_password.txt
# For Keeper KSM, populate this file. Otherwise leave it empty.
touch docker/secrets/keeper_ksm_token.txt
chmod 600 docker/secrets/admin_initial_password.txt docker/secrets/keeper_ksm_token.txt
```

**Step 4. Create the audit data directory.**

```bash
mkdir -p data/audit
```

**Step 5. Build and start the stack.**

```bash
docker compose -f docker/docker-compose.yml up -d --build
```

**Step 6. Wait for Ollama to pull the model.** The `ollama-init` one-shot container will pull the model configured in `OLLAMA_MODEL`. This runs once and exits. Check progress:

```bash
docker compose -f docker/docker-compose.yml logs -f ollama-init
```

**Step 7. Verify health.**

```bash
# Gateway
curl -sf http://localhost:8080/healthz

# Backoffice (from host only)
curl -sf http://127.0.0.1:8443/dashboard/health \
  -H "Cookie: yashigani_admin_session=<token>"
```

The gateway responds with HTTP 200 on `/healthz`. The backoffice `/dashboard/health` endpoint requires an authenticated admin session.

### 3.2 Environment Variable Reference

All variables are read at container startup. Changes require a container restart.

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `YASHIGANI_ENV` | string | — | **Yes** | Environment scope label. Must be non-empty. Values: `production`, `staging`, `development`, `local`, `test`. Used as KSM scope prefix. |
| `YASHIGANI_VERSION` | string | `latest` | No | Docker image tag. |
| `GATEWAY_PORT` | string | `8080` | No | Host:port binding for the gateway. |
| `UPSTREAM_MCP_URL` | string | — | **Yes** | Full base URL of the upstream MCP server. Example: `http://my-mcp-server:8000`. Set as `YASHIGANI_UPSTREAM_URL` inside the gateway container. |
| `BACKOFFICE_PORT` | string | `127.0.0.1:8443` | No | Host binding for the backoffice. Default binds to localhost only. |
| `YASHIGANI_ADMIN_USERNAME` | string | `admin` | No | Username for the initial bootstrap admin account. |
| `YASHIGANI_ADMIN_PASSWORD` | string | — | See note | Initial admin password in plaintext. Used only if the Docker secret is not mounted. Minimum 36 characters. Set via Docker secret `admin_initial_password` in production. |
| `YASHIGANI_KSM_PROVIDER` | string | `keeper` (prod) / `docker` (dev) | No | KSM provider. Valid values: `docker`, `keeper`, `aws`, `azure`, `gcp`. Auto-selects `docker` when `YASHIGANI_ENV` is `dev`, `local`, or `test`. |
| `KSM_ROTATION_SECRET_KEY` | string | `` (disabled) | No | KSM key name to rotate automatically. Leave empty to disable rotation. |
| `KSM_ROTATION_CRON` | string | `0 3 * * *` | No | Standard 5-field cron expression for rotation schedule. Minimum interval: 1 hour. |
| `REDIS_PASSWORD` | string | `change_me_before_deploy` | **Yes** | Redis authentication password. Must be changed before production use. |
| `REDIS_URL` | string | `redis://localhost:6379/0` | No | Full Redis URL used by individual services. Automatically constructed in Compose from service names. |
| `OLLAMA_MODEL` | string | `qwen2.5:3b` | No | Ollama model tag for injection classification. Must be pulled before use. |
| `OLLAMA_BASE_URL` | string | `http://localhost:11434` | No | Ollama base URL. Set to `http://ollama:11434` in Compose. |
| `YASHIGANI_INJECT_THRESHOLD` | float | `0.85` | No | Confidence threshold (0.70–0.99) for attempting sanitization on `CREDENTIAL_EXFIL` detections. |
| `YASHIGANI_AUDIT_LOG_PATH` | string | `/var/log/yashigani/audit.log` | No | Volume path for the audit log file. Set to `/data/audit/audit.log` in Compose. |
| `YASHIGANI_AUDIT_MAX_FILE_SIZE_MB` | int | `100` | No | Maximum audit log file size in megabytes before rotation. |
| `YASHIGANI_AUDIT_RETENTION_DAYS` | int | `90` | No | Number of days to retain rotated audit log files. |
| `AUDIT_DATA_PATH` | string | `./data/audit` | No | Host path for the `audit_data` Docker volume bind mount. |
| `YASHIGANI_ADMIN_MIN_TOTAL` | int | `2` | No | Minimum total admin accounts. Delete operations blocked at this floor. |
| `YASHIGANI_ADMIN_MIN_ACTIVE` | int | `2` | No | Minimum active (non-disabled) admin accounts. Disable operations blocked at this floor. |
| `YASHIGANI_ADMIN_SOFT_TARGET` | int | `3` | No | Soft target for admin account count. Dashboard warns when below this value. |
| `YASHIGANI_USER_MIN_TOTAL` | int | `1` | No | Minimum total user/operator accounts. Delete blocked at this floor. |
| `YASHIGANI_OPA_URL` | string | `http://localhost:8181` | No | OPA base URL. Set to `http://policy:8181` in Compose. |

**Provider-specific environment variables** are documented in [Section 4 — KSM Configuration](#4-ksm-configuration).

### 3.3 Docker Secrets

Docker secrets are mounted read-only into containers at `/run/secrets/<name>`.

| Secret name | File | Used by | Purpose |
|---|---|---|---|
| `admin_initial_password` | `docker/secrets/admin_initial_password.txt` | `backoffice` | Initial admin account password (plaintext, minimum 36 chars). Read once at bootstrap. |
| `keeper_ksm_token` | `docker/secrets/keeper_ksm_token.txt` | `gateway`, `backoffice` | Keeper KSM one-time access token. Read at provider initialization. |

The backoffice reads `admin_initial_password` from `/run/secrets/admin_initial_password`. If the file is absent, the code falls back to the `YASHIGANI_ADMIN_PASSWORD` environment variable. In production, always use the Docker secret; do not set the environment variable.

The Keeper provider reads `KSM_KEEPER_ONE_TIME_TOKEN` from `/run/secrets/KSM_KEEPER_ONE_TIME_TOKEN`. The lookup order is: Docker secret file first, then the environment variable of the same name.

### 3.4 First-Run Bootstrap

On backoffice container startup, the `_bootstrap()` function in `backoffice/entrypoint.py` executes before the ASGI app is created. It checks whether any accounts exist in the `LocalAuthService._accounts` dict. If the store is empty, it creates the initial admin account as follows:

1. Reads the password from `/run/secrets/admin_initial_password` (Docker secret, preferred).
2. Falls back to the `YASHIGANI_ADMIN_PASSWORD` environment variable.
3. If neither is set, logs a warning and skips bootstrap. No account is created. The backoffice will be inaccessible until an account is created via direct service configuration.

The bootstrap account is created with:
- Username: value of `YASHIGANI_ADMIN_USERNAME` (default: `admin`)
- Password: the value read from secret/env (minimum 36 characters enforced by `hash_password`)
- `force_password_change: True` — admin must change password on first login
- `force_totp_provision: True` — admin must provision TOTP on first login

**The initial plaintext password is never logged.** After bootstrap, the secret file should be deleted or rotated. The admin must complete password change and TOTP provisioning before the backoffice is fully operational.

---

## 4. KSM Configuration

The KSM subsystem provides a uniform interface for secrets retrieval, creation, rotation, and revocation across five providers. The active provider is selected at startup via `YASHIGANI_KSM_PROVIDER`.

**Scope enforcement.** Every provider enforces an optional key scope prefix. Keys may be prefixed as `<scope>/<name>` (e.g., `production/db-password`). If a key contains a `/` prefix that does not match the provider's `environment_scope` (set from `YASHIGANI_ENV`), a `ScopeViolationError` is raised and the operation is denied. Keys without a `/` prefix are not scope-checked.

### 4.1 Docker Secrets Provider

**Value:** `YASHIGANI_KSM_PROVIDER=docker`

**Auth method:** Filesystem read. Secrets are mounted by Docker or Podman at container start time from `/run/secrets/`.

**Required env vars:** None beyond `YASHIGANI_ENV`.

**Optional env vars:** None.

**Scope enforcement:** Active. The scope prefix is stripped for filesystem lookup. The key `production/db-password` resolves to `/run/secrets/db-password`.

**Limitations:**
- Read-only. `set_secret`, `rotate_secret`, `revoke_token`, and `delete_secret` all raise `ProviderError`.
- `list_secrets` returns metadata from directory listing. Version is always `docker-static`.
- Intended for local, development, and demo deployments only. Not suitable for production rotation workflows.

**Path traversal protection:** The provider rejects any key whose filename component contains `..`, `/`, or `\`.

### 4.2 Keeper Secrets Manager Provider

**Value:** `YASHIGANI_KSM_PROVIDER=keeper`

**Auth method:** One-time access token. On first use, the token is exchanged for application credentials stored in an `InMemoryKeyValueStorage`. The token is consumed and should not be reused.

**Required env vars / secrets:**
- Docker secret `/run/secrets/KSM_KEEPER_ONE_TIME_TOKEN` (preferred), or
- Environment variable `KSM_KEEPER_ONE_TIME_TOKEN`

**Optional dependency:** `keeper-secrets-manager-core>=16` (installed via `pip install 'yashigani[keeper]'`).

**Scope enforcement:** Active.

**Behavior:**
- `get_secret`: Retrieves the `password` field, then `text` field, from the Keeper record.
- `set_secret`: Updates existing records only. New record creation is not supported via the SDK; records must be created in Keeper Vault manually before they can be set programmatically.
- `rotate_secret`: Calls `set_secret` internally. Returns version string `keeper-rotated-<key>`.
- `delete_secret`: Not supported via SDK. Raises `ProviderError`. Deletion must be performed in Keeper Vault manually.

### 4.3 AWS Secrets Manager Provider

**Value:** `YASHIGANI_KSM_PROVIDER=aws`

**Auth method:** IAM role (preferred — no credentials in environment). Falls back to explicit key/secret if both `KSM_AWS_ACCESS_KEY_ID` and `KSM_AWS_SECRET_ACCESS_KEY` are set.

**Required env vars:**
- `KSM_AWS_REGION` — AWS region. Defaults to `us-east-1`.
- `KSM_AWS_SECRET_ARN_PREFIX` — Optional ARN prefix prepended to key names. Leave empty if secret names are used directly.

**Optional env vars:**
- `KSM_AWS_ACCESS_KEY_ID` — AWS access key ID (avoid in production; prefer IAM role).
- `KSM_AWS_SECRET_ACCESS_KEY` — AWS secret access key (avoid in production).

**Optional dependency:** `boto3>=1.34` (installed via `pip install 'yashigani[aws]'`).

**Scope enforcement:** Active. The scope prefix is stripped before constructing the ARN.

**Behavior:**
- `set_secret`: Attempts `put_secret_value` first; creates the secret if it does not exist (`ResourceNotFoundException`).
- `delete_secret`: Soft delete via `ForceDeleteWithoutRecovery=False`. AWS recovery window applies.
- `rotate_secret`: Calls `set_secret` and returns the latest version ID from `describe_secret`.

### 4.4 Azure Key Vault Provider

**Value:** `YASHIGANI_KSM_PROVIDER=azure`

**Auth method:** Managed identity (`DefaultAzureCredential`) by default. Falls back to service principal if all three of `KSM_AZURE_TENANT_ID`, `KSM_AZURE_CLIENT_ID`, and `KSM_AZURE_CLIENT_SECRET` are set.

**Required env vars:**
- `KSM_AZURE_VAULT_URL` — Full URL of the Azure Key Vault. Example: `https://my-vault.vault.azure.net/`. Raises `KeyError` if absent.

**Optional env vars:**
- `KSM_AZURE_TENANT_ID` — Azure AD tenant ID (for service principal auth).
- `KSM_AZURE_CLIENT_ID` — Service principal client ID.
- `KSM_AZURE_CLIENT_SECRET` — Service principal client secret.

**Optional dependency:** `azure-keyvault-secrets>=4.8` and `azure-identity>=1.16` (installed via `pip install 'yashigani[azure]'`).

**Scope enforcement:** Active. Key name translation: underscores (`_`) are replaced with hyphens (`-`) to conform to Azure Key Vault naming constraints.

**Behavior:**
- `rotate_secret`: Calls `set_secret` and returns the secret version from `get_secret` properties.
- `delete_secret`: Initiates an async deletion via `begin_delete_secret` and waits for completion.

### 4.5 GCP Secret Manager Provider

**Value:** `YASHIGANI_KSM_PROVIDER=gcp`

**Auth method:** Workload identity (preferred). Falls back to service account key file if `KSM_GCP_CREDENTIALS_FILE` is set.

**Required env vars:**
- `KSM_GCP_PROJECT_ID` — GCP project ID. Raises `KeyError` if absent.

**Optional env vars:**
- `KSM_GCP_CREDENTIALS_FILE` — Path to a service account JSON key file. If set, the value is assigned to `GOOGLE_APPLICATION_CREDENTIALS`.

**Optional dependency:** `google-cloud-secret-manager>=2.20` (installed via `pip install 'yashigani[gcp]'`).

**Scope enforcement:** Active.

**Behavior:**
- `get_secret`: Accesses the `latest` version of the secret.
- `set_secret`: Adds a new secret version. Creates the secret with automatic replication if it does not exist.
- `rotate_secret`: Calls `set_secret` and returns version string `gcp-rotated-<key>`.

---

## 5. KSM Secret Rotation

### 5.1 Automatic Rotation (Cron)

Rotation is activated by setting `KSM_ROTATION_SECRET_KEY` to a non-empty value. The `KSMRotationScheduler` is instantiated and started during backoffice bootstrap.

**Configuration:**

| Variable | Default | Description |
|---|---|---|
| `KSM_ROTATION_SECRET_KEY` | `` (disabled) | KSM key to rotate on schedule. Empty value disables rotation. |
| `KSM_ROTATION_CRON` | `0 3 * * *` | 5-field cron expression. Must fire at most once per hour. |

**Cron validation.** Before the scheduler starts, the cron expression is validated in two steps:
1. It is parsed by APScheduler's `CronTrigger.from_crontab`. Invalid expressions raise `ValueError`.
2. The interval between two consecutive fires is computed. If the interval is less than 1 hour (3600 seconds), a `ValueError` is raised. This minimum interval is a hard enforcement — it cannot be overridden via configuration.

**Rotation procedure.** At each scheduled fire:
1. A new 64-character hex secret is generated via `secrets.token_hex(32)`.
2. `provider.rotate_secret(key, new_value)` is called.
3. Immediately after, `provider.get_secret(key)` is called and the retrieved value is compared to `new_value`. If they do not match, a `RotationError` is raised (post-rotation validation failure).
4. On success, a `KSM_ROTATION_SUCCESS` audit event is written.
5. The plaintext new value is deleted from local scope in the `finally` block.

**Concurrency protection.** The rotation procedure acquires a threading lock (`threading.Lock`). If a rotation is already in progress when a new schedule fire arrives, the new fire is skipped with a warning log.

### 5.2 Retry Behaviour

Failed rotations are retried up to 3 times. Retry delays: 300 seconds, 300 seconds, 300 seconds (5 minutes each). After all retries are exhausted:
- A `KSM_ROTATION_CRITICAL` audit event is written.
- The `on_event` callback is called with `outcome="critical"`.
- The error is logged at `ERROR` level.

Rotation failures also write a `KSM_ROTATION_FAILURE` audit event for each failed attempt.

### 5.3 Manual Rotation Trigger

Manual rotation is triggered via the backoffice API:

```
POST /admin/kms/rotate-now
```

This calls `scheduler.trigger_now()`, which calls `_rotate(rotation_type="manual")` directly (not through the cron scheduler). Manual rotations use the same retry logic as scheduled rotations. The manual trigger is audit-logged as `setting=kms_manual_rotation`.

### 5.4 Updating the Schedule

The rotation schedule can be updated at runtime via the API without restarting the service:

```
POST /admin/kms/schedule
Body: {"cron_expr": "0 2 * * *"}
```

The new expression is validated against the 1-hour minimum interval before being accepted. The running APScheduler job is rescheduled immediately. The change is audit-logged.

### 5.5 Minimum Interval Enforcement

The 1-hour minimum interval is enforced both at initial startup and on every schedule update via the `/admin/kms/schedule` endpoint. A cron expression that would fire more frequently than every 3600 seconds is rejected with HTTP 422 and `error: invalid_cron_expression`.

---

## 6. Gateway

### 6.1 Request Inspection Pipeline

Every inbound request with a non-empty body passes through the following pipeline stages:

```
Inbound request body (bytes)
        │
        ▼
[1] UTF-8 decode (binary bodies skip inspection — passed through as-is)
        │
        ▼
[2] CredentialMasker.mask_string()
    Applies regex patterns sequentially to mask credentials
    before the content reaches the classifier model
        │
        ▼
[3] PromptInjectionClassifier.classify(masked_content)
    POST to Ollama /api/chat (local only)
    Returns: label, confidence, exfil_indicators, detected_payload_spans
        │
        ├─── CLEAN ──────────────────────────────────────────────────────▶ [5]
        │
        ├─── CREDENTIAL_EXFIL
        │       confidence >= threshold? YES → sanitize()
        │         sanitization success AND tokens_remaining >= 3?
        │           YES → action=SANITIZED, forward clean_query      ──▶ [4]
        │           NO  → action=DISCARDED, return user_alert        ──▶ end
        │       confidence < threshold → action=DISCARDED            ──▶ end
        │
        └─── PROMPT_INJECTION_ONLY
                always → action=DISCARDED, return user_alert         ──▶ end
        │
        ▼ (CLEAN or SANITIZED path)
[4] Forwarded body (original or sanitized)
        │
        ▼
[5] OPA policy check
    POST http://policy:8181/v1/data/yashigani/allow
    Input: method, path, session_id, agent_id, user_id, headers
    allow=true  → proceed
    allow=false → HTTP 403 POLICY_DENIED
    any error   → deny (fail-closed)
        │
        ▼
[6] Forward to upstream MCP server
    httpx.AsyncClient with base_url=UPSTREAM_MCP_URL
    Headers injected: X-Yashigani-Request-Id, X-Forwarded-For
    Hop-by-hop headers stripped
        │
        ▼
[7] Upstream response returned to caller
    X-Yashigani-Request-Id added to response headers
        │
        ▼
[8] Audit event written (GatewayRequestEvent) for every request
    action: FORWARDED | DISCARDED | DENIED | BLOCKED
```

**Note:** The classifier receives the masked query (credentials replaced by `[REDACTED:*]` tokens). The raw query is never sent to the model and is never logged (`raw_query_logged` is hardcoded to `False`).

### 6.2 Two-Tier Detection

The inspection pipeline produces two distinct threat classifications with different severity levels and response actions.

**CREDENTIAL_EXFIL — Severity: CRITICAL**

Triggered when the classifier identifies both a prompt injection payload and instructions to exfiltrate credentials, tokens, API keys, passwords, or other authentication material.

Response logic:
- If `confidence >= YASHIGANI_INJECT_THRESHOLD` (default 0.85): attempt sanitization via `sanitize()`. If sanitization produces a clean query with 3 or more whitespace-delimited tokens, forward the sanitized version (`action=SANITIZED`). Otherwise, discard.
- If `confidence < threshold`: discard without attempting sanitization (`action=DISCARDED`).

Admin alert payload: `alert_type=CREDENTIAL_EXFIL_DETECTED`, `severity=CRITICAL`.
User alert payload: `code=QUERY_MODIFIED` (if sanitized) or `code=QUERY_DISCARDED`.

**PROMPT_INJECTION_ONLY — Severity: HIGH**

Triggered when the classifier identifies a prompt injection payload (instructions to override the system prompt, ignore instructions, impersonate another AI, etc.) but no credential exfiltration instructions.

Response logic: Always discard. No sanitization attempt is made.

Admin alert payload: `alert_type=PROMPT_INJECTION_DETECTED`, `severity=HIGH`.
User alert payload: `code=QUERY_DISCARDED`, `message="Your query was not processed due to a policy violation."`.

Both tiers:
- Write a `PROMPT_INJECTION_DETECTED` audit event.
- Set `admin_alerted=True` and `user_alerted=True` in the audit record.
- Never log the raw query (`raw_query_logged=False` — invariant in the schema).
- Return HTTP 200 to the caller with the user alert JSON body (the discard is transparent at the HTTP level).

### 6.3 Sanitization: Span Excision

When the classifier returns `CREDENTIAL_EXFIL` with confidence at or above threshold, the sanitizer attempts to reconstruct a usable query by excising the detected payload spans.

**Algorithm (from `inspection/sanitizer.py`):**

1. Validate spans: each span must have `start >= 0`, `end <= len(text)`, and `start < end`. Invalid spans raise `ValueError`.
2. Sort spans by start offset.
3. Merge overlapping or adjacent spans into a minimal set.
4. Remove spans from the text in descending order (right to left) to preserve character offsets.
5. Collapse multiple whitespace characters into a single space and strip leading/trailing whitespace.
6. Count whitespace-delimited tokens in the result.
7. **Discard threshold:** If the token count is less than 3 (`_MIN_CLEAN_TOKENS = 3`), the sanitizer returns `success=False` and `clean_query=None`. The pipeline then discards the request rather than forwarding an effectively empty body.

Any exception during sanitization results in `success=False` and a discard decision. The sanitizer never raises.

### 6.4 OPA Policy

The default policy in `policy/yashigani.rego` enforces the following rules:

**Default:** `deny` (all requests denied unless explicitly allowed).

**Allow condition:** All of the following must be true:
- `input.session_id` is non-empty and not `"anonymous"`
- `input.agent_id` is non-empty and not `"unknown"`
- `input.method` is in `{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}`
- The path does not match any blocked pattern

**Blocked paths:**
- Any path starting with `/admin`
- Any path starting with `/.well-known/internal`
- Exactly `/metrics`
- Exactly `/healthz`

**Fail-closed:** If OPA is unreachable or returns an HTTP error, the gateway denies the request (returns HTTP 403 `POLICY_DENIED`) and logs the error. OPA is never cloud-delegated.

**Extending the policy.** Add new Rego rules to `policy/yashigani.rego`. The OPA container mounts the `../policy` directory read-only at `/policies`. Changes take effect after the OPA container is restarted. The package namespace is `yashigani` and the decision is read from `/v1/data/yashigani/allow`.

Example: restrict traffic to a known set of agent IDs by adding an external data file:

```rego
# In policy/yashigani.rego
allow if {
    input.session_id != ""
    input.session_id != "anonymous"
    input.agent_id in data.yashigani.allowed_agents
    input.method in allowed_methods
    not path_blocked
}
```

Then provide `policy/data.json`:
```json
{
  "yashigani": {
    "allowed_agents": ["agent-001", "agent-002"]
  }
}
```

### 6.5 Request and Response Headers

**Headers injected by the gateway into upstream requests:**

| Header | Value |
|---|---|
| `X-Yashigani-Request-Id` | UUID v4 generated per request |
| `X-Forwarded-For` | Client IP (first value from existing `X-Forwarded-For`, or `request.client.host`) |

**Headers stripped from upstream requests before forwarding** (hop-by-hop headers):
`Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailers`, `Transfer-Encoding`, `Upgrade`, `Host`

**Headers injected into responses to callers:**

| Header | Value |
|---|---|
| `X-Yashigani-Request-Id` | Same UUID as injected upstream |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |

**Headers stripped from upstream responses before passing to callers:** Same hop-by-hop set as above.

**Headers explicitly excluded from the OPA input document:**
`Authorization` and `Cookie` are never forwarded to OPA.

**Request identity headers read by the gateway:**

| Header | Purpose |
|---|---|
| `Cookie: yashigani_session` | Primary session identification |
| `Authorization` | API key or Bearer token (hashed to derive session_id if no cookie) |
| `X-Yashigani-Agent-Id` | Identifies the AI agent making the request (passed to OPA and audit) |
| `X-Yashigani-User-Id` | Identifies the end-user (passed to audit) |

---

## 7. Backoffice Admin Portal

The backoffice is a FastAPI application bound to port 8443. It serves as the administrative control plane for all Yashigani configuration. It has no access to the data plane (gateway traffic) other than sharing the audit log volume and Redis instance.

Security headers applied to all backoffice responses:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Content-Security-Policy: default-src 'self'`
- `Referrer-Policy: no-referrer`

Swagger UI, ReDoc, and the OpenAPI schema endpoint are all disabled in production.

CORS: no cross-origin requests are permitted (`allow_origins=[]`).

All routes except `/auth/login` require a valid admin session cookie (`yashigani_admin_session`). The middleware verifies `account_tier == "admin"` to prevent cross-tier access.

### 7.1 Authentication: Login Flow

**Endpoint:** `POST /auth/login`

**Request body:**
```json
{
  "username": "admin",
  "password": "<password>",
  "totp_code": "123456"
}
```

**Field constraints:**
- `username`: 1–64 characters
- `password`: minimum 1 character (hashing enforces the 36-character minimum)
- `totp_code`: exactly 6 digits (`^\d{6}$`)

**Authentication sequence:**
1. Account lookup by username.
2. Lockout check: if `failed_attempts >= 5`, account is locked for 30 minutes (`locked_until = now + 1800`). The same generic error `invalid_credentials` is returned for unknown user, wrong password, and locked account to prevent username enumeration (ASVS V2.1).
3. Argon2id password verification (`time_cost=3`, `memory_cost=65536`, `parallelism=4`).
4. If `force_totp_provision=True`: authentication succeeds with reason `totp_provision_required`. The response includes `"force_totp_provision": true`. The caller must redirect to TOTP provisioning before a full session is useful.
5. TOTP verification with replay prevention. The window key `<secret_b32>:<unix_time // 30>` is checked against an in-process used-codes cache. Valid window is ±1 step (30 seconds each side).

**Success response:**
```json
{
  "status": "ok",
  "force_password_change": false,
  "force_totp_provision": false
}
```

**Session cookie:** Set on the response with `HttpOnly=true`, `Secure=true`, `SameSite=Strict`, `max-age=14400` (4 hours), `path=/`.

**Concurrent session handling:** Creating a new session invalidates all existing sessions for the same account (ASVS V3 — no concurrent sessions).

**Session timeouts:**
- Idle timeout: 15 minutes (`_IDLE_TIMEOUT_SECONDS = 900`). `last_active_at` is updated on every authenticated request.
- Absolute timeout: 4 hours (`_ABSOLUTE_TIMEOUT_SECONDS = 14400`).

**Failure response:** HTTP 401 with `{"error": "invalid_credentials"}` for all failure cases.

### 7.2 Forced Changes on First Login

The login response includes two flags that indicate required follow-up actions:

- `force_password_change: true` — The admin must call `POST /auth/password/change` before the account is fully operational.
- `force_totp_provision: true` — The admin must complete TOTP provisioning via `POST /auth/totp/provision`.

Both flags are set to `true` on newly created accounts. They are independent: an account may require one or both changes.

**Password change (`POST /auth/password/change`):**

Request body:
```json
{
  "current_password": "<current>",
  "new_password": "<new password, minimum 36 chars>"
}
```

On success: ALL sessions for the account are invalidated including the current session. The session cookie is cleared. The caller must re-authenticate. Response: `{"status": "ok", "sessions_invalidated": true, "re_authentication_required": true}`.

### 7.3 TOTP Provisioning Flow

**Endpoint:** `POST /auth/totp/provision`

This endpoint requires an active admin session. It should be called when `force_totp_provision=true` is returned from login.

**Request body:**
```json
{
  "totp_code": "123456"
}
```

**Flow:**
1. A new TOTP secret is generated (`pyotp.random_base32()`).
2. A provisioning URI (`otpauth://totp/...`) and a base64-encoded PNG QR code are generated.
3. Eight recovery codes are generated in format `XXXX-XXXX-XXXX` (3 groups of 4 uppercase hex digits).
4. The recovery codes are hashed with Argon2id and stored. The plaintext codes are included in the response once.
5. The submitted `totp_code` is verified against the newly generated secret. If verification fails: the secret and recovery codes are cleared from the account record, `force_totp_provision` is reset to `True`, and HTTP 400 is returned with `error: invalid_totp_code`.
6. On success: `force_totp_provision` is set to `False`. A `TOTP_PROVISION_COMPLETED` audit event is written.

**Success response:**
```json
{
  "status": "ok",
  "qr_code_png_b64": "<base64 PNG>",
  "provisioning_uri": "otpauth://totp/Yashigani:admin?...",
  "recovery_codes": ["ABCD-EF01-2345", "..."],
  "recovery_codes_count": 8,
  "message": "Store these recovery codes securely. They will not be shown again."
}
```

The QR code and recovery codes are displayed once. Yashigani does not store the plaintext recovery codes after this response is sent. The admin must store them in a secure location.

### 7.4 API Endpoint Reference

All endpoints require an authenticated admin session (`yashigani_admin_session` cookie, `account_tier=admin`) unless otherwise noted.

#### Authentication Routes (`/auth`)

| Method | Path | Auth Required | Description |
|---|---|---|---|
| POST | `/auth/login` | No | Authenticate with username + password + TOTP. Returns session cookie. |
| POST | `/auth/logout` | Yes | Invalidate current session and clear cookie. |
| GET | `/auth/status` | Yes | Return `account_id`, `account_tier`, `expires_at` for current session. |
| POST | `/auth/password/change` | Yes | Change password. Invalidates all sessions. |
| POST | `/auth/totp/provision` | Yes | Provision TOTP. Returns QR code and 8 recovery codes (shown once). |

#### Dashboard Routes (`/dashboard`)

| Method | Path | Description |
|---|---|---|
| GET | `/dashboard/health` | Aggregate health across KMS, rotation scheduler, inspection, Redis, resource monitor, audit, auth. Returns `status: ok/degraded/critical`. |
| GET | `/dashboard/resources` | Resource pressure index, TTL tier, memory pressure, CPU throttle ratio, metrics source. |
| GET | `/dashboard/alerts` | Recent admin alerts from in-memory ring buffer (last 200). Query param: `limit` (1–200, default 50). |

#### Admin Account Routes (`/admin/accounts`)

| Method | Path | Request Body | Response | Guards |
|---|---|---|---|---|
| GET | `/admin/accounts` | — | Account list with totals, minimums, soft target. | Admin session |
| POST | `/admin/accounts` | `{username, password (min 36)}` | `{status, account_id, username}` | Admin session |
| DELETE | `/admin/accounts/{username}` | — | `{status: ok}` | Admin session. HTTP 409 `ADMIN_MINIMUM_VIOLATION` if total would drop below `admin_min_total`. |
| POST | `/admin/accounts/{username}/disable` | — | `{status: ok}` | Admin session. HTTP 409 `ADMIN_ACTIVE_MINIMUM_VIOLATION` if active count would drop below `admin_min_active`. |
| POST | `/admin/accounts/{username}/enable` | — | `{status: ok}` | Admin session |
| POST | `/admin/accounts/{username}/force-reset` | `{action: "password_reset" or "totp_reprovision"}` | `{status: ok}` | Admin session. Invalidates all sessions for target. |

#### User Account Routes (`/admin/users`)

| Method | Path | Request Body | Response | Guards |
|---|---|---|---|---|
| GET | `/admin/users` | — | User list with totals and minimum. | Admin session |
| POST | `/admin/users` | `{username, password (min 36)}` | `{status, account_id}` | Admin session |
| DELETE | `/admin/users/{username}` | — | `{status: ok}` | Admin session. HTTP 409 `USER_MINIMUM_VIOLATION` if last user. |
| POST | `/admin/users/{username}/full-reset` | `{totp_code}` | `{status: ok}` | Admin session + admin TOTP re-verification. HTTP 403 `invalid_admin_totp` on failure. |
| POST | `/admin/users/{username}/disable` | — | `{status: ok}` | Admin session |
| POST | `/admin/users/{username}/enable` | — | `{status: ok}` | Admin session |

#### KSM Routes (`/admin/kms`)

| Method | Path | Request Body | Response | Guards |
|---|---|---|---|---|
| GET | `/admin/kms/status` | — | Provider name, scope, health status. | Admin session |
| GET | `/admin/kms/schedule` | — | `{configured, cron_expr, secret_key (redacted), running}` | Admin session |
| POST | `/admin/kms/schedule` | `{cron_expr}` | `{status, cron_expr}` | Admin session. HTTP 422 if interval < 1 hour or invalid expression. |
| POST | `/admin/kms/rotate-now` | — | `{status, message}` | Admin session. HTTP 503 if scheduler not configured. |
| GET | `/admin/kms/secrets` | — | `{secrets: [...metadata], total}` | Admin session. Secret values are never returned. |

#### Audit Routes (`/admin/audit`)

| Method | Path | Description |
|---|---|---|
| GET | `/admin/audit/export` | Stream audit log. Query params: `output_format` (`ndjson` or `csv`), `date_from` (ISO 8601 prefix), `date_to` (ISO 8601 prefix). Streaming response, never buffered in memory. |
| GET | `/admin/audit/masking/scope` | Return current masking scope configuration. |
| PUT | `/admin/audit/masking/scope` | `{mask_all_by_default: bool}` — Update global masking default. |
| POST | `/admin/audit/masking/scope/agent` | `{agent_id, mask: bool}` — Set per-agent masking override. |
| DELETE | `/admin/audit/masking/scope/agent/{agent_id}` | Remove per-agent override. HTTP 404 if not found. |
| POST | `/admin/audit/masking/scope/user` | `{user_handle, mask: bool}` — Set per-user masking override. |
| DELETE | `/admin/audit/masking/scope/user/{handle}` | Remove per-user override. |
| POST | `/admin/audit/masking/scope/component` | `{component, mask: bool}` — Set per-component masking override. |
| DELETE | `/admin/audit/masking/scope/component/{component}` | Remove per-component override. |
| GET | `/admin/audit/siem` | List SIEM targets. `auth_value` is never returned. |
| POST | `/admin/audit/siem` | `{name, target_type, url, auth_header, auth_value, enabled}` — Add SIEM target. HTTP 409 if name taken. |
| DELETE | `/admin/audit/siem/{name}` | Remove a SIEM target. HTTP 404 if not found. |
| POST | `/admin/audit/siem/{name}/test` | Send synthetic test event to SIEM target. HTTP 502 on delivery failure. |

#### Inspection Routes (`/admin/inspection`)

| Method | Path | Description |
|---|---|---|
| GET | `/admin/inspection/status` | Pipeline health, active model, threshold, mode, available Ollama models. |
| GET | `/admin/inspection/models` | List all model tags available in the local Ollama instance. |
| POST | `/admin/inspection/model` | `{model}` — Switch active classifier model. HTTP 422 if model not in Ollama. |
| GET | `/admin/inspection/threshold` | Return current threshold value. |
| POST | `/admin/inspection/threshold` | `{threshold: float}` (0.70–0.99) — Update threshold. |
| GET | `/admin/inspection/mode` | Return current mode (`strict` or `permissive`). |
| POST | `/admin/inspection/mode` | `{mode: "strict" or "permissive"}` — Update mode. |

---

## 8. Admin Account Management

### 8.1 Minimum Counts

The backoffice enforces minimum admin account counts as a safety mechanism to prevent accidental lockout. These limits are configurable via environment variables but cannot be set below the defaults.

| Variable | Default | Enforced at |
|---|---|---|
| `YASHIGANI_ADMIN_MIN_TOTAL` | `2` | `DELETE /admin/accounts/{username}` |
| `YASHIGANI_ADMIN_MIN_ACTIVE` | `2` | `POST /admin/accounts/{username}/disable` |
| `YASHIGANI_ADMIN_SOFT_TARGET` | `3` | Dashboard warning (`below_soft_target: true`) |

### 8.2 ADMIN_MINIMUM_VIOLATION

**Error code:** `ADMIN_MINIMUM_VIOLATION`
**HTTP status:** 409 Conflict
**Trigger:** `DELETE /admin/accounts/{username}` when `total_admin_count() <= admin_min_total`

Response body:
```json
{
  "error": "ADMIN_MINIMUM_VIOLATION",
  "message": "Cannot delete: minimum 2 admin accounts required"
}
```

### 8.3 ADMIN_ACTIVE_MINIMUM_VIOLATION

**Error code:** `ADMIN_ACTIVE_MINIMUM_VIOLATION`
**HTTP status:** 409 Conflict
**Trigger:** `POST /admin/accounts/{username}/disable` when `active_admin_count() <= admin_min_active`

Response body:
```json
{
  "error": "ADMIN_ACTIVE_MINIMUM_VIOLATION",
  "message": "Cannot disable: minimum 2 active admin accounts required"
}
```

### 8.4 Soft Target Warning

The `GET /admin/accounts` response includes `"below_soft_target": true` when `total_admin_count() < admin_soft_target`. This is a dashboard warning, not a blocking enforcement. The recommended practice is to maintain at least 3 admin accounts to allow for one account to be offline or under reset at any time.

### 8.5 Force Reset

An admin can force a password reset or TOTP re-provisioning for any other admin account via `POST /admin/accounts/{username}/force-reset`. This:
- Sets `force_password_change=True` (for `password_reset` action) or clears the TOTP secret and recovery codes and sets `force_totp_provision=True` (for `totp_reprovision`).
- Invalidates all sessions for the target account.
- Writes a `CONFIG_CHANGED` audit event.

No TOTP re-verification of the acting admin is required for admin-to-admin force reset (unlike user full-reset which requires TOTP verification).

---

## 9. User and Operator Account Management

### 9.1 Minimum Count

| Variable | Default | Enforced at |
|---|---|---|
| `YASHIGANI_USER_MIN_TOTAL` | `1` | `DELETE /admin/users/{username}` |

### 9.2 USER_MINIMUM_VIOLATION

**Error code:** `USER_MINIMUM_VIOLATION`
**HTTP status:** 409 Conflict
**Trigger:** `DELETE /admin/users/{username}` when `total_user_count() <= user_min_total`

Response body:
```json
{
  "error": "USER_MINIMUM_VIOLATION",
  "message": "Cannot delete the last user account"
}
```

### 9.3 Full Reset

**Endpoint:** `POST /admin/users/{username}/full-reset`

Full reset is a destructive action that strips all access from a user account. It requires admin TOTP re-verification (ASVS V2.8 — re-authentication required for sensitive operations). This verification is server-side enforced in the route handler, not just at the UI level.

**TOTP failure path:** If the admin's TOTP code is invalid, HTTP 403 is returned with `error: invalid_admin_totp`. A `FULL_RESET_TOTP_FAILURE` audit event is written with `failure_reason="invalid"`.

**On successful reset, the following is cleared:**
- TOTP secret
- Recovery codes
- `force_password_change` set to `True`
- `force_totp_provision` set to `True`
- `failed_attempts` reset to `0`
- `locked_until` reset to `0.0`
- Password reset to a new auto-generated 36-character temporary password

**What is retained:**
- Username
- Account UUID (`account_id`)
- Audit history (events are immutable in the volume sink)

**Post-reset:** All active sessions for the user are invalidated. A `USER_FULL_RESET` audit event is written with `admin_totp_verified=True`.

---

## 10. Audit Log

### 10.1 Volume Sink

The volume sink is always active and cannot be disabled. It writes newline-delimited JSON (NDJSON) records to a file on a mounted volume.

**Configuration:**

| Variable | Default | Description |
|---|---|---|
| `YASHIGANI_AUDIT_LOG_PATH` | `/var/log/yashigani/audit.log` | Absolute path to the active log file. Set to `/data/audit/audit.log` in Compose. |
| `YASHIGANI_AUDIT_MAX_FILE_SIZE_MB` | `100` | Maximum file size in MB before rotation. |
| `YASHIGANI_AUDIT_RETENTION_DAYS` | `90` | Number of days to retain rotated log files. |

**Rotation:** When the active log file reaches `max_file_size_mb`, it is renamed to `audit.log.<YYYYMMDD-HHMMSS>` (UTC timestamp) and a new `audit.log` file is opened. Rotated files older than `retention_days` are deleted automatically on the next rotation trigger. The glob pattern for rotated files is `audit.log.*`.

**Write behaviour:** The `AuditLogWriter.write()` call holds a threading lock for the volume write. If the write fails (`OSError`), `AuditWriteError` is raised and propagates to the caller. Callers are required to abort their operation on `AuditWriteError`.

**Line buffering:** The log file is opened with `buffering=1` (line-buffered). Each record is flushed immediately after write.

### 10.2 SIEM Forwarding

SIEM forwarding is optional, failure-tolerant, and fire-and-forget. Delivery failure never blocks the volume write or the triggering operation.

Three target types are supported:

**`webhook`:** Posts the raw NDJSON record with `Content-Type: application/json`.

**`splunk_hec`:** Wraps the event in a Splunk HEC envelope: `{"time": <unix>, "event": <event_dict>, "sourcetype": "yashigani"}`. Posts with `Content-Type: application/json`.

**`elastic_opensearch`:** Posts a bulk index request with NDJSON format: `{"index": {"_index": "yashigani-audit"}}\n<event_json>\n`. Posts with `Content-Type: application/x-ndjson`.

**SIEM delivery retry:** Three attempts with delays of 1 second, 5 seconds, and 25 seconds between attempts. After all retries are exhausted, a `SIEM_DELIVERY_FAILED` event is written to the volume sink.

**Adding a SIEM target via API:**

```
POST /admin/audit/siem
{
  "name": "my-splunk",
  "target_type": "splunk_hec",
  "url": "https://splunk.example.com:8088/services/collector/event",
  "auth_header": "Authorization",
  "auth_value": "Splunk <HEC_TOKEN>",
  "enabled": true
}
```

Name constraints: 1–64 characters, pattern `^[a-z0-9_-]+$`.

**Testing a SIEM target:**

```
POST /admin/audit/siem/{name}/test
```

Sends a synthetic `SIEM_CONNECTION_TEST` event. Returns `{"status": "ok", "http_status": 200}` on success, or HTTP 502 with error details on failure.

**Removing a SIEM target:**

```
DELETE /admin/audit/siem/{name}
```

### 10.3 Masking Scope

**Default:** `mask_all_by_default=True`. All events are masked unless explicitly overridden.

**Override semantics — masking wins.** An event is un-masked only if:
1. It is NOT an immutable floor event type (see below), AND
2. There is at least one applicable override that is explicitly `False`, AND
3. No applicable override is `True`.

In other words, any `True` override anywhere in the applicable set forces masking regardless of other overrides.

**Override dimensions:**
- Per-agent: keyed by `agent_id` (from the `X-Yashigani-Agent-Id` request header)
- Per-user: keyed by `user_handle`
- Per-component: keyed by component name

Multiple overrides can apply to a single event. The "masking wins" rule applies across all dimensions simultaneously.

**Immutable floor event types.** These event types are ALWAYS masked regardless of any configuration. No override can disable masking for these events:

| Event type |
|---|
| `CREDENTIAL_LEAK_DETECTED` |
| `PROMPT_INJECTION_CREDENTIAL_EXFIL` |
| `TOTP_RESET_CONSOLE` |
| `EMERGENCY_UNLOCK_EXECUTED` |
| `RECOVERY_CODE_USED` |
| `KSM_ROTATION_SUCCESS` |
| `KSM_ROTATION_FAILURE` |
| `KSM_ROTATION_CRITICAL` |
| `MASKING_CONFIG_CHANGED` |
| `USER_FULL_RESET` |
| `FULL_RESET_TOTP_FAILURE` |

**Masking patterns applied.** The `CredentialMasker` applies the following regex patterns in sequence to all string fields:

| Pattern | Replacement |
|---|---|
| JWT (three base64url segments: `eyJ...`) | `[REDACTED:jwt]` |
| Bearer token in header/string | `[REDACTED:bearer]` |
| OpenAI/Anthropic/generic `sk-` API keys (20+ chars after prefix) | `[REDACTED:api_key]` |
| GitHub PAT (`ghp_` + 36 chars) | `[REDACTED:api_key]` |
| GitLab PAT (`glpat-` + 20+ chars) | `[REDACTED:api_key]` |
| AWS access key ID (`AKIA` + 16 chars) | `[REDACTED:api_key]` |
| 32–64 character hex strings | `[REDACTED:api_key]` |
| PEM private key header | `[REDACTED:private_key]` |
| Basic auth header | `[REDACTED:basic_auth]` |

**Invariant:** `raw_query_logged` is always forced to `False` in `mask_event()`. This cannot be overridden by configuration.

### 10.4 Log Export

**Endpoint:** `GET /admin/audit/export`

**Query parameters:**
- `output_format`: `ndjson` (default) or `csv`
- `date_from`: ISO 8601 date prefix (e.g., `2025-01` or `2025-01-15`)
- `date_to`: ISO 8601 date prefix

**Behaviour:**
- Reads both the active `audit.log` and all rotated `audit.log.*` files, sorted oldest-first.
- Filters records by comparing the first 10 characters of the `timestamp` field against the `date_from` and `date_to` prefixes. Comparison is lexicographic ISO 8601 string comparison.
- Streams records as they are read. The full result set is never buffered in memory.
- Invalid JSON lines are silently skipped.
- Unreadable files are silently skipped.

**NDJSON output:** Each record is serialized as a single JSON line followed by `\n`. `Content-Type: application/x-ndjson`. Filename: `yashigani-audit.ndjson`.

**CSV output:** First record's keys are used as the header row. Subsequent records emit one row per event. Newline characters in field values are replaced with spaces to prevent CSV injection. `Content-Type: text/csv`. Filename: `yashigani-audit.csv`.

---

## 11. Inspection Pipeline Configuration

### 11.1 Model Selection

The classifier uses Ollama's local HTTP API. No external network call is ever made for classification. The model must be pulled locally before use.

**Environment variable:** `OLLAMA_MODEL` (default: `qwen2.5:3b`)

**API endpoint:** `POST /admin/inspection/model`

```json
{"model": "qwen2.5:7b"}
```

If Ollama is reachable, the model is validated against the list of locally available models. If the specified model is not present, HTTP 422 is returned with `error: model_not_available` and the `available_models` list. Pull the model first:

```bash
docker exec yashigani-ollama-1 ollama pull qwen2.5:7b
```

### 11.2 Threshold

The threshold controls when the sanitizer is invoked for `CREDENTIAL_EXFIL` detections.

**Valid range:** 0.70 to 0.99 inclusive.
**Default:** 0.85 (from `YASHIGANI_INJECT_THRESHOLD`).

**API endpoints:**
```
GET  /admin/inspection/threshold
POST /admin/inspection/threshold
Body: {"threshold": 0.90}
```

**Interpretation:**
- Higher threshold (closer to 0.99): more conservative. Only very high-confidence detections trigger sanitization. Lower-confidence detections are always discarded.
- Lower threshold (closer to 0.70): more aggressive. Lower-confidence detections also trigger sanitization attempts.

Setting the threshold does not affect `PROMPT_INJECTION_ONLY` behaviour — those detections are always discarded regardless of confidence.

### 11.3 Mode

Two pipeline modes are available:

**`strict` (default):** Any detection at or above the threshold triggers sanitization or discard. This is the safe default.

**`permissive`:** Detections below the threshold are logged and an alert is generated, but the original request is allowed through. Detections at or above the threshold still trigger sanitization or discard.

**API endpoints:**
```
GET  /admin/inspection/mode
POST /admin/inspection/mode
Body: {"mode": "strict"}
```

**Warning:** `permissive` mode should only be used in controlled testing environments. In production, leave the mode as `strict`.

### 11.4 Classifier Failure Behaviour

If the Ollama model call fails (network error, timeout, invalid JSON response), the classifier returns `label=CLEAN` with `confidence=0.0` and logs the error. The pipeline treats this as a clean request and forwards it. This is a fail-open behaviour for the inspection step; OPA policy enforcement still applies downstream.

If Ollama is unreachable at startup, the dashboard reports `inspection.status=critical`. The gateway continues to operate and forward requests; only the inspection step is degraded.

---

## 12. Credential Handle Service (CHS)

### 12.1 Opaque Handles

The CHS issues opaque handles for raw credentials stored in the KSM. AI agents and the inspection pipeline interact with handles only; they never see raw secret values.

**Handle format:** 32-character hex string (128-bit random value via `secrets.token_hex(16)`).

**Security invariants enforced by the CHS:**
- Raw credential values are never stored in the CHS registry (in-memory dict maps handle to KSM key, not to value).
- The registry is never persisted to disk.
- Handles are validated at issue time: `get_secret(key)` is called to confirm the key exists in KSM before the handle is issued (fail fast).
- Audit logging records handle issuance and resolution. The key name is hashed to a 12-character SHA-256 prefix for safe logging.

### 12.2 Dynamic TTL Tiers

Handle TTL is dynamically adjusted based on the container's resource pressure index (RPI). The `ResourceMonitor` polls cgroup v2 metrics every 30 seconds (configurable). The RPI formula:

```
pressure_index = min(1.0, 0.7 × memory_pressure + 0.3 × cpu_throttle_ratio)
```

Where:
- `memory_pressure = memory.current / memory.max` (from cgroup v2)
- `cpu_throttle_ratio = throttled_usec / (throttled_usec + usage_usec)` (from `cpu.stat`)

If cgroup v2 is not available, the monitor falls back to the Docker stats API (queries `GET /containers/{HOSTNAME}/stats?stream=false`). If neither is available, `pressure_index=0.0` and `source="unavailable"`.

**TTL tiers:**

| Pressure index | Tier | TTL |
|---|---|---|
| > 0.8 | Critical | 120 seconds (hard floor, `TTL_FLOOR_SECONDS`) |
| 0.6–0.8 | High | 300 seconds |
| 0.3–0.6 | Medium | 900 seconds (default, overridable) |
| < 0.3 | Low | 1800 seconds (ceiling, overridable) |

**Admin-configured ceiling:** The `CredentialHandleService` is initialized with `max_ttl_seconds=14400` (4 hours). The effective TTL for a new handle is `min(resource_monitor.current_ttl_seconds, max_ttl_seconds)`.

**Background reaper:** A daemon thread runs every 60 seconds and removes expired and revoked handles from the registry.

### 12.3 Handle Operations

**Issue:** `CredentialHandleService.issue(secret_key)` — validates the key exists in KSM, computes TTL from RPI, creates a handle, stores `(handle_id → Handle)`, and returns the `handle_id`. Raises `ProviderError` if KSM is unreachable (fail closed).

**Resolve:** `CredentialHandleService.resolve(handle_id, requester_id)` — checks the handle is not unknown, not revoked, and not expired. Calls `get_secret(handle.secret_key)` and returns the raw value. `resolved_count` is incremented. If the handle has expired, it is deleted from the registry and `ValueError` is raised.

**Revoke:** `CredentialHandleService.revoke(handle_id)` — sets `handle.revoked=True`. Future resolve calls raise `ValueError`.

---

## 13. SSO Integration

### 13.1 OIDC Setup

The OIDC provider (`yashigani.sso.oidc`) implements OpenID Connect as a Relying Party using the `authlib` library.

**Required configuration** (via `OIDCConfig`):

| Field | Description |
|---|---|
| `client_id` | OIDC client ID registered with the IdP |
| `client_secret` | OIDC client secret |
| `discovery_url` | OpenID Connect discovery document URL (e.g., `https://accounts.google.com/.well-known/openid-configuration`) |
| `redirect_uri` | Callback URL registered with the IdP |
| `scopes` | Requested scopes. Default: `["openid", "email", "profile"]` |

**Flow:**
1. Call `OIDCProvider.get_authorization_url(state, nonce)` to get the IdP redirect URL.
2. Redirect the user to the IdP.
3. On callback, call `OIDCProvider.exchange_code(code, state)`.
4. The provider fetches the token endpoint URL from the discovery document, exchanges the code for tokens, validates the ID token signature using the IdP's JWKS, and validates claims (expiry, issuer, etc.) with 30-second leeway.
5. Returns `OIDCUserInfo` with `subject`, `email`, `name`, and `raw_claims`.

JWKS and metadata are cached in-process after first retrieval.

### 13.2 SAMLv2 Setup

The SAML provider (`yashigani.sso.saml`) implements SAMLv2 Service Provider functionality using `python3-saml` (OneLogin).

**Required configuration** (via `SAMLConfig`):

| Field | Description |
|---|---|
| `sp_entity_id` | Service Provider entity ID |
| `sp_acs_url` | Assertion Consumer Service URL (POST binding) |
| `sp_sls_url` | Single Logout Service URL (Redirect binding) |
| `idp_entity_id` | Identity Provider entity ID |
| `idp_sso_url` | IdP SSO URL (Redirect binding) |
| `idp_sls_url` | IdP SLS URL (Redirect binding) |
| `idp_x509_cert` | IdP signing certificate (PEM body without headers) |
| `sp_private_key` | SP private key (PEM body without headers) |
| `sp_certificate` | SP certificate (PEM body without headers) |
| `name_id_format` | Default: `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` |

**Security settings enforced:**
- `strict: True` — strict signature and schema validation
- `authnRequestsSigned: True`
- `logoutRequestSigned: True`
- `logoutResponseSigned: True`
- `wantMessagesSigned: True`
- `wantAssertionsSigned: True`
- `signatureAlgorithm: rsa-sha256`
- `digestAlgorithm: sha256`

**Flow:**
1. Call `SAMLProvider.get_login_url(request_data)` to get the IdP redirect URL.
2. On callback (POST binding), call `SAMLProvider.process_response(request_data)`.
3. The provider validates the SAML response, checks for errors, and verifies authentication. Returns `SAMLUserInfo` with `subject` (NameID), `email`, `attributes`, and `session_index`.

### 13.3 TOTP Provisioning Token Flow for First-Time SSO Users

When `REQUIRE_YASHIGANI_TOTP_ON_SSO=true`, SSO users who have not yet provisioned a Yashigani TOTP must complete provisioning before receiving a full session.

**Flow:**
1. IdP assertion validates successfully. Yashigani receives `user_subject`.
2. `SSOTotpProvisioningService.needs_provisioning(user_subject)` is checked. Returns `True` if the user has no provisioning record in Redis.
3. A single-use provisioning token is issued: `SSOTotpProvisioningService.issue_token(user_subject)`. The token is a 32-byte URL-safe random string. TTL: 600 seconds (10 minutes). Backed by Redis; previous unfinished tokens are replaced.
4. The user is redirected to `/user/auth/totp/provision?token=<token_id>`.
5. The user scans the QR code and submits their first TOTP code.
6. `SSOTotpProvisioningService.consume_token(token_id)` is called. The token is deleted from Redis on first use (single-use). Returns `user_subject` on success, `None` if expired or already used.
7. On successful TOTP verification: `mark_provisioned(user_subject)` writes a persistent Redis key (`yashigani:sso_totp_provisioned:{subject}`) with a 10-year TTL. Eight recovery codes are generated.
8. A full session token is issued.

**Audit events:** `TOTP_PROVISION_TOKEN_ISSUED` is written at step 3. `TOTP_PROVISION_COMPLETED` is written at step 7. `TOTP_PROVISION_FAILED` is written with `reason=expired_token`, `reason=reuse`, or `reason=invalid_code` on failure.

---

## 14. Security Controls Reference

### 14.1 OWASP ASVS Level 3 — Implemented Controls

| ASVS Control | Requirement | Implementation |
|---|---|---|
| V2.1 | Credential enumeration prevention | `authenticate()` returns identical `invalid_credentials` error for unknown user, wrong password, and locked account. |
| V2.1.4 | Session invalidation on password change | `POST /auth/password/change` calls `invalidate_all_for_account()` for all sessions including the current one. |
| V2.4 | Argon2id parameters | `PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)` — meets OWASP V2.4 minimums. |
| V2.8 | TOTP replay prevention | `verify_totp()` uses a window-keyed used-codes cache: `<secret>:<unix_time // 30>`. Valid window: ±1 step. |
| V2.8 | Re-authentication for sensitive operations | `POST /admin/users/{username}/full-reset` requires admin TOTP code re-verification, server-side enforced. |
| V3.2 | Session token entropy | 256-bit session tokens via `secrets.token_hex(32)`. |
| V3.2 | Session cookie attributes | `HttpOnly=True`, `Secure=True`, `SameSite=Strict`. |
| V3.3 | Session timeouts | Idle: 15 minutes. Absolute: 4 hours. Implemented in `SessionStore.get()`. |
| V3.3 | Concurrent session prevention | `SessionStore.create()` calls `invalidate_all_for_account()` before issuing new session. |
| V4.2 | Local policy enforcement | OPA policy engine runs as a local sidecar container. No cloud delegation. Fail-closed on OPA errors. |
| V6.4 | Secret management | KSM abstraction layer with five providers. Secrets never stored in plaintext in env vars (Docker Secrets preferred). CHS handles provide indirection so raw secrets never traverse the inspection layer. |
| V7.1 | Audit log volume | Always-active NDJSON volume sink. `AuditWriteError` aborts the triggering operation if the write fails. |
| V7.4 | Audit event integrity | Immutable floor event types cannot have masking disabled. `raw_query_logged` is hardcoded `False`. Rotated logs are renamed with UTC timestamps and retention-managed. |
| V13.2 | TLS enforcement | `Strict-Transport-Security: max-age=31536000; includeSubDomains` on all responses. Backoffice binds to localhost by default (TLS termination expected at ingress). |

### 14.2 OWASP API Security Top 10 Mitigations

| Risk | Mitigation in Yashigani |
|---|---|
| API1 — Broken Object Level Authorization | Session tier enforcement in middleware: `account_tier != "admin"` → HTTP 403. Admin routes inaccessible to user-tier sessions. |
| API2 — Broken Authentication | Argon2id + TOTP MFA on all backoffice access. 256-bit session tokens. No API keys for admin plane. |
| API3 — Broken Object Property Level Authorization | SIEM `auth_value` never returned in list responses. Secret values never returned by KSM routes. Session token never returned in session listings (first 8 chars only). |
| API4 — Unrestricted Resource Consumption | Request body size limit: 4 MB (`max_request_body_bytes`). Redis memory limit: 256 MB (`maxmemory 256mb`). |
| API5 — Broken Function Level Authorization | CORS disabled entirely on backoffice. All routes require admin session. Cross-tier access returns HTTP 403. |
| API6 — Unrestricted Access to Sensitive Business Flows | Admin minimum enforcement prevents lockout. Rotation scheduler enforces 1-hour minimum interval. Full-reset requires TOTP re-verification. |
| API7 — Server Side Request Forgery | SIEM target URLs are admin-configured. Ollama and OPA communicate only on the internal Docker network. |
| API8 — Security Misconfiguration | Swagger/ReDoc/OpenAPI endpoints disabled. Generic exception handler masks internal errors. Security headers on all responses. |
| API9 — Improper Inventory Management | All routes documented in this document. OpenAPI schema not exposed externally. |
| API10 — Unsafe Consumption of APIs | OPA response parsed strictly (`data.get("result", False)` — any non-True value is a deny). Classifier response schema validated strictly. Invalid label → CLEAN/0.0. |

### 14.3 Agentic AI Security Controls

| Threat | Control |
|---|---|
| Prompt injection via agent input | `PromptInjectionClassifier` with local Ollama model on every request body. Two-tier classification: `CREDENTIAL_EXFIL` and `PROMPT_INJECTION_ONLY`. |
| Credential exfiltration via agent | `CredentialMasker` applied before classifier. CHS handles prevent raw secrets from appearing in request bodies. |
| Model jailbreak affecting classification | Classifier output is parsed as strict JSON against a fixed schema. Any deviation (invalid label, non-JSON output) defaults to `CLEAN/0.0` rather than approving a blocked request. The model is instructed to output only JSON and at temperature 0.0. |
| Prompt injection in classifier input | User content is JSON-encoded (`json.dumps(content)`) before insertion into the classifier prompt, preventing special characters from escaping the content boundary. |
| Agent identity spoofing | `X-Yashigani-Agent-Id` is passed to OPA policy. OPA can enforce agent allowlists. Session ID derived from auth header hash or cookie — not from user-controlled headers. |
| Unbounded credential handle lifetime | CHS TTL dynamically reduced under memory/CPU pressure. Hard floor of 120 seconds. Admin-configured ceiling of 4 hours. |

---

## 15. Troubleshooting

### 15.1 Ollama Unreachable

**Symptom:** `GET /admin/inspection/status` returns `{"healthy": false, "ollama_models_available": []}`. Dashboard shows `inspection.status=critical`. The gateway continues to forward requests but inspection is degraded (classifier returns `CLEAN/0.0` on all requests).

**Diagnosis:**
```bash
# From inside the gateway container
curl -sf http://ollama:11434/api/tags
# If this fails, Ollama is not running or not reachable on the internal network
```

**Resolution steps:**
1. Check Ollama container status: `docker compose ps ollama`
2. Check Ollama logs: `docker compose logs ollama`
3. Verify the model was pulled: `docker compose logs ollama-init`
4. If the model was not pulled, run the init container manually: `docker compose run --rm ollama-init`
5. If the container is running but the model is missing: `docker exec <ollama_container> ollama pull qwen2.5:3b`
6. Verify the internal network connectivity from the gateway: `docker compose exec gateway curl -sf http://ollama:11434/api/tags`

### 15.2 OPA Deny

**Symptom:** Gateway returns HTTP 403 with `{"error": "POLICY_DENIED", "request_id": "..."}` for requests that should be allowed.

**Diagnosis:**
```bash
# Test the OPA decision directly with representative input
curl -s -X POST http://localhost:8181/v1/data/yashigani/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "method": "POST",
      "path": "/your/path",
      "session_id": "your-session-id",
      "agent_id": "your-agent-id",
      "user_id": "unknown",
      "headers": {}
    }
  }'
# Expected: {"result": true}
```

**Common causes:**
- `session_id` is `""` or `"anonymous"`: the request lacks an `Authorization` header and no `yashigani_session` cookie is present.
- `agent_id` is `""` or `"unknown"`: the `X-Yashigani-Agent-Id` request header is missing or empty.
- Path matches a blocked pattern: paths starting with `/admin`, `/.well-known/internal`, or exactly `/metrics` or `/healthz` are blocked by the default policy.
- Custom policy rule is blocking the request: review your additions to `policy/yashigani.rego`.

**OPA connectivity error** (gateway cannot reach OPA): Gateway returns HTTP 403 and logs `"OPA check failed ... denying (fail-closed)"`. Verify: `docker compose ps policy`, check OPA logs, confirm the `internal` network is up.

### 15.3 KSM Rotation Failure

**Symptom:** `KSM_ROTATION_FAILURE` or `KSM_ROTATION_CRITICAL` events in the audit log. Dashboard may show rotation scheduler as stopped or degraded.

**Diagnosis:**
```bash
# Trigger a test rotation manually via the API
curl -s -X POST http://127.0.0.1:8443/admin/kms/rotate-now \
  -H "Cookie: yashigani_admin_session=<token>"
# Response will include error detail if rotation fails

# Check KSM provider health
curl -s http://127.0.0.1:8443/admin/kms/status \
  -H "Cookie: yashigani_admin_session=<token>"
```

**Common causes and resolutions:**

| Cause | Resolution |
|---|---|
| `KSM_ROTATION_SECRET_KEY` is set but the key does not exist in the provider | Create the key in the KSM provider (e.g., create the record in Keeper Vault, or the secret in AWS). |
| Keeper: one-time token already consumed | Generate a new one-time token in Keeper Vault and update the Docker secret. Restart the service. |
| AWS: IAM role lacks `secretsmanager:PutSecretValue` | Grant the appropriate IAM policy to the EC2 instance role or ECS task role. |
| Azure: managed identity lacks `Key Vault Secrets Officer` role | Assign the role in Azure IAM. |
| GCP: service account lacks `Secret Manager Secret Version Adder` role | Grant the role in GCP IAM. |
| Provider health check fails | Verify network connectivity to the KSM endpoint from inside the container. |
| Rotation is triggered but a concurrent rotation is in progress | This is normal operation. The second trigger is skipped with a warning log. Wait for the in-progress rotation to complete. |

**After all retries exhausted:** A `KSM_ROTATION_CRITICAL` audit event is written. The scheduler does not stop; the next cron fire will attempt rotation again. If the underlying issue is resolved before the next fire, rotation will succeed normally.

### 15.4 Admin Lockout Recovery

**Symptom:** All admin accounts are locked, disabled, or their TOTP seeds are lost. The backoffice is inaccessible.

**Prevention:** Maintain at least 3 admin accounts (the `admin_soft_target` default). Store the 8 TOTP recovery codes for each account in a secure offline location (password manager, HSM).

**Recovery using a TOTP recovery code.** If the TOTP device is lost but recovery codes are available, the recovery code can be used in place of the TOTP code at login. Recovery codes are verified against their Argon2id hashes. Each code is single-use; `RecoveryCodeUsedEvent` is written with `codes_remaining` decremented.

**Emergency unlock via console (last resort).** If all sessions and recovery codes are exhausted, an `EMERGENCY_UNLOCK_EXECUTED` event must be initiated through a console operation that directly accesses the `LocalAuthService._accounts` dict. This requires direct host or container access. The exact procedure depends on the deployment configuration. The event is a security-critical immutable floor event and cannot be masked.

**Rebuilding the initial admin account.** If the account store is completely lost (in-memory, no persistence), restart the backoffice container with `YASHIGANI_ADMIN_PASSWORD` set (or the Docker secret populated). The bootstrap routine will recreate the initial account on startup.

**Note:** In v0.1.0, the `LocalAuthService` uses an in-memory dict as the account store. Session and account state is lost on container restart. Production deployments should back this store with a persistent database. This is documented as a v0.1.0 limitation in the source code.

---

*End of Yashigani v0.1.0 Technical Documentation.*
