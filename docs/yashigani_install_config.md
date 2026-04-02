# Yashigani v1.0 — Installation and Configuration Guide

**Version:** 1.0
**Last updated:** 2026-04-01
**Applies to:** Docker Compose and Kubernetes (Helm) deployments

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Quick Start (Demo — 5 Minutes)](#2-quick-start-demo--5-minutes)
3. [Installer Walk-Through (Interactive)](#3-installer-walk-through-interactive)
4. [Manual Installation (Full Detail)](#4-manual-installation-full-detail)
5. [License Activation](#5-license-activation)
6. [KMS Configuration](#6-kms-configuration)
7. [Inspection Pipeline Configuration](#7-inspection-pipeline-configuration)
8. [SSO Configuration (Professional/Enterprise)](#8-sso-configuration-professionalenterprise)
9. [SIEM Integration](#9-siem-integration)
10. [Alertmanager Configuration](#10-alertmanager-configuration)
10a. [Direct Webhook Alert Sinks (v0.7.0)](#10a-direct-webhook-alert-sinks-v070)
11. [Agent Registration](#11-agent-registration)
12. [Rate Limiting Configuration](#12-rate-limiting-configuration)
13. [Kubernetes Deployment](#13-kubernetes-deployment)
14. [Production Hardening Checklist](#14-production-hardening-checklist)
15. [Troubleshooting](#15-troubleshooting)
16. [Upgrade Procedure](#16-upgrade-procedure)
17. [Optional Agent Bundles (v0.8.0)](#17-optional-agent-bundles-v080)
18. [Response Path Inspection (v0.9.0)](#18-response-path-inspection-v090)
19. [WebAuthn / Passkeys Configuration (v0.9.0)](#19-webauthn--passkeys-configuration-v090)
20. [Credential Summary and Dual Admin Accounts (v0.9.1)](#20-credential-summary-and-dual-admin-accounts-v091)
21. [Open WebUI Configuration (v1.0)](#21-open-webui-configuration-v10)
22. [Optimization Engine (v1.0)](#22-optimization-engine-v10)
23. [Budget System (v1.0)](#23-budget-system-v10)
24. [Container Pool Manager (v1.0)](#24-container-pool-manager-v10)
25. [Multi-IdP Identity Broker (v1.0)](#25-multi-idp-identity-broker-v10)

---

## 1. Prerequisites

### 1.1 Hardware Requirements

| Resource | Demo / Dev | Production |
|---|---|---|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8 GB (16 GB with Ollama GPU) |
| Disk | 20 GB | 50+ GB |
| OS | Any (Linux / macOS / VM) | Linux x86_64 or arm64 |

> **Note:** If you enable GPU acceleration for Ollama (recommended for production), the host must have a CUDA-capable NVIDIA GPU (driver 525+), Apple Silicon (any M-series), or an AMD GPU with ROCm support. Expect an additional 4–8 GB VRAM (or unified memory) per loaded model. The installer detects GPU hardware automatically in v0.8.4 and prints model recommendations based on available VRAM.

### 1.2 Software Requirements

Install the following before proceeding:

**Linux:**

```bash
# Docker Engine 24+
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# Docker Compose v2 (bundled with Docker Engine 24+ as a plugin)
docker compose version  # must be >= 2.0.0

# Git
sudo apt-get install -y git   # Debian/Ubuntu
sudo dnf install -y git       # RHEL/Fedora
```

**macOS:**

1. Install [Docker Desktop for Mac](https://www.docker.com/products/docker-desktop/) (version 4.x or later — includes Docker Compose v2). The installer detects Docker Desktop by checking `/Applications/Docker.app` (v0.8.4).
2. If the `docker` CLI is not in your PATH after installing Docker Desktop, the preflight check will detect this and offer to create the symlink automatically: `sudo ln -sf /Applications/Docker.app/Contents/Resources/bin/docker /usr/local/bin/docker` — just press Y when prompted.
3. Alternatively, install Podman Desktop or the Podman CLI — Podman is supported as a first-class runtime (v0.8.4+). The installer auto-detects the container runtime, resolves the correct compose command (`docker compose`, `docker-compose`, or `podman compose`), and auto-applies the Podman Compose override file when Podman is the active runtime.
4. Install Git via Homebrew: `brew install git`
5. In Docker Desktop preferences, increase memory to at least 6 GB and disk to at least 30 GB.

> **Shell compatibility (v0.8.4):** The installer runs on macOS default bash (3.2) without errors. No need to install bash 4+ via Homebrew. The preflight check reports your login shell (`$SHELL`, typically zsh on modern macOS) rather than the script executor.

> **Verify your environment before installing:** Run `bash scripts/test-installer.sh` for a 28-check automated verification of your setup (platform detection, GPU, runtime, bash compatibility, file integrity).

**Verify your environment:**

```bash
docker --version        # Docker version 24.x or later
docker compose version  # Docker Compose version v2.x or later
git --version           # git version 2.x or later
```

### 1.3 Network Requirements

Before starting, confirm the following network conditions are met:

- **Ports 80 and 443** must be open and reachable from the internet if using ACME (Let's Encrypt) TLS mode. Port 80 is used for the ACME HTTP-01 challenge; port 443 is your application traffic. If your load balancer or upstream firewall handles 80→443 redirect externally, port 80 must still reach the host for the initial certificate issuance.
- **DNS A record** (or AAAA for IPv6) pointing your fully qualified domain name (FQDN) to the server's public IP address. This is mandatory for ACME mode. Allow up to 5 minutes for DNS propagation before starting the stack.
- **Outbound HTTPS** (port 443) must be permitted from the host for Let's Encrypt ACME endpoints and for Ollama model pulls from `ollama.ai` and Hugging Face registries.
- **Internal Docker networking** is isolated by default. All non-edge services (gateway, backoffice, policy, redis, budget-redis, postgres, etc.) attach to an internal bridge network with `internal: true`. Only Caddy (ports 80/443) is exposed to the host. Ollama attaches to an external network to allow outbound model pulls from `ollama.ai` and Hugging Face registries. Budget-redis runs as a dedicated Redis instance with `maxmemory-policy noeviction` for budget state persistence (v1.0).

> **Warning:** Do not expose Redis (6379), budget-redis (6380), Postgres (5432), or Prometheus (9090) ports to the host in production. These services are intentionally not bound to host interfaces in the default `docker-compose.yml`.

---

## 2. Quick Start (Demo — 5 Minutes)

For a fast local demo with a self-signed certificate, use the one-liner installer:

```bash
curl -sSL https://get.yashigani.io | bash -s -- \
    --domain localhost \
    --tls-mode selfsigned \
    --upstream-url http://your-mcp-server:8080 \
    --non-interactive
```

This downloads the stack, generates your `.env`, starts all containers, and prints your first-run credentials.

If you prefer to review every file before running anything, use the manual quick start instead:

**Step 1.** Clone the repository:

```bash
git clone https://github.com/agnosticsec-com/yashigani
cd yashigani
```

**Step 2.** Copy and minimally configure the environment file:

```bash
cp .env.example .env
```

Open `.env` in your editor and set at minimum:

```dotenv
YASHIGANI_TLS_DOMAIN=localhost
YASHIGANI_TLS_MODE=selfsigned
UPSTREAM_MCP_URL=http://your-mcp-server:8080
```

**Step 3.** Start the stack:

```bash
docker compose up -d
```

**Step 4.** Retrieve your first-run credentials:

```bash
docker compose logs backoffice | grep -A 30 "FIRST-RUN"
```

Your admin password, Redis password, Postgres password, Grafana admin password, and Prometheus basic-auth hash are all printed in this block. Save them immediately — they are shown only once in the logs.

**Step 5.** Open the admin panel in your browser at `https://localhost/admin`. Accept the self-signed certificate warning. Log in with the credentials from Step 4.

> **Note:** Self-signed mode is for local development and demos only. It uses Caddy's internal CA, which browsers will not trust by default. For production, always use `acme` or `ca` mode.

---

## 3. Installer Walk-Through (Interactive)

Running `./install.sh` without flags launches an interactive wizard. In v0.9.0 the installer was redesigned around three deployment modes. The `--mode` flag is replaced by `--deploy`.

### 3.1 Deployment Mode Selection

The installer's first prompt asks for the deployment mode:

```
Select deployment mode:
  1) Demo        — localhost, self-signed cert, auto-generate everything (1-2 prompts)
  2) Production  — public or internal hostname, ACME or CA cert, full configuration
  3) Enterprise  — multi-org, external managed databases, BYOK AES key

Enter choice [1-3]:
```

Alternatively, supply the flag non-interactively:

```bash
./install.sh --deploy demo        # or: 1
./install.sh --deploy production  # or: 2
./install.sh --deploy enterprise  # or: 3
```

**Demo mode** is intentionally minimal: it defaults to `localhost`, `selfsigned` TLS, auto-generates all secrets, and starts the stack with 1–2 prompts (upstream URL and optional license key). No KMS, SIEM, or SSO configuration is asked. Suitable for evaluations and local development.

**Production mode** and **Enterprise mode** prompt through the full configuration wizard described in steps 3–12 below.

### 3.2 Full Wizard (Production / Enterprise)

**Step 1 — Preflight checks.** Verifies container runtime (Docker Engine, Docker Desktop, or Podman), available disk space, and available RAM. GPU hardware is detected via `platform-detect.sh` — Apple Silicon M-series, NVIDIA (nvidia-smi), AMD (rocm-smi), and lspci fallback. Model recommendations are printed based on detected VRAM (v0.8.4). The health check script auto-detects the compose command for Docker or Podman environments. The preflight now also verifies that the sensitivity pipeline prerequisites (regex, FastText, Ollama) are available (v1.0).

**Step 2 — Container platform.** Asks whether you are deploying to Docker Compose or Kubernetes (Helm). Choose **Docker Compose** for standalone hosts; choose **Kubernetes** if you have an existing cluster and `kubectl` configured.

**Step 3 — Deployment stream.** Choose one of:
- `opensource` — All open-source components. No license required.
- `corporate` — Adds enterprise auth (SAML/OIDC/SCIM), audit log export, and KMS integrations. Requires a license.
- `saas` — Multi-tenant SaaS configuration. Requires a license and specific infra prerequisites. Contact sales before selecting this.

**Step 4 — Domain and TLS mode.** Enter your FQDN (e.g., `mcp-gateway.example.com`). Then choose:
- `acme` — Let's Encrypt. Use this if the host is publicly reachable and you have DNS set up.
- `ca` — Mount your own certificate. Use for enterprise internal deployments.
- `selfsigned` — Caddy internal CA. Use for local dev/demo only.

**Step 5 — Upstream MCP URL.** Enter the URL of your backend MCP server. Example: `http://mcp-server.internal:8080`. Maps to `UPSTREAM_MCP_URL`. Multiple comma-separated URLs are accepted for load balancing.

**Step 6 — AES key provisioning (v0.9.0).** Choose how the AES-256-GCM column encryption key is provisioned:
- Auto-generate (default) — the installer generates a cryptographically random 32-byte key and stores it in the configured KMS.
- BYOK — supply your own key with `--aes-key /path/to/key.bin`. The installer loads the file and stores it in KMS.

**Step 7 — KMS provider.** Choose how secrets are stored:
- `docker` — Docker secrets on local filesystem. Default and simplest. Also compatible with Podman secrets.
- `aws` — AWS Secrets Manager. Recommended for AWS-hosted deployments.
- `azure` — Azure Key Vault.
- `gcp` — GCP Secret Manager.
- `keeper` — Keeper Secrets Manager.
- `vault` — HashiCorp Vault (self-hosted, dev mode only — not for production).

**Step 8 — Inspection pipeline backend.** Choose the LLM used for the second-pass injection analysis:
- `ollama` — Fully local. No data leaves the host. Choose this for air-gapped or privacy-sensitive deployments.
- `anthropic` — Claude Haiku. Fast and accurate. Requires API key.
- `gemini` — Gemini 1.5 Flash. Requires API key.
- `azure_openai` — GPT-4o-mini via Azure. Requires Azure OpenAI resource.

The installer prompts for API keys immediately if you select a cloud backend, and stores them in the KMS provider chosen in Step 7.

**Step 9 — Injection threshold.** Sets `YASHIGANI_INJECT_THRESHOLD`. Default `0.85`. Range `0.70`–`0.99`. Lower = more sensitive. Higher = more permissive. The default is appropriate for most production environments.

**Step 10 — SIEM mode.** Choose one of `none`, `splunk`, `elasticsearch`, or `wazuh`. If you choose `wazuh`, the installer adds the Wazuh Compose override file automatically.

**Step 11 — License key.** Enter the path to your `.ysg` license file if you have one, or press Enter to skip for Community tier. The installer copies the file to `docker/secrets/license_key`. License files are signed with ECDSA P-256 (ML-DSA-65 migration planned when cryptography ships FIPS 204).

**Step 12 — Admin accounts (v0.9.1).** Set `YASHIGANI_ADMIN_USERNAME` to your primary admin email address. The installer creates **two** admin accounts at bootstrap — each with a random themed username (animals/flowers/robots theme, e.g. "phoenix", "condor") and an independent 36-character password. Both accounts are configured with TOTP 2FA at install time; the TOTP secret key and `otpauth://` URI are printed for each account.

> **Anti-lockout design:** Two independent admin accounts are provisioned so that a lost password or lost TOTP device for one account does not lock out the system. Treat both accounts as equally privileged and store their credentials separately.

**Step 13 — HIBP breach check.** Before the stack starts, the installer checks all generated passwords against the Have I Been Pwned API using SHA-1 k-Anonymity prefix lookup. Any password found in a known breach is automatically regenerated and re-checked. If the HIBP API is unreachable, the check is skipped silently — installation is never blocked by an unreachable breach database.

**Step 14 — Launch.** The installer runs `docker compose up -d`, tails `backoffice` logs until the stack is healthy, then prints the one-time credential summary.

**Step 15 — Credential summary.** At the end of install, a formatted credential block is displayed once with a red warning banner:

```
============================================================
  WARNING: These credentials will NOT be shown again.
  Save them immediately to a secure password manager.
============================================================

  Admin 1 Username : phoenix
  Admin 1 Password : <36-char random>
  Admin 1 TOTP Key : <base32 secret>
  Admin 1 TOTP URI : otpauth://totp/Yashigani%3Aphoenix?secret=...

  Admin 2 Username : condor
  Admin 2 Password : <36-char random>
  Admin 2 TOTP Key : <base32 secret>
  Admin 2 TOTP URI : otpauth://totp/Yashigani%3Acondor?secret=...

  Postgres Password : <36-char random>
  Redis Password    : <36-char random>
  Grafana Password  : <36-char random>
  AES-256-GCM Key   : <hex>

============================================================
```

All credentials are also written to `docker/secrets/` with chmod 600. They will not be printed again.

> **Tip:** You can re-run `./install.sh` at any time to change settings. It will detect an existing `.env` and ask if you want to update individual sections without redeploying everything.

> **Air-gapped deployments:** Pass `--offline` to skip all outbound pulls and work entirely from pre-loaded images. Pre-pull all images on a connected host and transfer them with `docker save` / `docker load` before running the installer in offline mode.

---

## 4. Manual Installation (Full Detail)

This section is for operators who prefer full control over every configuration option.

### 4.1 Clone and Verify

**Step 1.** Clone the repository and enter the project directory:

```bash
git clone https://github.com/agnosticsec-com/yashigani
cd yashigani
```

**Step 2.** Verify the release tag matches the version you intend to deploy:

```bash
git tag --list | grep "v1.0"
git checkout v1.0.0
```

**Step 3.** Verify file integrity (if the project provides checksums):

```bash
sha256sum -c SHA256SUMS
```

### 4.2 Configure `.env`

Copy the example file and open it for editing:

```bash
cp .env.example .env
$EDITOR .env
```

The following tables document every significant variable, grouped by category.

---

#### Core Settings

| Variable | Required | Valid Values | Production Recommendation | Demo Recommendation |
|---|---|---|---|---|
| `YASHIGANI_DEPLOYMENT_STREAM` | Yes | `opensource`, `corporate`, `saas` | `corporate` or `saas` | `opensource` |
| `YASHIGANI_ADMIN_USERNAME` | Yes | email address | your admin email | `admin@localhost` |
| `YASHIGANI_AGENT_TOKEN_MIN_LENGTH` | No | integer, min 64 | `128` | `64` |
| `YASHIGANI_AUDIT_RETENTION_DAYS` | No | integer | `365` | `30` |

---

#### TLS Settings

| Variable | Required | Valid Values | Production Recommendation | Demo Recommendation |
|---|---|---|---|---|
| `YASHIGANI_TLS_DOMAIN` | Yes | FQDN or `localhost` | your public FQDN | `localhost` |
| `YASHIGANI_TLS_MODE` | Yes | `acme`, `ca`, `selfsigned` | `acme` or `ca` | `selfsigned` |

---

#### Gateway Settings

| Variable | Required | Valid Values | Notes |
|---|---|---|---|
| `UPSTREAM_MCP_URL` | Yes | HTTP/HTTPS URL | Your backend MCP server. Use internal DNS in Docker environments. |
| `YASHIGANI_INJECT_THRESHOLD` | No | `0.70`–`0.99` | Default `0.85`. Tune based on false positive/negative tolerance. |

---

#### Auth and Identity Settings

| Variable | Required | Valid Values | Notes |
|---|---|---|---|
| `YASHIGANI_DEPLOYMENT_STREAM` | Yes | `opensource`, `corporate`, `saas` | Controls feature flags including SSO and SCIM. |

---

#### KMS Settings

| Variable | Required | Valid Values | Notes |
|---|---|---|---|
| `YASHIGANI_KSM_PROVIDER` | No | `docker`, `aws`, `azure`, `gcp`, `keeper`, `vault` | Default: `docker`. Set to match your secret backend. |
| `AWS_ACCESS_KEY_ID` | If `aws` | IAM key | Or use instance role (no key needed). |
| `AWS_SECRET_ACCESS_KEY` | If `aws` | IAM secret | Or use instance role. |
| `AWS_DEFAULT_REGION` | If `aws` | AWS region | e.g., `us-east-1` |
| `AZURE_KEYVAULT_URL` | If `azure` | Vault URL | e.g., `https://my-vault.vault.azure.net` |
| `AZURE_CLIENT_ID` | If `azure` (no MI) | UUID | Service principal client ID. |
| `AZURE_CLIENT_SECRET` | If `azure` (no MI) | secret string | Service principal secret. |
| `AZURE_TENANT_ID` | If `azure` | UUID | Azure AD tenant. |
| `GOOGLE_APPLICATION_CREDENTIALS` | If `gcp` | file path | Path to GCP service account JSON. |
| `VAULT_ADDR` | If `vault` | URL | e.g., `http://vault:8200` |

---

#### Inspection Pipeline Settings

| Variable | Required | Valid Values | Notes |
|---|---|---|---|
| `YASHIGANI_INSPECTION_DEFAULT_BACKEND` | No | `ollama`, `anthropic`, `gemini`, `azure_openai` | Default: `ollama` |
| `YASHIGANI_INSPECTION_FALLBACK_CHAIN` | No | comma-separated backends | e.g., `ollama,gemini,fail_closed` |
| `OLLAMA_MODEL` | No | any Ollama model tag | Default: `qwen2.5:3b` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | No | OTLP gRPC URL | Default: `http://otel-collector:4317` |
| `FASTTEXT_MODEL_PATH` | No | file path | Default: `/app/models/fasttext_classifier.bin` |

---

#### Postgres Settings

| Variable | Required | Valid Values | Notes |
|---|---|---|---|
| `POSTGRES_PASSWORD` | No | string | Set in `.env` for Compose interpolation; PgBouncer uses this via `DATABASE_URL` for proper auth. Auto-generated by the installer. |
| `REDIS_PASSWORD` | No | string | Set in `.env` for Compose interpolation. Auto-generated by the installer. |
| `BUDGET_REDIS_PASSWORD` | No | string | Set in `.env` for Compose interpolation. Dedicated budget-redis instance (v1.0). Auto-generated by the installer. |
| `YASHIGANI_DB_DSN` | No | PostgreSQL DSN | Auto-constructed from the `postgres_password` secret on first run. Override only if using an external Postgres instance. |

---

#### Observability Settings

| Variable | Required | Valid Values | Notes |
|---|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | No | URL | Default: `http://otel-collector:4317` |

---

#### SIEM Settings

| Variable | Required | Valid Values | Notes |
|---|---|---|---|
| `YASHIGANI_SIEM_MODE` | No | `none`, `splunk`, `elasticsearch`, `wazuh` | Default: `none` |

---

#### Licensing

| Variable | Required | Valid Values | Notes |
|---|---|---|---|
| `YASHIGANI_LICENSE_FILE` | No | file path | Omit for Community tier. Set to `/run/secrets/license_key` if using Docker secret. |

---

### 4.3 TLS Configuration

> **Post-quantum TLS (v0.9.0):** A hybrid X25519+ML-KEM-768 Caddyfile configuration is included in the repository as a commented block (`caddy/Caddyfile.pq`). This requires Caddy 2.10 (not yet released). Enable it once Caddy 2.10 ships to provide quantum-resistant key exchange while maintaining full backward compatibility with classical TLS clients.

#### ACME Mode (Production — Let's Encrypt)

This is the default and recommended mode for any publicly accessible deployment.

**Step 1.** Confirm your DNS A record is live:

```bash
dig +short your-domain.example.com
# Should return your server's public IP
```

**Step 2.** Confirm ports 80 and 443 are reachable:

```bash
# From an external host or using a public checker:
curl -I http://your-domain.example.com
```

**Step 3.** Set in `.env`:

```dotenv
YASHIGANI_TLS_DOMAIN=your-domain.example.com
YASHIGANI_TLS_MODE=acme
```

That is all. Caddy handles certificate issuance via ACME HTTP-01 challenge on port 80 and automatic renewal 30 days before expiry.

> **Warning:** If port 80 is blocked by your firewall or cloud security group, Caddy cannot complete the ACME HTTP-01 challenge and TLS startup will fail. Check your security group/firewall rules before starting.

---

#### CA Mode (Enterprise/Internal)

Use this mode when your organization has an internal CA or you have purchased a certificate from a public CA.

**Step 1.** Create the TLS directory:

```bash
mkdir -p docker/tls
```

**Step 2.** Copy your certificate and private key:

```bash
cp /path/to/your/server.crt docker/tls/server.crt
cp /path/to/your/server.key docker/tls/server.key
chmod 600 docker/tls/server.key
```

The certificate file must include the full chain (server cert + intermediate CA certs, concatenated in PEM format).

**Step 3.** Set in `.env`:

```dotenv
YASHIGANI_TLS_DOMAIN=your-domain.example.com
YASHIGANI_TLS_MODE=ca
```

> **Note:** Certificate renewal in CA mode is your responsibility. Set a calendar reminder at least 30 days before expiry. To rotate the certificate: replace the files in `docker/tls/`, then run `docker compose restart caddy`.

---

#### Self-Signed Mode (Demo/Local)

**Step 1.** Set in `.env`:

```dotenv
YASHIGANI_TLS_DOMAIN=localhost
YASHIGANI_TLS_MODE=selfsigned
```

No certificate files are needed. Caddy generates a certificate from its own internal CA.

> **Warning:** Self-signed certificates will trigger browser certificate warnings. Users must manually accept the risk. Never use this mode for any environment accessible to end users.

---

### 4.4 Start the Stack

**Step 1.** Pull all images before starting (recommended to avoid timeout issues on slow connections):

```bash
docker compose pull
```

**Step 2.** Start all services in detached mode:

```bash
docker compose up -d
```

**Step 3.** Confirm all containers started successfully:

```bash
docker compose ps
```

All services should show status `running` or `healthy`. The `ollama-init` service may show `exited (0)` after successfully pulling the model — this is expected.

**Step 4.** Watch the backoffice logs for the first-run credential block:

```bash
docker compose logs -f backoffice
```

Wait until you see the `FIRST-RUN` block (typically within 30–90 seconds on a fast disk).

---

### 4.5 Postgres Bootstrap

On first start, the backoffice service automatically runs `scripts/bootstrap_postgres.py`. This script performs the following actions:

1. **Generates a 36-character random password** for the `yashigani_app` Postgres role using `openssl rand -base64 48`. The password is written to `docker/secrets/postgres_password` and injected as a Docker secret. `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, and `BUDGET_REDIS_PASSWORD` are also written to `.env` for Compose interpolation.
2. **Constructs the DB DSN** (`YASHIGANI_DB_DSN`) from the generated password and the service hostname. PgBouncer receives proper auth via `DATABASE_URL` with the password.
3. **Creates the `yashigani_app` role** in Postgres with limited privileges (no superuser, no create database).
4. **Runs all Alembic migrations** in order, creating the full schema (`yashigani` database, all tables including identity, billing, optimization, and pool tables, indexes, and constraint definitions). Alembic migrations are bundled in the backoffice Docker image.
5. **Seeds initial configuration** rows (default OPA policy including `policy/v1_routing.rego`, default rate limits, default audit retention settings, default budget tiers).
6. **Writes `admin_initial_password`** to `docker/secrets/` for bootstrap detection. TOTP secrets are pre-provisioned from the installer secrets directory during bootstrap.
7. **Initializes the budget-redis instance** with `noeviction` policy and seeds default org-cap, group, and individual budget tiers (v1.0).
8. **Starts the Container Pool Manager** which pre-warms per-identity isolation containers and begins self-healing monitors (v1.0).

If this process fails (e.g., because Postgres is not yet ready), backoffice will retry with exponential backoff for up to 5 minutes before exiting. Check `docker compose logs backoffice` and `docker compose logs postgres` together if the backoffice container restarts repeatedly.

> **Tip:** If you are connecting to an external Postgres instance rather than the bundled container, set `YASHIGANI_DB_DSN` explicitly in `.env` before starting. The bootstrap script will skip password generation and use your provided DSN directly, but will still run Alembic migrations.

---

### 4.6 First-Run Credentials

After a successful bootstrap, retrieve all generated credentials with:

```bash
docker compose logs backoffice | grep -A 30 "FIRST-RUN"
```

The block looks like this:

```
FIRST-RUN CREDENTIALS — SAVE THESE NOW, SHOWN ONCE
====================================================
Admin account:        admin@example.com
Admin password:       <36-char-random>
Redis password:       <36-char-random>
Postgres password:    <36-char-random>
Grafana admin pass:   <36-char-random>
Prometheus basic auth hash:  <bcrypt hash>
====================================================
```

These passwords are stored in `docker/secrets/`. You should:

1. Copy all credentials to your password manager or secrets vault immediately.
2. Log in to the admin panel at `https://your-domain/admin`.
3. Navigate to Admin → Account → Change Password to set a memorable password (or SSO once configured).
4. Enroll TOTP (Admin → Account → Two-Factor Authentication) before sharing admin access with anyone else.

> **Warning:** The credentials are printed to logs only once. If you lose them before saving, you can retrieve each value from the corresponding file in `docker/secrets/` on the host filesystem. However, treat those files as sensitive — ensure they are readable only by the Docker daemon user.

---

## 5. License Activation

### 5.1 Community Tier

No action required. Community tier is active by default with no license file. Feature limits apply: 5 agents, 10 end users, 2 admin seats, no SSO. Licensed under Apache 2.0.

### 5.2 Starter, Professional, Professional Plus, and Enterprise Tiers

A `.ysg` license file is provided by Yashigani after purchase. Activate it using any of the following methods:

**Method A — Via installer:**

```bash
./install.sh --license-key /path/to/your/license.ysg
```

**Method B — Via admin panel (post-install):**

1. Log in to the admin panel.
2. Navigate to Admin → License → Upload License.
3. Upload your `.ysg` file and click Activate.
4. The panel confirms activation and shows your tier, seat count, and expiry date.

**Method C — Via Docker secret (before starting):**

```bash
mkdir -p docker/secrets
cp /path/to/your/license.ysg docker/secrets/license_key
```

Then in `.env`:

```dotenv
YASHIGANI_LICENSE_FILE=/run/secrets/license_key
```

**Method D — Via environment variable:**

```dotenv
YASHIGANI_LICENSE_FILE=/absolute/path/to/license.ysg
```

### 5.3 What Changes After License Activation

| Feature | Community | Starter | Professional | Professional Plus | Enterprise |
|---|---|---|---|---|---|
| Agent limit | 5 | 100 | 500 | 2,000 | Unlimited |
| End user limit | 10 | 250 | 1,000 | 10,000 | Unlimited |
| Admin seat limit | 2 | 25 | 50 | 200 | Unlimited |
| Organization limit | 1 | 1 | 1 | 5 | Unlimited |
| OIDC SSO | No | Yes | Yes | Yes | Yes |
| SAML v2 SSO | No | No | Yes | Yes | Yes |
| SCIM Provisioning | No | No | Yes | Yes | Yes |
| KMS integrations | Docker only | All | All | All | All |
| Audit log export | No | Yes | Yes | Yes | Yes |
| Annual price | Free | See agnosticsec.com/pricing | See agnosticsec.com/pricing | See agnosticsec.com/pricing | Custom |
| SLA support | Community (Apache 2.0) | Email | Business hours | Business hours+ | 24/7 named |

---

## 6. KMS Configuration

Yashigani stores all sensitive credentials (API keys, passwords, tokens) through its Key Management Service (KMS) abstraction layer. The provider is set via `YASHIGANI_KSM_PROVIDER`.

### 6.1 Docker Secrets (Default, Community)

No configuration required. Secrets are stored as files in `docker/secrets/` on the host and mounted read-only into containers at `/run/secrets/`. The backoffice bootstrap manages creation and rotation.

Verify secrets are present after first run:

```bash
ls -la docker/secrets/
```

### 6.2 AWS Secrets Manager

**Step 1.** Set the provider and credentials in `.env`:

```dotenv
YASHIGANI_KSM_PROVIDER=aws
AWS_DEFAULT_REGION=us-east-1
```

**Step 2a.** If running on an EC2 instance with an IAM instance role, no additional credentials are needed. Ensure the instance role has the following IAM policy:

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:GetSecretValue",
    "secretsmanager:PutSecretValue",
    "secretsmanager:CreateSecret",
    "secretsmanager:DeleteSecret"
  ],
  "Resource": "arn:aws:secretsmanager:us-east-1:*:secret:yashigani/*"
}
```

**Step 2b.** If using static credentials (not recommended for production):

```dotenv
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

All secrets are stored under the prefix `yashigani/` in Secrets Manager.

### 6.3 Azure Key Vault

**Step 1.** Create a Key Vault in Azure and note its URL.

**Step 2.** Set in `.env`:

```dotenv
YASHIGANI_KSM_PROVIDER=azure
AZURE_KEYVAULT_URL=https://your-vault.vault.azure.net
```

**Step 3a.** If using managed identity (recommended for Azure-hosted deployments), assign the `Key Vault Secrets Officer` role to the VM's managed identity. No additional credentials needed.

**Step 3b.** If using a service principal:

```dotenv
AZURE_CLIENT_ID=your-sp-client-id
AZURE_CLIENT_SECRET=your-sp-client-secret
AZURE_TENANT_ID=your-tenant-id
```

### 6.4 GCP Secret Manager

**Step 1.** Enable the Secret Manager API in your GCP project.

**Step 2.** Create a service account with the `Secret Manager Admin` role and download the JSON key.

**Step 3.** Place the key in Docker secrets:

```bash
cp /path/to/gcp-sa-key.json docker/secrets/gcp_sa_key.json
```

**Step 4.** Set in `.env`:

```dotenv
YASHIGANI_KSM_PROVIDER=gcp
GOOGLE_APPLICATION_CREDENTIALS=/run/secrets/gcp_sa_key.json
```

### 6.5 HashiCorp Vault (Optional Profile)

> **Warning:** The bundled Vault container runs in dev mode (`vault server -dev`). Dev mode stores all data in memory — it is lost when the container restarts. Use this for local testing only. For production, deploy Vault externally and point `VAULT_ADDR` at your external Vault cluster.

**Step 1.** Prepare AppRole credentials:

```bash
# Place these files before starting with --profile vault
echo "your-vault-role-id" > docker/secrets/vault_role_id
echo "your-vault-secret-id" > docker/secrets/vault_secret_id
chmod 600 docker/secrets/vault_role_id docker/secrets/vault_secret_id
```

**Step 2.** Set in `.env`:

```dotenv
YASHIGANI_KSM_PROVIDER=vault
VAULT_ADDR=http://vault:8200
```

**Step 3.** Start the stack with the vault profile:

```bash
docker compose --profile vault up -d
```

---

## 7. Inspection Pipeline Configuration

Yashigani uses a two-stage pipeline to detect prompt injection attacks:

- **Stage 1 — FastText first-pass:** A lightweight FastText binary classifier (`fasttext_classifier.bin`) performs a high-speed first-pass scan. This runs on every request with sub-millisecond latency and eliminates clear benign requests from further analysis.
- **Stage 2 — LLM second-pass:** Requests that exceed the FastText suspicion threshold are forwarded to a full LLM for semantic analysis. The LLM is configured via `YASHIGANI_INSPECTION_DEFAULT_BACKEND`.

### 7.1 Ollama (Default — Fully Local)

Ollama runs as a Docker service. An `ollama-init` helper container pulls the configured model on first start.

**Default model:** `qwen2.5:3b` — a fast, accurate 3B-parameter model that runs well on CPU with 4–6 GB RAM.

**Step 1.** To change the model, update `.env`:

```dotenv
OLLAMA_MODEL=llama3.2:3b
```

Any model tag from [ollama.com/library](https://ollama.com/library) is valid.

**Step 2.** Monitor the model pull on first start:

```bash
docker compose logs -f ollama-init
```

The pull can take 2–10 minutes depending on your internet connection and model size.

**Step 3 (optional) — GPU acceleration:**

Starting in v0.8.4, the installer detects your GPU automatically and prints model recommendations. GPU acceleration configuration depends on your hardware:

**NVIDIA:** Open `docker-compose.yml` and uncomment the `deploy.resources` block under the `ollama` service. Requires `nvidia-container-toolkit` (driver 525+):

```yaml
ollama:
  deploy:
    resources:
      reservations:
        devices:
          - driver: nvidia
            count: 1
            capabilities: [gpu]
```

Then restart Ollama:

```bash
docker compose up -d ollama
```

**Apple Silicon (M-series):** GPU acceleration for Ollama is automatic when using Docker Desktop 4.x+ on macOS. No additional configuration is needed. Increase Docker Desktop memory allocation to match your model size (see preflight_check.md Section 4a for recommendations).

**AMD (ROCm):** Requires ROCm-compatible driver and runtime. Contact support for ROCm-specific Compose configuration.

### 7.2 Cloud Backends (Anthropic, Gemini, Azure OpenAI)

Cloud backends are supported on all tiers.

**Step 1.** Register your API key via the admin panel: Admin → KMS → Add Secret. Use the following secret name conventions:

| Backend | Secret Name |
|---|---|
| Anthropic | `anthropic_api_key` |
| Gemini | `gemini_api_key` |
| Azure OpenAI | `azure_openai_key` |

**Step 2.** For Azure OpenAI, also set these in `.env`:

```dotenv
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com
AZURE_OPENAI_DEPLOYMENT=gpt-4o-mini
```

**Step 3.** Set the default backend in `.env`:

```dotenv
YASHIGANI_INSPECTION_DEFAULT_BACKEND=anthropic
```

### 7.3 Fallback Chain

Configure a fallback chain to ensure inspection continues if a backend is unavailable:

```dotenv
YASHIGANI_INSPECTION_FALLBACK_CHAIN=ollama,gemini,fail_closed
```

The gateway tries each backend in order. `fail_closed` means that if all configured backends are unavailable, all requests are blocked until a backend becomes healthy. Omit `fail_closed` to allow requests through when all backends are down (not recommended for production).

### 7.4 Injection Threshold

```dotenv
YASHIGANI_INJECT_THRESHOLD=0.85
```

- Values closer to `0.70` increase sensitivity — more potential injections are caught, but benign requests may be incorrectly blocked.
- Values closer to `0.99` increase permissiveness — fewer false positives, but subtle injections may pass.
- The default of `0.85` is calibrated against Yashigani's internal benchmark dataset and is appropriate for most deployments.

> **Tip:** Start with the default threshold and monitor the Grafana dashboard (Admin → Grafana → Injection Analysis) for false positive and false negative rates over your first week of traffic. Adjust by 0.02–0.03 increments based on observed data.

---

## 8. SSO Configuration (Starter / Professional / Enterprise)

SSO requires a Professional or Enterprise license. Ensure your license is activated before proceeding.

### 8.1 SAML v2

**Step 1.** Retrieve Yashigani's SP metadata from your running instance:

```bash
curl -k https://your-domain/admin/sso/saml/metadata -o yashigani-sp-metadata.xml
```

**Step 2.** Import `yashigani-sp-metadata.xml` into your identity provider (Okta, Azure AD, Google Workspace, Ping, etc.) as a new SAML application.

**Step 3.** Configure the following attribute mappings in your IdP:

| SAML Attribute | Yashigani Mapping |
|---|---|
| `email` or `NameID` | User email |
| `firstName` | First name |
| `lastName` | Last name |
| `groups` | RBAC group membership |

**Step 4.** Download the IdP metadata XML from your IdP.

**Step 5.** Upload the IdP metadata in Yashigani: Admin → SSO → SAML → Upload IdP Metadata.

**Step 6.** Test the SAML flow: Admin → SSO → SAML → Test Configuration. This opens a new browser tab and attempts a SAML authentication round-trip. A green checkmark confirms success.

### 8.2 OpenID Connect

**Step 1.** Register Yashigani as an OIDC client with your IdP. Use the following redirect URI:

```
https://your-domain/admin/oidc/callback
```

Note the `client_id` and `client_secret` assigned by your IdP.

**Step 2.** Store the client secret in KMS via admin panel: Admin → KMS → Add Secret → Name: `oidc_client_secret`.

**Step 3.** Configure OIDC in the admin panel: Admin → SSO → OIDC.

Enter:
- **Issuer URL:** e.g., `https://accounts.google.com` or `https://login.microsoftonline.com/tenant-id/v2.0`
- **Client ID:** from Step 1
- **Scopes:** `openid email profile` (add `groups` if your IdP supports group claims)

**Step 4.** Click Save and then Test Configuration to verify.

### 8.3 SCIM Provisioning

SCIM allows your IdP to automatically provision and deprovision users and groups in Yashigani.

**Step 1.** Generate a SCIM bearer token: Admin → SSO → SCIM → Generate Token. Copy the token — it is shown only once.

**Step 2.** In your IdP's SCIM provisioning settings, configure:
- **SCIM Endpoint:** `https://your-domain/scim/v2`
- **Bearer Token:** the token from Step 1
- **Supported Operations:** Create, Update, Deactivate

**Step 3.** Test the SCIM connection in your IdP. Then enable automatic provisioning.

> **Note:** SCIM provisioning does not override manually created local accounts. If a user exists in both SCIM and local accounts, SCIM takes precedence for attribute updates.

---

## 9. SIEM Integration

### 9.1 None (Default)

No action required. Audit events are stored in Postgres only. Retention is controlled by `YASHIGANI_AUDIT_RETENTION_DAYS` (default: 90 days).

### 9.2 Splunk HEC

**Step 1.** In Yashigani admin: Admin → Audit → SIEM Integration → Add Integration → Splunk HEC.

**Step 2.** Enter:
- **HEC URL:** e.g., `https://splunk.example.com:8088/services/collector`
- **HEC Token:** stored automatically in KMS — enter the token value and Yashigani stores it securely
- **Index:** e.g., `yashigani_audit`
- **Source type:** `_json` or a custom source type

**Step 3.** Click Save and then Send Test Event to verify connectivity.

### 9.3 Elasticsearch

**Step 1.** Admin → Audit → SIEM Integration → Add Integration → Elasticsearch.

**Step 2.** Enter:
- **Elasticsearch URL:** e.g., `https://elastic.example.com:9200`
- **API Key:** stored in KMS
- **Index Pattern:** e.g., `yashigani-audit-{yyyy.MM.dd}`

**Step 3.** Click Save and Send Test Event.

### 9.4 Wazuh (Self-Hosted, Auto-Deploy)

**Step 1.** Start the stack with the Wazuh Compose override:

```bash
docker compose \
  -f docker/docker-compose.yml \
  -f docker/docker-compose.wazuh.yml \
  up -d
```

**Step 2.** Retrieve the auto-generated Wazuh credentials:

```bash
docker compose logs wazuh-manager | grep -A 10 "WAZUH CREDENTIALS"
```

> **Warning:** All Wazuh service passwords are auto-generated using the same 36-character policy as the rest of Yashigani's bootstrap. Save them immediately — same procedure as Section 4.6.

**Step 3.** Access the Wazuh dashboard at: `https://your-domain/admin/wazuh`

Log in with the credentials from Step 2.

**Step 4.** In `.env`, configure the SIEM mode:

```dotenv
YASHIGANI_SIEM_MODE=wazuh
```

---

## 10. Alertmanager Configuration

Alertmanager routes Prometheus alerts to notification channels. Edit `config/alertmanager.yml` to configure receivers.

### 10.1 Slack

```yaml
receivers:
  - name: slack-warnings
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
        channel: '#yashigani-alerts'
        send_resolved: true
```

### 10.2 Email (SMTP)

```yaml
receivers:
  - name: email-ops
    email_configs:
      - to: 'ops-team@example.com'
        from: 'yashigani-alerts@example.com'
        smarthost: 'smtp.example.com:587'
        auth_username: 'yashigani-alerts@example.com'
        auth_password_file: '/run/secrets/smtp_password'
        require_tls: true
```

Store the SMTP password in `docker/secrets/smtp_password`.

### 10.3 PagerDuty

```yaml
receivers:
  - name: pagerduty-critical
    pagerduty_configs:
      - service_key_file: '/run/secrets/pagerduty_key'
        description: '{{ .CommonAnnotations.summary }}'
```

Store the PagerDuty integration key in `docker/secrets/pagerduty_key`.

### 10.4 SMS via Twilio

```yaml
receivers:
  - name: sms-critical
    webhook_configs:
      - url: 'http://gateway:8080/internal/twilio-sms'
        http_config:
          bearer_token_file: '/run/secrets/twilio_token'
```

### 10.5 Three-Channel Escalation Policy

The default `config/alertmanager.yml` ships with a three-tier escalation structure:

- **Warning severity:** Routes to `slack-warnings` + `email-ops`. No page.
- **Critical severity:** Routes to `slack-warnings` + `email-ops` + `pagerduty-critical`. Also triggers SMS if Twilio is configured.
- **Resolved:** Sends resolved notifications to all channels that received the firing alert.

After editing `config/alertmanager.yml`, reload without restarting the container:

```bash
docker compose exec alertmanager \
  wget -q --post-data='' -O - http://localhost:9093/-/reload
```

---

## 10a. Direct Webhook Alert Sinks (v0.7.0)

In addition to the Alertmanager pipeline (section 10), Yashigani v0.7.0 introduced lightweight **direct webhook alerting** to Slack, Microsoft Teams, and PagerDuty. These sinks are configured entirely within the backoffice and fire on security-critical events within the same request cycle — no separate Alertmanager configuration required.

Direct sinks are ideal for small deployments or teams that need immediate security event notifications without standing up the full observability stack.

### 10a.1 Configure via Backoffice

Navigate to Admin → Settings → Alert Sinks.

| Field | Description |
|-------|-------------|
| Slack incoming webhook URL | Create at api.slack.com → Apps → Incoming Webhooks |
| Microsoft Teams webhook URL | Create in Teams → Channel → Connectors → Incoming Webhook |
| PagerDuty routing key | Events API v2 key from PagerDuty → Service → Integrations |

Leave any field empty to disable that sink. All three can be active simultaneously.

### 10a.2 Configure via API

```bash
curl -X PUT https://your-domain/admin/alerts/config \
  -H "Cookie: yashigani_session=YOUR_SESSION_COOKIE" \
  -H "Content-Type: application/json" \
  -d '{
    "slack_webhook_url": "https://hooks.slack.com/services/T.../B.../...",
    "teams_webhook_url": "https://outlook.office.com/webhook/...",
    "pagerduty_routing_key": "your-pd-routing-key",
    "alert_on_credential_exfil": true,
    "alert_on_anomaly_threshold": true,
    "license_expiry_warning_days": 14,
    "license_limit_warning_pct": 90
  }'
```

### 10a.3 Test a Sink

```bash
curl -X POST https://your-domain/admin/alerts/test/slack \
  -H "Cookie: yashigani_session=YOUR_SESSION_COOKIE"
```

Replace `slack` with `teams` or `pagerduty` for the other sinks. Returns `{"status": "delivered", "sink": "slack"}` on success.

### 10a.4 Trigger Events

| Event | Trigger condition |
|-------|------------------|
| Credential exfil | Fired immediately on detection within the inspection pipeline (v0.7.1) |
| Licence expiry warning | Fired once per calendar day when `days_until_expiry ≤ license_expiry_warning_days` (v0.7.1) |

> **Note:** Direct alert sinks complement Alertmanager — they are not a replacement. Alertmanager remains the recommended path for metric-based alerts, multi-team routing, and deduplication. Direct sinks are for security event push notifications.

---

## 11. Agent Registration

### 11.1 Via Admin Panel

**Step 1.** Navigate to Admin → Agents → Register Agent.

**Step 2.** Fill in:
- **Name:** A unique identifier for this agent (e.g., `code-assistant`, `data-analyst`).
- **Description:** Human-readable description.
- **Upstream Path Prefix:** The path prefix in the MCP server that this agent's tools are registered under (e.g., `/tools/code`).

**Step 3.** Click Register. The auto-generated token is displayed. This is the only time the full token is shown. Copy it to your secrets manager immediately.

**Step 4.** Configure your MCP client to include the token in its `Authorization: Bearer` header when connecting to Yashigani's gateway.

### 11.2 Via API

```bash
curl -X POST https://your-domain/admin/agents \
  -H "Cookie: yashigani_session=YOUR_SESSION_COOKIE" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-agent",
    "description": "Production code assistant agent",
    "path_prefix": "/tools/code",
    "allowed_cidrs": ["10.0.0.0/8", "192.168.1.0/24"]
  }'
```

The response includes the generated token and a `quick_start` snippet:

```json
{
  "id": "agt_abc123",
  "name": "my-agent",
  "token": "ey...full-64-char-token...",
  "created_at": "2026-03-27T12:00:00Z",
  "quick_start": {
    "curl": "curl -X POST https://<your-gateway-url>/mcp \\\n  -H 'Authorization: Bearer ey...' \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":1}'",
    "python_httpx": "import httpx\nclient = httpx.Client(\n    base_url='https://<your-gateway-url>',\n    headers={'Authorization': 'Bearer ey...'}\n)\nresp = client.post('/mcp', json={'jsonrpc':'2.0','method':'tools/list','id':1})",
    "health_check": "curl https://<your-gateway-url>/health -H 'Authorization: Bearer ey...'"
  }
}
```

> **Note:** Token minimum length is controlled by `YASHIGANI_AGENT_TOKEN_MIN_LENGTH` (default: 64). Tokens shorter than this value are rejected. For high-security environments, set this to 128.

### 11.4 IP Allowlisting (v0.7.0)

Restrict which source IPs can use an agent token by setting `allowed_cidrs` at registration time or via the edit form. An empty list (default) means no IP restriction — any source IP may use the token once it passes PSK verification.

```json
{
  "allowed_cidrs": ["10.0.0.0/8", "172.16.0.0/12"]
}
```

When a request arrives from an IP outside the allowlist, the gateway returns HTTP 403 and writes an `IPAllowlistViolationEvent` to the audit log including the violating IP and agent ID. IPv4 and IPv6 CIDR notation are both supported.

### 11.3 Tier Limits

- **Community:** 20 agents · 50 end users · 10 admin seats. Returns HTTP 402 when any limit is reached.
- **Starter:** 100 agents · 250 end users · 25 admin seats. OIDC SSO enabled.
- **Professional:** 500 agents · 1,000 end users · 50 admin seats. Full SSO (SAML + OIDC + SCIM).
- **Professional Plus:** 2,000 agents · 10,000 end users · 200 admin seats · 5 orgs.
- **Enterprise:** Unlimited on all dimensions.

---

## 12. Rate Limiting Configuration

Rate limiting is implemented in Redis using a sliding window algorithm.

### 12.1 Global Rate Limits

Configure global defaults in the admin panel: Admin → Rate Limiting.

Set:
- **Requests per minute per agent token** (default: 100)
- **Requests per minute per source IP** (default: 200)
- **Burst allowance** (default: 20% above the per-minute rate)

### 12.2 Per-Endpoint Overrides

Some MCP tool endpoints have different latency and cost profiles and should have tighter or looser limits.

Admin → Rate Limiting → Endpoint Overrides → Add Override.

Enter:
- **Path pattern:** e.g., `/tools/execute` or `/tools/*`
- **Requests per minute:** override value
- **Applies to:** All agents, or a specific agent

### 12.3 RBAC Group Overrides

Privileged user groups (e.g., `admin`, `power-users`) can be granted higher rate limits.

Admin → RBAC → Groups → select group → Set Rate Limit Override.

Enter the per-minute request limit for members of this group.

### 12.4 Adaptive Throttle Thresholds (v0.7.0)

The adaptive rate limiter reduces effective limits when the Resource Pressure Index (RPI) exceeds configurable thresholds. These thresholds are now runtime-configurable without a gateway restart:

| Threshold | Default | Effect |
|-----------|---------|--------|
| `rpi_scale_medium` | 0.80 | Requests scaled to 80% of limit |
| `rpi_scale_high` | 0.50 | Requests scaled to 50% of limit |
| `rpi_scale_critical` | 0.25 | Requests scaled to 25% of limit |

Update via Admin → Rate Limiting → Adaptive Thresholds. Changes take effect on the next request cycle. All threshold changes are written to the audit log as `RateLimitThresholdChangedEvent` with previous and new values.

> **Tip:** After any rate limit change, verify it is in effect by watching the Redis key for your agent: `docker compose exec redis redis-cli keys "rl:*"`. Changes take effect within 60 seconds.

---

## 13. Kubernetes Deployment

### 13.1 Prerequisites

- `kubectl` configured and pointing at your target cluster.
- Helm v3.10+.
- cert-manager installed in the cluster (recommended for TLS).
- An ingress controller (nginx-ingress recommended).

### 13.2 Install via Installer Script

```bash
./install.sh --mode k8s --namespace yashigani
```

The installer detects the `--mode k8s` flag and runs the Helm flow instead of Docker Compose.

### 13.3 Manual Helm Install

**Step 1.** Update Helm dependencies:

```bash
helm dependency update helm/yashigani
```

**Step 2.** Install or upgrade the release:

```bash
helm upgrade --install yashigani helm/yashigani \
  --namespace yashigani \
  --create-namespace \
  --set gateway.env.upstreamUrl=http://mcp-server.default.svc.cluster.local:8080 \
  --set global.tlsDomain=yashigani.example.com \
  --set global.tlsMode=acme
```

**Step 3.** Monitor the rollout:

```bash
kubectl rollout status deployment/yashigani-backoffice -n yashigani
kubectl rollout status deployment/yashigani-gateway -n yashigani
```

**Step 4.** Retrieve first-run credentials:

```bash
kubectl logs -n yashigani \
  -l app.kubernetes.io/component=backoffice \
  --tail=200 | grep -A 30 "FIRST-RUN"
```

### 13.4 Key Helm Values

| Helm Value | Description | Example |
|---|---|---|
| `global.tlsDomain` | Your FQDN | `yashigani.example.com` |
| `global.tlsMode` | TLS mode | `acme` |
| `gateway.env.upstreamUrl` | MCP backend URL | `http://mcp-server:8080` |
| `gateway.image.tag` | Gateway image tag | `v1.0.0` |
| `backoffice.image.tag` | Backoffice image tag | `v1.0.0` |
| `redis.existingSecretName` | Use existing Redis secret | `my-redis-secret` |
| `caddy.enabled` | Enable/disable Caddy | `false` (if using nginx-ingress) |
| `ollama.enabled` | Enable/disable local Ollama | `false` (if using cloud backend) |

### 13.5 Using nginx-ingress Instead of Caddy

In Kubernetes, Caddy is typically replaced by an ingress controller. Set:

```bash
helm upgrade --install yashigani helm/yashigani \
  --namespace yashigani \
  --set caddy.enabled=false \
  --set ingress.enabled=true \
  --set ingress.className=nginx \
  --set ingress.tls.enabled=true \
  --set ingress.tls.certManagerIssuer=letsencrypt-prod
```

---

## 14. Production Hardening Checklist

Run through this checklist before exposing Yashigani to production traffic.

### Security

- [ ] TLS mode is `acme` or `ca` — confirm `selfsigned` is not set
- [ ] Admin password has been changed from the first-run generated value
- [ ] TOTP (two-factor authentication) is enrolled for all admin accounts
- [ ] Minimum 2 admin accounts are configured (avoids single point of lockout)
- [ ] Redis password is set and present in `docker/secrets/redis_password`
- [ ] Postgres password is set and not the default
- [ ] KMS provider is set to a managed service (`aws`, `azure`, `gcp`) — not `docker` for production
- [ ] Container seccomp profiles are enabled (verify: `docker inspect yashigani-gateway-1 | grep -i seccomp`)
- [ ] AppArmor profiles are applied on Linux hosts
- [ ] No non-edge service ports are bound to `0.0.0.0` on the host

### Configuration

- [ ] `YASHIGANI_DEPLOY_STREAM` is set correctly (`corporate` or `saas` for licensed deployments)
- [ ] `YASHIGANI_AUDIT_RETENTION_DAYS` is configured per your compliance requirements
- [ ] OPA policy in `config/policy.rego` has been reviewed and customized for your use case
- [ ] `YASHIGANI_INJECT_THRESHOLD` is tuned based on observed traffic (default 0.85 is a starting point)
- [ ] Rate limits are configured appropriately for expected traffic volume
- [ ] License key is activated (Admin → License) for Professional/Enterprise features

### Observability

- [ ] Prometheus is accessible at `https://your-domain/metrics-federate` (with basic auth)
- [ ] Grafana dashboards load correctly at `https://your-domain/admin/grafana`
- [ ] Jaeger trace UI loads at `https://your-domain/admin/jaeger`
- [ ] Alertmanager receivers are configured (not just the default null receiver)
- [ ] A test alert has been sent to verify each notification channel

### Data and Backup

- [ ] Ollama model is pulled and the ollama service reports `healthy`
- [ ] SIEM integration is configured and a test event has been sent successfully
- [ ] Backup is configured for the `postgres_data` Docker volume (e.g., pg_dump cron, Velero in K8s)
- [ ] Backup for `redis_data` volume is configured (or Redis is configured as non-persistent cache-only)

---

## 15. Troubleshooting

### Gateway won't start

**Symptom:** `yashigani-gateway-1` exits immediately or enters a restart loop.

**Check:**

```bash
docker compose logs gateway
```

**Common causes:**
- `UPSTREAM_MCP_URL` is not set or the URL is unreachable. Verify the MCP server is running and accessible from within the Docker network: `docker compose exec gateway curl -v $UPSTREAM_MCP_URL`
- Postgres is not yet healthy. Gateway waits for Postgres but has a finite retry limit. Check: `docker compose logs postgres`

---

### Caddy ACME fails (TLS certificate not issued)

**Symptom:** Caddy logs contain `error obtaining certificate` or `ACME challenge failed`.

**Check:**

```bash
docker compose logs caddy
```

**Common causes:**
- DNS A record is not pointing to the server's public IP. Run `dig +short your-domain.example.com` from an external resolver.
- Port 80 is blocked by a firewall or cloud security group.
- Another process is using port 80 on the host.

---

### Ollama model not loaded

**Symptom:** Inspection requests fail with `backend unavailable: ollama`.

**Check:**

```bash
docker compose logs ollama-init
docker compose logs ollama
```

**Common causes:**
- `ollama-init` timed out during model pull. Re-run it: `docker compose restart ollama-init`
- Insufficient disk space for the model. Check: `df -h /var/lib/docker`
- Ollama container is running but the model is not loaded. Manually pull: `docker compose exec ollama ollama pull qwen2.5:3b`

---

### Backoffice login fails

**Symptom:** Cannot log in to the admin panel with the generated credentials.

**Check:**

```bash
docker compose logs backoffice | grep -i "FIRST-RUN\|error\|password"
```

**Common causes:**
- You are using the wrong credentials. The first-run block is printed only once — search the logs carefully.
- The admin account email in `YASHIGANI_ADMIN_USERNAME` has a typo. Check `.env`.
- A previous partial bootstrap left the database in an inconsistent state. Reset by removing the `postgres_data` volume (warning: deletes all data): `docker compose down -v && docker compose up -d`

---

### Rate limiting not working

**Symptom:** Requests are not being rate-limited even at high request rates.

**Check:**

```bash
docker compose exec redis redis-cli ping
docker compose exec redis redis-cli keys "rl:*"
```

**Common causes:**
- Redis is unhealthy. Restart it: `docker compose restart redis`
- Rate limiting is configured but the agent token is not being sent by the client (rate limiting is per-token). Verify the `Authorization: Bearer` header is present in requests.

---

### SSO login fails (SAML or OIDC)

**Symptom:** Users are redirected back to the login page after authenticating with the IdP.

**Check:**

```bash
docker compose logs backoffice | grep -i "sso\|saml\|oidc\|auth"
```

**Common causes:**
- IdP metadata is outdated. Re-download and re-upload in Admin → SSO.
- The SAML assertion audience does not match Yashigani's entity ID. Verify the SP metadata URL in your IdP configuration matches `https://your-domain/admin/sso/saml/metadata`.
- For OIDC: the redirect URI registered with the IdP does not exactly match `https://your-domain/admin/oidc/callback`.

---

### License not activating

**Symptom:** After uploading the license, it shows as invalid or the tier does not update.

**Common causes:**
- The license `.ysg` file is corrupted or incomplete. Verify the file size matches what was provided.
- The license is issued for a different organization domain than `YASHIGANI_ADMIN_USERNAME`. The license domain must match the admin email domain.
- The license has expired. Check the expiry date with: `openssl cms -verify -noverify -in license.ysg -inform DER -noout -text`

---

### Postgres migrations failed

**Symptom:** Backoffice logs show Alembic errors; the admin panel returns 500 errors.

**Check:**

```bash
docker compose logs backoffice | grep -i "alembic\|migration\|error"
```

**Common causes:**
- Postgres was not ready when backoffice started and the retry limit was exceeded. Restart backoffice after confirming Postgres is healthy: `docker compose restart backoffice`
- A migration was previously run against a different schema version. Contact support with the full Alembic error message.

---

## 16. Upgrade Procedure

### 16.0 Via update.sh (Recommended — v0.8.4+)

For existing installations at v0.8.4 or later, use the `update.sh` script. It handles backup, pull, restart, migration, and automatic rollback in a single command:

```bash
./update.sh
```

For a specific target version:

```bash
./update.sh --version v1.0.0
```

`update.sh` automatically backs up `.env`, `docker/secrets/`, and `config/` before pulling new images. If the backoffice fails to reach a healthy state within the timeout, it restores the pre-update backup and brings up the previous image versions.

> **Note:** Take a Postgres volume snapshot before running any update. See Section 4.5 and the tip at the end of Section 16.2 for the snapshot command.

### 16.1 Via Installer (Legacy Path)

```bash
./install.sh --upgrade
```

The installer pulls the latest images, checks for breaking `.env` changes, backs up your current `.env` to `.env.bak`, and restarts the stack. Alembic migrations run automatically. Prefer `update.sh` for v0.8.4+ installations.

### 16.2 Manual Upgrade

**Step 1.** Pull the latest changes from Git (if running from source):

```bash
git fetch origin
git checkout v1.0.0   # replace with target version
```

**Step 2.** Pull updated images:

```bash
docker compose pull
```

**Step 3.** Restart the stack, removing any containers whose image or configuration has changed:

```bash
docker compose up -d --remove-orphans
```

**Step 4.** Verify Alembic migrations ran successfully:

```bash
docker compose logs backoffice | grep -i "alembic\|migration\|upgrade"
```

A successful migration looks like:

```
INFO  [alembic.runtime.migration] Running upgrade abc123 -> def456, add_rbac_group_overrides
INFO  [alembic.runtime.migration] Running upgrade def456 -> ghi789, add_scim_tokens
```

**Step 5.** Confirm all services are healthy:

```bash
docker compose ps
```

**Step 6.** Log in to the admin panel and verify the version shown in Admin → About matches the new version.

> **Warning:** Never skip Alembic migrations by manually editing the database. The `alembic_version` table must always reflect the true schema state. If you need to roll back a migration, use `docker compose exec backoffice alembic downgrade -1` and consult the changelog for breaking changes.

> **Tip:** Before any upgrade in production, take a snapshot of the `postgres_data` volume: `docker run --rm -v yashigani_postgres_data:/data -v $(pwd):/backup alpine tar czf /backup/postgres-backup-$(date +%Y%m%d).tar.gz -C /data .`

---

## 17. Optional Agent Bundles (v0.8.0)

> **Disclaimer:** These third-party agent containers are provided **AS IS** by Agnostic Security as a courtesy integration. Image digests are pinned to upstream-tagged releases and updated as part of the Yashigani release cycle. **All support, bug reports, and feature requests must go to the upstream maintainers.** Agnostic Security accepts no support obligation for these integrations.

Three agent bundles are available as opt-in installs. They are **not installed by default** but work out of the box with the `--agent-bundles` flag. The installer auto-registers agents via the backoffice API and writes PSK tokens to `docker/secrets/`. In v1.0, agent bundles use the unified identity model with the `kind` field to distinguish human and service identities.

| Agent | Stack | License | Integration | Compose Profile |
|-------|-------|---------|-------------|-----------------|
| LangGraph | Python | Apache 2.0 | MCP → Yashigani → tools | `langgraph` |
| Goose | Python | Apache 2.0 | MCP → Yashigani → tools | `goose` |
| OpenClaw | Node.js 24 | TBD (verify at openclaw.ai) | OpenClaw Gateway (:18789) → Yashigani → LLMs | `openclaw` |

### 17.1 Docker Compose — Opt-In via Profiles

**Interactive installer (v0.8.4+):** The installer presents a numbered menu:

```
Available agent bundles:

    1) LangGraph   — Python MCP-native orchestration (Apache 2.0)
    2) Goose       — Python MCP-native dev assistant (Apache 2.0)
    3) OpenClaw    — Node.js 24 personal AI, 30+ channels (~800 MB, license TBD)
    4) All of the above
    0) None — skip agent bundles

  Enter your choices (comma-separated, e.g. 1,3 or 4 for all) [0]:
```

**Non-interactive / CLI:** Use `--agent-bundles` with comma-separated names:

```bash
./install.sh --agent-bundles langgraph,goose
```

Or activate manually after install:

```bash
docker compose --profile langgraph up -d
docker compose --profile goose up -d
docker compose --profile openclaw up -d
```

> **OpenClaw note:** The Node.js 24 image is approximately 800 MB — significantly larger than the Python agent images (~200 MB). Ensure you have sufficient disk space before enabling OpenClaw. OpenClaw runs its own Gateway on port **18789**, which must be reachable by incoming messaging channel webhooks.

### 17.2 Kubernetes (Helm) — Values Toggles

Enable per agent via Helm values:

```bash
helm upgrade yashigani ./helm/yashigani \
  --set agentBundles.langgraph.enabled=true \
  --set agentBundles.goose.enabled=true
```

Or in your values override file:

```yaml
agentBundles:
  langgraph:
    enabled: true
  goose:
    enabled: true
  openclaw:
    enabled: true
    # OpenClaw exposes port 18789 via its own Gateway service
```

### 17.3 Backoffice API

The backoffice exposes bundle metadata and the disclaimer via:

| Endpoint | Description |
|----------|-------------|
| `GET /admin/agent-bundles` | List all bundles with metadata and disclaimer |
| `GET /admin/agent-bundles/disclaimer` | Disclaimer text for UI banner rendering |

### 17.4 Agent Token Auto-Registration

The installer auto-registers agent bundles via the backoffice API at install time. When an agent bundle container starts, it uses the token in its secret file to authenticate with Yashigani's agent registry. In v1.0, all identities (human and service) share a unified identity model with a `kind` field (`human` or `service`); agent bundles are registered as `kind: service`. The installer generates these tokens and places them in:

- **Compose:** `docker/secrets/{name}_token`
- **Helm:** Kubernetes Secret `yashigani-{name}-token` (must be pre-created before install)

Each bundle is assigned a **restricted RBAC policy** by default — it can only reach LLM provider paths and is not granted access to internal Yashigani management endpoints. The OPA data document is pre-populated with the bundle agent entries immediately after bootstrap. In v1.0, routing decisions for agent bundles are also governed by `policy/v1_routing.rego` and the Optimization Engine's 4-signal routing logic (P1-P9 priority levels).

---

---

## 18. Response Path Inspection (v0.9.0)

v0.9.0 adds `ResponseInspectionPipeline` — a bidirectional inspection layer that applies the same FastText + LLM fallback pipeline to upstream responses before they are returned to the client. This closes the indirect prompt injection vector where a malicious upstream response could hijack an agent's next action.

### 18.1 How It Works

- Upstream responses pass through FastText first-pass (sub-5ms, offline).
- Responses that exceed the suspicion threshold are forwarded to the configured LLM backend for semantic analysis.
- **BLOCKED** verdict: the gateway returns `502 Bad Gateway` to the client. The upstream response is not forwarded. The audit event records `response_inspection_verdict: BLOCKED` and emits a `RESPONSE_INJECTION_DETECTED` event.
- **FLAGGED** verdict: the response is forwarded to the client with the header `X-Yashigani-Response-Verdict: FLAGGED`. The audit event records the verdict.
- **CLEAN** verdict: the response is forwarded normally.

### 18.2 Per-Agent Configuration

Response inspection is configurable per agent via the admin panel (Admin → Agents → Edit) or the API:

```json
{
  "response_inspection": {
    "enabled": true,
    "fasttext_only": false,
    "exempt_content_types": ["application/json"]
  }
}
```

| Field | Default | Notes |
|-------|---------|-------|
| `enabled` | `true` | Set `false` to disable response inspection for this agent (not recommended) |
| `fasttext_only` | `false` | Skip the LLM second-pass; use only the FastText classifier. Reduces latency at the cost of accuracy. |
| `exempt_content_types` | `["application/json"]` | Content types that bypass inspection entirely (e.g., binary blobs, media files) |

### 18.3 `.env` Settings

```dotenv
YASHIGANI_INSPECT_RESPONSES=true        # Enable/disable globally (default: true)
YASHIGANI_RESPONSE_THRESHOLD=0.85       # Suspicion threshold for response classifier (default: matches request threshold)
```

---

## 19. WebAuthn / Passkeys Configuration (v0.9.0)

v0.9.0 adds phishing-resistant WebAuthn/Passkey MFA for backoffice admin accounts. Supported authenticators include: Face ID, Touch ID, Windows Hello, Android biometrics, YubiKey (FIDO2), and other FIDO2-compatible hardware tokens.

### 19.1 Registration

Admin users register a passkey via the backoffice:

1. Log in with username + password (and TOTP if enrolled).
2. Navigate to Admin → Account → Security → Passkeys → Register New Passkey.
3. The browser presents the platform authenticator (Face ID / Windows Hello) or prompts for a hardware key.
4. On success, the credential is stored encrypted with `pgp_sym_encrypt` in the `webauthn_credentials` table.

The following audit event is emitted: `WEBAUTHN_CREDENTIAL_REGISTERED`.

### 19.2 Authentication

Once a passkey is registered:

1. The login form presents a **Use Passkey** button alongside the password field.
2. The browser's platform authenticator handles the challenge locally — no credential material leaves the device.
3. The server verifies the assertion via `py_webauthn`.
4. Session is established. TOTP is not required if authentication succeeded via WebAuthn.

The following audit event is emitted: `WEBAUTHN_CREDENTIAL_USED`.

### 19.3 Credential Management

View and delete credentials: Admin → Account → Security → Passkeys.

```bash
# List credentials via API:
curl -H "Authorization: Bearer $TOKEN" \
  https://your-domain/auth/webauthn/credentials

# Delete a credential:
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  https://your-domain/auth/webauthn/credentials/{credential_id}
```

Deleting the last registered passkey falls back to TOTP (if enrolled) or password-only. The audit event `WEBAUTHN_CREDENTIAL_DELETED` is emitted on deletion.

### 19.4 `.env` Settings

```dotenv
YASHIGANI_WEBAUTHN_RP_ID=your-domain.example.com   # Relying Party ID (must match FQDN)
YASHIGANI_WEBAUTHN_RP_NAME=Yashigani               # Human-readable RP name shown in authenticator dialogs
YASHIGANI_WEBAUTHN_ORIGIN=https://your-domain.example.com  # Must match the exact origin of the backoffice
```

> **Note:** `YASHIGANI_WEBAUTHN_RP_ID` and `YASHIGANI_WEBAUTHN_ORIGIN` must be set to your actual domain. Passkey registration and authentication will fail if these values do not match the browser's current origin.

---

## 20. Credential Summary and Dual Admin Accounts (v0.9.1)

### 20.1 Dual Admin Accounts

Starting with v0.9.1, the installer creates two independent admin accounts during the bootstrap phase. Both accounts receive random themed usernames drawn from an animals/flowers/robots wordlist (e.g. "phoenix", "condor"). Each account receives:

- A unique 36-character cryptographically random password (generated with `openssl rand -base64 48`)
- An independent TOTP secret key and `otpauth://` URI (pre-provisioned during bootstrap from installer secrets)

This design eliminates the most common post-install lockout scenario: losing access to the single admin account due to a forgotten password or lost TOTP device.

> **Operational guidance:** Store the credentials for both accounts in separate entries in your password manager, ideally accessible to at least two members of your operations team. Never store both admin credentials in the same vault entry.

### 20.2 HIBP Breach Check at Install

The installer performs a Have I Been Pwned (HIBP) k-Anonymity check on all generated passwords before writing them to disk or starting the stack. The check works as follows:

1. The SHA-1 hash of each password is computed.
2. The first 5 characters of the hash are sent to `api.pwnedpasswords.com/range/{prefix}`.
3. The response contains all suffixes matching that prefix. If the full hash is found, the password has been seen in a known breach.
4. A matching password is discarded and a new one is generated and re-checked.
5. If the HIBP API is unreachable (network error, timeout), the check is skipped and installation continues — the HIBP check is **fail-open** and never blocks installation.

Only the first 5 hex characters of the hash are transmitted. The full password and full hash are never sent to HIBP or any external service.

### 20.3 HIBP Integration in Backoffice Auth

The `password.py` module in the backoffice checks every password change (user-initiated or admin-initiated) against the HIBP breach database using the same k-Anonymity method. A `PasswordBreachedError` exception is raised if the submitted password is found in the breach database, and the change is rejected with a user-facing error: "This password has appeared in a data breach. Please choose a different password."

This satisfies **OWASP ASVS V2.1.7**: "Verify that passwords submitted during account registration, login, and password change are checked against a set of breached passwords."

The check is fail-open: if the HIBP API is unreachable, the password change proceeds normally. Availability of the HIBP service never blocks authentication.

### 20.4 One-Time Credential Summary

At the end of install, a credential summary block is printed to the terminal once. It contains:

- Both admin usernames and passwords
- Both admin TOTP secret keys
- Both admin `otpauth://` TOTP URIs (scan with any TOTP app)
- All infrastructure passwords (Postgres, Redis, Grafana, Prometheus)
- The AES-256-GCM column encryption key

The block is preceded by a red warning banner:

```
============================================================
  WARNING: These credentials will NOT be shown again.
  Save them immediately to a secure password manager.
============================================================
```

All credentials are also written to `docker/secrets/` with chmod 600. On upgrade, existing secrets files are preserved and not overwritten.

> **Post-install:** To retrieve a stored secret after install, read the relevant file directly: `cat docker/secrets/admin_password_1`. Do not expose these files to other users or processes.

---

## 21. Open WebUI Configuration (v1.0)

v1.0 integrates Open WebUI as the primary chat interface, served at `/chat/*` behind Caddy. Open WebUI uses trusted headers injected by the gateway for seamless identity propagation.

### 21.1 Routing

Caddy routes all `/chat/*` requests to the Open WebUI container. Authentication is handled by the gateway before the request reaches Open WebUI — the gateway injects trusted headers (`X-Yashigani-User-Id`, `X-Yashigani-User-Kind`, `X-Yashigani-Groups`) that Open WebUI consumes for session establishment.

### 21.2 `.env` Settings

```dotenv
YASHIGANI_OPENWEBUI_ENABLED=true              # Enable Open WebUI (default: true in v1.0)
YASHIGANI_OPENWEBUI_TRUSTED_HEADER=X-Yashigani-User-Id   # Header containing authenticated user identity
```

### 21.3 Disabling Open WebUI

Set `YASHIGANI_OPENWEBUI_ENABLED=false` in `.env` and restart Caddy. The `/chat/*` routes will return 404.

---

## 22. Optimization Engine (v1.0)

The Optimization Engine provides 4-signal routing with P1-P9 priority levels for all MCP requests.

### 22.1 How It Works

Every incoming request is scored against four signals: identity priority, budget remaining, latency target, and model capability match. The engine assigns a priority level from P1 (highest) to P9 (lowest) and routes to the optimal backend accordingly.

### 22.2 `.env` Settings

```dotenv
YASHIGANI_OPTIMIZATION_ENABLED=true           # Enable Optimization Engine (default: true)
YASHIGANI_OPTIMIZATION_DEFAULT_PRIORITY=P5    # Default priority for unclassified requests
```

### 22.3 OPA Integration

The Optimization Engine consults `policy/v1_routing.rego` as a safety net before executing routing decisions. OPA can override or block routing decisions that violate policy constraints. Additionally, an LLM policy review step can be enabled for high-priority (P1-P3) routing decisions.

---

## 23. Budget System (v1.0)

v1.0 introduces a three-tier budget system: organization cap, group budget, and individual budget. Budget state is stored in a dedicated budget-redis instance with `noeviction` policy to prevent data loss.

### 23.1 Budget Tiers

| Tier | Scope | Description |
|------|-------|-------------|
| Organization cap | Org-wide | Hard ceiling on total spend across the organization |
| Group budget | RBAC group | Allocated from the org cap; shared by all members of a group |
| Individual budget | Per-identity | Allocated from the group budget; per-user or per-service spending limit |

### 23.2 `.env` Settings

```dotenv
BUDGET_REDIS_HOST=budget-redis                # Dedicated Redis instance for budget state
BUDGET_REDIS_PORT=6380                        # Separate from the rate-limiting Redis
BUDGET_REDIS_PASSWORD=<auto-generated>        # Set in .env for Compose interpolation
YASHIGANI_BUDGET_ENABLED=true                 # Enable budget enforcement (default: true)
```

### 23.3 Configuration

Budget tiers are managed via the backoffice: Admin -> Budget -> Organization Cap / Group Budgets / Individual Budgets. The budget system integrates with the unified identity model — budgets can be assigned to both human and service identities via the `kind` field.

---

## 24. Container Pool Manager (v1.0)

The Container Pool Manager provides per-identity container isolation with self-healing and postmortem capabilities.

### 24.1 How It Works

Each identity (human or service) can be assigned an isolated container from a pre-warmed pool. The pool manager monitors container health, automatically replaces failed containers, and generates postmortem reports for container failures.

### 24.2 `.env` Settings

```dotenv
YASHIGANI_POOL_ENABLED=true                  # Enable Container Pool Manager (default: true)
YASHIGANI_POOL_MIN_WARM=5                    # Minimum pre-warmed containers in pool
YASHIGANI_POOL_MAX_CONTAINERS=50             # Maximum containers across all identities
YASHIGANI_POOL_HEALTH_INTERVAL=30            # Health check interval in seconds
```

### 24.3 Postmortem

When a container fails, the pool manager captures logs, resource usage, and the triggering event into a postmortem record stored in PostgreSQL. Postmortems are viewable in the backoffice: Admin -> Pool -> Postmortems.

---

## 25. Multi-IdP Identity Broker (v1.0)

v1.0 adds a multi-IdP identity broker supporting both OIDC and SAML v2, with tier-gated access.

### 25.1 Unified Identity Model

All identities — human users and service accounts — share a single identity model with a `kind` field (`human` or `service`). The identity broker resolves identities from multiple IdPs into this unified model. The `identity/` module handles identity lifecycle, federation, and the `kind` field mapping.

### 25.2 Multiple IdP Support

Multiple OIDC and SAML v2 identity providers can be configured simultaneously. The broker routes authentication requests to the appropriate IdP based on email domain or explicit IdP selection at the login screen.

### 25.3 Tier Gating

| Feature | Community | Starter | Professional | Enterprise |
|---------|-----------|---------|--------------|------------|
| Single OIDC IdP | No | Yes | Yes | Yes |
| Multiple OIDC IdPs | No | No | Yes | Yes |
| Single SAML v2 IdP | No | No | Yes | Yes |
| Multiple SAML v2 IdPs | No | No | No | Yes |
| Multi-IdP broker | No | No | No | Yes |

---

*Yashigani v1.0 — Installation and Configuration Guide — 2026-04-01*
