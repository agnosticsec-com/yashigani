# Yashigani v0.6.0 — Implementation Plan

**Date:** 2026-03-27
**Author:** Maxine (PM/PO — Lead Architect)
**Status:** COMPLETE — 2026-03-27
**Predecessor:** v0.5.0 (PostgreSQL · Multi-sink audit · JWT · OTEL · FastText · Vault · Loki · Wazuh — 114 py files)

---

## 1. Executive Summary

v0.6.0 is the **distribution and monetisation** release. Two parallel tracks:

**Track A — Universal Installer**
A single `install.sh` that works on any Linux distro, macOS (Intel + Apple Silicon), any major
VM hypervisor, and any major cloud provider. Auto-detects OS, CPU architecture, container runtime,
and cloud environment. Installs Docker/Podman if absent, runs the full wizard, bootstraps credentials,
and verifies health — all in one command.

**Track B — Licensing System**
Three product tiers enforced offline via ECDSA P-256 / SHA-256 signature on a JSON license payload.
Public key embedded in the application; private key + certificate held by Yashigani and applied later.
Community tier requires no key; Professional and Enterprise require a signed license file.

| Tier | Key | Agents/MCPs | Orgs | SAML / OIDC / SCIM | Price |
|------|-----|-------------|------|--------------------|-------|
| **Community** | None | 10 | 1 | ✗ | Free |
| **Professional** | Required | Unlimited | 1 | ✓ | Paid |
| **Enterprise** | Required | Unlimited | Unlimited | ✓ | Paid |

---

## 2. Scope

### Track A — Universal Installer (7 scripts, 1 entry point)

#### 2A.1 Platform Detection (`scripts/platform-detect.sh`)
Full rewrite of existing `detect-platform.sh`. Detects and exports:

| Variable | Values |
|----------|--------|
| `YSG_OS` | `linux` \| `macos` |
| `YSG_DISTRO` | `ubuntu` \| `debian` \| `rhel` \| `fedora` \| `amzn` \| `alpine` \| `arch` \| `macos` |
| `YSG_ARCH` | `amd64` \| `arm64` |
| `YSG_CLOUD` | `aws` \| `gcp` \| `azure` \| `digitalocean` \| `hetzner` \| `none` |
| `YSG_VM` | `kvm` \| `vmware` \| `virtualbox` \| `hyperv` \| `none` |
| `YSG_RUNTIME` | `docker` \| `podman` \| `none` |
| `YSG_COMPOSE` | `plugin` \| `standalone` \| `none` |
| `YSG_K8S` | `true` \| `false` (kubectl + helm present) |

Cloud detection via instance metadata APIs (no auth, link-local):
- AWS: `http://169.254.169.254/latest/meta-data/` (IMDSv1 + IMDSv2 token probe)
- GCP: `http://metadata.google.internal/computeMetadata/v1/` (Metadata-Flavor: Google header)
- Azure: `http://169.254.169.254/metadata/instance` (Metadata: true header)
- DigitalOcean: `http://169.254.169.254/metadata/v1/` (DO-specific path check)
- Hetzner: `http://169.254.169.254/` (Hetzner-specific path check)

VM hypervisor detection via `systemd-detect-virt`, `/proc/cpuinfo`, or DMI strings.

#### 2A.2 Runtime Installer (`scripts/install-runtime.sh`)
Installs Docker Engine + Compose plugin if not already present. Per-distro logic:

| Distro family | Method |
|---------------|--------|
| Ubuntu / Debian | `apt-get` + official Docker apt repo |
| RHEL / CentOS / Fedora | `dnf` + docker-ce repo |
| Amazon Linux 2/2023 | `yum` + amazon-linux-extras or dnf |
| Alpine | `apk add docker docker-cli-compose` |
| macOS (Intel) | `brew install --cask docker` |
| macOS (Apple Silicon) | `brew install --cask docker` + Rosetta-free arm64 image |
| Podman (Linux) | `podman-compose` alias shim |

Post-install: start daemon, add current user to `docker` group, verify `docker run hello-world`.

#### 2A.3 Preflight Checks (`scripts/preflight.sh`)
Updated for v0.6.0:
- Required ports: 80, 443 (Caddy), 5432 (Postgres internal), 6379 (Redis internal)
- Disk: ≥ 10 GB free on the Docker data root
- Memory: ≥ 2 GB RAM (4 GB recommended for Ollama)
- DNS: resolve `$YASHIGANI_TLS_DOMAIN` (skip in selfsigned mode)
- Docker daemon: running and responsive
- Docker Compose: v2.x or standalone ≥ 1.29
- CPU arch compatibility: arm64 images available for all services

#### 2A.4 Configuration Wizard (`scripts/wizard.sh`)
Interactive (TTY) or non-interactive (`--non-interactive`) modes.

Collects and writes `.env`:
1. Domain / TLS mode (acme / ca / selfsigned)
2. Admin email
3. License key (optional — skipped = Community tier)
4. Upstream MCP URL
5. KMS provider (docker / aws / azure / gcp / keeper / vault)
6. Cloud-specific: auto-populate region/bucket/key-arn from IMDs on AWS/GCP/Azure
7. Inspection backend (ollama / cloud)
8. Deployment stream (opensource / corporate / saas)
9. SIEM mode (none / splunk / elasticsearch / wazuh)

Non-interactive accepts all via CLI flags and env vars.

#### 2A.5 Main Installer Entry Point (`install.sh`)
Orchestrates everything. One curl-pipe-bash command:

```bash
curl -sSL https://get.yashigani.io | bash
# or with options:
curl -sSL https://get.yashigani.io | bash -s -- \
    --non-interactive \
    --domain yashigani.example.com \
    --admin-email admin@example.com \
    --tls-mode acme \
    --license-key /path/to/license.ysg
```

Execution flow:
```
detect-platform → preflight → [install-runtime] → wizard → docker compose pull
→ bootstrap (generate passwords) → docker compose up -d → health-check → print summary
```

Idempotent: re-running upgrades an existing install.

#### 2A.6 Health Check (`scripts/health-check.sh`)
Post-install verification:
- Gateway `/healthz` → 200
- Backoffice `/healthz` → 200
- Postgres `pg_isready`
- Redis `PING`
- OPA `/health` → 200
- Ollama `/api/tags` → 200
- Print: access URL, first-run credential reminder

#### 2A.7 Uninstaller (`scripts/uninstall.sh`)
- `--keep-data` flag to preserve postgres/audit volumes
- Stops and removes containers
- Optionally removes volumes and config
- Removes generated secrets

---

### Track B — Licensing System (1 module, feature gates, admin API)

#### 2B.1 License Model (`src/yashigani/licensing/model.py`)

```python
class LicenseTier(str, Enum):
    COMMUNITY    = "community"
    PROFESSIONAL = "professional"
    ENTERPRISE   = "enterprise"

@dataclass(frozen=True)
class LicenseState:
    tier: LicenseTier
    org_domain: str          # single domain enforced for community/professional
    max_agents: int          # 10 for community, -1 (unlimited) for paid
    max_orgs: int            # 1 for community/professional, -1 for enterprise
    features: frozenset[str] # "saml", "oidc", "scim", "multi_org"
    issued_at: datetime
    expires_at: datetime | None
    license_id: str | None
    valid: bool
    error: str | None
```

Community defaults (no file, hardcoded):
```python
COMMUNITY_LICENSE = LicenseState(
    tier=LicenseTier.COMMUNITY,
    org_domain="*",
    max_agents=10,
    max_orgs=1,
    features=frozenset(),          # no SSO features
    issued_at=datetime.min,
    expires_at=None,
    license_id=None,
    valid=True,
    error=None,
)
```

#### 2B.2 License Verifier (`src/yashigani/licensing/verifier.py`)

Signature scheme: **ECDSA P-256 with SHA-256** (matches user's "SHA-256 / public-private certificate" spec).

License file format (`.ysg`):
```
{base64url(utf8(json_payload))}.{base64url(ecdsa_p256_sha256_signature)}
```

Payload JSON:
```json
{
  "v": 1,
  "tier": "professional",
  "org_domain": "example.com",
  "max_agents": -1,
  "max_orgs": 1,
  "features": ["saml", "oidc", "scim"],
  "issued_at": "2026-04-01T00:00:00Z",
  "expires_at": "2027-04-01T00:00:00Z",
  "license_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

Embedded public key: PEM stored as a module-level constant in `verifier.py`.
**Placeholder key included now; real Yashigani signing key inserted before production.**

Verification logic:
1. Split on last `.` → payload_b64, sig_b64
2. Decode both
3. Parse payload JSON
4. Verify ECDSA signature (cryptography library — already a v0.5.0 dep)
5. Check `expires_at` ≥ now (if set)
6. Check `v == 1`
7. Return `LicenseState` on success, `LicenseState(valid=False, error=…)` on failure

No network call. 100% offline. Verification cost: < 1 ms.

#### 2B.3 License Loader (`src/yashigani/licensing/loader.py`)

Resolution order:
1. `YASHIGANI_LICENSE_FILE` env var (path to `.ysg` file)
2. `/run/secrets/license_key` (Docker secret)
3. `./license.ysg` in working directory
4. Not found → `COMMUNITY_LICENSE` (never an error)

#### 2B.4 License Enforcer (`src/yashigani/licensing/enforcer.py`)

```python
def require_feature(feature: str) -> None:
    """Raise LicenseFeatureGated(402) if feature not in current license."""

def check_agent_limit(current_count: int) -> None:
    """Raise LicenseLimitExceeded(402) if count >= max_agents and not unlimited."""

def check_org_limit(current_count: int) -> None:
    """Raise LicenseLimitExceeded(402) if count >= max_orgs and not unlimited."""
```

HTTP responses for gated features:
```json
{
  "error": "LICENSE_FEATURE_GATED",
  "feature": "saml",
  "tier": "community",
  "upgrade_url": "https://yashigani.io/pricing",
  "message": "SAML SSO requires Professional or Enterprise license"
}
```
Status: **402 Payment Required**.

#### 2B.5 Feature Gates — Wired Into

| Route / component | Gate |
|-------------------|------|
| `POST /admin/sso/saml/*` | `require_feature("saml")` |
| `POST /admin/sso/oidc/*` | `require_feature("oidc")` |
| `GET/POST /scim/v2/*` | `require_feature("scim")` |
| `POST /admin/agents` | `check_agent_limit(current_count)` |
| `POST /admin/accounts` (new org) | `check_org_limit(current_count)` |

Community tier: username+password+TOTP (`/auth/*`) always unrestricted.
KMS, audit, inspection, rate limiting, OTEL, FastText — all unrestricted in community.

#### 2B.6 License Admin API (`src/yashigani/backoffice/routes/license.py`)

```
GET  /admin/license          — current tier, features, expiry, agent/org usage vs limits
POST /admin/license/activate — upload a .ysg license file, verify + apply immediately
DELETE /admin/license        — revert to community (requires admin confirmation)
```

#### 2B.7 Installer Integration
- Wizard step: "Enter license key file path (optional, press Enter for Community edition)"
- If provided: copy to `/run/secrets/license_key`, verify before proceeding
- If invalid: warn + offer Community fallback
- Post-install summary: print tier, limits, feature availability

#### 2B.8 Signing Infrastructure (Yashigani-internal, not shipped to users)
- `scripts/keygen.py` — generate ECDSA P-256 keypair, output public key PEM + private key PEM
- `scripts/sign_license.py` — take JSON payload + private key, emit `.ysg` file
- Public key placeholder in `verifier.py` replaced with real key before v0.6.0 release
- Private key: never committed to repository

---

## 3. File Inventory

### New files (installer)
```
install.sh
scripts/platform-detect.sh          (replaces scripts/detect-platform.sh)
scripts/install-runtime.sh          (new)
scripts/preflight.sh                (replaces scripts/check-preflight.sh, v0.6.0 updated)
scripts/wizard.sh                   (new)
scripts/health-check.sh             (new)
scripts/uninstall.sh                (new)
```

### New files (licensing)
```
src/yashigani/licensing/__init__.py
src/yashigani/licensing/model.py
src/yashigani/licensing/verifier.py
src/yashigani/licensing/loader.py
src/yashigani/licensing/enforcer.py
src/yashigani/backoffice/routes/license.py
scripts/keygen.py                   (Yashigani-internal, gitignored)
scripts/sign_license.py             (Yashigani-internal, gitignored)
```

### Modified files
```
src/yashigani/backoffice/routes/__init__.py        (add license_router)
src/yashigani/backoffice/app.py                    (add license router)
src/yashigani/backoffice/entrypoint.py             (load + cache license at startup)
src/yashigani/backoffice/routes/scim.py            (add require_feature("scim"))
src/yashigani/sso/oidc.py                          (add require_feature("oidc"))
src/yashigani/sso/saml.py                          (add require_feature("saml"))
src/yashigani/agents/registry.py                   (add check_agent_limit on register)
.gitignore                                         (add scripts/keygen.py, scripts/sign_license.py)
.env.example                                       (add YASHIGANI_LICENSE_FILE)
docker/docker-compose.yml                          (add license secret volume mount)
```

---

## 4. Phase Breakdown

| Phase | Track | Scope | Agent? |
|-------|-------|-------|--------|
| 1 | A | `platform-detect.sh` + `install-runtime.sh` (Linux distros + macOS) | yes |
| 2 | A | `preflight.sh` + `wizard.sh` + `health-check.sh` + `uninstall.sh` | yes |
| 3 | A | `install.sh` main orchestrator (all modes, cloud-aware, idempotent) | yes |
| 4 | B | `licensing/` module (model + verifier + loader + enforcer) | yes |
| 5 | B | Feature gates wired into SSO + SCIM + agents + orgs | yes |
| 6 | B | License admin API (`/admin/license`) + backoffice wiring | yes |
| 7 | B | `keygen.py` + `sign_license.py` + placeholder public key | main |
| 8 | A+B | Installer license step + `.env.example` + compose secret + `.gitignore` | main |

---

## 5. Open Questions

None — all resolved by user spec:
- **Q1 (tiers)**: Community / Professional / Enterprise — RESOLVED ✓
- **Q2 (crypto)**: ECDSA P-256 + SHA-256, public key embedded, private key held by Yashigani — RESOLVED ✓
- **Q3 (community gates)**: No SAML/OIDC/SCIM, max 10 agents, 1 org, username+password+TOTP only — RESOLVED ✓
- **Q4 (KMS in community)**: KMS allowed in Community — RESOLVED ✓
- **Q5 (installer modes)**: compose (default), K8s (helm), bare-metal/VM — RESOLVED ✓

---

## 6. Metrics / Success Criteria

- `install.sh` completes end-to-end on: Ubuntu 22.04 amd64, Ubuntu 22.04 arm64, macOS Sonoma M2, Amazon Linux 2023, RHEL 9
- Community tier enforces 10-agent cap and returns 402 on 11th registration
- Community tier returns 402 with upgrade message on any SSO route
- Professional license loaded from file → SSO routes return 200 (not gated)
- Enterprise license → multi-org creation succeeds
- License verification is offline (no network call in verifier)
- Invalid/expired license → falls back to Community with warning log

---

*Awaiting GO to implement all 8 phases.*
