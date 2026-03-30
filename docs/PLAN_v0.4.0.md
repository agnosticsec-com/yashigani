# Yashigani v0.4.0 — Implementation Plan
## Themes: CI/CD — GitHub Actions, Security Scanning, Unit Tests, Image Build & Helm Deployment | Scaling — HPA, Redis Cluster, cert-manager, KEDA | Fail-over — Ollama HA, Health Probes, PDB, Topology Spread

**Date:** 2026-03-27
**Author:** Maxine (PM/PO)
**Status:** COMPLETE — 2026-03-27

---

## Executive Summary

- v0.4.0 delivers the full CI/CD spine: every PR is automatically linted, tested (≥80% coverage), and
  scanned before merge; every version tag produces a signed, SBOM-annotated multi-arch image pushed to GHCR.
- Security scanning is not an afterthought — it runs in two modes: fast (per-PR via `ci.yml`) and deep
  (daily scheduled via `security.yml`), covering SAST, SCA, container CVEs, and supply-chain signing.
- The Helm chart is a single umbrella chart with per-service sub-charts; this keeps values namespaced,
  allows teams to upgrade individual services independently, and maps 1:1 to the Docker Compose service list.
- Both Dockerfiles already use multi-stage builds and non-root users; the hardening work in this iteration
  is additive: pinning base image digests, adding `HEALTHCHECK`, and enforcing read-only root filesystem.
- No new persistent agents are introduced. All work is CI infrastructure — no HITL triggers are required
  unless Tiago decides to add an external registry or cloud KMS in a future phase.
- **Scaling (Phase 9):** The gateway and backoffice gain HorizontalPodAutoscalers (CPU 70% + memory 80%
  thresholds). The single-node Redis instance is replaced by a Bitnami Redis Cluster (3 primaries, 3
  replicas). Caddy's built-in ACME is superseded by cert-manager + nginx ingress in Kubernetes deployments.
  KEDA is introduced as an optional addon for Redis-queue-length-driven scaling of inspection workers.
- **Fail-over (Phase 10):** Ollama runs as a StatefulSet with 2 replicas behind a headless Service; the
  gateway's `InspectionPipeline` uses client-side round-robin across replicas. Every K8s workload receives
  a full health probe spec (liveness, readiness, startupProbe where needed). PodDisruptionBudgets prevent
  simultaneous eviction of stateless pods. Topology spread constraints distribute gateway and backoffice
  pods across availability zones for zone-level resilience.

---

## Phase Breakdown

---

### Phase 1 — Repository Scaffolding
**Goal:** Create the directory skeleton so subsequent phases have a home.
**Effort estimate:** 0.5 days

#### Files Created

| Path | Description |
|------|-------------|
| `.github/workflows/ci.yml` | Lint + test + Docker build gate |
| `.github/workflows/security.yml` | Deep security scan (daily + PR) |
| `.github/workflows/build-push.yml` | Multi-arch image build, push, sign, SBOM |
| `.github/workflows/helm-release.yml` | Helm chart package + publish to gh-pages |
| `.github/workflows/deploy.yml` | Manual Helm deploy to staging/production |
| `.github/CODEOWNERS` | Route PR reviews: Python → @yashigani/backend, Helm → @yashigani/platform |
| `.hadolint.yaml` | Hadolint config — fail on DL3008, DL3009, pin severity to warning for DL3013 |
| `.dockerignore` | Exclude `.git`, `__pycache__`, `*.pyc`, `tests/`, `docs/`, `.env*` |
| `sonar-project.properties` | SonarCloud project key, source path, coverage report path |
| `helm/yashigani/Chart.yaml` | Umbrella chart metadata, version 0.4.0 |
| `helm/yashigani/values.yaml` | Top-level values with per-service namespaced blocks |
| `helm/yashigani/charts/` | Directory for sub-chart archives (populated by `helm dep update`) |
| `helm/yashigani/templates/` | Umbrella-level resources: namespace, NetworkPolicy, RBAC |
| `helm/charts/gateway/` | Gateway sub-chart (Deployment, Service, HPA, Secret) |
| `helm/charts/backoffice/` | Backoffice sub-chart |
| `helm/charts/policy/` | OPA sub-chart |
| `helm/charts/redis/` | Redis sub-chart (uses Bitnami upstream as dependency) |
| `helm/charts/ollama/` | Ollama sub-chart |
| `helm/charts/prometheus/` | Prometheus sub-chart |
| `helm/charts/grafana/` | Grafana sub-chart |
| `helm/charts/caddy/` | Caddy sub-chart |
| `src/tests/unit/test_gateway_proxy.py` | Unit tests for gateway proxy module |
| `src/tests/unit/test_gateway_auth.py` | Unit tests for agent_auth + agent_router |
| `src/tests/unit/test_inspection.py` | Unit tests for inspection pipeline + classifier |
| `src/tests/unit/test_ratelimit.py` | Unit tests for rate limiter |
| `src/tests/unit/test_rbac.py` | Unit tests for RBAC model + store |
| `src/tests/conftest.py` | Shared fixtures: mock Redis, mock OPA, mock httpx |

#### Key Decisions

- `.github/` is created at repo root (standard GitHub location).
- `helm/` already exists at repo root as an empty directory — it is populated now.
- Sub-charts live under `helm/charts/` (sibling to the umbrella). The umbrella's
  `Chart.yaml` references them as local `file://` dependencies. This avoids network
  fetches during `helm dep update` in CI and keeps everything in the same repo until
  the chart is stable enough to split.
- `.dockerignore` is placed at repo root (Docker build context is `..` per
  `docker-compose.yml`).

---

### Phase 2 — Dockerfile Hardening
**Goal:** Both images pass Hadolint (zero ERRORs) and Trivy HIGH/CRITICAL (zero unfixed).
**Effort estimate:** 0.5 days

#### Current State Analysis

Both `Dockerfile.gateway` and `Dockerfile.backoffice` already implement:
- Multi-stage build (builder → runtime) ✓
- Non-root user `yashigani` (UID/GID 1001) ✓
- `PYTHONUNBUFFERED`, `PYTHONDONTWRITEBYTECODE` ✓
- No SSH keys, no `.git` copies ✓

#### Required Changes

**1. Pin base image to digest (Hadolint DL3007 / Trivy supply-chain)**

```dockerfile
# Before
FROM python:3.12-slim AS builder
# After — resolve digest at plan time; refresh quarterly or on CVE advisory
FROM python:3.12-slim@sha256:<digest> AS builder
```

Both Dockerfiles need digest pinning on both the `builder` and `runtime` stages.
The CI workflow will use `docker buildx imagetools inspect` to validate digests have
not drifted from the lock file.

**2. Pin apt packages with explicit versions (Hadolint DL3008)**

Neither Dockerfile currently calls `apt-get`. If a future layer adds it, the
`.hadolint.yaml` rule `DL3008: error` will catch it immediately. No change needed now
beyond enabling the rule.

**3. Add `HEALTHCHECK` instruction (Trivy MED / best practice)**

```dockerfile
# Gateway (after EXPOSE 8080)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')"

# Backoffice (after EXPOSE 8443)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8443/healthz')"
```

Using `python -c` (stdlib only) avoids adding `curl` to the runtime image.

**4. Drop all Linux capabilities + read-only root filesystem**

This is enforced at the Kubernetes/Helm layer (securityContext), not in the Dockerfile.
The Dockerfiles do not need to change; the Helm templates apply `readOnlyRootFilesystem: true`,
`allowPrivilegeEscalation: false`, and `drop: ["ALL"]` capabilities.

**5. No `pip` upgrade in runtime stage (Trivy HIGH pip version findings)**

Current runtime stage installs packages directly. Add explicit pip version pin:
```dockerfile
RUN pip install --no-cache-dir --upgrade "pip==24.3.1"
```
Run this as the last `RUN` in the builder stage only — not in runtime.

**6. Remove `requirements-kms.txt` and `requirements-phase2.txt` copy from runtime**

These files are copied but then only used during `pip install`. They should be deleted
after install to reduce image surface:
```dockerfile
RUN pip install ... -r requirements-phase2.txt \
 && rm requirements-kms.txt requirements-phase2.txt
```

#### Files Modified

| File | Change |
|------|--------|
| `docker/Dockerfile.gateway` | Digest pin, HEALTHCHECK, delete req files post-install |
| `docker/Dockerfile.backoffice` | Same as gateway |

---

### Phase 3 — Unit Test Expansion
**Goal:** Reach ≥80% line+branch coverage across all source modules.
**Effort estimate:** 2 days

#### Coverage Baseline

Currently, only `kms` and `audit` modules have tests. The following high-value, untested
modules must be covered to reach 80%:

| Priority | Module | Why High Value |
|----------|--------|----------------|
| P1 | `gateway/proxy.py` | Core data path — all MCP requests flow through it |
| P1 | `gateway/agent_auth.py` | Token validation — security-critical |
| P1 | `gateway/agent_router.py` | Agent dispatch logic |
| P1 | `inspection/pipeline.py` | Classification + sanitization chain |
| P1 | `inspection/classifier.py` | LLM classification result parsing |
| P2 | `ratelimit/limiter.py` | Redis-backed rate limiting |
| P2 | `rbac/model.py` + `rbac/store.py` | Permission enforcement |
| P2 | `auth/password.py` + `auth/session.py` | Auth primitives |
| P3 | `backoffice/routes/auth.py` | Admin login route |
| P3 | `sso/oidc.py` + `sso/saml.py` | SSO flows (mock IdP) |

Modules explicitly excluded from 80% gate (pragma: no cover or exclude pattern):
- `kms/providers/keeper.py`, `kms/providers/aws.py`, `kms/providers/azure.py`,
  `kms/providers/gcp.py` — require live credentials; integration tests only
- `inspection/backends/anthropic.py`, `gemini.py`, `azure_openai.py` — cloud calls
- `chs/gpu_monitor.py` — hardware dependency

#### Fixture Design (`src/tests/conftest.py`)

```python
# Three shared fixtures covering 90% of test dependencies:

@pytest.fixture
def mock_redis():
    """fakeredis.aioredis.FakeRedis — drop-in async Redis replacement."""
    # Uses fakeredis library (add to [dev] extras in pyproject.toml)

@pytest.fixture
def mock_opa():
    """httpx.MockTransport that returns allow=True by default; parameterisable."""
    # Tests that need OPA deny pass: mock_opa.set_decision("deny")

@pytest.fixture
def mock_ollama():
    """httpx.MockTransport that returns a canned classification JSON response."""
    # Covers inspection/backends/ollama.py without a live Ollama instance
```

Add `fakeredis>=2.21` to `[project.optional-dependencies] dev`.

#### Test File Conventions

- One test file per source module: `test_<module_name>.py`
- All test classes prefixed `Test` + PascalCase module name
- Async tests decorated `@pytest.mark.asyncio` (already set to `asyncio_mode = auto`)
- Mock boundaries: never mock internal functions — mock at I/O boundaries
  (Redis client, httpx.AsyncClient, file system via `tmp_path`)
- Each test file has a module docstring: `"""Unit tests for yashigani.<path>."""`

#### pyproject.toml changes

```toml
# Add to [project.optional-dependencies] dev
"fakeredis[aioredis]>=2.21",
"pytest-cov>=5",
"ruff>=0.4",
"mypy>=1.10",

# Add to [tool.coverage.report]
fail_under = 80
```

#### Files Created/Modified

| File | Change |
|------|--------|
| `src/tests/conftest.py` | New — shared fixtures |
| `src/tests/unit/test_gateway_proxy.py` | New |
| `src/tests/unit/test_gateway_auth.py` | New |
| `src/tests/unit/test_inspection.py` | New |
| `src/tests/unit/test_ratelimit.py` | New |
| `src/tests/unit/test_rbac.py` | New |
| `pyproject.toml` | Add fakeredis, pytest-cov, ruff, mypy to dev extras; add `fail_under = 80` |

---

### Phase 4 — GitHub Actions Workflows
**Goal:** Five workflow files wired and tested locally via `act` before commit.
**Effort estimate:** 1.5 days

---

#### 4.1 `ci.yml` — PR Gate

**Triggers:** `push` to `main`; `pull_request` targeting `main`

**Jobs (sequential within job, jobs run in parallel where possible):**

```
lint → test → docker-build-check
                ↓
            [on failure: block merge]
```

**lint job** (ubuntu-latest, Python 3.12):
1. `actions/checkout@v4`
2. `actions/setup-python@v5` with `python-version: "3.12"` and `cache: pip`
3. `pip install ruff mypy` (from pyproject.toml dev extras)
4. `ruff check src/` — zero tolerance for E/F codes
5. `ruff format --check src/` — formatting gate
6. `mypy src/yashigani/ --ignore-missing-imports --strict`

**test job** (ubuntu-latest, needs: lint):
1. `actions/checkout@v4`
2. `actions/setup-python@v5`
3. `pip install -e ".[dev]"`
4. `pytest src/tests/unit/ --cov=yashigani --cov-report=xml --cov-fail-under=80`
5. `actions/upload-artifact@v4` — upload `coverage.xml`
6. `codecov/codecov-action@v4` — post coverage to Codecov (token from secret)

**docker-build-check job** (ubuntu-latest, needs: test):
1. `actions/checkout@v4`
2. `docker/setup-buildx-action@v3`
3. `docker/setup-qemu-action@v3` (needed for multi-arch even in check-only mode)
4. Build gateway image: `docker buildx build --file docker/Dockerfile.gateway --platform linux/amd64 --load .`
5. Build backoffice image: same with `Dockerfile.backoffice`
6. `hadolint/hadolint-action@v3.1.0` — fail on ERROR; warn on WARNING
7. No push. Images discarded after job.

**SAST job** (ubuntu-latest, runs in parallel with test):
1. `actions/checkout@v4`
2. `returntocorp/semgrep-action@v1` — ruleset: `p/python`, `p/owasp-top-ten`
3. Upload SARIF to GitHub Security tab via `github/codeql-action/upload-sarif@v3`

---

#### 4.2 `security.yml` — Deep Security Scan

**Triggers:**
- `schedule: cron: '0 3 * * *'` (03:00 UTC daily, low-traffic window)
- `pull_request` — runs subset (Trivy + Bandit only, skip OWASP dep-check for speed)

**Jobs:**

**trivy-scan job:**
1. `actions/checkout@v4`
2. Build gateway image locally (no push): `docker build -f docker/Dockerfile.gateway -t yashigani/gateway:scan .`
3. `aquasecurity/trivy-action@master` — `scan-type: image`, `severity: CRITICAL,HIGH`,
   `exit-code: 1`, `ignore-unfixed: true`, `format: sarif`, `output: trivy-results.sarif`
4. Repeat for backoffice image
5. Upload both SARIF files to GitHub Security tab

**bandit-sast job:**
1. `pip install bandit[toml]`
2. `bandit -r src/yashigani/ -c pyproject.toml -f json -o bandit-report.json`
3. Fail if HIGH severity issues found (`-ll` flag)
4. Upload report as artifact

**pip-audit job:**
1. `pip install pip-audit`
2. `pip-audit --requirement <(pip freeze) --output json > pip-audit-report.json`
3. Fail on any CRITICAL or HIGH CVSS score (`--fail-on-cvss 7`)
4. Upload report as artifact

**semgrep-full job** (skipped on PR, runs on schedule only):
1. `returntocorp/semgrep-action@v1`
2. Rulesets: `p/python`, `p/owasp-top-ten`, `p/secrets`, `p/supply-chain`
3. Upload SARIF

**owasp-dep-check job** (skipped on PR, runs on schedule only):
1. `dependency-check/Dependency-Check_Action@main`
2. `--format JSON --format HTML`
3. Fail if CVSS ≥ 7
4. Upload HTML report as artifact (retained 30 days)

---

#### 4.3 `build-push.yml` — Image Release

**Triggers:** `push` with tags matching `v*.*.*`

**Concurrency:** `group: build-${{ github.ref }}`, `cancel-in-progress: false`
(never cancel a release build)

**Jobs:**

**build-push job** (ubuntu-latest):
1. `actions/checkout@v4`
2. `docker/setup-qemu-action@v3`
3. `docker/setup-buildx-action@v3` with driver `docker-container` (required for multi-arch cache)
4. `docker/login-action@v3` — registry: `ghcr.io`, username: `${{ github.actor }}`,
   password: `${{ secrets.GHCR_TOKEN }}`
5. Extract metadata: `docker/metadata-action@v5`
   - tags: `type=semver,pattern={{version}}`, `type=semver,pattern={{major}}.{{minor}}`,
     `type=sha,prefix=sha-`
   - labels: standard OCI labels
6. Build + push gateway:
   ```yaml
   uses: docker/build-push-action@v5
   with:
     context: .
     file: docker/Dockerfile.gateway
     platforms: linux/amd64,linux/arm64
     push: true
     tags: ghcr.io/${{ github.repository_owner }}/yashigani-gateway:${{ steps.meta.outputs.version }}
     cache-from: type=gha
     cache-to: type=gha,mode=max
     provenance: true
     sbom: true
   ```
7. Repeat for backoffice with image name `yashigani-backoffice`
8. **Cosign signing:**
   ```yaml
   - uses: sigstore/cosign-installer@v3
   - run: |
       cosign sign --yes \
         ghcr.io/${{ github.repository_owner }}/yashigani-gateway@${{ steps.build-gateway.outputs.digest }}
       cosign sign --yes \
         ghcr.io/${{ github.repository_owner }}/yashigani-backoffice@${{ steps.build-backoffice.outputs.digest }}
     env:
       COSIGN_PRIVATE_KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}
       COSIGN_PASSWORD: ${{ secrets.COSIGN_PASSWORD }}
   ```
9. **SBOM generation (Syft):**
   ```yaml
   - uses: anchore/sbom-action@v0
     with:
       image: ghcr.io/${{ github.repository_owner }}/yashigani-gateway:${{ steps.meta.outputs.version }}
       format: spdx-json
       output-file: sbom-gateway.spdx.json
   - uses: anchore/sbom-action/publish-sbom@v0
   ```
   Repeat for backoffice. SBOM attached as OCI artifact (attestation).

---

#### 4.4 `helm-release.yml` — Chart Publish

**Triggers:** `workflow_run` — `workflows: ["Build & Push Images"]`, `types: [completed]`
(only runs when `build-push.yml` succeeds on a version tag)

**Condition:** `${{ github.event.workflow_run.conclusion == 'success' }}`

**Jobs:**

**release job** (ubuntu-latest):
1. `actions/checkout@v4` with `fetch-depth: 0` (full history for gh-pages branch)
2. `helm/chart-testing-action@v2` — `helm lint helm/yashigani/`
3. Update `helm/yashigani/Chart.yaml` `appVersion` to match the git tag
   (`echo $GITHUB_REF_NAME | sed 's/v//'`)
4. `helm package helm/yashigani/ --destination .helm-packages/`
5. `helm/chart-releaser-action@v1.6.0`
   - Publishes chart to `gh-pages` branch
   - Creates GitHub Release with chart tarball attached
   - Config file: `.cr.yaml` (see Phase 1 file list)

**Files Modified:**
- `helm/yashigani/Chart.yaml` — `appVersion` updated programmatically by workflow

**New Files:**
- `.cr.yaml` — chart-releaser config: `charts-dir: helm`, `pages-branch: gh-pages`,
  `pages-index-path: index.yaml`

---

#### 4.5 `deploy.yml` — Manual Deploy

**Triggers:** `workflow_dispatch`

**Inputs:**
```yaml
inputs:
  environment:
    description: 'Target environment'
    required: true
    type: choice
    options: [staging, production]
  image_tag:
    description: 'Image tag to deploy (e.g. 0.4.0)'
    required: true
    type: string
  dry_run:
    description: 'Dry-run only (helm upgrade --dry-run)'
    required: false
    type: boolean
    default: false
```

**Environment protection:** GitHub environment `production` requires manual approval
from `@yashigani/platform` before job executes.

**deploy job** (ubuntu-latest):
1. `actions/checkout@v4`
2. Write kubeconfig from secret: `echo "$KUBECONFIG_B64" | base64 -d > /tmp/kubeconfig`
3. `azure/setup-helm@v3`
4. `helm repo add yashigani https://<org>.github.io/yashigani`
5. `helm repo update`
6. Cosign verify before deploy:
   ```bash
   cosign verify ghcr.io/.../yashigani-gateway:${{ inputs.image_tag }} \
     --key env://COSIGN_PUBLIC_KEY
   ```
7. `helm upgrade --install yashigani yashigani/yashigani \
     --namespace yashigani --create-namespace \
     --set gateway.image.tag=${{ inputs.image_tag }} \
     --set backoffice.image.tag=${{ inputs.image_tag }} \
     --values helm/environments/${{ inputs.environment }}.yaml \
     ${{ inputs.dry_run == 'true' && '--dry-run' || '' }}`
8. Post deploy status to PR comment if triggered from PR context

**Secrets used:** `KUBECONFIG_B64`, `COSIGN_PUBLIC_KEY`

**New Files:**
- `helm/environments/staging.yaml` — staging overrides (replicas=1, resource limits reduced)
- `helm/environments/production.yaml` — production overrides (replicas=2+, full resource limits)

---

### Phase 5 — Helm Chart Implementation
**Goal:** A functional umbrella chart that can deploy the full 8-service stack to K8s.
**Effort estimate:** 2.5 days

#### Architecture Decision: Umbrella Chart with Local Sub-charts

**Chosen approach:** One umbrella chart (`helm/yashigani/`) with local sub-charts
in `helm/charts/<service>/`. The umbrella's `Chart.yaml` references them via
`file://` dependencies.

**Rationale over alternative (monolithic chart):**
- Values are namespaced per service: `gateway.image.tag`, `redis.resources.limits` —
  avoids a 500-line flat values.yaml
- Individual services can be disabled: `ollama.enabled: false` for environments that
  pre-pull the model
- Bitnami Redis sub-chart can be swapped in later by changing one `dependencies` entry
- No chart registry needed at this stage — `file://` paths work in CI with `helm dep update`

#### Umbrella `Chart.yaml`

```yaml
apiVersion: v2
name: yashigani
description: Security enforcement gateway for MCP servers and agentic AI systems
type: application
version: 0.4.0
appVersion: "0.4.0"
dependencies:
  - name: gateway
    version: "0.4.0"
    repository: "file://../charts/gateway"
  - name: backoffice
    version: "0.4.0"
    repository: "file://../charts/backoffice"
  - name: policy
    version: "0.4.0"
    repository: "file://../charts/policy"
  - name: redis
    version: "0.4.0"
    repository: "file://../charts/redis"
  - name: ollama
    version: "0.4.0"
    repository: "file://../charts/ollama"
  - name: prometheus
    version: "0.4.0"
    repository: "file://../charts/prometheus"
  - name: grafana
    version: "0.4.0"
    repository: "file://../charts/grafana"
  - name: caddy
    version: "0.4.0"
    repository: "file://../charts/caddy"
```

#### Top-Level `values.yaml` Structure

```yaml
global:
  imageRegistry: ghcr.io
  imageOwner: <org>
  tlsDomain: ""
  tlsMode: acme          # acme | ca | selfsigned
  environment: production

gateway:
  enabled: true
  image:
    repository: yashigani-gateway
    tag: "0.4.0"
    pullPolicy: IfNotPresent
  replicaCount: 2
  resources:
    requests: { cpu: "250m", memory: "256Mi" }
    limits:   { cpu: "1",    memory: "512Mi" }
  hpa:
    enabled: true
    minReplicas: 2
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70
    targetMemoryUtilizationPercentage: 80
  service:
    port: 8080
  existingSecretName: yashigani-gateway-secrets

backoffice:
  enabled: true
  image:
    repository: yashigani-backoffice
    tag: "0.4.0"
    pullPolicy: IfNotPresent
  replicaCount: 1          # control plane — no HPA
  resources:
    requests: { cpu: "100m", memory: "128Mi" }
    limits:   { cpu: "500m", memory: "256Mi" }
  service:
    port: 8443
  existingSecretName: yashigani-backoffice-secrets

policy:
  enabled: true
  image:
    repository: openpolicyagent/opa
    tag: "latest-rootless"
  replicaCount: 1
  resources:
    requests: { cpu: "50m",  memory: "64Mi" }
    limits:   { cpu: "200m", memory: "128Mi" }

redis:
  enabled: true
  image:
    repository: redis
    tag: "7-alpine"
  resources:
    requests: { cpu: "50m",  memory: "64Mi" }
    limits:   { cpu: "200m", memory: "256Mi" }
  existingSecretName: yashigani-redis-secrets

ollama:
  enabled: true
  image:
    repository: ollama/ollama
    tag: "latest"
  resources:
    requests: { cpu: "500m", memory: "2Gi" }
    limits:   { cpu: "4",    memory: "8Gi" }
  model: qwen2.5:3b

prometheus:
  enabled: true
  retention: 30d
  resources:
    requests: { cpu: "100m", memory: "256Mi" }
    limits:   { cpu: "500m", memory: "1Gi" }

grafana:
  enabled: true
  resources:
    requests: { cpu: "50m",  memory: "128Mi" }
    limits:   { cpu: "200m", memory: "256Mi" }
  existingSecretName: yashigani-grafana-secrets

caddy:
  enabled: true
  image:
    repository: caddy
    tag: "2-alpine"
  service:
    type: LoadBalancer
    httpPort: 80
    httpsPort: 443
  existingSecretName: yashigani-caddy-secrets
```

#### Secret Management in Kubernetes

**Design principle:** Kubernetes Secrets are populated externally (via KSM provider or
`kubectl create secret`) before Helm install. Helm never creates secrets with plaintext
values in values.yaml. Charts reference secrets by name via `existingSecretName`.

**Mapping from Docker Compose secrets to K8s Secrets:**

| Docker Compose Secret | K8s Secret Name | Key |
|-----------------------|-----------------|-----|
| `redis_password` | `yashigani-redis-secrets` | `redis-password` |
| `grafana_admin_password` | `yashigani-grafana-secrets` | `admin-password` |
| Admin bootstrap creds | `yashigani-backoffice-secrets` | `admin-password`, `totp-seed` |
| PROMETHEUS_BASICAUTH_HASH | `yashigani-caddy-secrets` | `prometheus-basicauth-hash` |

**Pre-install Secret creation (documented in `helm/README.md`):**
```bash
kubectl create secret generic yashigani-redis-secrets \
  --from-literal=redis-password="$(openssl rand -base64 36)" \
  --namespace yashigani
```

For environments with KSM (Keeper, AWS, Azure, GCP): use the corresponding External
Secrets Operator `ExternalSecret` CRD — an `ExternalSecret` template is provided in
`helm/yashigani/templates/external-secrets/` (rendered only when
`global.useExternalSecrets: true`).

#### Gateway HPA Specification

```yaml
# helm/charts/gateway/templates/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: yashigani-gateway
  minReplicas: {{ .Values.gateway.hpa.minReplicas }}   # default: 2
  maxReplicas: {{ .Values.gateway.hpa.maxReplicas }}   # default: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: {{ .Values.gateway.hpa.targetCPUUtilizationPercentage }}  # 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: {{ .Values.gateway.hpa.targetMemoryUtilizationPercentage }} # 80
```

**Rationale for dual CPU+memory metrics:** The gateway's primary load is httpx proxy
overhead (CPU-bound) plus Redis session lookups (memory-bound from connection pool). A
pure CPU HPA misses the memory pressure from large MCP payloads at inspection time.

#### Security Context (all Pods)

```yaml
# Applied via _helpers.tpl in each sub-chart
securityContext:
  runAsNonRoot: true
  runAsUser: 1001
  runAsGroup: 1001
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
```

Volumes that require write access (`/data/audit`, `/tmp`):
- `emptyDir: {}` mounted at `/tmp`
- PVC mounted at `/data/audit`

#### NetworkPolicy

The umbrella chart deploys a default-deny `NetworkPolicy` and explicit allow rules
mirroring the Docker Compose network topology:

| Source | Destination | Port |
|--------|-------------|------|
| caddy | gateway | 8080 |
| caddy | backoffice | 8443 |
| caddy | prometheus | 9090 |
| gateway | policy (OPA) | 8181 |
| gateway | redis | 6379 |
| gateway | ollama | 11434 |
| backoffice | redis | 6379 |
| backoffice | policy (OPA) | 8181 |
| prometheus | gateway (scrape) | 8080 |
| prometheus | backoffice (scrape) | 8443 |
| grafana | prometheus | 9090 |

#### Files Created (Phase 5)

Each sub-chart under `helm/charts/<service>/` contains:
- `Chart.yaml`
- `values.yaml` (service-local defaults)
- `templates/deployment.yaml`
- `templates/service.yaml`
- `templates/configmap.yaml` (where applicable)
- `templates/hpa.yaml` (gateway only)
- `templates/networkpolicy.yaml` (in umbrella: `helm/yashigani/templates/`)
- `templates/_helpers.tpl`

Additional files:
- `helm/yashigani/templates/namespace.yaml`
- `helm/yashigani/templates/networkpolicy.yaml`
- `helm/yashigani/templates/NOTES.txt`
- `helm/environments/staging.yaml`
- `helm/environments/production.yaml`
- `helm/README.md`
- `.cr.yaml`

---

### Phase 6 — Secret Handling in CI
**Goal:** Zero secrets in logs; all sensitive values injected via GitHub Actions Secrets.
**Effort estimate:** 0.25 days (configuration, not code)

#### Secret Inventory

| Secret Name (GitHub) | Used In | Value |
|----------------------|---------|-------|
| `GHCR_TOKEN` | `build-push.yml` | GitHub PAT with `write:packages` scope |
| `COSIGN_PRIVATE_KEY` | `build-push.yml` | PEM private key (Cosign keyless not used — air-gap compatibility) |
| `COSIGN_PASSWORD` | `build-push.yml` | Passphrase for COSIGN_PRIVATE_KEY |
| `COSIGN_PUBLIC_KEY` | `deploy.yml` | PEM public key for verify step |
| `KUBECONFIG_B64` | `deploy.yml` | Base64-encoded kubeconfig — scoped to `yashigani` namespace only |
| `KUBECONFIG_STAGING_B64` | `deploy.yml` | Separate kubeconfig for staging cluster |
| `CODECOV_TOKEN` | `ci.yml` | Coverage upload token |
| `SONAR_TOKEN` | `ci.yml` (optional) | SonarCloud scan token |

**Environment-scoped secrets:** `KUBECONFIG_B64` (production) and
`KUBECONFIG_STAGING_B64` are stored in GitHub Environment Secrets (`production` and
`staging` environments respectively), not repository-level secrets. This means the
`deploy.yml` job cannot access the production kubeconfig unless the environment
protection rule (manual approval) has been satisfied.

#### Never-Log Enforcement

1. All secrets referenced as `${{ secrets.X }}` — GitHub automatically masks these
   values in log output.
2. `cosign sign` and `helm upgrade` commands never echo the kubeconfig path — piped
   directly to environment variable, deleted after use: `rm -f /tmp/kubeconfig`
3. Workflow step: `--no-log-level debug` on helm commands in production jobs.
4. `ACTIONS_STEP_DEBUG` is disabled at the repository level (default off).
5. SBOM files attached as OCI artifacts, not uploaded as workflow artifacts that might
   contain embedded credential strings.
6. `pip-audit` output is uploaded as artifact only — not echoed to stdout in full.

#### Key Generation (one-time setup)

```bash
# Generate Cosign keypair (run once, store in GitHub Secrets)
cosign generate-key-pair
# Produces cosign.key (COSIGN_PRIVATE_KEY) and cosign.pub (COSIGN_PUBLIC_KEY)
# COSIGN_PASSWORD set interactively during generation
```

---

### Phase 7 — Quality Gates & Branch Protection
**Goal:** The `main` branch cannot receive a PR unless all gates pass.
**Effort estimate:** 0.25 days (GitHub settings, not code)

#### Branch Protection Rules for `main`

Configure via GitHub Settings > Branches > Protection Rules:

| Rule | Setting |
|------|---------|
| Require status checks to pass | `lint`, `test`, `docker-build-check`, `semgrep-action` |
| Require branches to be up to date | Enabled |
| Require conversation resolution | Enabled |
| Require signed commits | Enabled (GPG or SSH signing) |
| Restrict force pushes | Enabled |
| Restrict deletions | Enabled |
| Required approvals | 1 (Tiago or delegated reviewer) |

#### Quality Gate Thresholds

| Gate | Threshold | Enforced By |
|------|-----------|-------------|
| Unit test coverage | ≥ 80% line + branch | `pytest --cov-fail-under=80` in `ci.yml` |
| Container CVEs | Zero HIGH/CRITICAL (unfixed) | Trivy `exit-code: 1` in `security.yml` |
| SAST | Zero HIGH findings | Bandit `-ll` flag; Semgrep `p/owasp-top-ten` |
| Dependency audit | Zero CVSS ≥ 7.0 | `pip-audit --fail-on-cvss 7` |
| Hadolint | Zero ERRORs | `hadolint-action` in `ci.yml` |
| mypy | Zero errors (strict mode) | `mypy --strict` in lint job |

#### Semgrep Rulesets

**PR (fast, ~60s):** `p/python` + `p/owasp-top-ten`
**Scheduled (thorough, ~5min):** add `p/secrets` + `p/supply-chain` + `p/xss`

Rationale: `p/secrets` has high false-positive rate on test fixtures — acceptable for
nightly runs where human review happens; too noisy for PR feedback.

---

### Phase 8 — Grafana Dashboard Additions
**Goal:** Surface CI/CD pipeline health and image vulnerability counts in Grafana.
**Effort estimate:** 0.5 days

#### New Metrics from CI/CD

CI/CD pipelines do not emit Prometheus metrics directly. However, two approaches bring
pipeline visibility into Grafana:

**Option A (Chosen): GitHub Actions Exporter**
Deploy `github-actions-exporter` as a sidecar or standalone service that polls the
GitHub API and exposes Prometheus metrics. Scrape from Prometheus.

New metrics surfaced:
- `github_workflow_run_duration_seconds{workflow,status}`
- `github_workflow_run_conclusion{workflow,conclusion}` — success/failure counts
- `trivy_vulnerabilities_total{image,severity}` — parsed from Trivy JSON output by a
  small Python script in `ci/parse_trivy.py` that POSTs to Pushgateway

**Option B:** Push Trivy findings to Pushgateway directly from CI. Simpler, no new
service, but Pushgateway is a stale-data risk.

**Decision:** Use Option A (GitHub Actions Exporter) for workflow health, and Option B
(Pushgateway) for Trivy severity counts. The Pushgateway already exists as a logical
extension of the Prometheus stack.

#### New Dashboard: `CI/CD Health`

File: `config/grafana/dashboards/cicd_health.json`

Panels:
1. **Workflow success rate (7d)** — `github_workflow_run_conclusion` grouped by workflow
2. **Mean build duration** — `github_workflow_run_duration_seconds` p50/p95
3. **Container CVE trend** — `trivy_vulnerabilities_total{severity=~"HIGH|CRITICAL"}`
   over 30 days — should trend toward zero
4. **Coverage trend** — static badge link (Codecov provides API endpoint for trend data)
5. **Last successful deploy timestamp** — annotation from `deploy.yml` posting to
   Grafana Annotations API

#### Pushgateway Addition

Add to `docker/docker-compose.yml` and to Helm chart:
- Service: `pushgateway` — `prom/pushgateway:latest`
- Prometheus scrape target: `pushgateway:9091`
- Not exposed externally (internal network only)

#### Files Created/Modified (Phase 8)

| File | Change |
|------|--------|
| `config/grafana/dashboards/cicd_health.json` | New dashboard |
| `config/prometheus.yml` | Add pushgateway scrape job + github-actions-exporter scrape job |
| `docker/docker-compose.yml` | Add pushgateway service |
| `ci/parse_trivy.py` | New — reads trivy JSON, pushes metrics to Pushgateway |
| `helm/charts/prometheus/templates/configmap.yaml` | Update scrape config |

---

### Phase 9 — Scaling
**Goal:** The gateway and backoffice scale horizontally under load; Redis becomes highly available; TLS
certificate provisioning is decoupled from Caddy; queue-depth-based autoscaling is available as an addon.
**Effort estimate:** 3 days

---

#### 9.1 HorizontalPodAutoscaler

HPAs are introduced for the two stateless application services. The single HPA template in each sub-chart
already exists (Phase 5); this phase tunes the thresholds and adds the backoffice HPA.

**Gateway HPA** (`helm/charts/gateway/templates/hpa.yaml`):

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {{ include "gateway.fullname" . }}
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {{ include "gateway.fullname" . }}
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300   # 5-minute cooldown — avoid flapping
      policies:
        - type: Pods
          value: 1
          periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
        - type: Percent
          value: 100
          periodSeconds: 30
```

**Backoffice HPA** (`helm/charts/backoffice/templates/hpa.yaml`):

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {{ include "backoffice.fullname" . }}
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {{ include "backoffice.fullname" . }}
  minReplicas: 2
  maxReplicas: 4
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
```

**Values additions** (`helm/yashigani/values.yaml` updates):

```yaml
backoffice:
  hpa:
    enabled: true
    minReplicas: 2
    maxReplicas: 4
    targetCPUUtilizationPercentage: 70
    targetMemoryUtilizationPercentage: 80
```

**Rationale for min=2:** A single replica is a single point of failure for rolling updates. min=2 ensures
a pod can be evicted or restarted without downtime. For backoffice, max=4 reflects that the admin control
plane has lower burst demand than the request gateway.

**Prerequisite:** Kubernetes metrics-server must be installed in the cluster. Add a note to `helm/README.md`
and check for metrics-server availability in the `NOTES.txt` post-install output.

---

#### 9.2 Redis Cluster (Replace Single-Node)

**Current state:** `docker/docker-compose.yml` and `helm/charts/redis/` use a single `redis:7-alpine`
container. This is a single point of failure with no replication and no horizontal write distribution.

**Target state:** Bitnami Redis Cluster sub-chart — 3 primary shards, 3 replicas (one replica per primary),
giving 6 pods total. Writes are distributed across shards via consistent hashing (hash slots). Reads can
be served from replicas.

##### Sub-chart dependency change

Update `helm/yashigani/Chart.yaml`:

```yaml
dependencies:
  - name: redis-cluster
    version: "10.x.x"
    repository: "https://charts.bitnami.com/bitnami"
    condition: redis.enabled
```

Remove the `file://../charts/redis` local sub-chart dependency. The Bitnami chart replaces it entirely.

##### Values block

```yaml
redis-cluster:
  enabled: true
  cluster:
    nodes: 6          # 3 primaries + 3 replicas
    replicas: 1       # replicas per primary
  usePassword: true
  existingSecret: yashigani-redis-secrets
  existingSecretPasswordKey: redis-password
  persistence:
    enabled: true
    size: 5Gi
    storageClass: ""  # use cluster default
  resources:
    requests: { cpu: "100m", memory: "128Mi" }
    limits:   { cpu: "500m", memory: "512Mi" }
```

##### Redis Cluster constraint: no multiple logical databases

**Critical:** Redis Cluster does not support multiple logical databases (`SELECT 1`, `SELECT 2`, etc.).
All keys must reside in database 0 (the single logical database in cluster mode). The current gateway and
backoffice use `redis://redis:6379/0`, `/1`, `/2`, `/3` for logical isolation of:
- `/0` — session tokens
- `/1` — rate-limit counters
- `/2` — inspection cache
- `/3` — audit queue

**Required change:** Replace DB-index isolation with key-prefix namespacing on db/0:

| Previous URL | New key prefix convention |
|---|---|
| `redis://redis:6379/0` (sessions) | keys prefixed `sess:` |
| `redis://redis:6379/1` (rate-limit) | keys prefixed `rl:` |
| `redis://redis:6379/2` (inspection cache) | keys prefixed `ic:` |
| `redis://redis:6379/3` (audit queue) | keys prefixed `aq:` |

All gateway and backoffice modules that construct Redis keys must be updated to include the appropriate
prefix. The Redis connection URL in all config files and environment variables becomes a single cluster
URL: `redis://yashigani-redis-cluster:6379/0` (or the cluster-aware URL format
`redis+cluster://node1:6379,node2:6379,node3:6379`).

**Hash slot compatibility:** Redis Cluster uses CRC16 of the key name to assign it to a hash slot (0–16383).
Multi-key operations (e.g., `MGET`, `EVAL` across keys) require all keys to be in the same slot. Where the
codebase uses pipelined multi-key operations, keys must use hash tags `{namespace}:key` to force co-location.
Audit this in `ratelimit/limiter.py` (sliding window uses two keys per agent — these must use hash tags).

**Files requiring key-prefix changes:**

| File | Change |
|---|---|
| `gateway/proxy.py` | Update Redis connection URL; prefix all session keys with `sess:` |
| `gateway/agent_auth.py` | Prefix token lookup keys with `sess:` |
| `ratelimit/limiter.py` | Prefix all rate-limit keys with `rl:{agent_id}:` (hash tag for atomic ops) |
| `inspection/pipeline.py` | Prefix inspection cache keys with `ic:` |
| `backoffice/routes/audit.py` | Prefix audit queue keys with `aq:` |
| `config/settings.py` or equivalent | Replace `REDIS_DB` env var with `REDIS_KEY_PREFIX` per module |
| `src/tests/conftest.py` | Update `mock_redis` fixture to use fakeredis cluster mode |
| `helm/yashigani/values.yaml` | Remove old redis block; add redis-cluster block |

**Migration path (single-node → cluster):**

1. Pre-migration: flush or export existing Redis data (sessions are short-lived; rate-limit counters
   reset naturally; audit queue must be drained before cutover).
2. Deploy Redis Cluster alongside old single-node (different K8s Service name).
3. Update gateway and backoffice env vars to point to cluster URL.
4. Rolling restart gateway + backoffice pods.
5. Decommission single-node Redis Service and PVC.
6. Verify: `redis-cli -c CLUSTER INFO` shows `cluster_state:ok` with all 16384 hash slots assigned.

**Docker Compose:** For local development, the single-node Redis is retained in `docker-compose.yml`
(Docker Compose does not support Redis Cluster natively without a custom multi-container setup). Add a
`docker-compose.cluster.yml` override for developers who need local cluster testing. The key-prefix
convention works identically against single-node Redis (prefix is just a naming convention — single-node
ignores it, cluster uses it for slot assignment).

---

#### 9.3 cert-manager (Replace Caddy ACME)

**Current state:** Caddy performs ACME (Let's Encrypt) certificate procurement automatically via its
built-in ACME client. This works well in Docker Compose but is problematic in Kubernetes because:
- Caddy pods cannot bind port 80 for HTTP-01 challenges without a LoadBalancer per pod
- Caddy's certificate store is local to the pod — not shared across replicas
- cert-manager is the Kubernetes-native standard; most clusters already have it

**Target state:** cert-manager manages all TLS certificates. nginx ingress replaces Caddy as the
Kubernetes ingress layer. Caddy remains available as a `helm/charts/caddy/` sub-chart for
non-Kubernetes deployments and Docker Compose, but is disabled by default in the Helm chart when
`global.ingressClass: nginx`.

##### cert-manager installation

cert-manager is installed as a cluster-level prerequisite (not managed by the Yashigani Helm chart,
to avoid permission conflicts). Document in `helm/README.md`:

```bash
helm repo add jetstack https://charts.jetstack.io
helm repo update
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --set installCRDs=true \
  --version v1.15.x
```

##### ClusterIssuer definitions

Two ClusterIssuers are defined in `helm/yashigani/templates/clusterissuer.yaml`
(rendered when `global.certManager.enabled: true`):

**Production (Let's Encrypt):**

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: {{ .Values.global.certManager.acmeEmail }}
    privateKeySecretRef:
      name: letsencrypt-prod-account-key
    solvers:
      - http01:
          ingress:
            class: nginx
```

**Development (self-signed):**

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: selfsigned-issuer
spec:
  selfSigned: {}
```

##### Ingress resource

```yaml
# helm/yashigani/templates/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: yashigani
  annotations:
    cert-manager.io/cluster-issuer: {{ .Values.global.certManager.issuer }}
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "10m"
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - {{ .Values.global.tlsDomain }}
      secretName: yashigani-tls
  rules:
    - host: {{ .Values.global.tlsDomain }}
      http:
        paths:
          - path: /api
            pathType: Prefix
            backend:
              service:
                name: yashigani-gateway
                port: { number: 8080 }
          - path: /admin
            pathType: Prefix
            backend:
              service:
                name: yashigani-backoffice
                port: { number: 8443 }
          - path: /grafana
            pathType: Prefix
            backend:
              service:
                name: yashigani-grafana
                port: { number: 3000 }
```

##### Values additions

```yaml
global:
  certManager:
    enabled: true           # false = use Caddy ACME (Docker Compose / legacy)
    issuer: letsencrypt-prod  # or selfsigned-issuer for dev
    acmeEmail: ""           # required when issuer = letsencrypt-prod

caddy:
  enabled: false            # disabled by default in K8s; set true for bare-metal/Docker Compose
```

##### Migration path (Caddy ACME → cert-manager)

1. Install cert-manager in cluster (see above).
2. Set `global.certManager.enabled: true` and `caddy.enabled: false` in production values.
3. Run `helm upgrade` — cert-manager will procure a new Let's Encrypt certificate.
4. Validate: `kubectl describe certificate yashigani-tls -n yashigani` shows `Ready: True`.
5. Update DNS if needed (nginx ingress LoadBalancer IP may differ from Caddy's).
6. Decommission Caddy pods.

**Note:** The existing `PROMETHEUS_BASICAUTH_HASH` secret (used by Caddy to protect the Prometheus
endpoint) is no longer needed in K8s. nginx ingress basic-auth annotations replace it, or the Prometheus
endpoint is restricted via NetworkPolicy to Grafana only (preferred — no additional auth layer needed
inside the cluster).

---

#### 9.4 KEDA — Optional Queue-Depth-Based Autoscaling

**Status:** Optional addon — enabled via `global.keda.enabled: true`. Not deployed by default.

**Use case:** The inspection pipeline enqueues jobs in Redis (`aq:` prefix, formerly `/3`). Under sustained
load, the queue depth grows faster than HPA CPU metrics react. KEDA can scale gateway replicas based on
the `LLEN aq:pending` queue length, providing sub-minute reaction time independent of CPU.

**Installation prerequisite** (cluster-level, not part of Yashigani chart):

```bash
helm repo add kedacore https://kedacore.github.io/charts
helm install keda kedacore/keda --namespace keda --create-namespace
```

**ScaledObject** (`helm/yashigani/templates/scaledobject.yaml`, rendered when `global.keda.enabled`):

```yaml
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: gateway-queue-scaler
spec:
  scaleTargetRef:
    name: yashigani-gateway
  minReplicaCount: 2
  maxReplicaCount: 10
  cooldownPeriod: 300
  triggers:
    - type: redis
      metadata:
        address: yashigani-redis-cluster:6379
        listName: "aq:pending"
        listLength: "20"          # scale up when >20 items per replica
        enableTLS: "false"
      authenticationRef:
        name: keda-redis-auth
---
apiVersion: keda.sh/v1alpha1
kind: TriggerAuthentication
metadata:
  name: keda-redis-auth
spec:
  secretTargetRef:
    - parameter: password
      name: yashigani-redis-secrets
      key: redis-password
```

**Interaction with HPA:** KEDA replaces (not supplements) the HPA for the gateway when enabled. Both
managing the same Deployment would conflict. The gateway HPA template must include:
`{{- if not .Values.global.keda.enabled }}` guard so only one scaler is active.

**Values additions:**

```yaml
global:
  keda:
    enabled: false
    queueThreshold: 20    # items per replica before scale-up triggers
```

#### Files Created/Modified (Phase 9)

| File | Type | Description |
|------|------|-------------|
| `helm/charts/backoffice/templates/hpa.yaml` | New | Backoffice HPA (min 2, max 4, CPU 70% + mem 80%) |
| `helm/yashigani/templates/clusterissuer.yaml` | New | cert-manager ClusterIssuer (Let's Encrypt + self-signed) |
| `helm/yashigani/templates/ingress.yaml` | New | nginx Ingress with cert-manager TLS annotation |
| `helm/yashigani/templates/scaledobject.yaml` | New | KEDA ScaledObject + TriggerAuthentication (optional) |
| `helm/yashigani/Chart.yaml` | Modified | Replace local redis sub-chart with Bitnami redis-cluster dependency |
| `helm/yashigani/values.yaml` | Modified | Add backoffice.hpa, redis-cluster block, certManager block, keda block; caddy.enabled default false |
| `helm/charts/redis/` | Removed | Superseded by Bitnami redis-cluster dependency |
| `helm/README.md` | Modified | Add cert-manager + KEDA prerequisite install instructions; Redis Cluster migration steps |
| `gateway/proxy.py` | Modified | Update Redis URL; prefix session keys `sess:` |
| `gateway/agent_auth.py` | Modified | Prefix token keys `sess:` |
| `ratelimit/limiter.py` | Modified | Prefix rate-limit keys `rl:{agent_id}:` with hash tags |
| `inspection/pipeline.py` | Modified | Prefix inspection cache keys `ic:` |
| `backoffice/routes/audit.py` | Modified | Prefix audit queue keys `aq:` |
| `src/tests/conftest.py` | Modified | Update mock_redis to support cluster-mode key prefixes |
| `docker/docker-compose.cluster.yml` | New | Override file for local Redis Cluster testing |

---

### Phase 10 — Fail-over
**Goal:** Every component survives the loss of a single pod, node, or availability zone without
service interruption. Ollama survives replica failure with automatic client-side routing. All
workloads expose health probes for Kubernetes to make informed scheduling and traffic decisions.
**Effort estimate:** 2.5 days

---

#### 10.1 Gateway Fail-over

The gateway is already stateless: all session state is stored in Redis, not in-process. There is no
in-memory session map that would break if traffic is routed to a different replica.

**Session affinity:** NOT required. The nginx Ingress must NOT have
`nginx.ingress.kubernetes.io/affinity: cookie` set — sticky sessions would undermine the HPA's
ability to balance load across replicas and would create false single-points-of-failure if a pod
is evicted.

**Fail-over behavior:** When a gateway pod is evicted or crashes, Kubernetes automatically routes
new connections to surviving replicas (ClusterIP round-robin). In-flight requests on the terminated
pod's TCP connections will fail and must be retried by the client. The nginx Ingress is configured
with `proxy-next-upstream: error timeout` to retry failed upstream connections on a different gateway
pod.

**Annotation to add to Ingress:**

```yaml
nginx.ingress.kubernetes.io/proxy-next-upstream: "error timeout"
nginx.ingress.kubernetes.io/proxy-next-upstream-tries: "3"
```

---

#### 10.2 Ollama Fail-over

**Current state:** Ollama runs as a single Deployment replica. If the pod is evicted during model
inference, the in-flight classification request fails and the inspection pipeline returns an error.

**Target state:** Ollama runs as a StatefulSet with 2 replicas behind a headless Service. The gateway's
`InspectionPipeline` maintains a client-side pool of Ollama endpoints and uses round-robin selection
with automatic failover to the next endpoint on connection error.

##### StatefulSet specification

```yaml
# helm/charts/ollama/templates/statefulset.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: yashigani-ollama
spec:
  serviceName: yashigani-ollama-headless
  replicas: 2
  selector:
    matchLabels:
      app: yashigani-ollama
  template:
    metadata:
      labels:
        app: yashigani-ollama
    spec:
      nodeSelector:
        accelerator: nvidia          # prefer GPU nodes
      tolerations:
        - key: nvidia.com/gpu
          operator: Exists
          effect: NoSchedule
      affinity:
        nodeAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              preference:
                matchExpressions:
                  - key: accelerator
                    operator: In
                    values: [nvidia]
          # Fallback: if no GPU nodes available, schedule on CPU nodes
          # (no requiredDuringScheduling — soft preference only)
      containers:
        - name: ollama
          image: ollama/ollama:latest
          ports:
            - containerPort: 11434
          resources:
            requests:
              cpu: "500m"
              memory: "2Gi"
              nvidia.com/gpu: "1"    # request 1 GPU; omitted on CPU fallback
            limits:
              cpu: "4"
              memory: "8Gi"
              nvidia.com/gpu: "1"
          volumeMounts:
            - name: ollama-data
              mountPath: /root/.ollama
  volumeClaimTemplates:
    - metadata:
        name: ollama-data
      spec:
        accessModes: [ReadWriteOnce]
        resources:
          requests:
            storage: 10Gi
```

**GPU node affinity rationale:** `nodeSelector: accelerator: nvidia` is a soft preference
(`preferredDuringScheduling`), not a hard requirement. If GPU nodes are unavailable (e.g., in
CI/CD or budget environments), Ollama falls back to CPU-only nodes. The GPU resource request
(`nvidia.com/gpu: 1`) must be removed from the CPU fallback values override — add a
`helm/environments/no-gpu.yaml` with `ollama.gpu.enabled: false` that removes the GPU resource
request and node selector.

##### Headless Service

```yaml
# helm/charts/ollama/templates/service-headless.yaml
apiVersion: v1
kind: Service
metadata:
  name: yashigani-ollama-headless
spec:
  clusterIP: None
  selector:
    app: yashigani-ollama
  ports:
    - port: 11434
      targetPort: 11434
```

A headless Service (`clusterIP: None`) exposes individual pod DNS entries:
`yashigani-ollama-0.yashigani-ollama-headless.yashigani.svc.cluster.local` and
`yashigani-ollama-1.yashigani-ollama-headless.yashigani.svc.cluster.local`.
The `InspectionPipeline` client pool uses these DNS names directly.

##### InspectionPipeline client-side pool

Changes to `inspection/pipeline.py`:

```python
class OllamaPool:
    """Round-robin pool of Ollama endpoints with automatic failover."""

    def __init__(self, endpoints: list[str]):
        self._endpoints = endpoints
        self._index = 0
        self._lock = asyncio.Lock()

    async def next_endpoint(self) -> str:
        async with self._lock:
            ep = self._endpoints[self._index % len(self._endpoints)]
            self._index += 1
            return ep

    async def classify(self, payload: dict) -> dict:
        for attempt in range(len(self._endpoints)):
            ep = await self.next_endpoint()
            try:
                async with httpx.AsyncClient(base_url=ep, timeout=30) as client:
                    r = await client.post("/api/generate", json=payload)
                    r.raise_for_status()
                    return r.json()
            except (httpx.ConnectError, httpx.TimeoutException):
                continue   # try next endpoint
        raise RuntimeError("All Ollama endpoints unreachable")
```

Configuration (env / config file):

```yaml
inspection:
  ollama_endpoints:
    - "http://yashigani-ollama-0.yashigani-ollama-headless.yashigani.svc.cluster.local:11434"
    - "http://yashigani-ollama-1.yashigani-ollama-headless.yashigani.svc.cluster.local:11434"
```

In Docker Compose, this collapses to `["http://ollama:11434"]` — the pool degrades gracefully to
a single-element list.

---

#### 10.3 LM Studio Fail-over

LM Studio is treated as an external service (not managed by Kubernetes). The `BackendRegistry`
already implements a fallback chain: if the primary backend fails, it tries the next registered
backend.

**`liveness_check_interval` config:** Add a periodic health-polling mechanism to `BackendRegistry`
that probes each registered LM Studio endpoint on a configurable interval and automatically removes
unresponsive endpoints from the active pool, re-adding them when they recover.

```python
# inspection/backends/registry.py additions

class BackendRegistry:
    liveness_check_interval: int = 60   # seconds between health checks

    async def _health_loop(self):
        """Background task: probe all backends; remove/re-add based on liveness."""
        while True:
            await asyncio.sleep(self.liveness_check_interval)
            for name, backend in self._all_backends.items():
                healthy = await backend.health_check()
                if healthy and name not in self._active_pool:
                    self._active_pool.add(name)
                    logger.info("Backend %s re-entered active pool", name)
                elif not healthy and name in self._active_pool:
                    self._active_pool.discard(name)
                    logger.warning("Backend %s removed from active pool", name)
```

Configuration:

```yaml
inspection:
  lm_studio:
    endpoints:
      - url: "http://192.168.1.100:1234"
        name: lmstudio-primary
      - url: "http://192.168.1.101:1234"
        name: lmstudio-secondary
    liveness_check_interval: 60   # seconds
    liveness_timeout: 5           # seconds per probe
```

**Re-entry policy:** An endpoint is re-added to the active pool after a single successful health
check. This avoids hysteresis but is acceptable because LM Studio instances are operator-managed
(not auto-restarted by K8s). A flapping instance will appear in logs.

---

#### 10.4 Health Probe Specification

Every Kubernetes workload must declare liveness, readiness, and (where applicable) startupProbe.
These are defined in each sub-chart's `deployment.yaml` or `statefulset.yaml`.

| Workload | Liveness | Readiness | startupProbe |
|---|---|---|---|
| gateway | `GET /healthz` | `GET /readyz` | Yes — 60s window, 5s period, failureThreshold 12 |
| backoffice | `GET /health` | `GET /readyz` | No |
| policy (OPA) | `GET /health` | `GET /health?bundle=true` | No |
| ollama | `GET /api/tags` | `GET /api/tags` | Yes — 120s window, 10s period, failureThreshold 12 (model load) |
| redis | `redis-cli ping` | `redis-cli ping` | No |
| prometheus | `GET /-/healthy` | `GET /-/ready` | No |
| grafana | `GET /api/health` | `GET /api/health` | No |

**Gateway probe detail:**

```yaml
startupProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
  failureThreshold: 12          # 60s total window
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 0
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 3
readinessProbe:
  httpGet:
    path: /readyz
    port: 8080
  initialDelaySeconds: 0
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 3
  successThreshold: 1
```

**`/readyz` vs `/healthz` distinction:**
- `/healthz` — liveness: returns 200 if the process is running and not deadlocked. Returns 503 only
  for catastrophic internal failures (e.g., OOM, deadlock detected).
- `/readyz` — readiness: returns 200 only when the pod is ready to serve traffic. Returns 503 during
  startup (before Redis connection established), during graceful shutdown, or when upstream
  dependencies (Redis, OPA) are temporarily unreachable. A non-ready pod is removed from the
  Service endpoint slice but not restarted — this prevents cascading failures when Redis has a
  momentary blip.

**OPA readiness note:** `GET /health?bundle=true` waits until the policy bundle has been downloaded
and activated. Without this, OPA may pass readiness while still using stale policies.

**Ollama startupProbe rationale:** Model loading (`qwen2.5:3b`, ~2GB) takes 30–90 seconds on first
start. A 120-second window (12 × 10s) covers worst-case cold start on a CPU-only node. Without the
startupProbe, the liveness probe would restart the pod during model loading, creating an infinite
restart loop.

**Redis probe implementation:**

```yaml
livenessProbe:
  exec:
    command: ["redis-cli", "-a", "$(REDIS_PASSWORD)", "ping"]
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 3
readinessProbe:
  exec:
    command: ["redis-cli", "-a", "$(REDIS_PASSWORD)", "ping"]
  periodSeconds: 5
  timeoutSeconds: 2
  failureThreshold: 3
```

The `REDIS_PASSWORD` env var is injected from `yashigani-redis-secrets` — same secret used by
application pods.

---

#### 10.5 PodDisruptionBudget

PDBs prevent Kubernetes node drain operations (e.g., for node upgrades) from evicting too many
pods simultaneously, which would cause downtime.

**PDB for each stateless service** (gateway, backoffice, OPA, Prometheus, Grafana):

```yaml
# helm/charts/gateway/templates/pdb.yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{ include "gateway.fullname" . }}
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: yashigani-gateway
```

`minAvailable: 1` ensures at least one pod is always running during voluntary disruptions. For
gateway (min 2 replicas via HPA), this allows draining one node at a time without downtime.

**PDB is NOT applied to:** Ollama (StatefulSet — K8s handles PDB for StatefulSets differently;
add separately if needed), Redis Cluster (Bitnami chart manages its own PDB).

**Values toggle:**

```yaml
gateway:
  pdb:
    enabled: true
    minAvailable: 1

backoffice:
  pdb:
    enabled: true
    minAvailable: 1
```

---

#### 10.6 Topology Spread Constraints

Topology spread constraints distribute gateway and backoffice pods across availability zones (AZs),
preventing all replicas from landing on nodes in the same AZ. If an AZ fails, surviving pods in
other AZs continue serving traffic.

**Gateway Deployment addition:**

```yaml
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: DoNotSchedule
    labelSelector:
      matchLabels:
        app: yashigani-gateway
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: DoNotSchedule
    labelSelector:
      matchLabels:
        app: yashigani-gateway
```

Two constraints are applied:
1. **Zone spread** (`topology.kubernetes.io/zone`): no AZ has more than 1 extra gateway pod vs.
   other AZs.
2. **Node spread** (`kubernetes.io/hostname`): no node has more than 1 extra gateway pod, ensuring
   pods are distributed even within a single AZ.

`whenUnsatisfiable: DoNotSchedule` is used (not `ScheduleAnyway`) because scheduling in an
imbalanced state defeats the purpose of AZ spread. If the cluster has fewer nodes than replicas,
the scheduler will leave pods Pending — this is visible in the HPA and should trigger an alert.

The same constraints are applied to the backoffice Deployment (substituting the `app` label).

**Values toggle:**

```yaml
gateway:
  topologySpread:
    enabled: true

backoffice:
  topologySpread:
    enabled: true
```

Set `enabled: false` in `helm/environments/staging.yaml` (staging typically has a single zone).

#### Files Created/Modified (Phase 10)

| File | Type | Description |
|------|------|-------------|
| `helm/charts/ollama/templates/statefulset.yaml` | New | Ollama StatefulSet (replaces Deployment) |
| `helm/charts/ollama/templates/service-headless.yaml` | New | Headless Service for per-pod DNS |
| `helm/charts/gateway/templates/pdb.yaml` | New | PodDisruptionBudget for gateway |
| `helm/charts/backoffice/templates/pdb.yaml` | New | PodDisruptionBudget for backoffice |
| `helm/charts/policy/templates/pdb.yaml` | New | PodDisruptionBudget for OPA |
| `helm/charts/prometheus/templates/pdb.yaml` | New | PodDisruptionBudget for Prometheus |
| `helm/charts/grafana/templates/pdb.yaml` | New | PodDisruptionBudget for Grafana |
| `helm/charts/gateway/templates/deployment.yaml` | Modified | Add health probes, topologySpreadConstraints |
| `helm/charts/backoffice/templates/deployment.yaml` | Modified | Add health probes, topologySpreadConstraints |
| `helm/charts/policy/templates/deployment.yaml` | Modified | Add OPA health probes |
| `helm/charts/ollama/templates/deployment.yaml` | Removed | Replaced by statefulset.yaml |
| `helm/charts/redis/templates/` | N/A | Replaced by Bitnami redis-cluster (Phase 9) |
| `helm/charts/prometheus/templates/deployment.yaml` | Modified | Add Prometheus health probes |
| `helm/charts/grafana/templates/deployment.yaml` | Modified | Add Grafana health probes |
| `helm/yashigani/values.yaml` | Modified | Add pdb, topologySpread, ollama.replicas=2 blocks |
| `helm/environments/staging.yaml` | Modified | Disable topologySpread; set ollama.replicas=1 |
| `helm/environments/no-gpu.yaml` | New | GPU-less override: remove nvidia resource requests and node selector |
| `inspection/pipeline.py` | Modified | Introduce OllamaPool with round-robin + failover |
| `inspection/backends/registry.py` | Modified | Add _health_loop for LM Studio liveness polling |
| `gateway/proxy.py` | Modified | Add /healthz and /readyz endpoints |
| `backoffice/routes/health.py` | New | /health and /readyz route handlers for backoffice |

---

### Phase 11 — Universal Installer
**Goal:** Ship a single `install.sh` at the repo root that deploys the complete Yashigani stack on any
supported runtime (Docker ≥ 24, Podman ≥ 4.6) and any supported platform (local x86_64/ARM64, VM,
AWS EC2, Azure VM, GCP Compute Engine), with guided credential setup, demo vs. production deployment
modes, and optional cloud KMS integration. Every credential the installer generates follows the
existing auto-generate-and-print-once policy; every credential the installer prompts for is handled
with no-echo input and is never written to `.env` in plaintext.
**Effort estimate:** 3 days

#### Cross-Phase Dependencies

| Dependency | Required For |
|-----------|-------------|
| Phase 2 — Dockerfile hardening (`HEALTHCHECK` added) | Phase 11 §11.6 `wait-for-bootstrap.sh` uses `/healthz` to confirm readiness |
| Phase 4 — `ci.yml` workflow skeleton | Phase 11 §11.7 adds `test-installer` job to the same file |
| Phase 5 — Helm chart `values.yaml` structure | Phase 11 §11.3 production mode references Helm value names for KMS and TLS blocks |
| Phase 8 — Docker Compose service definitions | Phase 11 §11.6 compose override file patches the existing `docker-compose.yml` |
| Phase 9 — Redis Cluster key-prefix migration | Phase 11 demo mode pulls the same compose stack; compose override must not conflict with cluster config |
| Phase 10 — Ollama StatefulSet + OllamaPool | Phase 11 §11.2 platform detection advises on GPU availability, which directly feeds `OllamaPool` backend selection |

---

#### 11.1 Runtime Agnosticism (Docker / Podman)

The installer supports Docker Engine ≥ 24 and Podman ≥ 4.6. Both runtimes expose a compose
sub-command (Docker via the v2 plugin `docker compose`; Podman via `podman compose` backed by
podman-compose or Podman's built-in compose). The legacy `docker-compose` v1 binary is explicitly
not supported and triggers a preflight error.

**Runtime detection algorithm (Phase 0 of installer):**

```bash
detect_runtime() {
  local preferred="${YASHIGANI_RUNTIME:-}"

  if [[ "${preferred}" == "podman" ]]; then
    _require_runtime podman
    RUNTIME=podman
    COMPOSE="podman compose"
    return
  fi

  # Default: prefer Docker if both present
  if command -v docker &>/dev/null && docker compose version &>/dev/null 2>&1; then
    RUNTIME=docker
    COMPOSE="docker compose"
  elif command -v podman &>/dev/null && podman compose version &>/dev/null 2>&1; then
    RUNTIME=podman
    COMPOSE="podman compose"
  else
    fatal "No supported container runtime found. Install Docker ≥ 24 or Podman ≥ 4.6."
  fi

  # Version guard
  local ver
  if [[ "${RUNTIME}" == "docker" ]]; then
    ver=$(docker version --format '{{.Server.Version}}' 2>/dev/null)
    _check_min_version "${ver}" "24" "Docker"
    # Security note — do not block
    if [[ "${EUID}" -eq 0 ]]; then
      warn "Running install.sh as root with Docker. This is a security risk. Consider using a non-root user with docker group membership."
    fi
  else
    ver=$(podman version --format '{{.Version}}' 2>/dev/null)
    _check_min_version "${ver}" "4.6" "Podman"
    PODMAN_ROOTLESS=$([[ "${EUID}" -ne 0 ]] && echo true || echo false)
  fi
}
```

All subsequent compose invocations use `${COMPOSE}` (never the literal `docker compose` or
`podman compose`). All container run calls use `${RUNTIME}`.

**Rootless Podman adjustments (Phase 6 of installer):**

When `RUNTIME=podman` and `PODMAN_ROOTLESS=true`, the installer writes
`docker/docker-compose.podman-override.yml` patching every service that mounts host volumes:

```yaml
# docker/docker-compose.podman-override.yml  (written by installer, not committed)
services:
  gateway:
    security_opt:
      - label=disable
    userns_mode: keep-id
  backoffice:
    security_opt:
      - label=disable
    userns_mode: keep-id
  redis:
    security_opt:
      - label=disable
    userns_mode: keep-id
  ollama:
    security_opt:
      - label=disable
    userns_mode: keep-id
```

The compose invocation in Phase 8 becomes:

```bash
if [[ -f docker/docker-compose.podman-override.yml ]]; then
  ${COMPOSE} -f docker/docker-compose.yml -f docker/docker-compose.podman-override.yml up -d
else
  ${COMPOSE} -f docker/docker-compose.yml up -d
fi
```

---

#### 11.2 Platform Detection

Platform detection runs during Phase 0 (preflight). It is implemented in
`scripts/detect-platform.sh` and sourced by `install.sh`. Detection is strictly non-blocking:
any failed probe (IMDS timeout, missing tool, unknown hypervisor) sets the platform to `local`
and continues. All IMDS calls use a maximum 1-second connect+read timeout.

**Detection table:**

| Platform | Detection Method | Exported Variables | Adaptations Applied |
|----------|-----------------|-------------------|---------------------|
| Local — x86_64 (Linux/macOS) | `uname -m` = `x86_64` | `PLATFORM=local` `ARCH=x86_64` | Default Ollama CPU image (`ollama/ollama:latest`) |
| Local — ARM64 / Apple Silicon | `uname -m` = `arm64` or `aarch64` | `PLATFORM=local` `ARCH=arm64` | Use ARM Ollama image variant (`ollama/ollama:latest` — multi-arch); warn that GPU passthrough is not available on macOS |
| Virtual machine (non-cloud) | `systemd-detect-virt` (non-none, non-wsl) OR `/proc/cpuinfo` contains `hypervisor` flag | `PLATFORM=vm` | Log note about VM GPU limits; suggest CPU-only inspection backend if no GPU device exposed |
| AWS EC2 | IMDSv2 `http://169.254.169.254/latest/meta-data/instance-type` (1 s timeout, `X-aws-ec2-metadata-token` header) | `PLATFORM=aws` `CLOUD_INSTANCE_TYPE=<type>` | Auto-detect GPU family (p3/p4/g4/g5 → `GPU_AVAILABLE=true`); offer AWS KMS + Secrets Manager in §11.3 prompts |
| Azure VM | IMDS `http://169.254.169.254/metadata/instance?api-version=2021-02-01` with `Metadata: true` header (1 s timeout) | `PLATFORM=azure` `CLOUD_VM_SKU=<sku>` | Auto-detect GPU SKU (`NC*`, `ND*`, `NV*` families → `GPU_AVAILABLE=true`); offer Azure Key Vault in §11.3 prompts |
| GCP Compute Engine | Metadata server `http://metadata.google.internal/computeMetadata/v1/instance/machine-type` with `Metadata-Flavor: Google` header (1 s timeout) | `PLATFORM=gcp` `CLOUD_MACHINE_TYPE=<type>` | Auto-detect A100/T4 families (`a2-*`, `n1-*` with accelerators → `GPU_AVAILABLE=true`); offer GCP Secret Manager in §11.3 prompts |

**`scripts/detect-platform.sh` skeleton:**

```bash
#!/usr/bin/env bash
# Sourced by install.sh — sets PLATFORM, ARCH, CLOUD_*, GPU_AVAILABLE

detect_platform() {
  ARCH=$(uname -m)
  GPU_AVAILABLE=false

  # --- Cloud IMDS probes (all non-blocking, 1s timeout) ---
  local instance_type
  instance_type=$(curl -sf --connect-timeout 1 --max-time 1 \
    -H "X-aws-ec2-metadata-token: $(curl -sf --connect-timeout 1 --max-time 1 \
        -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 10' \
        http://169.254.169.254/latest/api/token 2>/dev/null)" \
    http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null || true)

  if [[ -n "${instance_type}" ]]; then
    PLATFORM=aws
    CLOUD_INSTANCE_TYPE="${instance_type}"
    [[ "${instance_type}" =~ ^(p3|p4|g4|g5) ]] && GPU_AVAILABLE=true
    return
  fi

  local azure_json
  azure_json=$(curl -sf --connect-timeout 1 --max-time 1 \
    -H "Metadata: true" \
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null || true)
  if [[ -n "${azure_json}" ]]; then
    PLATFORM=azure
    CLOUD_VM_SKU=$(printf '%s' "${azure_json}" | jq -r '.compute.vmSize // empty' 2>/dev/null || true)
    [[ "${CLOUD_VM_SKU}" =~ ^Standard_(NC|ND|NV) ]] && GPU_AVAILABLE=true
    return
  fi

  local gcp_machine_type
  gcp_machine_type=$(curl -sf --connect-timeout 1 --max-time 1 \
    -H "Metadata-Flavor: Google" \
    http://metadata.google.internal/computeMetadata/v1/instance/machine-type 2>/dev/null || true)
  if [[ -n "${gcp_machine_type}" ]]; then
    PLATFORM=gcp
    CLOUD_MACHINE_TYPE="${gcp_machine_type##*/}"
    [[ "${CLOUD_MACHINE_TYPE}" =~ ^(a2-|n1-) ]] && GPU_AVAILABLE=true
    return
  fi

  # --- VM detection (non-cloud) ---
  local virt_type
  virt_type=$(systemd-detect-virt 2>/dev/null || true)
  if [[ -n "${virt_type}" && "${virt_type}" != "none" && "${virt_type}" != "wsl" ]]; then
    PLATFORM=vm
    return
  fi
  if grep -q "hypervisor" /proc/cpuinfo 2>/dev/null; then
    PLATFORM=vm
    return
  fi

  PLATFORM=local
}

detect_platform
```

---

#### 11.3 Deployment Modes

The mode is set via `--mode=demo` or `--mode=production` CLI flags, or via an interactive prompt
if neither is given. In non-interactive mode (`--non-interactive`), `--mode` is required.

##### Demo Mode

Demo mode is the default for local and VM platforms when no flag is passed.

| Setting | Value |
|---------|-------|
| `YASHIGANI_TLS_MODE` | `selfsigned` |
| `YASHIGANI_KSM_PROVIDER` | `docker` (secrets volume, no external KMS) |
| `YASHIGANI_ENV` | `development` |
| `YASHIGANI_OLLAMA_MODEL` | `qwen2.5:3b` |
| `YASHIGANI_ADMIN_MIN_TOTAL` | `1` |
| `YASHIGANI_ADMIN_MIN_ACTIVE` | `1` |

- Skips all cloud API credential prompts (user can configure later via admin UI).
- All system passwords are auto-generated by the existing bootstrap process and printed once to stdout.
- Prints the following ASCII banner immediately after mode selection:

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        DEMO MODE — NOT FOR PRODUCTION USE                    ║
║                                                              ║
║  TLS: self-signed   KMS: local volume   ENV: development     ║
║  All secrets are ephemeral. Run with --mode=production for   ║
║  a hardened, KMS-backed deployment.                          ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

##### Production Mode

Production mode enforces stricter defaults and collects required configuration interactively.

**Step 1 — Domain:**
```
Enter the fully-qualified domain name for Yashigani (e.g. yashigani.example.com):
```
Sets `YASHIGANI_TLS_DOMAIN`.

**Step 2 — TLS mode:**
```
Select TLS mode:
  1) ACME (Let's Encrypt) — requires port 80 reachable from the internet
  2) CA-signed — you supply the certificate and key paths
  3) Self-signed — not recommended for production
```
Sets `YASHIGANI_TLS_MODE` = `acme` / `ca` / `selfsigned`.
If `ca`, prompts for cert and key file paths (validated with `openssl x509 -noout`).

**Step 3 — KMS provider:**
```
Select KMS provider:
  1) docker  — local Docker secrets volume (Vault-backed)
  2) keeper  — Keeper Secrets Manager
  3) aws     — AWS Secrets Manager + KMS
  4) azure   — Azure Key Vault
  5) gcp     — GCP Secret Manager
```
Sets `YASHIGANI_KSM_PROVIDER`. Credential collection per provider:

| Provider | Prompted Fields | Storage |
|----------|----------------|---------|
| `docker` | None | n/a (vault bootstrapped automatically) |
| `keeper` | `KEEPER_CLIENT_ID`, `KEEPER_CLIENT_SECRET` | Written to temp file → imported via `scripts/import-kms-secrets.sh` → shredded |
| `aws` | `AWS_REGION`, `AWS_KMS_KEY_ARN`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | Same as above |
| `azure` | `AZURE_VAULT_URL`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | Same as above |
| `gcp` | `GCP_PROJECT`, `GCP_KEYRING`, `GCP_KEY`, `GOOGLE_APPLICATION_CREDENTIALS` (path to service account JSON) | Same as above |

If the platform-detection step identified a matching cloud provider (§11.2), the matching KMS
option is highlighted as the recommended choice.

**Step 4 — Inspection backend API keys (all optional/skippable):**

```
Configure cloud inspection backend API keys (press Enter to skip each — configure later via Admin UI > Settings > Backends):

  Anthropic API key (or Enter to skip):
  Azure OpenAI API key (or Enter to skip):
  Gemini API key (or Enter to skip):
```

If skipped, the installer prints:
```
  → To add later: Admin UI → Settings → Inspection Backends → Add Key
```

**Production mode fixed values:**

| Setting | Value |
|---------|-------|
| `YASHIGANI_ENV` | `production` |
| `YASHIGANI_ADMIN_MIN_TOTAL` | `2` |
| `YASHIGANI_ADMIN_MIN_ACTIVE` | `2` |

---

#### 11.4 Credential Handling

**Auto-generated (never prompted, printed once):**

These follow the existing bootstrap policy: each value is a 36-character random string generated
by `openssl rand -base64 27 | tr -d '=/+' | head -c 36`. All are generated by the bootstrap
container on first start and printed to stdout in a clearly delimited block.

| Credential | Generator | Destination |
|-----------|----------|------------|
| Redis password | bootstrap | `REDIS_PASSWORD` env var (Docker secret) |
| Grafana admin password | bootstrap | `GF_SECURITY_ADMIN_PASSWORD` (Docker secret) |
| Prometheus basic auth hash | bootstrap | `PROMETHEUS_BASIC_AUTH_HASH` (Docker secret) |
| TOTP seeds (per admin) | bootstrap | Stored in KMS, QR code printed to terminal |
| Admin account initial password | bootstrap | Printed once, never stored in plaintext |

**Prompted during install (production mode only):**

All prompted secrets use `read -rs` (no echo, no shell history). Prompts are never logged. The
exact shell idiom used throughout:

```bash
prompt_secret() {
  local var_name="$1" prompt_text="$2"
  local value
  printf '%s' "${prompt_text}: " >&2
  read -rs value
  printf '\n' >&2
  printf '%s' "${value}"   # caller captures via $()
  # value is a local var — dies with function scope
}

ANTHROPIC_API_KEY=$(prompt_secret ANTHROPIC_API_KEY "Anthropic API key (or Enter to skip)")
```

**Security rules — enforced without exception:**

1. Prompted secrets are NEVER written to `.env`. The `.env` file (Phase 5) contains only
   non-secret configuration (`YASHIGANI_TLS_MODE`, `YASHIGANI_ENV`, `PLATFORM`, etc.).
2. If cloud KMS credentials or API keys must be persisted temporarily (for import), they are
   written to a temp file created by `mktemp` with mode `0600`, imported by
   `scripts/import-kms-secrets.sh`, and then destroyed:
   ```bash
   shred -u "${tmp_secrets}" 2>/dev/null || rm -f "${tmp_secrets}"
   ```
   On macOS, `shred` is not available — `rm -f` is the documented fallback (the file was only
   ever in a `tmpfs`-backed `/tmp` on most macOS configurations).
3. At installer exit (trap `EXIT`), all variables holding secrets are explicitly unset:
   ```bash
   cleanup() {
     unset ANTHROPIC_API_KEY AZURE_OPENAI_KEY GEMINI_API_KEY
     unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
     unset AZURE_CLIENT_SECRET KEEPER_CLIENT_SECRET
     unset GCP_SA_JSON_PATH
     [[ -f "${tmp_secrets:-}" ]] && { shred -u "${tmp_secrets}" 2>/dev/null || rm -f "${tmp_secrets}"; }
   }
   trap cleanup EXIT
   ```

---

#### 11.5 Script Structure

`install.sh` is a single Bash script (POSIX-compatible except for `read -rs` which is a bash
built-in). It is not executable via `/bin/sh`. The shebang is `#!/usr/bin/env bash`.

Each phase prints a header of the form `=== Phase N: <name> ===` to stdout and logs to
`/tmp/yashigani-install.log`. Phases can be re-entered via `--resume-from=N` (the script
sources all prior phase outputs from saved state in `.install-state`).

```
install.sh
├── bootstrap helpers (fatal / warn / info / prompt_secret / _check_min_version)
├── trap EXIT → cleanup()
├── CLI argument parsing (--mode / --runtime / --non-interactive / --resume-from)
│
├── === Phase 0: Preflight Checks ===
│   ├── detect_runtime()       (sourced from scripts/check-preflight.sh)
│   ├── detect_platform()      (sourced from scripts/detect-platform.sh)
│   ├── check_required_tools() → curl, openssl, jq, git
│   └── check_port_availability() → 80, 443, 8080, 8443
│       └── Uses: ss -tlnp / lsof -i (platform-appropriate)
│
├── === Phase 1: Mode Selection ===
│   └── Interactive prompt or --mode flag → sets MODE=demo|production
│       └── Demo: print DEMO banner; Production: continue to Phase 2
│
├── === Phase 2: TLS and Domain Configuration ===
│   └── Production only: prompt domain, TLS mode, CA cert paths
│       └── Demo: YASHIGANI_TLS_MODE=selfsigned (no prompt)
│
├── === Phase 3: KMS Provider Selection and Credential Collection ===
│   └── Production only: prompt KMS provider; collect credentials via prompt_secret()
│       └── Write to tmp file (mode 0600) if needed
│
├── === Phase 4: Inspection Backend Credential Collection ===
│   └── Production only: optional prompts for Anthropic / Azure OpenAI / Gemini keys
│       └── Append to same tmp file
│
├── === Phase 5: Write .env File ===
│   └── Write non-secret env vars only (TLS mode, domain, platform, env, admin policy)
│       └── Explicitly excludes all values from prompt_secret() calls
│
├── === Phase 6: Write Runtime Override ===
│   └── Podman + rootless: write docker/docker-compose.podman-override.yml
│       └── Docker or root Podman: no-op
│
├── === Phase 7: Pull Images and Ollama Model ===
│   └── ${COMPOSE} pull (all services)
│   └── ${RUNTIME} pull ollama/ollama (if not already present)
│   └── Pull Ollama model (qwen2.5:3b for demo; configurable for production)
│       └── Uses: ${RUNTIME} run --rm ollama/ollama pull <model>
│
├── === Phase 8: Start Stack ===
│   └── ${COMPOSE} [-f docker/docker-compose.yml] [-f <podman-override>] up -d
│   └── Wait for containers to report "running" status
│
├── === Phase 9: Wait for Bootstrap and Print Credentials ===
│   └── scripts/wait-for-bootstrap.sh → polls container logs, 5-minute timeout
│   └── Prints credential block exactly once to stdout + /tmp/yashigani-install.log
│   └── If cloud KMS selected: run scripts/import-kms-secrets.sh; shred tmp file
│
└── === Phase 10: Post-Install Summary ===
    └── Print access URLs (http/https + admin UI port)
    └── Print relevant Admin UI paths for any skipped configuration
    └── Print: "Credentials saved to /tmp/yashigani-install.log — delete after noting them"
    └── Print runtime + platform detected
    └── Print: next steps (change admin password, configure MFA, review DEMO banner if applicable)
```

**`--resume-from=N` behaviour:**

The installer writes a `.install-state` file (key=value, not containing secrets) after each
phase completes. `--resume-from=N` sources `.install-state`, validates required keys are present,
and jumps to Phase N. Phases 0 and 5 always re-run (preflight and `.env` write are idempotent).

---

#### 11.6 Supporting Files

All files listed below are introduced by Phase 11. None exist prior to this phase.

| File | Role | Notes |
|------|------|-------|
| `install.sh` | Main installer script | Bash, `chmod +x`; sources `scripts/detect-platform.sh` and `scripts/check-preflight.sh` |
| `uninstall.sh` | Teardown script | `chmod +x`; runs `${COMPOSE} down`; asks before `--volumes` (destructive); asks before `docker volume prune` |
| `docker/docker-compose.podman-override.yml` | Rootless Podman adjustments | Written at install time by Phase 6; `.gitignore`'d (runtime-generated) |
| `scripts/detect-platform.sh` | Platform + cloud provider detection | Sourced (not executed) by `install.sh`; exports `PLATFORM`, `ARCH`, `CLOUD_*`, `GPU_AVAILABLE` |
| `scripts/check-preflight.sh` | Runtime detection + tool + port checks | Sourced by `install.sh`; exports `RUNTIME`, `COMPOSE`, `PODMAN_ROOTLESS` |
| `scripts/wait-for-bootstrap.sh` | Poll bootstrap container until credentials appear | Polls `${RUNTIME} logs backoffice` for the credential sentinel string; exits 1 after 300 s |
| `scripts/import-kms-secrets.sh` | Import cloud API keys into KMS; shred temp file | Called by Phase 9 of `install.sh`; uses `yashigani kms set <key> <value>` CLI; shreds temp file on exit |

**`scripts/wait-for-bootstrap.sh` logic:**

```bash
#!/usr/bin/env bash
# Usage: wait-for-bootstrap.sh <runtime> <timeout_seconds>
RUNTIME="${1:-docker}"
TIMEOUT="${2:-300}"
SENTINEL="=== YASHIGANI BOOTSTRAP COMPLETE ==="

elapsed=0
while [[ ${elapsed} -lt ${TIMEOUT} ]]; do
  if ${RUNTIME} logs backoffice 2>&1 | grep -qF "${SENTINEL}"; then
    ${RUNTIME} logs backoffice 2>&1 | sed -n "/\${SENTINEL}/,/END CREDENTIALS/p"
    exit 0
  fi
  sleep 5
  (( elapsed += 5 ))
done

printf 'ERROR: Bootstrap did not complete within %d seconds.\n' "${TIMEOUT}" >&2
printf 'Check logs: %s logs backoffice\n' "${RUNTIME}" >&2
exit 1
```

**`uninstall.sh` interaction flow:**

```
=== Yashigani Uninstaller ===

This will stop and remove all Yashigani containers.

Detected runtime: docker

Step 1/2: Stop and remove containers (docker compose down)?  [y/N]
Step 2/2: Also remove persistent volumes (redis data, ollama models)?
          WARNING: This is irreversible. [y/N]

[If volumes confirmed]
Also run 'docker volume prune --filter label=com.docker.compose.project=yashigani'? [y/N]
```

---

#### 11.7 CI Integration

Phase 4's `ci.yml` workflow gains a new job `test-installer` that validates the installer
end-to-end on every PR and push to `main`.

**Job definition (appended to `.github/workflows/ci.yml`):**

```yaml
  test-installer:
    name: Test Universal Installer (demo mode)
    runs-on: ubuntu-latest
    timeout-minutes: 15
    needs: []   # runs in parallel with lint, test, docker-build

    steps:
      - uses: actions/checkout@v4

      - name: Make scripts executable
        run: chmod +x install.sh uninstall.sh scripts/*.sh

      - name: Run installer in demo/non-interactive mode
        run: |
          ./install.sh \
            --mode=demo \
            --runtime=docker \
            --non-interactive

      - name: Assert all services are healthy (3-minute window)
        run: |
          deadline=$(( $(date +%s) + 180 ))
          services=(gateway backoffice redis ollama prometheus grafana caddy)
          while [[ $(date +%s) -lt ${deadline} ]]; do
            all_healthy=true
            for svc in "${services[@]}"; do
              status=$(docker inspect --format='{{.State.Health.Status}}' "yashigani-${svc}-1" 2>/dev/null || echo "missing")
              if [[ "${status}" != "healthy" ]]; then
                all_healthy=false
                break
              fi
            done
            ${all_healthy} && { echo "All services healthy."; exit 0; }
            sleep 10
          done
          echo "ERROR: Not all services became healthy within 3 minutes." >&2
          docker compose -f docker/docker-compose.yml ps
          exit 1

      - name: Tear down stack
        if: always()
        run: |
          docker compose -f docker/docker-compose.yml down --volumes --remove-orphans
```

The job does not require any secrets (demo mode uses no external KMS or API keys). It runs in
parallel with the existing `lint`, `test`, and `docker-build` jobs (no `needs` dependency on
them). The job is marked `timeout-minutes: 15` to cap runaway installs.

---

#### Files Created/Modified (Phase 11)

| File | Type | Description |
|------|------|-------------|
| `install.sh` | New | Main installer: runtime detection, platform detection, mode selection, credential handling, stack startup |
| `uninstall.sh` | New | Interactive teardown: stops containers, optionally removes volumes |
| `scripts/detect-platform.sh` | New | Platform + cloud IMDS detection; exports `PLATFORM`, `ARCH`, `CLOUD_*`, `GPU_AVAILABLE` |
| `scripts/check-preflight.sh` | New | Runtime detection, version guards, tool checks, port availability; exports `RUNTIME`, `COMPOSE`, `PODMAN_ROOTLESS` |
| `scripts/wait-for-bootstrap.sh` | New | Polls bootstrap container logs for sentinel string; 5-minute timeout; prints credential block |
| `scripts/import-kms-secrets.sh` | New | Imports cloud API keys into running KMS via `yashigani kms set`; shreds temp secrets file |
| `docker/docker-compose.podman-override.yml` | New (generated) | Rootless Podman adjustments: `userns_mode: keep-id` + `security_opt: label=disable` per service; written at install time, `.gitignore`'d |
| `.gitignore` | Modified | Add `docker/docker-compose.podman-override.yml` and `.install-state` |
| `.github/workflows/ci.yml` | Modified | Add `test-installer` job: runs `install.sh --mode=demo --runtime=docker --non-interactive`, asserts healthchecks within 3 minutes, tears down |

**Total new files: 7 | Modified files: 2**

---

## Workflow Dependency Diagram

```
Pull Request / push to main
        │
        ▼
   ┌─────────┐
   │  ci.yml │  ← Runs on every PR + push to main
   │  ───── │
   │  lint   │
   │  test   │──── coverage.xml ──► Codecov
   │  docker │
   │  build  │
   │  sast   │──── SARIF ──────────► GitHub Security
   └─────────┘
        │
        │ (merge to main)
        │
        ▼
   push tag v*.*.*
        │
        ▼
   ┌───────────────┐
   │ build-push.yml│  ← Triggers on version tags
   │  ────────── │
   │  build amd64 │
   │  build arm64 │──── image ──────► GHCR
   │  cosign sign │──── signature ──► GHCR (OCI artifact)
   │  syft SBOM   │──── sbom ───────► GHCR (OCI artifact)
   └───────────────┘
        │ on: success
        ▼
   ┌─────────────────┐
   │ helm-release.yml│  ← Triggers after build-push succeeds
   │  ─────────────│
   │  helm lint      │
   │  helm package   │──── chart.tgz ─► gh-pages branch
   │  cr release     │──── GitHub Release created
   └─────────────────┘

   ┌──────────────┐
   │ security.yml │  ← Daily 03:00 UTC + every PR (subset)
   │  ─────────── │
   │  trivy scan  │──── SARIF ──────► GitHub Security
   │  bandit      │
   │  pip-audit   │
   │  semgrep     │──── SARIF ──────► GitHub Security
   │  owasp dep   │──── HTML report─► Artifact
   └──────────────┘

   ┌────────────┐
   │ deploy.yml │  ← Manual workflow_dispatch only
   │  ───────── │
   │  cosign    │
   │  verify    │
   │  helm      │──────────────────► K8s cluster
   │  upgrade   │
   └────────────┘
```

---

## Complete File Inventory

| File | Type | Description |
|------|------|-------------|
| `.github/workflows/ci.yml` | New | PR gate: lint, test, docker build check, SAST |
| `.github/workflows/security.yml` | New | Daily deep scan: Trivy, Bandit, pip-audit, Semgrep, OWASP DC |
| `.github/workflows/build-push.yml` | New | Tag-triggered multi-arch build, GHCR push, Cosign sign, Syft SBOM |
| `.github/workflows/helm-release.yml` | New | Helm chart package + GitHub Pages publish |
| `.github/workflows/deploy.yml` | New | Manual Helm deploy to staging/production |
| `.github/CODEOWNERS` | New | PR review routing by path |
| `.hadolint.yaml` | New | Hadolint severity config |
| `.dockerignore` | New | Docker build context exclusions |
| `.cr.yaml` | New | chart-releaser config for gh-pages publish |
| `sonar-project.properties` | New | SonarCloud project config |
| `docker/Dockerfile.gateway` | Modified | Digest pin, HEALTHCHECK, post-install cleanup |
| `docker/Dockerfile.backoffice` | Modified | Same as gateway |
| `docker/docker-compose.yml` | Modified | Add pushgateway service |
| `pyproject.toml` | Modified | Add fakeredis, pytest-cov, ruff, mypy to dev extras; coverage fail_under=80 |
| `src/tests/conftest.py` | New | Shared fixtures: mock_redis, mock_opa, mock_ollama |
| `src/tests/unit/test_gateway_proxy.py` | New | Unit tests for gateway/proxy.py |
| `src/tests/unit/test_gateway_auth.py` | New | Unit tests for gateway/agent_auth.py + agent_router.py |
| `src/tests/unit/test_inspection.py` | New | Unit tests for inspection/pipeline.py + classifier.py |
| `src/tests/unit/test_ratelimit.py` | New | Unit tests for ratelimit/limiter.py |
| `src/tests/unit/test_rbac.py` | New | Unit tests for rbac/model.py + rbac/store.py |
| `helm/yashigani/Chart.yaml` | New | Umbrella chart metadata |
| `helm/yashigani/values.yaml` | New | Top-level values, all services namespaced |
| `helm/yashigani/templates/namespace.yaml` | New | Namespace definition |
| `helm/yashigani/templates/networkpolicy.yaml` | New | Default-deny + allow rules |
| `helm/yashigani/templates/NOTES.txt` | New | Post-install instructions |
| `helm/charts/gateway/Chart.yaml` | New | Gateway sub-chart metadata |
| `helm/charts/gateway/values.yaml` | New | Gateway defaults |
| `helm/charts/gateway/templates/deployment.yaml` | New | Deployment with securityContext |
| `helm/charts/gateway/templates/service.yaml` | New | ClusterIP service |
| `helm/charts/gateway/templates/hpa.yaml` | New | HPA (CPU + memory) |
| `helm/charts/gateway/templates/_helpers.tpl` | New | Template helpers |
| `helm/charts/backoffice/` | New | Backoffice sub-chart (same structure as gateway, no HPA) |
| `helm/charts/policy/` | New | OPA sub-chart |
| `helm/charts/redis/` | New | Redis sub-chart |
| `helm/charts/ollama/` | New | Ollama sub-chart |
| `helm/charts/prometheus/` | New | Prometheus sub-chart |
| `helm/charts/grafana/` | New | Grafana sub-chart |
| `helm/charts/caddy/` | New | Caddy sub-chart |
| `helm/environments/staging.yaml` | New | Staging value overrides |
| `helm/environments/production.yaml` | New | Production value overrides |
| `helm/README.md` | New | Pre-install secret creation instructions |
| `config/grafana/dashboards/cicd_health.json` | New | CI/CD Health Grafana dashboard |
| `config/prometheus.yml` | Modified | Add pushgateway + github-actions-exporter scrape targets |
| `ci/parse_trivy.py` | New | Parse Trivy JSON output and push to Pushgateway |
| `helm/charts/backoffice/templates/hpa.yaml` | New | Backoffice HPA (Phase 9) — min 2, max 4, CPU 70% + mem 80% |
| `helm/yashigani/templates/clusterissuer.yaml` | New | cert-manager ClusterIssuers: Let's Encrypt + self-signed (Phase 9) |
| `helm/yashigani/templates/ingress.yaml` | New | nginx Ingress with cert-manager TLS annotation (Phase 9) |
| `helm/yashigani/templates/scaledobject.yaml` | New | KEDA ScaledObject + TriggerAuthentication — optional (Phase 9) |
| `docker/docker-compose.cluster.yml` | New | Override for local Redis Cluster testing (Phase 9) |
| `helm/charts/ollama/templates/statefulset.yaml` | New | Ollama StatefulSet with 2 replicas, GPU affinity (Phase 10) |
| `helm/charts/ollama/templates/service-headless.yaml` | New | Headless Service for per-pod Ollama DNS (Phase 10) |
| `helm/charts/gateway/templates/pdb.yaml` | New | PodDisruptionBudget for gateway (Phase 10) |
| `helm/charts/backoffice/templates/pdb.yaml` | New | PodDisruptionBudget for backoffice (Phase 10) |
| `helm/charts/policy/templates/pdb.yaml` | New | PodDisruptionBudget for OPA (Phase 10) |
| `helm/charts/prometheus/templates/pdb.yaml` | New | PodDisruptionBudget for Prometheus (Phase 10) |
| `helm/charts/grafana/templates/pdb.yaml` | New | PodDisruptionBudget for Grafana (Phase 10) |
| `helm/environments/no-gpu.yaml` | New | GPU-less value overrides — removes nvidia resource requests (Phase 10) |
| `backoffice/routes/health.py` | New | /health and /readyz route handlers for backoffice (Phase 10) |
| `helm/charts/gateway/templates/deployment.yaml` | Modified | Add health probes + topology spread constraints (Phase 10) |
| `helm/charts/backoffice/templates/deployment.yaml` | Modified | Add health probes + topology spread constraints (Phase 10) |
| `helm/charts/policy/templates/deployment.yaml` | Modified | Add OPA liveness/readiness probes (Phase 10) |
| `helm/charts/prometheus/templates/deployment.yaml` | Modified | Add Prometheus health probes (Phase 10) |
| `helm/charts/grafana/templates/deployment.yaml` | Modified | Add Grafana health probes (Phase 10) |
| `helm/yashigani/Chart.yaml` | Modified | Replace local redis with Bitnami redis-cluster dependency (Phase 9) |
| `helm/yashigani/values.yaml` | Modified | Add backoffice.hpa, redis-cluster, certManager, keda, pdb, topologySpread blocks (Phase 9+10) |
| `helm/README.md` | Modified | Add cert-manager + KEDA prerequisites; Redis Cluster migration steps (Phase 9) |
| `helm/environments/staging.yaml` | Modified | Disable topologySpread; ollama replicas=1 (Phase 10) |
| `gateway/proxy.py` | Modified | Key-prefix migration (sess:) + /healthz /readyz endpoints (Phase 9+10) |
| `gateway/agent_auth.py` | Modified | Key-prefix migration: sess: (Phase 9) |
| `ratelimit/limiter.py` | Modified | Key-prefix migration: rl:{agent_id}: with hash tags (Phase 9) |
| `inspection/pipeline.py` | Modified | Key-prefix ic:; OllamaPool round-robin (Phase 9+10) |
| `inspection/backends/registry.py` | Modified | Add _health_loop for LM Studio liveness polling (Phase 10) |
| `backoffice/routes/audit.py` | Modified | Key-prefix migration: aq: (Phase 9) |
| `src/tests/conftest.py` | Modified | Update mock_redis for cluster-mode key prefixes (Phase 9) |

**Total new files: 57 | Modified files: 21**

---

## Open Questions (max 5)

1. ~~**Redis Cluster migration — data drain window**~~ **RESOLVED 2026-03-27:** Maintenance window
   is acceptable. Clean cutover approach confirmed — no dual-write transition required. Phase 9
   will implement a `scripts/redis-migrate.sh` that: (1) puts the stack into maintenance mode
   (Caddy returns 503), (2) flushes single-node Redis, (3) starts Redis Cluster, (4) restores
   stack. Sessions are invalidated; users re-authenticate after cutover. The `uninstall.sh`
   and upgrade runbook will document the expected downtime window (~2–5 minutes).

2. ~~**Ollama GPU availability and CPU fallback SLA**~~ **RESOLVED 2026-03-27:** Admin-configurable
   via the backoffice panel. Phase 4 (`inspection_backend.py`) gains a new `PUT /admin/inspection/gpu-failover`
   setting with three options the admin selects:

   | Option | Behaviour |
   |--------|-----------|
   | `cpu_ollama` | Stay on Ollama, CPU-only (default; slowest, no external API cost) |
   | `fallback_chain` | Trigger the existing `BackendRegistry` fallback chain (skip to next configured backend — e.g. Gemini or Anthropic) |
   | `fail_closed` | Block all requests until a GPU node is available (strictest) |

   The setting is persisted in `BackendConfigStore` (Redis db/1, key `inspection:gpu_failover_policy`).
   `OllamaPool` emits a `GPU_UNAVAILABLE` signal when all pool members are CPU-only; `BackendRegistry`
   reads the policy and acts accordingly. A Grafana panel "GPU Failover Policy" is added to
   `inspection_backend.json` showing the current active policy and time-since-last-GPU-available.

3. ~~**cert-manager cluster ownership**~~ **RESOLVED 2026-03-27:** The installer will request
   temporary cluster-admin credentials for the sole purpose of installing cert-manager CRDs and
   the `ClusterIssuer`. Credentials are **never stored** — held only in shell variables for the
   duration of the CRD install step, then immediately `unset`. Design for `scripts/install-cert-manager.sh`:

   - Prompts: `read -rs KUBECONFIG_ADMIN_DATA` (base64 kubeconfig) or accepts `--kubeconfig-admin=<path>`
   - Writes kubeconfig to a `mktemp 0600` temp file
   - Exports `KUBECONFIG=$TMPFILE` only for the duration of the `kubectl apply` and `helm install cert-manager` calls
   - On exit (success or failure): `shred -u $TMPFILE` (with `rm -f` fallback on macOS), then `unset KUBECONFIG KUBECONFIG_ADMIN_DATA`
   - Installs cert-manager via official Helm chart (`jetstack/cert-manager`, version pinned in `helm/Chart.lock`)
   - Applies `ClusterIssuer` manifests (Let's Encrypt prod + staging + self-signed dev)
   - After CRD install, switches back to the operator's normal (non-admin) kubeconfig for all subsequent Helm operations
   - The step is idempotent — if cert-manager CRDs already exist, the script skips installation and logs "cert-manager already installed, skipping"
   - CI `deploy.yml` uses a dedicated `CERT_MANAGER_BOOTSTRAP_KUBECONFIG` GitHub Actions secret (cluster-admin, scoped to `cert-manager` namespace only) that is rotated after first use

4. ~~**Kubernetes cluster topology — availability zones**~~ **RESOLVED 2026-03-27:** Single-AZ
   deployments are supported with an explicit admin warning flow. Multi-AZ can be configured
   post-install via the backoffice panel. Design:

   **Installer detection:**
   - At deploy time, `scripts/detect-platform.sh` queries the cluster for distinct zone labels:
     `kubectl get nodes -o jsonpath='{.items[*].metadata.labels.topology\.kubernetes\.io/zone}'`
   - If only one unique zone is detected, the installer prints a prominent warning block:

     ```
     ╔══════════════════════════════════════════════════════════════╗
     ║  WARNING — SINGLE AVAILABILITY ZONE DETECTED                ║
     ║  All pods will schedule on nodes in: <zone-name>            ║
     ║                                                              ║
     ║  Risks:                                                      ║
     ║  • A zone outage takes down the entire Yashigani stack       ║
     ║  • No pod anti-affinity enforcement across zones             ║
     ║  • Redis Cluster primaries may co-locate on same host        ║
     ║                                                              ║
     ║  Topology spread will be set to ScheduleAnyway (degraded).  ║
     ║  Add nodes in additional AZs and reconfigure in the         ║
     ║  Admin Panel → Infrastructure → Availability Zones.         ║
     ╚══════════════════════════════════════════════════════════════╝
     ```
   - Installer automatically sets `topologySpread.policy=ScheduleAnyway` (pods schedule but
     spread is best-effort) rather than `DoNotSchedule` (which would leave pods Pending)
   - The single-AZ constraint is recorded in a new `BackofficeState` field
     `cluster_az_count: int` populated at startup via a `kubectl get nodes` probe

   **Backoffice admin panel — `Admin → Infrastructure → Availability Zones`:**
   New route group `PUT /admin/infrastructure/topology` with:
   - `GET /admin/infrastructure/topology` — returns current AZ list (names, node count per AZ,
     spread policy, active warnings)
   - `PUT /admin/infrastructure/topology` — accepts `{ "zones": ["us-east-1a", "us-east-1b"],
     "spread_policy": "DoNotSchedule|ScheduleAnyway", "max_skew": 1 }` — triggers a
     `helm upgrade` via a server-side subprocess call (kubeconfig stored in KMS, not on disk)
     that patches `values.yaml` topology fields and applies them live
   - On update, the backoffice writes a `TopologyConfigChangedEvent` audit record and emits a
     Prometheus gauge `yashigani_cluster_az_count`
   - If `spread_policy` is changed to `DoNotSchedule` while only one AZ is present, the API
     returns HTTP 422 with `{ "error": "single_az_conflict", "detail": "DoNotSchedule requires
     ≥2 zones; detected 1" }` — the admin cannot set a configuration that will strand pods

   **Grafana:** New panel on `system_health.json` — "Cluster AZ Count" gauge with red threshold
   at 1 and green at ≥2, linked to the `yashigani_cluster_az_count` metric.

5. ~~**KEDA vs. HPA coexistence gating**~~ **RESOLVED 2026-03-27:** KEDA is the sole autoscaling
   mechanism. Native Kubernetes HPA objects are **never created** — KEDA manages everything via
   `ScaledObject` resources, which internally create and own the HPA. This gives maximum
   flexibility: KEDA can scale on CPU, memory, Redis queue depth, Prometheus metrics, and custom
   triggers simultaneously, all in one resource. Design:

   **Architecture decision — KEDA-first, no native HPA:**
   - The Helm template guard is inverted: `{{- if .Values.global.keda.enabled }}` renders
     `ScaledObject`; there is **no** native `HorizontalPodAutoscaler` template at all
   - `global.keda.enabled` defaults to `true` in `values.yaml`; set to `false` only for
     local Docker Compose / demo installs where K8s is not present
   - KEDA is installed as a Helm dependency (`kedacore/keda`) in `helm/Chart.yaml` before
     the Yashigani sub-charts, ensuring CRDs exist before any `ScaledObject` is applied

   **`ScaledObject` design per workload:**

   | Workload | Min | Max | Triggers |
   |----------|-----|-----|---------|
   | `gateway` | 2 | 10 | CPU 70% + memory 80% + Prometheus `yashigani_gateway_requests_total` rate |
   | `backoffice` | 2 | 4 | CPU 70% + memory 80% |
   | `ollama` | 1 | N (GPU node count) | Prometheus `yashigani_inspection_backend_latency_seconds` p95 > 5s |
   | `policy` (OPA) | 2 | 6 | CPU 60% |

   **Gateway `ScaledObject` — three simultaneous triggers (most flexible):**
   ```yaml
   triggers:
     - type: cpu
       metricType: Utilization
       metadata:
         value: "70"
     - type: memory
       metricType: Utilization
       metadata:
         value: "80"
     - type: prometheus
       metadata:
         serverAddress: http://prometheus:9090
         metricName: yashigani_gateway_rps
         query: sum(rate(yashigani_gateway_requests_total[1m]))
         threshold: "50"    # scale out when RPS > 50 per replica
   ```

   **Upgrade path from any previous native HPA:** A Helm `pre-upgrade` hook
   (`helm/templates/hooks/delete-legacy-hpa.yaml`) runs `kubectl delete hpa --all -n {{ .Release.Namespace }} --ignore-not-found` before the chart applies `ScaledObject` resources, eliminating the conflict window atomically. The hook is annotated `"helm.sh/hook-delete-policy": hook-succeeded` so it self-cleans.

   **Backoffice panel — `Admin → Infrastructure → Autoscaling`:**
   - `GET /admin/infrastructure/autoscaling` — returns current replica counts, KEDA trigger
     status, and last scale event per workload (read from K8s API via in-cluster service account)
   - `PUT /admin/infrastructure/autoscaling/{workload}` — allows admin to adjust `minReplicas`,
     `maxReplicas`, and trigger thresholds live; patches the `ScaledObject` via K8s API;
     writes `AutoscalingConfigChangedEvent` to audit log
   - Read-only dashboard mode when kubeconfig is not available (Docker Compose installs)

   **Grafana:** New `system_health.json` row — "Autoscaling" with panels for replica count
   per workload (timeseries), KEDA trigger firing rate, and scale-up/scale-down event markers.

---

*End of PLAN_v0.4.0.md — Maxine, 2026-03-27 — All 5 open questions resolved. 11 phases, ready for GO.*
