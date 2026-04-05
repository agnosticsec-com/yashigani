# Yashigani — Kubernetes Deployment Guide

Version: v0.9.3 | Chart version: 0.9.3

---

## Prerequisites

| Tool | Minimum version | Notes |
|------|-----------------|-------|
| kubectl | 1.28 | Configured for your target cluster |
| Helm | 3.14 | `helm version` to verify |
| cert-manager | 1.14 | Required for automatic TLS (`tlsMode: nginx`) |
| nginx-ingress | 1.10 | Required when `global.tlsMode: nginx` (default) |
| k3s or minikube | any recent | For local testing only |

Optional but recommended:

- **KEDA** — if `global.keda.enabled: true` (default). Required for event-driven autoscaling.
- **Prometheus Operator** — if you want ServiceMonitor CRDs; plain Prometheus works without it.

---

## Quick Start

### 1. Create the namespace and secrets

Yashigani requires several Kubernetes Secrets before install. Create them manually or with your secret management tool (External Secrets, Vault Agent, etc.).

```bash
# Namespace
kubectl create namespace yashigani

# Gateway secrets
kubectl create secret generic yashigani-gateway-secrets \
  -n yashigani \
  --from-literal=redis_password="$(openssl rand -hex 32)" \
  --from-literal=upstream_url="https://your-mcp-server.example.com"

# Backoffice secrets
kubectl create secret generic yashigani-backoffice-secrets \
  -n yashigani \
  --from-literal=redis_password="$(openssl rand -hex 32)" \
  --from-literal=admin_password="$(openssl rand -hex 24)"

# Redis shared secret (same password used above)
kubectl create secret generic yashigani-redis-secrets \
  -n yashigani \
  --from-literal=redis_password="<same-as-above>"

# Postgres
kubectl create secret generic yashigani-postgres-secrets \
  -n yashigani \
  --from-literal=postgres_password="$(openssl rand -hex 32)"

# DB credentials for partition maintenance CronJob
kubectl create secret generic yashigani-db-credentials \
  -n yashigani \
  --from-literal=url="postgresql://yashigani_app:<postgres_password>@yashigani-pgbouncer:5432/yashigani"

# Grafana
kubectl create secret generic yashigani-grafana-secrets \
  -n yashigani \
  --from-literal=grafana_admin_password="$(openssl rand -hex 24)"

# Open WebUI
kubectl create secret generic yashigani-open-webui-secrets \
  -n yashigani \
  --from-literal=secret_key="$(openssl rand -hex 32)"
```

### 2. Install the chart

```bash
helm install yashigani helm/yashigani/ \
  --namespace yashigani \
  --set global.tlsDomain=yashigani.example.com \
  --set global.acmeEmail=admin@example.com \
  --wait
```

### 3. Verify the release

```bash
# Check all pods are running
kubectl get pods -n yashigani

# Run Helm smoke tests
helm test yashigani -n yashigani --logs
```

---

## Configuration: Key values.yaml Parameters

### Global

| Key | Default | Description |
|-----|---------|-------------|
| `global.imageRegistry` | `ghcr.io` | Container registry prefix |
| `global.imageOwner` | `yashigani` | Registry namespace/org |
| `global.tlsDomain` | `yashigani.example.com` | **REQUIRED** — your public domain |
| `global.tlsMode` | `nginx` | `nginx` (cert-manager) or `caddy` (edge proxy) |
| `global.certManagerIssuer` | `letsencrypt-prod` | ClusterIssuer name for TLS |
| `global.acmeEmail` | `admin@example.com` | ACME registration email |
| `global.environment` | `production` | Passed to services as env hint |
| `global.keda.enabled` | `true` | Enable KEDA for event-driven scaling |
| `global.pdb.enabled` | `true` | Enable PodDisruptionBudgets |

### Gateway

| Key | Default | Description |
|-----|---------|-------------|
| `gateway.replicaCount` | `2` | Minimum replicas |
| `gateway.hpa.maxReplicas` | `10` | HPA ceiling |
| `gateway.env.upstreamUrl` | `""` | **REQUIRED** — upstream MCP server URL |
| `gateway.env.opaUrl` | `http://policy:8181` | OPA policy endpoint |
| `gateway.env.ollamaUrl` | `http://ollama:11434` | Ollama inference endpoint |
| `gateway.existingSecretName` | `yashigani-gateway-secrets` | Secret with `redis_password` |

### Backoffice

| Key | Default | Description |
|-----|---------|-------------|
| `backoffice.replicaCount` | `2` | Minimum replicas |
| `backoffice.service.port` | `8443` | Internal service port |
| `backoffice.existingSecretName` | `yashigani-backoffice-secrets` | Admin credential secret |

### Redis

| Key | Default | Description |
|-----|---------|-------------|
| `redis.persistence.enabled` | `true` | Enable PVC for Redis data |
| `redis.persistence.size` | `1Gi` | PVC size |
| `redis.existingSecretName` | `yashigani-redis-secrets` | Secret with `redis_password` |

### Budget Redis

| Key | Default | Description |
|-----|---------|-------------|
| `budgetRedis.enabled` | `true` | Dedicated Redis for token budget counters |
| `budgetRedis.persistence.size` | `1Gi` | PVC size |
| `budgetRedis.existingSecretName` | `yashigani-redis-secrets` | Reuses same Redis secret |

### Ollama

| Key | Default | Description |
|-----|---------|-------------|
| `ollama.image.tag` | `0.6.2` | Pinned to match docker-compose |
| `ollama.replicaCount` | `2` | HA replicas |
| `ollama.persistence.size` | `20Gi` | Model storage PVC |
| `ollama.model` | `qwen2.5:3b` | Default model to use |

### PostgreSQL + PgBouncer

| Key | Default | Description |
|-----|---------|-------------|
| `postgres.enabled` | `true` | Deploy bundled Postgres |
| `postgres.persistence.size` | `20Gi` | Data PVC size |
| `postgres.existingSecretName` | `yashigani-postgres-secrets` | Secret with `postgres_password` |
| `pgbouncer.enabled` | `true` | Deploy PgBouncer connection pooler |
| `pgbouncer.env.poolMode` | `transaction` | PgBouncer pool mode |

---

## Agent Bundles

Agent bundles are opt-in and disabled by default. Enable per-bundle at install or upgrade time:

```bash
# Enable Goose (AI developer assistant — ACP server on port 3284)
helm upgrade yashigani helm/yashigani/ -n yashigani \
  --set agentBundles.goose.enabled=true \
  --set agentBundles.goose.tokenSecretName=yashigani-goose-token

# Enable LangGraph
helm upgrade yashigani helm/yashigani/ -n yashigani \
  --set agentBundles.langgraph.enabled=true

# Enable OpenClaw (exposes port 18789 for messaging webhooks)
helm upgrade yashigani helm/yashigani/ -n yashigani \
  --set agentBundles.openclaw.enabled=true \
  --set agentBundles.openclaw.tokenSecretName=yashigani-openclaw-token
```

Each enabled bundle creates a Deployment and (where applicable) a Service. All agent traffic routes through the Yashigani gateway — direct LLM access is blocked by NetworkPolicy.

**Note:** CrewAI is enterprise-only as of v2.1. Contact sales@agnosticsec.com.

---

## TLS: cert-manager Integration

The chart ships three ClusterIssuers (rendered by `clusterissuers.yaml`):

| Name | Use case |
|------|----------|
| `letsencrypt-prod` | Production (requires public DNS) |
| `letsencrypt-staging` | Rate-limit-safe testing |
| `selfsigned` | Local/dev — no DNS required |

Set the active issuer:

```bash
helm upgrade yashigani helm/yashigani/ -n yashigani \
  --set global.certManagerIssuer=letsencrypt-staging  # testing
```

To use nginx-ingress + cert-manager (default):

```bash
# Install cert-manager
helm repo add jetstack https://charts.jetstack.io
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager --create-namespace \
  --set installCRDs=true

# Install nginx-ingress
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm install ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx --create-namespace
```

To use Caddy as the TLS edge proxy instead (Docker-compose parity):

```bash
helm upgrade yashigani helm/yashigani/ -n yashigani \
  --set global.tlsMode=caddy \
  --set caddy.enabled=true
```

---

## Monitoring: Prometheus and Grafana Access

Prometheus and Grafana are deployed cluster-internally. Access via port-forward or via the Ingress `/admin` route.

```bash
# Prometheus port-forward
kubectl port-forward svc/yashigani-prometheus 9090:9090 -n yashigani

# Grafana port-forward
kubectl port-forward svc/yashigani-grafana 3000:3000 -n yashigani
# Default user: grafana-admin
# Password: from yashigani-grafana-secrets / grafana_admin_password
```

Via Ingress (if `global.tlsDomain` is set):

- Grafana: `https://yashigani.example.com/admin/grafana`
- Prometheus (federate, basic auth via Caddy): `https://yashigani.example.com/metrics-federate`

---

## v2.2 Feature Flags

### PII Detection

```bash
helm upgrade yashigani helm/yashigani/ -n yashigani \
  --set pii.enabled=true \
  --set pii.mode=redact          # log | redact | block
```

Requires license feature `pii_log` (Community+) or `pii_redact` (Pro+). Configured at the backoffice level; values.yaml sets defaults only.

### DDoS Protection

Enabled by default. Tune thresholds:

```bash
helm upgrade yashigani helm/yashigani/ -n yashigani \
  --set ddosProtection.maxConnectionsPerIp=100 \
  --set ddosProtection.windowSeconds=30
```

### Response Inspection

Run the Ollama injection classifier over LLM responses (additional latency):

```bash
helm upgrade yashigani helm/yashigani/ -n yashigani \
  --set responseInspection.enabled=true
```

### SSO / Identity Provider

Configure IdPs via the backoffice UI at runtime. See `values.yaml` `sso.idps` for the static-config structure if you prefer GitOps-style IdP registration.

---

## Helm Smoke Tests

Three test Pods run after `helm test`:

| Test | What it checks |
|------|----------------|
| `test-gateway-health` | `GET /healthz` on gateway returns HTTP 200 |
| `test-backoffice-health` | `GET /healthz` on backoffice returns HTTP 200 |
| `test-redis-ping` | Both Redis instances respond to PING (auth expected in prod) |

```bash
helm test yashigani -n yashigani --logs
```

Test Pods are deleted on success (`hook-delete-policy: hook-succeeded`).

---

## Troubleshooting

### Pod stuck in Pending

```bash
kubectl describe pod <pod-name> -n yashigani
```

Common causes:
- PVC not bound — check `storageClass` in values.yaml; set `""` to use cluster default.
- Resource quota exceeded — check `kubectl describe resourcequota -n yashigani`.
- Node selector/affinity mismatch — check `topologySpread` settings.

### Gateway returns 502 Bad Gateway

- Check OPA policy pod: `kubectl logs -l app.kubernetes.io/name=yashigani-policy -n yashigani`
- Check Redis connectivity: `helm test yashigani -n yashigani`
- Verify `gateway.env.upstreamUrl` is set and reachable from within the cluster.

### TLS certificate not issued

```bash
kubectl describe certificaterequest -n yashigani
kubectl describe challenge -n yashigani
```

- Ensure `global.acmeEmail` is valid.
- For `letsencrypt-prod`, the domain must resolve publicly to the cluster's LoadBalancer IP.
- Use `letsencrypt-staging` for testing to avoid rate limits.

### Backoffice first-run credentials

On first boot, the backoffice generates admin credentials. Check:

```bash
kubectl logs -l app.kubernetes.io/name=yashigani-backoffice -n yashigani | grep -i "admin\|password\|credential"
```

### Agent bundle not routing through gateway

1. Verify `YASHIGANI_AGENT_TOKEN` secret is mounted correctly.
2. Check NetworkPolicy — agent bundles are only allowed to reach the gateway on port 8080.
3. Review gateway logs: `kubectl logs -l app.kubernetes.io/name=yashigani-gateway -n yashigani`

### Upgrade: legacy HPA cleanup

The `pre-upgrade` hook Job `delete-legacy-hpa` removes stale HPA objects before upgrade. If it fails:

```bash
kubectl get jobs -n yashigani
kubectl logs job/yashigani-delete-legacy-hpa -n yashigani
```

The Job requires the `yashigani` ServiceAccount to have `delete` on `horizontalpodautoscalers`. If RBAC is locked down, grant it temporarily or delete HPAs manually before upgrading.
