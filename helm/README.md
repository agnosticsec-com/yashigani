# Yashigani Helm Charts

Umbrella chart at `helm/yashigani/` with sub-charts under `helm/charts/`.

## Prerequisites

- Helm 3.14+
- Kubernetes 1.28+
- [KEDA](https://keda.sh) installed in the cluster (`keda` namespace)
- [cert-manager](https://cert-manager.io) installed in the cluster (`cert-manager` namespace)
- nginx-ingress controller installed (for `global.tlsMode=nginx`)

### Install KEDA

```bash
helm repo add kedacore https://kedacore.github.io/charts
helm repo update
helm upgrade --install keda kedacore/keda --namespace keda --create-namespace
```

### Install cert-manager

Use the provided bootstrap script (handles temporary credentials securely):

```bash
bash scripts/install-cert-manager.sh
```

Or manually:

```bash
helm repo add jetstack https://charts.jetstack.io
helm repo update
helm upgrade --install cert-manager jetstack/cert-manager \
  --namespace cert-manager --create-namespace \
  --version v1.14.5 --set installCRDs=true --wait
```

---

## Pre-Install: Create Secrets

All secrets must exist before install. Passwords must be 36 characters minimum (auto-generated recommended).

```bash
NAMESPACE=yashigani

# Generate passwords
REDIS_PASS=$(openssl rand -base64 27 | tr -d '=+/' | head -c 36)
GATEWAY_ADMIN_PASS=$(openssl rand -base64 27 | tr -d '=+/' | head -c 36)
BACKOFFICE_ADMIN_PASS=$(openssl rand -base64 27 | tr -d '=+/' | head -c 36)
GRAFANA_PASS=$(openssl rand -base64 27 | tr -d '=+/' | head -c 36)

echo "Generated passwords (save these securely):"
echo "  REDIS:      $REDIS_PASS"
echo "  GATEWAY:    $GATEWAY_ADMIN_PASS"
echo "  BACKOFFICE: $BACKOFFICE_ADMIN_PASS"
echo "  GRAFANA:    $GRAFANA_PASS"

kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# Gateway secret
kubectl create secret generic yashigani-gateway-secrets \
  --namespace "$NAMESPACE" \
  --from-literal=redis-password="$REDIS_PASS" \
  --from-literal=admin-password="$GATEWAY_ADMIN_PASS" \
  --dry-run=client -o yaml | kubectl apply -f -

# Backoffice secret
kubectl create secret generic yashigani-backoffice-secrets \
  --namespace "$NAMESPACE" \
  --from-literal=redis-password="$REDIS_PASS" \
  --from-literal=admin-password="$BACKOFFICE_ADMIN_PASS" \
  --dry-run=client -o yaml | kubectl apply -f -

# Redis secret
kubectl create secret generic yashigani-redis-secrets \
  --namespace "$NAMESPACE" \
  --from-literal=redis-password="$REDIS_PASS" \
  --dry-run=client -o yaml | kubectl apply -f -

# Grafana secret
kubectl create secret generic yashigani-grafana-secrets \
  --namespace "$NAMESPACE" \
  --from-literal=grafana-admin-password="$GRAFANA_PASS" \
  --dry-run=client -o yaml | kubectl apply -f -
```

---

## Dependency Update

Must be run before first install and after any sub-chart change:

```bash
helm dep update helm/yashigani/
```

---

## Install

### Staging

```bash
helm upgrade --install yashigani helm/yashigani/ \
  --namespace yashigani \
  --create-namespace \
  --values helm/yashigani/values.yaml \
  --set global.tlsDomain=staging.yashigani.example.com \
  --set global.acmeEmail=ops@example.com \
  --set global.certManagerIssuer=letsencrypt-staging \
  --set global.environment=staging \
  --wait \
  --timeout 10m
```

### Production

```bash
helm upgrade --install yashigani helm/yashigani/ \
  --namespace yashigani \
  --create-namespace \
  --values helm/yashigani/values.yaml \
  --set global.tlsDomain=yashigani.example.com \
  --set global.acmeEmail=ops@example.com \
  --set global.certManagerIssuer=letsencrypt-prod \
  --set global.environment=production \
  --wait \
  --timeout 10m
```

---

## Upgrade Procedure

1. Update the chart version in `helm/yashigani/Chart.yaml` and affected sub-charts.
2. Run `helm dep update helm/yashigani/` to refresh dependency archives.
3. Review changes with `helm diff upgrade` (requires helm-diff plugin):
   ```bash
   helm diff upgrade yashigani helm/yashigani/ --namespace yashigani
   ```
4. Apply the upgrade:
   ```bash
   helm upgrade yashigani helm/yashigani/ --namespace yashigani --wait --timeout 10m
   ```
5. The `pre-upgrade` hook (`delete-legacy-hpa`) will run automatically to remove native HPAs before KEDA ScaledObjects are applied.

---

## Secret Rotation Procedure

Rotate a secret without downtime (rolling restart approach):

```bash
NAMESPACE=yashigani
NEW_REDIS_PASS=$(openssl rand -base64 27 | tr -d '=+/' | head -c 36)

# 1. Update the secret
kubectl create secret generic yashigani-redis-secrets \
  --namespace "$NAMESPACE" \
  --from-literal=redis-password="$NEW_REDIS_PASS" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic yashigani-gateway-secrets \
  --namespace "$NAMESPACE" \
  --from-literal=redis-password="$NEW_REDIS_PASS" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic yashigani-backoffice-secrets \
  --namespace "$NAMESPACE" \
  --from-literal=redis-password="$NEW_REDIS_PASS" \
  --dry-run=client -o yaml | kubectl apply -f -

# 2. Rolling restart all affected deployments
kubectl rollout restart deployment/yashigani-gateway -n "$NAMESPACE"
kubectl rollout restart deployment/yashigani-backoffice -n "$NAMESPACE"
kubectl rollout restart deployment/yashigani-redis -n "$NAMESPACE"

# 3. Wait for rollout completion
kubectl rollout status deployment/yashigani-gateway -n "$NAMESPACE"
kubectl rollout status deployment/yashigani-backoffice -n "$NAMESPACE"

echo "Secret rotation complete. Monitor /healthz endpoints."
```

---

## Redis Cluster Migration (Phase 9)

When ready to migrate from single-node to Redis Cluster:

```bash
bash scripts/redis-migrate.sh
```

See `scripts/redis-migrate.sh` for full procedure with confirmation prompt.
