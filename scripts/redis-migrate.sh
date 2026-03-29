#!/usr/bin/env bash
# redis-migrate.sh — Maintenance-window cutover from single-node Redis to Redis Cluster.
#
# This script is DESTRUCTIVE (FLUSHALL). Run only during a scheduled maintenance window.
# Users will need to re-authenticate after migration (sessions are not migrated).
#
# Usage:
#   bash scripts/redis-migrate.sh [--force]
#
# Flags:
#   --force    Skip the interactive confirmation prompt (for CI pipelines)
#
# Prerequisites:
#   - kubectl configured for the target cluster
#   - NAMESPACE env var set (default: yashigani)
#   - redis-cli available locally or via kubectl exec
set -euo pipefail

NAMESPACE="${NAMESPACE:-yashigani}"
REDIS_SECRET_NAME="yashigani-redis-secrets"
FORCE=false

# Parse arguments
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=true ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

# Cleanup trap — always restore state on failure
cleanup() {
  local exit_code=$?
  if [ $exit_code -ne 0 ]; then
    echo ""
    echo "ERROR: Migration failed with exit code $exit_code."
    echo "Manual recovery required:"
    echo "  1. Check: kubectl get pods -n $NAMESPACE"
    echo "  2. Scale gateway back up if needed:"
    echo "     kubectl scale deployment yashigani-gateway -n $NAMESPACE --replicas=2"
    echo "     kubectl scale deployment yashigani-backoffice -n $NAMESPACE --replicas=2"
    echo "  3. Investigate Redis state before retrying."
  fi
}
trap cleanup EXIT

log() { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $*"; }

# ── Step 0: Warning and confirmation ─────────────────────────────────────────

echo "================================================================"
echo "  YASHIGANI REDIS CLUSTER MIGRATION"
echo "  Namespace: $NAMESPACE"
echo "================================================================"
echo ""
echo "WARNING: This script will:"
echo "  1. Scale gateway and backoffice to 0 (maintenance mode)"
echo "  2. FLUSH ALL DATA from the current single-node Redis"
echo "  3. Apply Redis Cluster configuration"
echo "  4. Scale services back up"
echo ""
echo "All user sessions will be invalidated. Users must re-authenticate."
echo "Estimated downtime: 3-10 minutes depending on cluster provisioning speed."
echo ""

if [ "$FORCE" = false ]; then
  read -r -p "Type 'MIGRATE' to confirm you want to proceed: " confirm
  if [ "$confirm" != "MIGRATE" ]; then
    echo "Migration cancelled."
    exit 0
  fi
fi

log "Migration confirmed. Starting..."

# ── Step 1: Record current replica counts for rollback ───────────────────────

GATEWAY_REPLICAS=$(kubectl get deployment yashigani-gateway -n "$NAMESPACE" \
  -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "2")
BACKOFFICE_REPLICAS=$(kubectl get deployment yashigani-backoffice -n "$NAMESPACE" \
  -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "2")

log "Current replicas — gateway: $GATEWAY_REPLICAS, backoffice: $BACKOFFICE_REPLICAS"

# ── Step 2: Scale down to zero (maintenance mode) ────────────────────────────

log "Scaling down gateway and backoffice to 0..."
kubectl scale deployment yashigani-gateway -n "$NAMESPACE" --replicas=0
kubectl scale deployment yashigani-backoffice -n "$NAMESPACE" --replicas=0

# ── Step 3: Wait for pods to terminate ───────────────────────────────────────

log "Waiting for gateway pods to terminate..."
kubectl wait --for=delete pod -l app=yashigani-gateway -n "$NAMESPACE" \
  --timeout=120s 2>/dev/null || true

log "Waiting for backoffice pods to terminate..."
kubectl wait --for=delete pod -l app=yashigani-backoffice -n "$NAMESPACE" \
  --timeout=120s 2>/dev/null || true

log "All application pods terminated."

# ── Step 4: Flush single-node Redis ──────────────────────────────────────────

log "Flushing single-node Redis (FLUSHALL)..."

REDIS_PASSWORD=$(kubectl get secret "$REDIS_SECRET_NAME" -n "$NAMESPACE" \
  -o jsonpath='{.data.redis-password}' | base64 -d)

REDIS_POD=$(kubectl get pod -l app=yashigani-redis -n "$NAMESPACE" \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [ -z "$REDIS_POD" ]; then
  log "No Redis pod found — assuming Redis deployment will be replaced."
else
  kubectl exec -n "$NAMESPACE" "$REDIS_POD" -- \
    redis-cli -a "$REDIS_PASSWORD" FLUSHALL
  log "FLUSHALL complete."
fi

unset REDIS_PASSWORD

# ── Step 5: Apply Redis Cluster configuration ─────────────────────────────────

log "Applying Redis Cluster manifests..."

# Update helm values to enable cluster mode
# In a full CI workflow this would trigger a helm upgrade.
# For now, apply the cluster values override:
helm upgrade yashigani helm/yashigani/ \
  --namespace "$NAMESPACE" \
  --reuse-values \
  --set redis.cluster.enabled=true \
  --wait \
  --timeout 5m || {
    log "Helm upgrade failed. Attempting rollback to single-node..."
    helm rollback yashigani --namespace "$NAMESPACE" --wait
    log "Rollback complete. Scaling services back up with original replica counts..."
    kubectl scale deployment yashigani-gateway -n "$NAMESPACE" --replicas="$GATEWAY_REPLICAS"
    kubectl scale deployment yashigani-backoffice -n "$NAMESPACE" --replicas="$BACKOFFICE_REPLICAS"
    exit 1
  }

# ── Step 6: Wait for Redis Cluster health ────────────────────────────────────

log "Waiting for Redis pods to be ready..."
kubectl wait --for=condition=ready pod -l app=yashigani-redis -n "$NAMESPACE" \
  --timeout=180s

log "Redis Cluster is healthy."

# ── Step 7: Scale services back up ───────────────────────────────────────────

log "Scaling gateway back to $GATEWAY_REPLICAS replicas..."
kubectl scale deployment yashigani-gateway -n "$NAMESPACE" --replicas="$GATEWAY_REPLICAS"

log "Scaling backoffice back to $BACKOFFICE_REPLICAS replicas..."
kubectl scale deployment yashigani-backoffice -n "$NAMESPACE" --replicas="$BACKOFFICE_REPLICAS"

log "Waiting for gateway rollout..."
kubectl rollout status deployment/yashigani-gateway -n "$NAMESPACE" --timeout=120s

log "Waiting for backoffice rollout..."
kubectl rollout status deployment/yashigani-backoffice -n "$NAMESPACE" --timeout=120s

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo "================================================================"
echo "  Migration complete."
echo "  Users will need to re-authenticate (all sessions invalidated)."
echo "  Monitor: kubectl get pods -n $NAMESPACE"
echo "================================================================"
