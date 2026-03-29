#!/usr/bin/env bash
# install-cert-manager.sh — Install cert-manager with temporary cluster-admin credentials.
# Credentials are held only in shell variables and a mktemp 0600 file.
# Both are destroyed on exit, success or failure.
set -euo pipefail

CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-v1.14.5}"
NAMESPACE="cert-manager"
TMPKUBE=""

cleanup() {
    if [ -n "$TMPKUBE" ] && [ -f "$TMPKUBE" ]; then
        if command -v shred >/dev/null 2>&1; then
            shred -u "$TMPKUBE"
        else
            rm -f "$TMPKUBE"
        fi
    fi
    unset KUBECONFIG KUBECONFIG_ADMIN_DATA
    echo "Credentials cleared."
}
trap cleanup EXIT

# Accept kubeconfig via file or stdin
if [ -n "${KUBECONFIG_ADMIN:-}" ]; then
    TMPKUBE="$KUBECONFIG_ADMIN"
else
    echo "=== cert-manager Bootstrap ==="
    echo "Paste base64-encoded cluster-admin kubeconfig (Ctrl+D when done):"
    KUBECONFIG_ADMIN_DATA=$(cat | base64 -d)
    TMPKUBE=$(mktemp)
    chmod 600 "$TMPKUBE"
    echo "$KUBECONFIG_ADMIN_DATA" > "$TMPKUBE"
    unset KUBECONFIG_ADMIN_DATA
fi

export KUBECONFIG="$TMPKUBE"

# Check if cert-manager is already installed
if kubectl get namespace "$NAMESPACE" >/dev/null 2>&1 && \
   kubectl get deployment -n "$NAMESPACE" cert-manager >/dev/null 2>&1; then
    echo "cert-manager already installed — skipping."
    exit 0
fi

echo "Installing cert-manager ${CERT_MANAGER_VERSION}..."
helm repo add jetstack https://charts.jetstack.io
helm repo update
helm upgrade --install cert-manager jetstack/cert-manager \
    --namespace "$NAMESPACE" \
    --create-namespace \
    --version "$CERT_MANAGER_VERSION" \
    --set installCRDs=true \
    --wait

echo "Applying ClusterIssuers..."
kubectl apply -f helm/yashigani/templates/clusterissuers.yaml

echo "cert-manager installation complete."
