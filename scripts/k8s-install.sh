#!/usr/bin/env bash
# scripts/k8s-install.sh — Yashigani Kubernetes install wrapper
# Last updated: 2026-05-03T14:00:00+01:00
#
# Thin wrapper around install.sh --mode k8s that sets Kubernetes-sensible
# defaults and validates pre-conditions before delegating.
#
# Retro #3u: install.sh --mode k8s exists but has no ergonomic entry-point
# with K8s-specific defaults or pre-condition checks.
#
# Usage:
#   bash scripts/k8s-install.sh [OPTIONS]
#   # All OPTIONS are forwarded to install.sh unchanged.
#
# Implicit defaults (only applied when not already set on argv or env):
#   --mode k8s
#   --non-interactive          (K8s installs run in CI/CD — no TTY)
#   YSG_RUNTIME=k8s
#
# Pre-conditions checked (hard-stop on failure):
#   1. kubectl is in PATH and reachable cluster exists
#   2. helm is in PATH
#   3. Either --domain or YASHIGANI_DOMAIN env var is set
#   4. Namespace is not "default" (accidental deployment guard)
#
# Examples:
#   # Minimal K8s install
#   bash scripts/k8s-install.sh \
#     --domain yashigani.example.com \
#     --admin-email admin@example.com \
#     --namespace yashigani \
#     --deploy production
#
#   # Dry-run to review steps
#   bash scripts/k8s-install.sh \
#     --domain yashigani.example.com \
#     --dry-run

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INSTALL_SH="${REPO_ROOT}/install.sh"

# Hardened PATH — never trust inherited PATH for privileged scripts
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

if [[ ! -f "$INSTALL_SH" ]]; then
  printf "ERROR: install.sh not found at %s\n" "$INSTALL_SH" >&2
  exit 1
fi

# ── Parse our own args to extract pre-condition values ───────────────────────
_domain=""
_namespace="yashigani"
_dry_run=false

_pass_through=()
_i=0
_args=("$@")
while [[ $_i -lt ${#_args[@]} ]]; do
  _a="${_args[$_i]}"
  case "$_a" in
    --domain)
      _i=$((_i + 1))
      _domain="${_args[$_i]:-}"
      _pass_through+=("--domain" "$_domain")
      ;;
    --domain=*)
      _domain="${_a#--domain=}"
      _pass_through+=("$_a")
      ;;
    --namespace)
      _i=$((_i + 1))
      _namespace="${_args[$_i]:-}"
      _pass_through+=("--namespace" "$_namespace")
      ;;
    --namespace=*)
      _namespace="${_a#--namespace=}"
      _pass_through+=("$_a")
      ;;
    --dry-run)
      _dry_run=true
      _pass_through+=("$_a")
      ;;
    --mode)
      # absorb --mode arg if caller passed it; we always inject --mode k8s
      _i=$((_i + 1))
      ;;
    --mode=*)
      : # absorbed
      ;;
    *)
      _pass_through+=("$_a")
      ;;
  esac
  _i=$((_i + 1))
done

# Fall back to env var for domain
if [[ -z "$_domain" ]]; then
  _domain="${YASHIGANI_DOMAIN:-}"
fi

# ── Pre-condition checks ──────────────────────────────────────────────────────
_fail() { printf "ERROR: %s\n" "$*" >&2; exit 1; }

if ! command -v kubectl >/dev/null 2>&1; then
  _fail "kubectl not found in PATH — install kubectl before running k8s-install.sh"
fi

if ! command -v helm >/dev/null 2>&1; then
  _fail "helm not found in PATH — install helm before running k8s-install.sh"
fi

if [[ "$_dry_run" != "true" ]]; then
  if ! kubectl cluster-info >/dev/null 2>&1; then
    _fail "kubectl cannot reach a cluster — configure KUBECONFIG or set context before running"
  fi
fi

if [[ -z "$_domain" ]]; then
  _fail "--domain (or YASHIGANI_DOMAIN env var) is required for Kubernetes installs"
fi

if [[ "$_namespace" == "default" ]]; then
  _fail "Namespace 'default' is not allowed for Yashigani — use a dedicated namespace (e.g. yashigani)"
fi

# ── Export K8s runtime ────────────────────────────────────────────────────────
export YSG_RUNTIME=k8s

# ── Delegate to install.sh with K8s defaults ─────────────────────────────────
printf "[k8s-install] Delegating to install.sh --mode k8s (namespace: %s, domain: %s)\n" \
  "$_namespace" "$_domain"

exec bash "$INSTALL_SH" \
  --mode k8s \
  --non-interactive \
  --namespace "$_namespace" \
  "${_pass_through[@]+"${_pass_through[@]}"}"
