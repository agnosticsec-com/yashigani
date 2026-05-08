#!/usr/bin/env bash
# uninstall.sh — Tear down the Yashigani stack.
# Usage: ./uninstall.sh [--remove-volumes] [--runtime=docker|podman] [--yes|-y]

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker/docker-compose.yml"
REMOVE_VOLUMES="false"
RUNTIME="${RUNTIME:-}"
YES="false"

for arg in "$@"; do
    case "$arg" in
        --remove-volumes) REMOVE_VOLUMES="true" ;;
        --runtime=*)      RUNTIME="${arg#*=}" ;;
        --yes|-y)         YES="true" ;;
        --help|-h)
            cat <<'EOF'
Usage: ./uninstall.sh [OPTIONS]

Stops the Yashigani stack and optionally removes all data.

Options:
  --remove-volumes    Also permanently delete all data volumes
                      (Redis, audit logs, Ollama models, metrics history)
  --runtime=RUNTIME   Force a specific container runtime (docker|podman)
  --yes, -y           Skip confirmation prompts (for unattended/CI use).
                      Safety note: when combined with --remove-volumes this
                      will DELETE ALL DATA without prompting. Pass both flags
                      only when you are certain data loss is acceptable.
  --help, -h          Print this message and exit
EOF
            exit 0
            ;;
        *) printf "Unknown option: %s\nRun with --help for usage.\n" "$arg" >&2; exit 1 ;;
    esac
done

# Detect runtime
if [ -z "$RUNTIME" ]; then
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        RUNTIME="docker"
    elif command -v podman >/dev/null 2>&1; then
        RUNTIME="podman"
    else
        echo "ERROR: No container runtime found."
        exit 1
    fi
fi
COMPOSE="$RUNTIME compose"

echo "=== Yashigani Uninstaller ==="
echo "Runtime: $RUNTIME"
echo ""

if [ "$REMOVE_VOLUMES" = "true" ]; then
    echo "WARNING: --remove-volumes will PERMANENTLY DELETE all data:"
    echo "  - Redis data (sessions, RBAC, rate-limit state)"
    echo "  - Audit logs"
    echo "  - Ollama models (large download on next start)"
    echo "  - Grafana/Prometheus metrics history"
    echo ""
    if [ "$YES" = "false" ]; then
        read -rp "Type 'yes' to confirm permanent data deletion: " confirm
        if [ "$confirm" != "yes" ]; then
            echo "Cancelled. No data was deleted."
            exit 0
        fi
    else
        echo "Skipping confirmation (--yes supplied)."
    fi
    DOWN_ARGS="--volumes --remove-orphans"
else
    echo "Stopping services (volumes preserved)."
    echo "Use --remove-volumes to also delete all data."
    DOWN_ARGS="--remove-orphans"
fi

# shellcheck disable=SC2086
$COMPOSE -f "$COMPOSE_FILE" down $DOWN_ARGS
echo ""
echo "Yashigani stopped."
[ "$REMOVE_VOLUMES" = "true" ] && echo "All volumes deleted." || echo "Data volumes preserved."
