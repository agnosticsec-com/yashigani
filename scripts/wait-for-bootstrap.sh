#!/usr/bin/env bash
# wait-for-bootstrap.sh — Poll backoffice logs for first-run credentials.
# Usage: scripts/wait-for-bootstrap.sh [compose-file] [timeout-seconds]

set -euo pipefail

COMPOSE_FILE="${1:-docker/docker-compose.yml}"
TIMEOUT="${2:-300}"
ELAPSED=0
INTERVAL=5
COMPOSE="${COMPOSE:-docker compose}"

echo "Waiting for bootstrap to complete (timeout: ${TIMEOUT}s)..."

while true; do
    if $COMPOSE -f "$COMPOSE_FILE" logs backoffice 2>/dev/null | grep -q "FIRST-RUN CREDENTIALS"; then
        echo ""
        echo "=== Bootstrap complete. Credentials ==="
        $COMPOSE -f "$COMPOSE_FILE" logs backoffice 2>/dev/null | \
            awk '/FIRST-RUN CREDENTIALS/,/END CREDENTIALS/'
        echo "======================================="
        exit 0
    fi

    if [ $ELAPSED -ge $TIMEOUT ]; then
        echo "ERROR: Bootstrap timeout after ${TIMEOUT}s."
        echo "Check logs: $COMPOSE -f $COMPOSE_FILE logs backoffice"
        exit 1
    fi

    printf "."
    sleep $INTERVAL
    ELAPSED=$((ELAPSED + INTERVAL))
done
