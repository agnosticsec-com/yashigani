#!/usr/bin/env bash
# check-preflight.sh — Pre-flight checks before install.
# Source this file: . scripts/check-preflight.sh
# Exits with error if any required check fails.

set -euo pipefail

ERRORS=0

check_tool() {
    local tool="$1"
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "  MISSING: $tool"
        ERRORS=$((ERRORS + 1))
    else
        echo "  OK: $tool ($(command -v "$tool"))"
    fi
}

check_port() {
    local port="$1"
    local desc="$2"
    if command -v ss >/dev/null 2>&1; then
        if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
            echo "  IN USE: port $port ($desc)"
            ERRORS=$((ERRORS + 1))
            return
        fi
    elif command -v lsof >/dev/null 2>&1; then
        if lsof -i ":$port" >/dev/null 2>&1; then
            echo "  IN USE: port $port ($desc)"
            ERRORS=$((ERRORS + 1))
            return
        fi
    fi
    echo "  OK: port $port ($desc) is free"
}

echo "=== Preflight: Required tools ==="
check_tool curl
check_tool openssl
check_tool jq
check_tool git

echo ""
echo "=== Preflight: Port availability ==="
check_port 80   "HTTP"
check_port 443  "HTTPS"
check_port 8080 "Gateway"
check_port 8443 "Backoffice"

echo ""
echo "=== Preflight: Runtime ==="
if [ -z "${RUNTIME:-}" ]; then
    echo "  ERROR: RUNTIME not set (call detect_runtime first)"
    ERRORS=$((ERRORS + 1))
else
    echo "  OK: RUNTIME=$RUNTIME"
fi

if [ $ERRORS -gt 0 ]; then
    echo ""
    echo "Preflight FAILED: $ERRORS error(s). Resolve the issues above and re-run."
    exit 1
fi
echo ""
echo "Preflight PASSED."
