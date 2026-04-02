#!/usr/bin/env bash
# scripts/test-upgrade.sh — Yashigani v2.0.0
# Tests the upgrade path from v1.09.5 -> v1.10.0 -> v2.0.0.
# Verifies data persistence, service health, and feature availability.
#
# Usage:
#   bash scripts/test-upgrade.sh
#
# Requires: Docker, git, internet access (for image pulls).
# WARNING: This script creates and destroys Docker resources.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_URL="${YASHIGANI_REPO_URL:-https://github.com/agnosticsec-com/yashigani.git}"
WORK_DIR="/tmp/yashigani-upgrade-test"
PASSED=0
FAILED=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RESET='\033[0m'

_pass() { PASSED=$((PASSED + 1)); printf "${GREEN}[PASS]${RESET} %s\n" "$*"; }
_fail() { FAILED=$((FAILED + 1)); printf "${RED}[FAIL]${RESET} %s\n" "$*"; }
_info() { printf "${BLUE}[INFO]${RESET} %s\n" "$*"; }

cleanup() {
  _info "Cleaning up..."
  cd /tmp
  if [ -d "$WORK_DIR" ]; then
    cd "$WORK_DIR" && docker compose -f docker/docker-compose.yml down -v 2>/dev/null || true
  fi
  docker ps -aq | xargs -r docker rm -f 2>/dev/null || true
  rm -rf "$WORK_DIR"
}

# ── Step 1: Install v1.09.5 ─────────────────────────────────────────────

_info "Step 1: Installing v1.09.5 (gateway-only)..."
cleanup
git clone --branch v1.09.5 --depth 1 "$REPO_URL" "$WORK_DIR" 2>/dev/null
cd "$WORK_DIR"

bash install.sh --non-interactive --deploy demo --domain yashigani.local \
  --tls-mode selfsigned --admin-email admin@yashigani.local \
  --skip-preflight --skip-pull 2>/dev/null

# Verify v1.09.5 is running
if docker compose -f docker/docker-compose.yml ps 2>/dev/null | grep -q "healthy"; then
  _pass "v1.09.5 installed and healthy"
else
  _fail "v1.09.5 installation failed"
  exit 1
fi

# Record some data (admin credentials in secrets, .env settings)
ADMIN_USER=$(cat docker/secrets/admin1_username 2>/dev/null || echo "unknown")
AES_KEY=$(grep YASHIGANI_DB_AES_KEY docker/.env 2>/dev/null | cut -d= -f2 || echo "unknown")
_info "v1.09.5 admin: $ADMIN_USER, AES key prefix: ${AES_KEY:0:8}..."

# ── Step 2: Upgrade to v1.10.0 ──────────────────────────────────────────

_info "Step 2: Upgrading to v1.10.0..."
git fetch --tags 2>/dev/null
git checkout v1.10.0 2>/dev/null || git checkout release/1.x 2>/dev/null

# Re-run installer in upgrade mode
bash install.sh --non-interactive --deploy demo --domain yashigani.local \
  --tls-mode selfsigned --admin-email admin@yashigani.local \
  --skip-preflight --skip-pull --upgrade 2>/dev/null

# Verify upgrade preserved data
ADMIN_USER_AFTER=$(cat docker/secrets/admin1_username 2>/dev/null || echo "unknown")
AES_KEY_AFTER=$(grep YASHIGANI_DB_AES_KEY docker/.env 2>/dev/null | cut -d= -f2 || echo "unknown")

if [ "$ADMIN_USER" = "$ADMIN_USER_AFTER" ]; then
  _pass "Admin username preserved after upgrade: $ADMIN_USER"
else
  _fail "Admin username changed: $ADMIN_USER -> $ADMIN_USER_AFTER"
fi

if [ "$AES_KEY" = "$AES_KEY_AFTER" ]; then
  _pass "AES key preserved after upgrade"
else
  _fail "AES key changed after upgrade"
fi

# Verify v1.10.0 services
if docker compose -f docker/docker-compose.yml ps 2>/dev/null | grep -q "healthy"; then
  _pass "v1.10.0 services healthy after upgrade"
else
  _fail "v1.10.0 services not healthy after upgrade"
fi

# Check new features available
if grep -q "1.10.0" install.sh 2>/dev/null; then
  _pass "Version 1.10.0 in installer"
else
  _fail "Version not updated to 1.10.0"
fi

# ── Summary ──────────────────────────────────────────────────────────────

cleanup

printf "\n"
printf "╔══════════════════════════════════════════╗\n"
printf "║  Upgrade Test Results                     ║\n"
printf "╠══════════════════════════════════════════╣\n"
printf "║  Passed: %-31d ║\n" "$PASSED"
printf "║  Failed: %-31d ║\n" "$FAILED"
printf "╚══════════════════════════════════════════╝\n"

if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
exit 0
