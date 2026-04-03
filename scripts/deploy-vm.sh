#!/usr/bin/env bash
# scripts/deploy-vm.sh — Deploy latest code to the test VM.
# One command: git pull → rebuild all images → full restart → health check → Ava QA.
#
# Usage: bash scripts/deploy-vm.sh [--skip-qa] [--vm-ip 192.168.64.2]
#
# NO piecemeal scp. NO partial rebuilds. Full clean deploy from git every time.

set -euo pipefail

VM_IP="${VM_IP:-192.168.64.2}"
VM_USER="max"
VM_KEY="$HOME/.ssh/yashigani_vm"
DOMAIN="yashigani.local"
SKIP_QA=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-qa) SKIP_QA=true; shift ;;
    --vm-ip) VM_IP="$2"; shift 2 ;;
    *) echo "Unknown: $1"; exit 1 ;;
  esac
done

SSH="ssh -i $VM_KEY -o StrictHostKeyChecking=no ${VM_USER}@${VM_IP}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RESET='\033[0m'

step() { printf "${BLUE}[DEPLOY]${RESET} %s\n" "$*"; }
ok()   { printf "${GREEN}[OK]${RESET}     %s\n" "$*"; }
fail() { printf "${RED}[FAIL]${RESET}   %s\n" "$*"; exit 1; }

# --- Step 1: Push to git first ---
step "Checking git status..."
cd "$REPO_DIR"
if [[ -n "$(git status --porcelain)" ]]; then
  fail "Uncommitted changes. Commit first, then deploy."
fi
COMMIT=$(git log --oneline -1)
ok "Clean working tree: $COMMIT"

# --- Step 2: Pull on VM ---
step "Pulling latest code on VM..."
$SSH "cd ~/yashigani-test && git stash 2>/dev/null; git pull 2>&1 | tail -3; git log --oneline -1" || fail "Git pull failed"
ok "VM has latest code"

# --- Step 3: Rebuild all images ---
step "Rebuilding gateway image (no cache)..."
$SSH "cd ~/yashigani-test && podman rmi -f localhost/yashigani/gateway:latest 2>/dev/null; podman build --no-cache -f docker/Dockerfile.gateway -t yashigani/gateway:latest . 2>/dev/null | tail -1" || fail "Gateway build failed"
ok "Gateway image rebuilt"

step "Rebuilding backoffice image (no cache)..."
$SSH "cd ~/yashigani-test && podman rmi -f localhost/yashigani/backoffice:latest 2>/dev/null; podman build --no-cache -f docker/Dockerfile.backoffice -t yashigani/backoffice:latest . 2>/dev/null | tail -1" || fail "Backoffice build failed"
ok "Backoffice image rebuilt"

# --- Step 4: Full restart ---
step "Full stack restart..."
$SSH "export PATH=\$PATH:\$HOME/.local/bin; cd ~/yashigani-test/docker && podman-compose -f docker-compose.yml down 2>/dev/null && podman-compose -f docker-compose.yml up -d 2>&1 | tail -1" || fail "Compose up failed"
ok "Stack restarting"

# --- Step 5: Wait for health ---
step "Waiting for services to be healthy (60s)..."
sleep 60
HEALTHY=$($SSH "podman ps --format '{{.Status}}' 2>&1 | grep -c healthy" || echo "0")
step "Healthy services: $HEALTHY"
if [[ "$HEALTHY" -lt 14 ]]; then
  fail "Only $HEALTHY services healthy (expected 14+)"
fi
ok "$HEALTHY services healthy"

# --- Step 6: Run Ava QA ---
if [[ "$SKIP_QA" == "true" ]]; then
  step "Skipping QA (--skip-qa)"
else
  step "Running Ava QA test suite..."

  # Reset backoffice for clean auth state
  $SSH "export PATH=\$PATH:\$HOME/.local/bin; cd ~/yashigani-test/docker && podman stop docker_backoffice_1 2>/dev/null && podman rm docker_backoffice_1 2>/dev/null && podman-compose -f docker-compose.yml up -d backoffice 2>&1 | tail -1"
  sleep 20

  cd "$REPO_DIR"
  if python3 scripts/test-ui.py --vm-ip "$VM_IP" --domain "$DOMAIN"; then
    ok "Ava QA: ALL PASSED"
  else
    fail "Ava QA: FAILURES DETECTED — do not ship"
  fi
fi

printf "\n${GREEN}╔══════════════════════════════════════╗${RESET}\n"
printf "${GREEN}║  Deploy complete: $COMMIT  ║${RESET}\n"
printf "${GREEN}╚══════════════════════════════════════╝${RESET}\n"
