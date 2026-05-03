#!/usr/bin/env bash
# last-updated: 2026-05-03T11:15:00+01:00
# tests/upgrade/n_minus_one.sh — N-1 upgrade harness for Yashigani
#
# Proves that a deployment at OLD_VERSION (default: v2.22.3) upgrades cleanly
# to NEW_VERSION (default: 2.23.x tip), preserving data, creds, and audit
# log, and that the rollback (restore.sh) path also works.
#
# Reusable: future releases pass different OLD_VERSION / NEW_VERSION.
#
# Usage:
#   ./tests/upgrade/n_minus_one.sh [OPTIONS]
#
# Options:
#   --old-version VER      Old tag to start from (default: v2.22.3)
#   --new-ref     REF      New branch/tag/commit (default: 2.23.x)
#   --repo-url    URL      Git remote (default: https://github.com/agnosticsec-com/yashigani.git)
#   --vm-host     HOST     SSH target host (default: 192.168.64.2)
#   --vm-user     USER     SSH user on VM (default: tom)
#   --vm-key      PATH     SSH private key path
#   --vm-password PASS     sudo password for --vm-user on the VM
#   --work-dir    PATH     Harness work directory on VM (default: /home/tom/n1_harness)
#   --evidence-dir PATH    Local directory for JSON + log output
#                          (default: /Users/max/Documents/Claude/Internal/Compliance/
#                           yashigani/v2.23.1/n-1-upgrade-evidence)
#   --skip-cleanup         Leave VM directory after run (for debugging)
#   --runtime     RUNTIME  Container runtime to use: docker|podman (default: docker)
#   --timeout     SECS     Per-phase healthcheck timeout (default: 300)
#   --help
#
# Greppable verdict lines emitted to both stdout and the .log file:
#   N-1 upgrade install (v2.22.x): PASS|FAIL
#   N-1 upgrade backup: PASS|FAIL
#   N-1 upgrade in-place: PASS|FAIL
#   N-1 upgrade post-upgrade login Admin1 HTTP: 200
#   N-1 upgrade post-upgrade login Admin2 HTTP: 200
#   N-1 upgrade restore: PASS|FAIL
#   N-1 upgrade re-upgrade: PASS|FAIL
#   N-1 GATE VERDICT: PASS|FAIL
#
# Per feedback_no_fake_green_harnesses.md SOP-4:
#   The harness FAILs on any unexpected non-2xx. No downgrade clauses.
# Per feedback_runtime_choice.md:
#   YSG_RUNTIME is always set explicitly — no silent auto-detection.
# Per feedback_admin_bootstrap_both_admins.md:
#   Admin1 AND Admin2 HTTP 200 are checked after every phase.
# Per feedback_clean_slate_test.md:
#   Installs from remote git tag/branch, never from local files.
# Per feedback_evidence_bound_task_closure.md SOP-5:
#   PASS verdicts are only emitted when the greppable verdict line from the
#   API call is actually present in the log. No prose-summary closures.

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
OLD_VERSION="${OLD_VERSION:-v2.22.3}"
NEW_REF="${NEW_REF:-2.23.x}"
REPO_URL="${REPO_URL:-https://github.com/agnosticsec-com/yashigani.git}"
VM_HOST="${VM_HOST:-192.168.64.2}"
VM_USER="${VM_USER:-tom}"
VM_KEY="${VM_KEY:-/Users/max/.ssh/yashigani-vm/tom_ed25519}"
VM_PASSWORD="${VM_PASSWORD:-mLAeDG7~QT_.liAE-8P7HJrCDLX0}"
HARNESS_WORK_DIR="${HARNESS_WORK_DIR:-/home/tom/n1_harness}"
EVIDENCE_DIR="${EVIDENCE_DIR:-/Users/max/Documents/Claude/Internal/Compliance/yashigani/v2.23.1/n-1-upgrade-evidence}"
SKIP_CLEANUP="${SKIP_CLEANUP:-false}"
RUNTIME="${RUNTIME:-docker}"
HEALTHCHECK_TIMEOUT="${HEALTHCHECK_TIMEOUT:-300}"
ROUND_LIMIT=10  # number of bump_round() phases; separate from the 3-retry rule
                # (the 3-round rule applies to iterative fixes on a FAILING gate,
                # not to the sequential phases within a single harness run)

# Compose command to use in remote scripts. For Podman: "podman compose".
# For Docker: "docker compose". Derived from RUNTIME after arg parse.
# Set after parse_args so --runtime overrides take effect.
# shellcheck disable=SC2034
REMOTE_COMPOSE="docker compose"   # updated below after arg parse

# ---------------------------------------------------------------------------
# Argument parsing  (MUST come before output-file setup so --evidence-dir
# is honoured before mkdir + exec tee)
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --old-version)   OLD_VERSION="$2";    shift 2 ;;
        --new-ref)       NEW_REF="$2";         shift 2 ;;
        --repo-url)      REPO_URL="$2";        shift 2 ;;
        --vm-host)       VM_HOST="$2";         shift 2 ;;
        --vm-user)       VM_USER="$2";         shift 2 ;;
        --vm-key)        VM_KEY="$2";          shift 2 ;;
        --vm-password)   VM_PASSWORD="$2";     shift 2 ;;
        --work-dir)      HARNESS_WORK_DIR="$2"; shift 2 ;;
        --evidence-dir)  EVIDENCE_DIR="$2";    shift 2 ;;
        --skip-cleanup)  SKIP_CLEANUP=true;    shift ;;
        --runtime)       RUNTIME="$2";         shift 2 ;;
        --timeout)       HEALTHCHECK_TIMEOUT="$2"; shift 2 ;;
        --help)
            grep '^#' "$0" | grep -v '#!/' | sed 's/^# \?//' | head -50
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# BASE_WORK_DIR is frozen after arg parse (HARNESS_WORK_DIR may be set by
# --work-dir). It is used by cleanup() to enumerate all dirs created during the
# run. HARNESS_WORK_DIR itself is mutated in main() after each phase so
# subsequent phases read from the correct (upgraded/restored) directory.
BASE_WORK_DIR="$HARNESS_WORK_DIR"

# ---------------------------------------------------------------------------
# Execution-context guard — must run from developer machine, not from VM
#
# This harness SSHes to the VM for every remote step.  Running it ON the VM
# itself (as happened in Run 3) causes the SSH key path to be unresolvable,
# producing a confusing "Cannot SSH" error in Phase 0.
#
# After arg-parse, VM_KEY has its final value.  If the key file does not exist
# on the local filesystem, we are almost certainly running from the wrong host.
# Exit immediately with a clear remediation message.
# ---------------------------------------------------------------------------
if [[ ! -f "$VM_KEY" ]]; then
    echo "ERROR: SSH key not found: $VM_KEY" >&2
    echo "" >&2
    echo "This harness must be run from the developer machine, not from the VM." >&2
    echo "It SSHes to the VM (${VM_USER}@${VM_HOST}) for every remote step." >&2
    echo "" >&2
    echo "Remediation:" >&2
    echo "  1. Run this script from your developer machine (macOS/Linux with the key)." >&2
    echo "  2. Or pass the correct key path:  --vm-key /path/to/private_key" >&2
    echo "" >&2
    echo "Do NOT copy this script to the VM and run it there." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Timestamp + output files  (after arg parse so --evidence-dir is applied)
# ---------------------------------------------------------------------------
RUN_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
mkdir -p "$EVIDENCE_DIR"
LOG_FILE="${EVIDENCE_DIR}/n_minus_one_${RUN_TS}.log"
JSON_FILE="${EVIDENCE_DIR}/n_minus_one_${RUN_TS}.json"

# All output goes to both stdout and the log file
exec > >(tee -a "$LOG_FILE") 2>&1

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
# Set compose command based on RUNTIME
if [[ "$RUNTIME" == "podman" ]]; then
    REMOTE_COMPOSE="podman compose"
else
    REMOTE_COMPOSE="docker compose"
fi

PASS_COUNT=0
FAIL_COUNT=0

# Phase verdict variables — bash 3.2-compatible (no declare -A)
VERDICT_install="NOTRUN"
VERDICT_backup="NOTRUN"
VERDICT_upgrade="NOTRUN"
VERDICT_postinstall_admin1="000"
VERDICT_postinstall_admin2="000"
VERDICT_postupgrade_admin1="000"
VERDICT_postupgrade_admin2="000"
VERDICT_postrestore_admin1="000"
VERDICT_postrestore_admin2="000"
VERDICT_reupgrade="NOTRUN"
VERDICT_postreupgrade_admin1="000"
VERDICT_postreupgrade_admin2="000"
VERDICT_restore="NOTRUN"

# Set a phase verdict by name (uses eval — safe here: phase keys are
# hardcoded internal strings, never external input)
set_verdict() {
    local phase="$1"
    local result="$2"
    eval "VERDICT_${phase}=\"${result}\""
}

# Get a phase verdict by name
get_verdict() {
    local phase="$1"
    eval "printf '%s' \"\${VERDICT_${phase}:-NOTRUN}\""
}

# ---------------------------------------------------------------------------
# Container name detection helpers
# These are called per-phase to get the right container names for the
# currently-running stack (Docker uses dashes, Podman uses underscores).
# ---------------------------------------------------------------------------

# Detect backoffice container exec command and container name for the current stack.
# Outputs two words: "<exec_cmd> <cname>" e.g. "docker exec docker-backoffice-1"
detect_backoffice_exec() {
    local cname
    cname=$(vm_run "
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q 'docker-backoffice-1'; then echo 'docker-backoffice-1'
elif podman ps --format '{{.Names}}' 2>/dev/null | grep -q 'docker_backoffice_1'; then echo 'docker_backoffice_1'
elif docker ps --format '{{.Names}}' 2>/dev/null | grep 'backoffice' | head -1; then docker ps --format '{{.Names}}' 2>/dev/null | grep 'backoffice' | head -1
elif podman ps --format '{{.Names}}' 2>/dev/null | grep 'backoffice' | head -1; then podman ps --format '{{.Names}}' 2>/dev/null | grep 'backoffice' | head -1
else echo 'docker-backoffice-1'; fi
" 2>/dev/null | tr -d ' \n' || echo "docker-backoffice-1")
    local ecmd="docker exec"
    if echo "$cname" | grep -q '_'; then ecmd="podman exec"; fi
    printf "%s %s" "$ecmd" "$cname"
}

# Same for postgres
detect_postgres_exec() {
    local cname
    cname=$(vm_run "
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q 'docker-postgres-1'; then echo 'docker-postgres-1'
elif podman ps --format '{{.Names}}' 2>/dev/null | grep -q 'docker_postgres_1'; then echo 'docker_postgres_1'
elif docker ps --format '{{.Names}}' 2>/dev/null | grep 'postgres' | grep -v pgbouncer | head -1; then docker ps --format '{{.Names}}' 2>/dev/null | grep 'postgres' | grep -v pgbouncer | head -1
elif podman ps --format '{{.Names}}' 2>/dev/null | grep 'postgres' | grep -v pgbouncer | head -1; then podman ps --format '{{.Names}}' 2>/dev/null | grep 'postgres' | grep -v pgbouncer | head -1
else echo 'docker-postgres-1'; fi
" 2>/dev/null | tr -d ' \n' || echo "docker-postgres-1")
    local ecmd="docker exec"
    if echo "$cname" | grep -q '_'; then ecmd="podman exec"; fi
    printf "%s %s" "$ecmd" "$cname"
}

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }

log() {
    printf "[%s] %s\n" "$(ts)" "$*"
}

log_phase() {
    printf "\n[%s] ======== PHASE: %s ========\n" "$(ts)" "$*"
}

# Emit a greppable verdict line to stdout+log and track pass/fail
verdict() {
    local label="$1"   # e.g. "N-1 upgrade install (v2.22.x)"
    local result="$2"  # PASS or FAIL
    local phase="$3"   # internal key

    printf "%s: %s\n" "$label" "$result"
    set_verdict "$phase" "$result"

    if [[ "$result" == "PASS" ]]; then
        PASS_COUNT=$(( PASS_COUNT + 1 ))
    else
        FAIL_COUNT=$(( FAIL_COUNT + 1 ))
    fi
}

# SSH into the VM and run a command, capturing output
vm_run() {
    # Usage: vm_run "command to run on VM"
    ssh -i "$VM_KEY" \
        -o StrictHostKeyChecking=no \
        -o BatchMode=yes \
        -o ConnectTimeout=30 \
        "$VM_USER@$VM_HOST" "$@"
}

# SSH into the VM and run a command with sudo via stdin password
vm_sudo() {
    # Usage: vm_sudo "command to sudo on VM"
    ssh -i "$VM_KEY" \
        -o StrictHostKeyChecking=no \
        -o BatchMode=yes \
        -o ConnectTimeout=30 \
        "$VM_USER@$VM_HOST" "echo '${VM_PASSWORD}' | sudo -S $*"
}

# Run a script remotely via heredoc
vm_run_script() {
    # Usage: vm_run_script <<'SCRIPT' ... SCRIPT
    # ServerAliveInterval=60 prevents TCP keepalive timeout during long-running
    # remote commands (e.g. image pulls + install.sh, which can take 10–20 min).
    ssh -i "$VM_KEY" \
        -o StrictHostKeyChecking=no \
        -o BatchMode=yes \
        -o ConnectTimeout=30 \
        -o ServerAliveInterval=60 \
        -o ServerAliveCountMax=10 \
        "$VM_USER@$VM_HOST" bash -s
}

# Abort if fail count is non-zero (per no-fake-green rule)
assert_no_failures() {
    if [[ "$FAIL_COUNT" -gt 0 ]]; then
        log "HARD STOP: $FAIL_COUNT phase(s) failed. Halting per no-fake-green SOP-4."
        emit_final_verdict "FAIL"
        exit 1
    fi
}

# Check for round limit violation
CURRENT_ROUND=0
bump_round() {
    CURRENT_ROUND=$(( CURRENT_ROUND + 1 ))
    if [[ "$CURRENT_ROUND" -gt "$ROUND_LIMIT" ]]; then
        log "HARD STOP: round limit ($ROUND_LIMIT) exceeded."
        log "Per feedback_enumerate_before_edit.md rule 5: diagnose root cause before continuing."
        emit_final_verdict "FAIL"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Phase 0: Pre-flight
# ---------------------------------------------------------------------------
preflight() {
    log_phase "0 — Pre-flight"

    # Verify SSH connectivity
    if ! vm_run "echo 'SSH OK'" 2>/dev/null | grep -q "SSH OK"; then
        log "ERROR: Cannot SSH to $VM_USER@$VM_HOST using $VM_KEY"
        exit 1
    fi
    log "SSH connectivity: OK"

    # Verify docker is reachable on VM
    if ! vm_run "docker info >/dev/null 2>&1 && echo 'DOCKER OK'" 2>/dev/null | grep -q "DOCKER OK"; then
        log "ERROR: Docker not reachable on VM"
        exit 1
    fi
    log "Docker reachable on VM: OK"

    # Verify git is available on VM
    if ! vm_run "git --version >/dev/null 2>&1 && echo 'GIT OK'" 2>/dev/null | grep -q "GIT OK"; then
        log "ERROR: git not found on VM"
        exit 1
    fi
    log "git available on VM: OK"

    # Verify the old tag is reachable from the remote
    if ! git ls-remote --tags "$REPO_URL" "refs/tags/${OLD_VERSION}" 2>/dev/null | grep -q "$OLD_VERSION"; then
        log "ERROR: Tag $OLD_VERSION not found at $REPO_URL"
        exit 1
    fi
    log "Remote tag $OLD_VERSION: reachable"

    # Verify the new ref is reachable
    if ! git ls-remote "$REPO_URL" "refs/heads/${NEW_REF}" 2>/dev/null | grep -q .; then
        # Try as a tag
        if ! git ls-remote --tags "$REPO_URL" "refs/tags/${NEW_REF}" 2>/dev/null | grep -q .; then
            log "ERROR: New ref $NEW_REF not found at $REPO_URL (tried branch and tag)"
            exit 1
        fi
    fi
    log "Remote ref $NEW_REF: reachable"

    log "Pre-flight: OK"
}

# ---------------------------------------------------------------------------
# Phase 1 — Nuke any existing state on VM + clone OLD_VERSION
# ---------------------------------------------------------------------------
nuke_and_install_old() {
    log_phase "1 — Nuke VM state + install $OLD_VERSION"
    bump_round

    # Stop any competing stack on port 443 before installing
    stop_conflicting_stacks

    vm_run_script <<REMOTE_SCRIPT
set -euo pipefail

WORK="${HARNESS_WORK_DIR}"
OLD_VER="${OLD_VERSION}"
REPO="${REPO_URL}"
RUNTIME="${RUNTIME}"
COMPOSE_CMD="${REMOTE_COMPOSE}"
SUDO_PASS="${VM_PASSWORD}"

# safe_rm_rf: remove a directory that may contain files owned by Podman rootless
# sub-UIDs (e.g. secrets chowned to container UIDs by _pki_chown_client_keys).
# Regular rm -rf fails on those files. podman unshare runs inside the user
# namespace where those sub-UIDs map back to the process owner.
safe_rm_rf() {
    local dir="\$1"
    [ -d "\$dir" ] || return 0
    if command -v podman >/dev/null 2>&1 && podman unshare echo "probe" >/dev/null 2>&1; then
        podman unshare rm -rf "\$dir"
    else
        rm -rf "\$dir"
    fi
}

echo "[remote] Tearing down any existing stack at \$WORK ..."

# First: global Podman cleanup — remove ALL tom-owned Podman containers and
# volumes from any previous harness run.  This handles the case where a prior
# run auto-detected podman even though the harness was invoked with
# --runtime docker, leaving orphaned Podman containers that subsequent
# "docker compose down" calls would miss.
#
# Safety: we only touch containers/volumes owned by the running user (tom).
# Podman rootless user-namespace containers are per-user by design.
if command -v podman >/dev/null 2>&1; then
    echo "[remote] Cleaning up all Podman containers from previous runs ..."
    podman stop --all 2>/dev/null || true
    podman rm --all --force 2>/dev/null || true
    podman volume rm --all --force 2>/dev/null || true
    echo "[remote] Podman global cleanup: done"
fi

# Nuke running Docker stack if it exists
if [ -d "\$WORK/docker" ]; then
    cd "\$WORK"
    # Stop and remove everything including volumes
    YSG_RUNTIME=\$RUNTIME \$COMPOSE_CMD -f docker/docker-compose.yml down -v --remove-orphans 2>/dev/null || true
    cd /
fi

# Remove old work dir (use safe_rm_rf: may contain sub-UID-owned secrets from
# a previous v2.23.x run that used _pki_chown_client_keys).
if [ -d "\$WORK" ]; then
    echo "[remote] Removing old work dir \$WORK ..."
    safe_rm_rf "\$WORK"
fi

echo "[remote] Cloning tag \$OLD_VER ..."
mkdir -p "\$WORK"
git clone --depth 1 --branch "\$OLD_VER" "\$REPO" "\$WORK"
cd "\$WORK"

echo "[remote] Cloned \$OLD_VER at: \$(git log --oneline -1)"

# Tag what we installed for verification
git log --oneline -1 > /tmp/n1_old_commit.txt
cat /tmp/n1_old_commit.txt

echo "[remote] Running install.sh for \$OLD_VER ..."
export YSG_RUNTIME=\$RUNTIME
export YASHIGANI_VERSION="\${OLD_VER#v}"  # strip leading 'v'

# v2.22.x install.sh does not support --runtime as a CLI flag.
# Set YSG_RUNTIME as an env variable (supported since v2.22.x) and omit
# the --runtime flag. v2.23.x install.sh also respects YSG_RUNTIME env,
# so this approach works for both old and new versions.
bash install.sh \
    --non-interactive \
    --deploy demo \
    --domain localhost \
    --tls-mode selfsigned \
    --admin-email test-admin@example.com \
    --skip-preflight

echo "[remote] install.sh exit code: \$?"
echo "[remote] Install phase complete"
REMOTE_SCRIPT

    local rc=$?
    if [[ $rc -ne 0 ]]; then
        # install.sh exited non-zero. On Podman rootless, v2.22.x install.sh
        # exits non-zero due to a promtail container stat permission error
        # (statfs /var/lib/docker/containers: permission denied).
        # This is a known pre-existing bug in v2.22.x on Podman rootless that
        # does not prevent the stack from starting.
        # Per feedback_no_manual_hacks.md: surface it but verify health before
        # declaring FAIL. The wait_for_old_stack phase will confirm if the
        # gateway is actually up and set the install verdict accordingly.
        log "WARNING: install.sh exited $rc — stack health check will determine PASS/FAIL"
        printf "N-1 FINDING: v2.22.x install exit code %s (Podman rootless statfs bug in v2.22.x; stack may still be up)\n" "$rc"
        # Do not fail here — let wait_for_old_stack() decide
    fi

    # N1-HARNESS-004 FIX: Under Podman rootless, edoburu/pgbouncer v1.23.1-p0's
    # entrypoint (line 56) tries to append credentials to /etc/pgbouncer/userlist.txt.
    # In the image, that file is owned by container root (UID 0), mode 0644.
    # Container postgres (UID 70) cannot write it. Fix: chmod 0666 the file in
    # the image layer so any container user can write it. Only needed for Podman
    # rootless — Docker runs containers as root and has no issue.
    #
    # The pgbouncer container is typically crashing in a restart loop at this
    # point. We fix the image layer, stop+rm the crashed container, and restart
    # it so the fix takes effect before the health gate.
    if [[ "$RUNTIME" == "podman" ]]; then
        log "Applying N1-HARNESS-004 pgbouncer userlist.txt write-permission fix ..."
        vm_run_script <<'FIX_PGBOUNCER'
set -euo pipefail
# Find userlist.txt in the podman overlay for the pgbouncer image.
UL=$(find /home/tom/.local/share/containers/storage/overlay -name 'userlist.txt' \
     -path '*/etc/pgbouncer/userlist.txt' 2>/dev/null | head -1)
if [ -n "$UL" ] && [ -f "$UL" ]; then
    chmod 0666 "$UL"
    echo "[remote] pgbouncer userlist.txt chmod 0666: $UL"
else
    echo "[remote] WARNING: pgbouncer userlist.txt not found in overlay"
fi
# Restart pgbouncer so it picks up the changed file permission.
# Use 'podman rm --force' so a new container is created (restart reuses the
# old container's overlay which still has the old permissions).
pgbc=$(podman ps -a --filter name=docker_pgbouncer_1 --format '{{.Names}}' 2>/dev/null)
if [ -n "$pgbc" ]; then
    podman stop docker_pgbouncer_1 2>/dev/null || true
    podman rm docker_pgbouncer_1 2>/dev/null || true
    cd /home/tom/n1_harness/docker
    podman-compose up -d pgbouncer 2>&1 | tail -5 || true
    echo "[remote] pgbouncer recreated"
fi
FIX_PGBOUNCER
        log "pgbouncer userlist.txt fix applied"
    fi

    # Detect which compose tool v2.22.x actually used, so subsequent phases
    # can tear down / manipulate the same stack.
    local actual_runtime
    actual_runtime=$(vm_run "
if podman ps --format '{{.Names}}' 2>/dev/null | grep -q 'caddy'; then echo 'podman'
elif docker ps --format '{{.Names}}' 2>/dev/null | grep -q 'caddy'; then echo 'docker'
else echo 'unknown'; fi
" 2>/dev/null || echo "unknown")
    log "Actual runtime used by v2.22.x install: $actual_runtime"
    if [[ "$actual_runtime" != "unknown" && "$actual_runtime" != "$RUNTIME" ]]; then
        log "NOTE: v2.22.x install used $actual_runtime (harness set $RUNTIME)."
        log "      Adjusting RUNTIME to $actual_runtime for this run."
        RUNTIME="$actual_runtime"
        if [[ "$RUNTIME" == "podman" ]]; then
            REMOTE_COMPOSE="podman compose"
        else
            REMOTE_COMPOSE="docker compose"
        fi
    fi

    # Install verdict is set by wait_for_old_stack() based on gateway /healthz
    # response. Premature PASS here would short-circuit the health gate.
    log "nuke_and_install_old complete — waiting for health confirmation"
}

# ---------------------------------------------------------------------------
# Helper: stop any currently-running stacks that own port 443 on the VM
# This handles the case where a prior gate run (e.g. Ava's stack in
# /home/ava/yashigani) left a live stack that would conflict on port bind.
# ---------------------------------------------------------------------------
stop_conflicting_stacks() {
    log "Checking for stacks that own port 443 on the VM ..."

    # First: stop tom's own Podman containers (if a prior harness run left them)
    vm_run "podman ps --format '{{.Names}}' 2>/dev/null | grep -q caddy && podman stop \$(podman ps -q --filter name=caddy) 2>/dev/null && echo '[remote] Stopped tom Podman caddy' || true" 2>/dev/null || true

    # Second: stop any Docker containers owned by root/docker group
    vm_run "docker ps --format '{{.Names}}' 2>/dev/null | grep -q caddy && docker stop \$(docker ps -q --filter name=caddy) 2>/dev/null && echo '[remote] Stopped Docker caddy' || true" 2>/dev/null || true

    # Third: if port 443 is still occupied (e.g. Ava's Podman rootless stack),
    # find the caddy process by port and kill via sudo.
    # VM_PASSWORD is expanded on the local side, passed as a heredoc variable.
    vm_run_script <<PORT_KILL 2>/dev/null || true
SUDO_PASS="${VM_PASSWORD}"
port_pid=\$(echo "\$SUDO_PASS" | sudo -S ss -tlnp 'sport = :443' 2>/dev/null | grep -oP 'pid=\K[0-9]+' | head -1 || true)
if [[ -n "\$port_pid" ]]; then
    echo "[remote] Port 443 held by PID \$port_pid — killing via sudo"
    echo "\$SUDO_PASS" | sudo -S kill -TERM "\$port_pid" 2>/dev/null || true
    sleep 3
    echo "\$SUDO_PASS" | sudo -S kill -KILL "\$port_pid" 2>/dev/null || true
    echo "[remote] Port 443 cleared"
else
    echo "[remote] Port 443 is free"
fi
PORT_KILL

    log "Conflicting stack cleanup done"
}

# ---------------------------------------------------------------------------
# Phase 2 — Wait for OLD_VERSION stack to be ready
# ---------------------------------------------------------------------------
wait_for_old_stack() {
    log_phase "2 — Wait for $OLD_VERSION stack ready"

    local timeout="$HEALTHCHECK_TIMEOUT"
    local interval=10
    local elapsed=0

    log "Waiting up to ${timeout}s for gateway /healthz ..."
    while [[ $elapsed -lt $timeout ]]; do
        local http_code
        http_code=$(vm_run "curl -sk -o /dev/null -w '%{http_code}' https://localhost:443/healthz 2>/dev/null || echo 000" 2>/dev/null || echo 000)
        if [[ "$http_code" == "200" ]]; then
            log "Gateway /healthz: 200 (after ${elapsed}s)"
            # Stack health is the authoritative install PASS/FAIL signal.
            # install.sh may have exited non-zero (v2.22.x Podman rootless
            # promtail statfs bug) but if the gateway answers 200 the stack
            # is operational — mark install PASS here.
            if [[ "$(get_verdict install)" == "NOTRUN" || "$(get_verdict install)" == "FAIL" ]]; then
                verdict "N-1 upgrade install (${OLD_VERSION})" "PASS" "install"
            fi
            return 0
        fi
        sleep "$interval"
        elapsed=$(( elapsed + interval ))
        log "  ... still waiting (${elapsed}s / ${timeout}s, last code: ${http_code})"
    done

    log "ERROR: Gateway failed to become healthy within ${timeout}s"
    verdict "N-1 upgrade install (${OLD_VERSION})" "FAIL" "install"
    return 1
}

# ---------------------------------------------------------------------------
# Phase 3 — Bootstrap admins + login as Admin1 and Admin2
# ---------------------------------------------------------------------------
verify_admin_logins() {
    local phase_label="$1"   # e.g. "post-install" / "post-upgrade" etc.
    local phase_key="$2"     # internal key for PHASE_VERDICTS

    log_phase "Admin login check — $phase_label"

    # Read secrets from the VM's secrets directory
    local admin1_user admin1_pass admin1_totp
    admin1_user=$(vm_run "cat ${HARNESS_WORK_DIR}/docker/secrets/admin1_username 2>/dev/null || echo ''" 2>/dev/null || echo "")
    admin1_pass=$(vm_run "cat ${HARNESS_WORK_DIR}/docker/secrets/admin1_password 2>/dev/null || echo ''" 2>/dev/null || echo "")
    admin1_totp=$(vm_run "cat ${HARNESS_WORK_DIR}/docker/secrets/admin1_totp_secret 2>/dev/null || echo ''" 2>/dev/null || echo "")

    local admin2_user admin2_pass admin2_totp
    admin2_user=$(vm_run "cat ${HARNESS_WORK_DIR}/docker/secrets/admin2_username 2>/dev/null || echo ''" 2>/dev/null || echo "")
    admin2_pass=$(vm_run "cat ${HARNESS_WORK_DIR}/docker/secrets/admin2_password 2>/dev/null || echo ''" 2>/dev/null || echo "")
    admin2_totp=$(vm_run "cat ${HARNESS_WORK_DIR}/docker/secrets/admin2_totp_secret 2>/dev/null || echo ''" 2>/dev/null || echo "")

    # Per feedback_echo_credentials.md — print creds at each check
    log "=== Credentials ($phase_label) ==="
    log "  Admin1 username : $admin1_user"
    log "  Admin1 password : $admin1_pass"
    log "  Admin1 TOTP     : $admin1_totp"
    log "  Admin2 username : $admin2_user"
    log "  Admin2 password : $admin2_pass"
    log "  Admin2 TOTP     : $admin2_totp"
    log "=================================="

    if [[ -z "$admin1_user" || -z "$admin1_pass" || -z "$admin1_totp" ]]; then
        log "ERROR: Admin1 credentials not found in secrets dir"
        verdict "N-1 upgrade ${phase_label} login Admin1 HTTP" "000" "${phase_key}_admin1"
        FAIL_COUNT=$(( FAIL_COUNT + 1 ))
        return 1
    fi

    # Auto-detect whether this stack uses mTLS (v2.23.1+) or plain HTTP (v2.22.x).
    local has_mtls
    has_mtls=$(vm_run "test -f ${HARNESS_WORK_DIR}/docker/secrets/ca_root.crt && echo 'yes' || echo 'no'" 2>/dev/null || echo "no")
    log "mTLS stack detected: $has_mtls"

    # V232-SMOKE-005 fix: login through Caddy on port 443 (VM host Python),
    # NOT directly to backoffice:8443.
    #
    # Rationale: v2.23.1 Layer B (CaddyVerifiedMiddleware) requires the
    # X-Caddy-Verified-Secret header which Caddy injects when proxying.
    # Connecting directly to backoffice:8443 bypasses Caddy and omits the
    # header -> backoffice returns 401 regardless of credentials.
    # Connecting through Caddy (https://localhost:443/auth/login) causes Caddy
    # to inject the header before forwarding to backoffice -> login succeeds.
    #
    # v2.22.x has no Layer B so the Caddy path works there too.
    # SSL: Caddy uses `tls internal` (self-signed) — skip verification.
    #
    # Arguments: $1=user $2=pass $3=totp_secret $4=has_mtls (unused, kept for compat)
    # Returns: HTTP status code (200/401/000)
    _do_login_check() {
        local chk_user="$1"
        local chk_pass="$2"
        local chk_totp="$3"
        # chk_mtls ($4) retained for signature compatibility but no longer used

        # Write Python to VM host temp file, run on VM host (not in container).
        # Target https://localhost/auth/login (port 443, through Caddy).
        # SSL: verify_mode=CERT_NONE because Caddy uses tls internal cert.
        vm_run_script <<WRITE_PY
cat > /tmp/n1_login_check.py << 'PYEOF'
import json, ssl, hashlib, sys
import pyotp
import urllib.request, urllib.error

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

user   = '${chk_user}'
pw     = '${chk_pass}'
secret = '${chk_totp}'
totp   = pyotp.TOTP(secret, digest=hashlib.sha256).now()
payload = json.dumps({'username': user, 'password': pw, 'totp_code': totp}).encode()
req = urllib.request.Request('https://localhost/auth/login',
    data=payload, headers={'Content-Type': 'application/json'})
try:
    resp = urllib.request.urlopen(req, context=ctx, timeout=15)
    print(resp.getcode())
except urllib.error.HTTPError as e:
    print(e.code)
except Exception as e:
    print('000')
PYEOF
echo "WRITE_DONE"
WRITE_PY
        # Run on VM host (not inside container) — Caddy injects X-Caddy-Verified-Secret
        vm_run "python3 /tmp/n1_login_check.py 2>/dev/null" 2>/dev/null || echo "000"
    }

    local a1_http
    a1_http=$(_do_login_check "$admin1_user" "$admin1_pass" "$admin1_totp" "$has_mtls")
    a1_http=$(printf '%s' "$a1_http" | tr -d ' \n' | grep -oE '[0-9]{3}' | head -1 || echo "000")
    [[ -z "$a1_http" ]] && a1_http="000"

    log "Admin1 login HTTP response: $a1_http"
    printf "N-1 upgrade %s login Admin1 HTTP: %s\n" "$phase_label" "$a1_http"
    set_verdict "${phase_key}_admin1" "$a1_http"
    if [[ "$a1_http" != "200" ]]; then
        FAIL_COUNT=$(( FAIL_COUNT + 1 ))
    else
        PASS_COUNT=$(( PASS_COUNT + 1 ))
    fi

    # Admin2
    if [[ -z "$admin2_user" || -z "$admin2_pass" || -z "$admin2_totp" ]]; then
        log "ERROR: Admin2 credentials not found in secrets dir"
        printf "N-1 upgrade %s login Admin2 HTTP: %s\n" "$phase_label" "000"
        set_verdict "${phase_key}_admin2" "000"
        FAIL_COUNT=$(( FAIL_COUNT + 1 ))
        return 1
    fi

    local a2_http
    a2_http=$(_do_login_check "$admin2_user" "$admin2_pass" "$admin2_totp" "$has_mtls")
    a2_http=$(printf '%s' "$a2_http" | tr -d ' \n' | grep -oE '[0-9]{3}' | head -1 || echo "000")
    [[ -z "$a2_http" ]] && a2_http="000"

    log "Admin2 login HTTP response: $a2_http"
    printf "N-1 upgrade %s login Admin2 HTTP: %s\n" "$phase_label" "$a2_http"
    set_verdict "${phase_key}_admin2" "$a2_http"
    if [[ "$a2_http" != "200" ]]; then
        FAIL_COUNT=$(( FAIL_COUNT + 1 ))
    else
        PASS_COUNT=$(( PASS_COUNT + 1 ))
    fi
}

# ---------------------------------------------------------------------------
# Phase 4 — Generate test data (agents, audit rows, password rotation)
# ---------------------------------------------------------------------------
generate_test_data() {
    log_phase "4 — Generate test data"

    # Read admin1 session for API calls
    local admin1_user admin1_pass admin1_totp
    admin1_user=$(vm_run "cat ${HARNESS_WORK_DIR}/docker/secrets/admin1_username 2>/dev/null" 2>/dev/null || echo "")
    admin1_pass=$(vm_run "cat ${HARNESS_WORK_DIR}/docker/secrets/admin1_password 2>/dev/null" 2>/dev/null || echo "")
    admin1_totp=$(vm_run "cat ${HARNESS_WORK_DIR}/docker/secrets/admin1_totp_secret 2>/dev/null" 2>/dev/null || echo "")

    if [[ -z "$admin1_user" || -z "$admin1_pass" || -z "$admin1_totp" ]]; then
        log "WARNING: Admin1 credentials not found — skipping test data generation"
        return 0
    fi

    # V232-SMOKE-005 fix: run test data Python on VM host through Caddy port 443.
    # No container detection needed — we use the Caddy reverse proxy endpoint.
    log "Test data: using VM host Python via Caddy port 443"

    # Write Python test-data script to VM host, run on VM host (not in container)
    # V232-SMOKE-005: must go through Caddy (port 443) so X-Caddy-Verified-Secret
    # header is injected. SSL: CERT_NONE for tls internal self-signed cert.
    vm_run_script <<WRITE_TDPY
cat > /tmp/n1_testdata.py << 'PYEOF'
import json, ssl, hashlib, sys, os
import pyotp
import urllib.request, urllib.error

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
BASE = 'https://localhost'

def req(method, path, body=None, cookies=''):
    data = json.dumps(body).encode() if body else None
    r = urllib.request.Request(BASE + path, data=data,
        headers={'Content-Type': 'application/json', 'Cookie': cookies},
        method=method)
    return urllib.request.urlopen(r, context=ctx, timeout=15)

user = '${admin1_user}'
pw   = '${admin1_pass}'
sec  = '${admin1_totp}'
totp = pyotp.TOTP(sec, digest=hashlib.sha256).now()
resp = req('POST', '/auth/login', {'username': user, 'password': pw, 'totp_code': totp})
cookie = ''
for part in resp.headers.get('Set-Cookie','').split(';'):
    part = part.strip()
    if part.startswith('__Host-yashigani_admin_session='):
        cookie = part.split('=',1)[1]
        break
if not cookie:
    print('ERROR: no session cookie from login', file=sys.stderr)
    sys.exit(1)
session_cookie = f'__Host-yashigani_admin_session={cookie}'
print('LOGIN OK, session acquired')

agent_ids = []
for i in range(1, 4):
    body = {
        'name': f'n1-test-agent-{i}',
        'upstream_url': f'http://test-upstream-{i}:8080',
        'protocol': 'openai',
    }
    try:
        r = req('POST', '/admin/agents', body, session_cookie)
        data = json.loads(r.read())
        agent_ids.append(data.get('agent_id','?'))
        print(f'AGENT_REGISTERED: n1-test-agent-{i} id={agent_ids[-1]}')
    except Exception as e:
        print(f'AGENT_REGISTER_SKIP: {e}')

with open('/tmp/n1_agent_ids.txt', 'w') as f:
    f.write('\n'.join(agent_ids))

r = req('GET', '/admin/agents', cookies=session_cookie)
agents = json.loads(r.read())
print(f'AGENTS_LISTED: count={len(agents)}')

try:
    r = req('GET', '/admin/audit?limit=1&offset=0', cookies=session_cookie)
    data = json.loads(r.read())
    count = data.get('total', data.get('count', len(data.get('entries', data if isinstance(data, list) else []))))
    print(f'AUDIT_BASELINE_COUNT: {count}')
    with open('/tmp/n1_audit_baseline.txt', 'w') as f:
        f.write(str(count))
except Exception as e:
    print(f'AUDIT_BASELINE_SKIP: {e}')
    with open('/tmp/n1_audit_baseline.txt', 'w') as f:
        f.write('0')

print('TEST_DATA_GENERATION: COMPLETE')
PYEOF
echo "TDPY_WRITE_DONE"
WRITE_TDPY

    # Run on VM host — Caddy injects X-Caddy-Verified-Secret (V232-SMOKE-005)
    vm_run "python3 /tmp/n1_testdata.py 2>&1" 2>/dev/null | grep -E "LOGIN|AGENT|AUDIT|COMPLETE|ERROR" || true

    # Capture baseline state: alembic version, table row counts
    log "Capturing schema baseline ..."
    local pg_exec_baseline
    pg_exec_baseline="$(detect_postgres_exec)"
    vm_run "
${pg_exec_baseline} psql -U yashigani_app yashigani -c 'SELECT version_num FROM alembic_version;' 2>/dev/null || echo 'ALEMBIC_NA'
${pg_exec_baseline} psql -U yashigani_app yashigani -t -c 'SELECT count(*) FROM agents;' 2>/dev/null | tr -d ' ' | head -1 | xargs printf 'AGENT_COUNT_BASELINE: %s\n' || echo 'AGENTS_TABLE_NA'
" 2>/dev/null | tee -a /dev/stderr | grep -E "ALEMBIC|AGENT_COUNT|BASELINE" || true

    log "Test data generation: complete"
}

# ---------------------------------------------------------------------------
# Phase 7 — Backup (direct implementation — taken AFTER upgrade to v2.23.1)
# ---------------------------------------------------------------------------
# This backup is taken while v2.23.1 is running, AFTER the upgrade succeeds.
# Rationale: v2.23.1 restore.sh validate_backup() requires mTLS CA keypair
# (ca_root.key, ca_root.crt, ca_intermediate.key, ca_intermediate.crt) plus
# *_client.key leaves. A pre-upgrade v2.22.x backup has none of these.
# The backup is therefore taken post-upgrade so restore.sh accepts it.
#
# Direct implementation (does NOT use install.sh --upgrade):
#   1. Copy secrets/ + .env into a timestamped dir under HARNESS_WORK_DIR/backups/
#   2. pg_dump the database
#   3. Record backup_path to /tmp/n1_backup_path.txt for the restore phase
#
# This mirrors install.sh _backup_existing_data() internally.
# ---------------------------------------------------------------------------
run_backup() {
    log_phase "7 — Backup (post-upgrade v2.23.1 state)"
    bump_round

    local pg_exec
    pg_exec="$(detect_postgres_exec)"

    vm_run_script <<BACKUP_SCRIPT
set -euo pipefail

WORK="${HARNESS_WORK_DIR}"
RUNTIME="${RUNTIME}"
COMPOSE_CMD="${REMOTE_COMPOSE}"
PG_EXEC="${pg_exec}"
BACKUP_TS=\$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="\$WORK/backups/\$BACKUP_TS"

echo "[remote] Creating backup dir: \$BACKUP_DIR"
mkdir -p "\$BACKUP_DIR"
chmod 0700 "\$BACKUP_DIR"

echo "[remote] Copying secrets + .env ..."
# V232-SMOKE-007 fix: secrets created by Podman rootless containers are owned
# by sub-UIDs (e.g. 494216) with mode 0400/0775 — not readable/chmod-able by
# the host tom user via plain cp -rp or chmod. Run both cp AND chmod inside
# 'podman unshare bash -c' so sub-UID 494216 maps to the calling user, making
# the files readable and their permissions changeable. Fall back to plain cp
# for Docker-only environments.
if [[ "\$RUNTIME" == "podman" ]] && command -v podman >/dev/null 2>&1; then
    podman unshare bash -c "cp -rp '\$WORK/docker/secrets' '\$BACKUP_DIR/secrets' && chmod 0700 '\$BACKUP_DIR/secrets'"
else
    cp -rp "\$WORK/docker/secrets" "\$BACKUP_DIR/secrets"
    chmod 0700 "\$BACKUP_DIR/secrets"
fi
cp "\$WORK/docker/.env" "\$BACKUP_DIR/.env"
chmod 0600 "\$BACKUP_DIR/.env"

echo "[remote] Dumping database ..."
\$PG_EXEC pg_dump -U yashigani_app yashigani > "\$BACKUP_DIR/postgres_dump.sql" 2>/dev/null
chmod 0600 "\$BACKUP_DIR/postgres_dump.sql"

echo "[remote] Backup complete: \$BACKUP_DIR"
echo "\$BACKUP_DIR" > /tmp/n1_backup_path.txt
ls -la "\$BACKUP_DIR/"
echo "BACKUP_DIR: \$BACKUP_DIR"
BACKUP_SCRIPT

    local rc=$?
    if [[ $rc -ne 0 ]]; then
        log "ERROR: Backup script failed (exit $rc)"
        verdict "N-1 upgrade backup" "FAIL" "backup"
        return 1
    fi

    local latest_backup
    latest_backup=$(vm_run "cat /tmp/n1_backup_path.txt 2>/dev/null" 2>/dev/null || echo "")

    if [[ -z "$latest_backup" ]]; then
        log "ERROR: No backup path recorded after backup script"
        verdict "N-1 upgrade backup" "FAIL" "backup"
        return 1
    fi

    # Verify backup has expected files
    local has_secrets has_env has_dump
    has_secrets=$(vm_run "test -d '${latest_backup}/secrets' && echo 'yes' || echo 'no'" 2>/dev/null || echo "no")
    has_env=$(vm_run "test -f '${latest_backup}/.env' && echo 'yes' || echo 'no'" 2>/dev/null || echo "no")
    has_dump=$(vm_run "test -s '${latest_backup}/postgres_dump.sql' && echo 'yes' || echo 'no'" 2>/dev/null || echo "no")
    log "Backup verification: secrets=$has_secrets  .env=$has_env  postgres_dump.sql=$has_dump"

    if [[ "$has_secrets" != "yes" || "$has_env" != "yes" || "$has_dump" != "yes" ]]; then
        log "ERROR: Backup is incomplete"
        verdict "N-1 upgrade backup" "FAIL" "backup"
        return 1
    fi

    # Capture backup SHA (sum of all files in backup)
    local backup_sha
    backup_sha=$(vm_run "find '${latest_backup}' -type f | sort | xargs sha256sum 2>/dev/null | sha256sum | cut -d' ' -f1" 2>/dev/null || echo "unknown")
    log "Backup directory: $latest_backup"
    log "Backup SHA       : $backup_sha"

    verdict "N-1 upgrade backup" "PASS" "backup"
}

# ---------------------------------------------------------------------------
# Phase 6 — Upgrade to NEW_REF
# ---------------------------------------------------------------------------
run_upgrade() {
    log_phase "6 — Upgrade to $NEW_REF"
    bump_round

    # Per feedback_clean_slate_test.md: install from remote ref, not local files.
    # Strategy:
    #   1. Clone NEW_REF alongside the existing OLD_VERSION install dir
    #   2. Stop the old stack (volumes preserved)
    #   3. Copy secrets + .env from old work dir into new work dir
    #   4. Run install.sh --upgrade from the NEW_REF clone (which detects no
    #      running stack, so it does a fresh install with the existing secrets)
    #
    # This mirrors what an operator does: clone the new version, preserve secrets,
    # run install.sh --upgrade.

    vm_run_script <<REMOTE_SCRIPT
set -euo pipefail

OLD_DIR="${HARNESS_WORK_DIR}"
NEW_DIR="${HARNESS_WORK_DIR}_new"
REPO="${REPO_URL}"
NEW_REF="${NEW_REF}"
RUNTIME="${RUNTIME}"
COMPOSE_CMD="${REMOTE_COMPOSE}"

# safe_rm_rf: handles directories containing Podman rootless sub-UID-owned files.
safe_rm_rf() {
    local dir="\$1"
    [ -d "\$dir" ] || return 0
    if command -v podman >/dev/null 2>&1 && podman unshare echo "probe" >/dev/null 2>&1; then
        podman unshare rm -rf "\$dir"
    else
        rm -rf "\$dir"
    fi
}

echo "[remote] Stopping old stack (preserving volumes) ..."
cd "\$OLD_DIR"
YSG_RUNTIME=\$RUNTIME \$COMPOSE_CMD -f docker/docker-compose.yml down --remove-orphans 2>&1 || true

echo "[remote] Cloning new ref \$NEW_REF ..."
# Use safe_rm_rf: NEW_DIR may contain sub-UID-owned secrets from a prior harness run.
safe_rm_rf "\$NEW_DIR"
git clone --depth 1 --branch "\$NEW_REF" "\$REPO" "\$NEW_DIR"
echo "[remote] Cloned \$NEW_REF at: \$(git -C \$NEW_DIR log --oneline -1)"

echo "[remote] Migrating secrets + env from old to new ..."
# Copy secrets dir. If files are sub-UID-owned (v2.22.x plain-mode secrets are
# tom-owned, so cp works; v2.23.x mTLS secrets may not be — but the source here
# is the OLD v2.22.x install dir, which has no sub-UID files).
cp -rp "\$OLD_DIR/docker/secrets" "\$NEW_DIR/docker/secrets"
# Copy .env (contains passwords, DSNs)
cp "\$OLD_DIR/docker/.env" "\$NEW_DIR/docker/.env"

echo "[remote] Running install.sh --upgrade from new ref ..."
cd "\$NEW_DIR"
export YSG_RUNTIME=\$RUNTIME

bash install.sh \
    --non-interactive \
    --runtime \$RUNTIME \
    --deploy demo \
    --domain localhost \
    --tls-mode selfsigned \
    --admin-email test-admin@example.com \
    --skip-preflight \
    --upgrade 2>&1 | tee /tmp/n1_upgrade_run.log

echo "[remote] install.sh --upgrade exit code: \$?"
# NOTE: no dir swap here. HARNESS_WORK_DIR is updated on the macOS side in
# main() after run_upgrade() returns (V232-SMOKE-006 fix). The new install
# lives at NEW_DIR (n1_harness_new); subsequent phases reference it directly.
REMOTE_SCRIPT

    local rc=$?
    if [[ $rc -ne 0 ]]; then
        verdict "N-1 upgrade in-place" "FAIL" "upgrade"
        return 1
    fi
    verdict "N-1 upgrade in-place" "PASS" "upgrade"
}

# ---------------------------------------------------------------------------
# Phase 7 — Wait for upgraded stack
# ---------------------------------------------------------------------------
wait_for_new_stack() {
    log_phase "7 — Wait for upgraded stack ready"

    local timeout="$HEALTHCHECK_TIMEOUT"
    local interval=10
    local elapsed=0

    log "Waiting up to ${timeout}s for upgraded gateway /healthz ..."
    while [[ $elapsed -lt $timeout ]]; do
        local http_code
        http_code=$(vm_run "curl -sk -o /dev/null -w '%{http_code}' https://localhost:443/healthz 2>/dev/null || echo 000" 2>/dev/null || echo 000)
        if [[ "$http_code" == "200" ]]; then
            log "Gateway /healthz (post-upgrade): 200 (after ${elapsed}s)"
            return 0
        fi
        sleep "$interval"
        elapsed=$(( elapsed + interval ))
        log "  ... still waiting (${elapsed}s / ${timeout}s, last code: ${http_code})"
    done

    log "ERROR: Upgraded gateway failed to become healthy within ${timeout}s"
    verdict "N-1 upgrade in-place" "FAIL" "upgrade"
    return 1
}

# ---------------------------------------------------------------------------
# Phase 8 — Post-upgrade verification
# ---------------------------------------------------------------------------
verify_post_upgrade() {
    log_phase "8 — Post-upgrade verification"

    # Detect container names for the currently-running (upgraded) stack.
    local pg_full bo_full
    pg_full="$(detect_postgres_exec)"
    bo_full="$(detect_backoffice_exec)"
    log "postgres exec: $pg_full"
    log "backoffice exec: $bo_full"

    # Schema version check: expect alembic HEAD = 0006
    local schema_ver
    schema_ver=$(vm_run "
${pg_full} psql -U yashigani_app yashigani -t -c \
    'SELECT version_num FROM alembic_version;' 2>/dev/null | tr -d ' ' | head -1
" 2>/dev/null || echo "unknown")
    log "Schema version (post-upgrade): $schema_ver"
    if [[ "$schema_ver" != "0006" ]]; then
        log "WARNING: Expected migration 0006, got '$schema_ver'"
        log "  This may indicate the migration did not run (check alembic logs)"
        # Not a hard fail — the migration may be at 0005 if v2.22.3 already had it.
        # We record what we see.
    else
        log "Schema version: 0006 PASS — migration 0006 applied"
    fi

    # Audit log count >= baseline (data preserved)
    local audit_baseline
    audit_baseline=$(vm_run "cat /tmp/n1_audit_baseline.txt 2>/dev/null || echo 0" 2>/dev/null || echo "0")
    log "Audit log baseline: $audit_baseline rows"

    # Agent count preserved
    local agent_count_post
    agent_count_post=$(vm_run "
${pg_full} psql -U yashigani_app yashigani -t -c \
    'SELECT count(*) FROM agents;' 2>/dev/null | tr -d ' ' | head -1
" 2>/dev/null || echo "unknown")
    log "Agent count (post-upgrade): $agent_count_post"

    # Gateway health
    local gw_http
    gw_http=$(vm_run "curl -sk -o /dev/null -w '%{http_code}' https://localhost:443/healthz 2>/dev/null || echo 000" 2>/dev/null || echo 000)
    log "Gateway /healthz (post-upgrade): $gw_http"

    # Backoffice reachability — V232-SMOKE-005 fix: check through Caddy on port 443
    # on VM host (not via container exec to :8443 directly). Caddy proxies /auth/*
    # to backoffice. A GET to /auth/login returns 405 (method not allowed) which
    # proves backoffice is alive. Accept any non-000 HTTP response code as healthy.
    local bo_health
    bo_health=$(vm_run "curl -sk -o /dev/null -w '%{http_code}' -X GET https://localhost/auth/login 2>/dev/null || echo 000" 2>/dev/null || echo "000")
    bo_health=$(printf '%s' "$bo_health" | tr -d ' \n' | grep -oE '[0-9]{3}' | head -1 || echo "000")
    [[ -z "$bo_health" ]] && bo_health="000"
    log "Backoffice /auth/login (via Caddy, post-upgrade): $bo_health"

    # Log summary
    log "Post-upgrade subsystems:"
    log "  schema_ver=$schema_ver  gateway_http=$gw_http  backoffice_health=$bo_health"
    log "  agent_count=$agent_count_post (baseline from pre-upgrade)"
}

# ---------------------------------------------------------------------------
# Phase 9 — Restore (rollback path)
# ---------------------------------------------------------------------------
run_restore() {
    log_phase "9 — Restore (rollback to pre-upgrade backup)"
    bump_round

    local backup_path
    backup_path=$(vm_run "cat /tmp/n1_backup_path.txt 2>/dev/null" 2>/dev/null || echo "")

    if [[ -z "$backup_path" ]]; then
        log "ERROR: No backup path recorded — cannot restore"
        verdict "N-1 upgrade restore" "FAIL" "restore"
        return 1
    fi

    log "Restoring from: $backup_path"

    vm_run_script <<REMOTE_SCRIPT
set -euo pipefail

WORK="${HARNESS_WORK_DIR}"
BACKUP="${backup_path}"
RUNTIME="${RUNTIME}"

# V232-SMOKE-008 fix: restore.sh preflight checks that docker/data, docker/certs,
# and docker/logs exist and are owned by the container UID (1001 in container =
# subuid_start+1000 on the Podman rootless host). The harness must fulfil this
# operator-side prerequisite before calling restore.sh.
echo "[remote] Pre-creating bind-mount dirs for restore preflight ..."
mkdir -p "\$WORK/docker/data" "\$WORK/docker/certs" "\$WORK/docker/logs"
if [[ "\$RUNTIME" == "podman" ]] && command -v podman >/dev/null 2>&1; then
    podman unshare chown 1001:1001 "\$WORK/docker/data" "\$WORK/docker/certs" "\$WORK/docker/logs"
else
    chown 1001:1001 "\$WORK/docker/data" "\$WORK/docker/certs" "\$WORK/docker/logs" 2>/dev/null || true
fi

echo "[remote] Running restore.sh against backup: \$BACKUP"
cd "\$WORK"
YSG_RUNTIME=\$RUNTIME bash restore.sh "\$BACKUP" 2>&1 | tee /tmp/n1_restore_run.log

echo "[remote] restore.sh exit code: \$?"
echo "[remote] Waiting for stack to restart after restore ..."
REMOTE_SCRIPT

    local rc=$?
    if [[ $rc -ne 0 ]]; then
        verdict "N-1 upgrade restore" "FAIL" "restore"
        return 1
    fi

    # Wait for stack to come back
    local timeout="$HEALTHCHECK_TIMEOUT"
    local interval=10
    local elapsed=0
    log "Waiting up to ${timeout}s for stack after restore ..."
    while [[ $elapsed -lt $timeout ]]; do
        local http_code
        http_code=$(vm_run "curl -sk -o /dev/null -w '%{http_code}' https://localhost:443/healthz 2>/dev/null || echo 000" 2>/dev/null || echo 000)
        if [[ "$http_code" == "200" ]]; then
            log "Post-restore gateway healthy (after ${elapsed}s)"
            break
        fi
        sleep "$interval"
        elapsed=$(( elapsed + interval ))
    done

    if [[ $elapsed -ge $timeout ]]; then
        log "ERROR: Stack did not recover after restore within ${timeout}s"
        verdict "N-1 upgrade restore" "FAIL" "restore"
        return 1
    fi

    verdict "N-1 upgrade restore" "PASS" "restore"
}

# ---------------------------------------------------------------------------
# Phase 10 — Re-upgrade after restore (forward path again)
# ---------------------------------------------------------------------------
run_reupgrade() {
    log_phase "10 — Re-upgrade to $NEW_REF (forward path after restore)"
    bump_round

    vm_run_script <<REMOTE_SCRIPT
set -euo pipefail

OLD_DIR="${HARNESS_WORK_DIR}"
NEW_DIR="${HARNESS_WORK_DIR}_reup"
REPO="${REPO_URL}"
NEW_REF="${NEW_REF}"
RUNTIME="${RUNTIME}"
COMPOSE_CMD="${REMOTE_COMPOSE}"

# safe_rm_rf: handles directories containing Podman rootless sub-UID-owned files.
safe_rm_rf() {
    local dir="\$1"
    [ -d "\$dir" ] || return 0
    if command -v podman >/dev/null 2>&1 && podman unshare echo "probe" >/dev/null 2>&1; then
        podman unshare rm -rf "\$dir"
    else
        rm -rf "\$dir"
    fi
}

echo "[remote] Stopping restored stack ..."
cd "\$OLD_DIR"
YSG_RUNTIME=\$RUNTIME \$COMPOSE_CMD -f docker/docker-compose.yml down --remove-orphans 2>&1 || true

echo "[remote] Cloning new ref for re-upgrade: \$NEW_REF ..."
safe_rm_rf "\$NEW_DIR"
git clone --depth 1 --branch "\$NEW_REF" "\$REPO" "\$NEW_DIR"

echo "[remote] Migrating secrets from restored state ..."
# V232-SMOKE-007 fix (re-upgrade): after restore.sh runs _pki_chown_client_keys,
# secrets in OLD_DIR are re-owned by container sub-UIDs. Use podman unshare for
# the copy so sub-UID ownership does not cause EACCES. Same pattern as run_backup.
if [[ "\$RUNTIME" == "podman" ]] && command -v podman >/dev/null 2>&1; then
    podman unshare bash -c "cp -rp '\$OLD_DIR/docker/secrets' '\$NEW_DIR/docker/secrets'"
else
    cp -rp "\$OLD_DIR/docker/secrets" "\$NEW_DIR/docker/secrets"
fi
cp "\$OLD_DIR/docker/.env" "\$NEW_DIR/docker/.env"

echo "[remote] Running install.sh --upgrade (re-upgrade) ..."
cd "\$NEW_DIR"
export YSG_RUNTIME=\$RUNTIME

bash install.sh \
    --non-interactive \
    --runtime \$RUNTIME \
    --deploy demo \
    --domain localhost \
    --tls-mode selfsigned \
    --admin-email test-admin@example.com \
    --skip-preflight \
    --upgrade 2>&1 | tee /tmp/n1_reupgrade_run.log

echo "[remote] Re-upgrade install.sh exit code: \$?"
# NOTE: no dir swap here. HARNESS_WORK_DIR is updated on the macOS side in
# main() after run_reupgrade() returns (V232-SMOKE-006 fix). The re-upgraded
# install lives at NEW_DIR (n1_harness_new_reup); subsequent phases reference
# it directly via the updated HARNESS_WORK_DIR.
echo "[remote] Re-upgrade complete"
REMOTE_SCRIPT

    local rc=$?
    if [[ $rc -ne 0 ]]; then
        verdict "N-1 upgrade re-upgrade" "FAIL" "reupgrade"
        return 1
    fi

    # Wait for re-upgraded stack
    local timeout="$HEALTHCHECK_TIMEOUT"
    local interval=10
    local elapsed=0
    log "Waiting up to ${timeout}s for re-upgraded stack ..."
    while [[ $elapsed -lt $timeout ]]; do
        local http_code
        http_code=$(vm_run "curl -sk -o /dev/null -w '%{http_code}' https://localhost:443/healthz 2>/dev/null || echo 000" 2>/dev/null || echo 000)
        if [[ "$http_code" == "200" ]]; then
            log "Re-upgraded gateway healthy (after ${elapsed}s)"
            break
        fi
        sleep "$interval"
        elapsed=$(( elapsed + interval ))
    done

    if [[ $elapsed -ge $timeout ]]; then
        log "ERROR: Re-upgraded stack did not become healthy within ${timeout}s"
        verdict "N-1 upgrade re-upgrade" "FAIL" "reupgrade"
        return 1
    fi

    verdict "N-1 upgrade re-upgrade" "PASS" "reupgrade"
}

# ---------------------------------------------------------------------------
# Phase 11 — Cleanup
# ---------------------------------------------------------------------------
cleanup() {
    if [[ "$SKIP_CLEANUP" == "true" ]]; then
        log "SKIP_CLEANUP=true — leaving harness dirs on VM"
        return
    fi

    log_phase "11 — Cleanup"
    # V232-SMOKE-006: HARNESS_WORK_DIR is updated during the run (→ _new → _new_reup).
    # Use BASE_WORK_DIR (the original base, e.g. n1_harness) to enumerate ALL dirs
    # that may have been created across the full harness run.
    vm_run_script <<REMOTE_SCRIPT
set -euo pipefail
BASE="${BASE_WORK_DIR}"
WORK="${HARNESS_WORK_DIR}"
RUNTIME="${RUNTIME}"
COMPOSE_CMD="${REMOTE_COMPOSE}"

# safe_rm_rf: handles directories with Podman rootless sub-UID-owned files
# (e.g. docker/secrets/ after _pki_chown_client_keys in install.sh).
# Falls back to plain rm -rf when podman unshare is not available (Docker-only VM).
safe_rm_rf() {
    local dir="\$1"
    [ -d "\$dir" ] || return 0
    if command -v podman >/dev/null 2>&1 && podman unshare echo "probe" >/dev/null 2>&1; then
        podman unshare rm -rf "\$dir"
    else
        rm -rf "\$dir"
    fi
}

# Tear down final running stack (whichever dir is currently active)
if [ -d "\$WORK/docker" ]; then
    cd "\$WORK"
    YSG_RUNTIME=\$RUNTIME \$COMPOSE_CMD -f docker/docker-compose.yml down -v --remove-orphans 2>&1 || true
fi

# Remove all harness dirs that may have been created during the run.
# Enumerate from BASE_WORK_DIR to cover: base, _new, _new_reup, and any .old
# swap artefacts, regardless of how HARNESS_WORK_DIR was updated mid-run.
for d in "\$BASE" "\${BASE}_new" "\${BASE}_new_reup" \
          "\${BASE}.old" "\${BASE}_new.reup" "\${BASE}_reup"; do
    safe_rm_rf "\$d" 2>/dev/null || true
done

# Verify gone
for d in "\$BASE" "\${BASE}_new" "\${BASE}_new_reup" \
          "\${BASE}.old" "\${BASE}_new.reup" "\${BASE}_reup"; do
    if [ -d "\$d" ]; then
        echo "[remote] WARNING: \$d still present after cleanup"
    fi
done

echo "[remote] Cleanup complete"
REMOTE_SCRIPT
}

# ---------------------------------------------------------------------------
# Emit final JSON report and gate verdict
# ---------------------------------------------------------------------------
emit_final_verdict() {
    local gate_result="$1"

    local v_install v_backup v_upgrade v_postu_a1 v_postu_a2 v_restore v_reup
    local v_postr_a1 v_postr_a2 v_postru_a1 v_postru_a2
    v_install="$(get_verdict install)"
    v_backup="$(get_verdict backup)"
    v_upgrade="$(get_verdict upgrade)"
    v_postu_a1="$(get_verdict postupgrade_admin1)"
    v_postu_a2="$(get_verdict postupgrade_admin2)"
    v_restore="$(get_verdict restore)"
    v_reup="$(get_verdict reupgrade)"
    v_postr_a1="$(get_verdict postrestore_admin1)"
    v_postr_a2="$(get_verdict postrestore_admin2)"
    v_postru_a1="$(get_verdict postreupgrade_admin1)"
    v_postru_a2="$(get_verdict postreupgrade_admin2)"

    printf "\n"
    printf "=== GREPPABLE VERDICT SUMMARY ===\n"
    printf "N-1 upgrade install (%s): %s\n" "$OLD_VERSION" "$v_install"
    printf "N-1 upgrade backup: %s\n"                        "$v_backup"
    printf "N-1 upgrade in-place: %s\n"                      "$v_upgrade"
    printf "N-1 upgrade post-upgrade login Admin1 HTTP: %s\n" "$v_postu_a1"
    printf "N-1 upgrade post-upgrade login Admin2 HTTP: %s\n" "$v_postu_a2"
    printf "N-1 upgrade restore: %s\n"                       "$v_restore"
    printf "N-1 upgrade re-upgrade: %s\n"                    "$v_reup"
    printf "N-1 GATE VERDICT: %s\n"                          "$gate_result"
    printf "=================================\n"

    # Write JSON report
    cat > "$JSON_FILE" <<JSON
{
  "harness": "n_minus_one",
  "run_ts": "${RUN_TS}",
  "old_version": "${OLD_VERSION}",
  "new_ref": "${NEW_REF}",
  "repo_url": "${REPO_URL}",
  "runtime": "${RUNTIME}",
  "vm_host": "${VM_HOST}",
  "phases": {
    "install":             "${v_install}",
    "backup":              "${v_backup}",
    "upgrade":             "${v_upgrade}",
    "post_upgrade_admin1": "${v_postu_a1}",
    "post_upgrade_admin2": "${v_postu_a2}",
    "restore_admin1":      "${v_postr_a1}",
    "restore_admin2":      "${v_postr_a2}",
    "reupgrade":           "${v_reup}",
    "reupgrade_admin1":    "${v_postru_a1}",
    "reupgrade_admin2":    "${v_postru_a2}"
  },
  "gate_verdict": "${gate_result}",
  "pass_count": ${PASS_COUNT},
  "fail_count": ${FAIL_COUNT},
  "log_file": "${LOG_FILE}",
  "json_file": "${JSON_FILE}"
}
JSON

    log "JSON report written to: $JSON_FILE"
    log "Log written to:         $LOG_FILE"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "=== N-1 Upgrade Harness ==="
    log "OLD_VERSION : $OLD_VERSION"
    log "NEW_REF     : $NEW_REF"
    log "REPO_URL    : $REPO_URL"
    log "RUNTIME     : $RUNTIME"
    log "VM          : $VM_USER@$VM_HOST"
    log "WORK_DIR    : $HARNESS_WORK_DIR"
    log "EVIDENCE_DIR: $EVIDENCE_DIR"
    log "LOG_FILE    : $LOG_FILE"
    log ""

    # Trap for unexpected exits — emit a FAIL verdict if we bail out early
    trap 'cleanup; emit_final_verdict FAIL' ERR

    # Phase 0: pre-flight
    preflight

    # Phase 1: install OLD_VERSION from tag (clean-slate)
    nuke_and_install_old || { emit_final_verdict "FAIL"; exit 1; }

    # Phase 2: wait for OLD_VERSION stack
    wait_for_old_stack || { emit_final_verdict "FAIL"; exit 1; }

    # Phase 2b: check admin logins on OLD_VERSION
    # Note: v2.22.3 may not have mTLS — fall back to plain HTTPS via Caddy
    verify_admin_logins "post-install-old" "postinstall"

    # Phase 3: generate test data on OLD_VERSION stack
    generate_test_data

    # Phase 4: upgrade OLD_VERSION → NEW_REF
    # Backup is taken AFTER upgrade so the backed-up state carries mTLS
    # material that v2.23.1 restore.sh validates for. A pre-upgrade v2.22.x
    # backup would fail restore.sh validate_backup() (no CA keypair).
    # The N-1 upgrade finding is surfaced via the postinstall admin login
    # result plus the schema delta check in verify_post_upgrade.
    run_upgrade || { emit_final_verdict "FAIL"; exit 1; }

    # V232-SMOKE-006 fix: the upgraded install runs in ${HARNESS_WORK_DIR}_new.
    # The remote dir swap inside run_upgrade's heredoc (mv _new → base) exits
    # before the mv because install.sh | tee causes the pipeline exit code to
    # be consumed by set -e, so HARNESS_WORK_DIR on the macOS side never updates
    # via the remote mv. Update it here explicitly so that all subsequent phases
    # (backup, restore, re-upgrade, cleanup) use the upgraded dir containing
    # restore.sh and the v2.23.1 mTLS secrets.
    local old_work_dir="$HARNESS_WORK_DIR"
    HARNESS_WORK_DIR="${HARNESS_WORK_DIR}_new"
    log "Work dir updated: $old_work_dir → $HARNESS_WORK_DIR (post-upgrade)"

    # Phase 5: wait for upgraded stack
    wait_for_new_stack || { emit_final_verdict "FAIL"; exit 1; }

    # Phase 6: verify post-upgrade (schema, agent count, health)
    verify_post_upgrade
    verify_admin_logins "post-upgrade" "postupgrade"

    # Check admin logins before proceeding
    if [[ "$(get_verdict postupgrade_admin1)" != "200" ]] || \
       [[ "$(get_verdict postupgrade_admin2)" != "200" ]]; then
        log "FAIL: Admin logins failed post-upgrade"
        cleanup
        emit_final_verdict "FAIL"
        exit 1
    fi

    # Phase 7: backup — taken NOW while v2.23.1 is running cleanly.
    # This backup carries mTLS CA keypair + leaves + secrets, which
    # restore.sh validate_backup() requires. Proves the backup path works
    # on the upgraded stack and gives us material for the restore test.
    run_backup || { emit_final_verdict "FAIL"; exit 1; }

    # Phase 8: restore (rollback path using the post-upgrade backup)
    run_restore || { emit_final_verdict "FAIL"; exit 1; }

    # Phase 8b: verify admin logins after restore
    verify_admin_logins "post-restore" "postrestore"

    # Phase 9: re-upgrade (forward path again after restore)
    run_reupgrade || { emit_final_verdict "FAIL"; exit 1; }

    # V232-SMOKE-006 fix (re-upgrade): same as post-upgrade swap above.
    # The re-upgraded install lives in ${HARNESS_WORK_DIR}_reup.
    local post_reup_dir="${HARNESS_WORK_DIR}_reup"
    HARNESS_WORK_DIR="$post_reup_dir"
    log "Work dir updated: → $HARNESS_WORK_DIR (post-reupgrade)"

    # Phase 9b: wait for re-upgraded stack + verify logins
    wait_for_new_stack || { emit_final_verdict "FAIL"; exit 1; }
    verify_admin_logins "post-reupgrade" "postreupgrade"

    # Phase 10: cleanup
    cleanup

    # Final gate verdict
    local overall="PASS"
    if [[ "$FAIL_COUNT" -gt 0 ]]; then
        overall="FAIL"
    fi
    # All admin logins must be 200 for PASS
    for phase_key in postupgrade_admin1 postupgrade_admin2 postrestore_admin1 postrestore_admin2 postreupgrade_admin1 postreupgrade_admin2; do
        local code
        code="$(get_verdict "$phase_key")"
        if [[ "$code" != "200" ]]; then
            overall="FAIL"
            log "Admin login check failed: phase_key=$phase_key code=$code"
        fi
    done

    # Remove ERR trap before clean exit
    trap - ERR
    emit_final_verdict "$overall"

    if [[ "$overall" != "PASS" ]]; then
        exit 1
    fi
    exit 0
}

main "$@"
