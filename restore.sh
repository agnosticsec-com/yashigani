#!/usr/bin/env bash
set -euo pipefail
# Last updated: 2026-04-24T00:00:00Z (v2.23.1 P0 fixes — #77/#78/#79)

# Tight umask so any files/dirs created during restore inherit 0600/0700.
# Overrides the host default (often 022) which would leave intermediate
# artefacts (pre-restore snapshots, temp extractions) world-readable.
umask 077

# =============================================================================
# Yashigani Restore Script
#
# Restores a backup created by install.sh (upgrade detection).
# Backup location: ./backups/<timestamp>/
#
# Usage:
#   bash restore.sh                          # list available backups
#   bash restore.sh <backup_dir>             # restore from specific backup
#   bash restore.sh --latest                 # restore from most recent backup
#   bash restore.sh --latest --k8s -n ns     # restore into Kubernetes
#
# Supported platforms:
#   - Docker Compose (Linux/macOS)
#   - Podman Compose (Linux/macOS)
#   - Kubernetes (via kubectl)
#
# What gets restored:
#   - docker/secrets/    (admin passwords, TOTP secrets, service tokens)
#   - docker/.env        (environment variables, database passwords)
#   - postgres_dump.sql  (database — if available in backup)
#
# What does NOT get restored (by design):
#   - Container images (rebuilt from source)
#   - Docker/Podman volumes other than Postgres (recreated on startup)
#   - OPA policies (loaded from git)
# =============================================================================

# ---------------------------------------------------------------------------
# Color output — only when stdout is a TTY
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  C_GREEN="\033[0;32m"
  C_RED="\033[0;31m"
  C_YELLOW="\033[0;33m"
  C_BOLD="\033[1m"
  C_RESET="\033[0m"
else
  C_GREEN=""
  C_RED=""
  C_YELLOW=""
  C_BOLD=""
  C_RESET=""
fi

WORK_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKUPS_DIR="${WORK_DIR}/backups"
K8S_MODE=false
K8S_NAMESPACE="yashigani"

log_info()    { printf "    --> %s\n" "$*"; }
log_success() { printf "    ${C_GREEN}ok${C_RESET}  %s\n" "$*"; }
log_error()   { printf "    ${C_RED}!!  ERROR: %s${C_RESET}\n" "$*" >&2; }
log_warn()    { printf "    ${C_YELLOW}!!  WARNING: %s${C_RESET}\n" "$*"; }

# ---------------------------------------------------------------------------
# Detect container runtime (same logic as install.sh)
# ---------------------------------------------------------------------------
detect_runtime() {
  if [[ "$K8S_MODE" == "true" ]]; then
    RUNTIME="k8s"
    return
  fi

  if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    RUNTIME="docker"
    COMPOSE_CMD=("docker" "compose" "-f" "${WORK_DIR}/docker/docker-compose.yml")
  elif command -v podman &>/dev/null; then
    RUNTIME="podman"
    # Prefer docker-compose standalone if available (Podman uses it via plugin)
    if command -v docker-compose &>/dev/null; then
      COMPOSE_CMD=("docker-compose" "-f" "${WORK_DIR}/docker/docker-compose.yml")
    else
      COMPOSE_CMD=("podman" "compose" "-f" "${WORK_DIR}/docker/docker-compose.yml")
    fi
  else
    RUNTIME="none"
    COMPOSE_CMD=()
  fi
}

# ---------------------------------------------------------------------------
# Find the Postgres container/pod
# ---------------------------------------------------------------------------
find_pg_container() {
  case "$RUNTIME" in
    docker)
      docker ps --format '{{.Names}}' 2>/dev/null | grep -E 'postgres' | grep -v pgbouncer | head -1
      ;;
    podman)
      podman ps --format '{{.Names}}' 2>/dev/null | grep -E 'postgres' | grep -v pgbouncer | head -1
      ;;
    k8s)
      kubectl get pods -n "$K8S_NAMESPACE" -l app.kubernetes.io/name=postgres \
        --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || \
      kubectl get pods -n "$K8S_NAMESPACE" -o name 2>/dev/null | grep postgres | grep -v pgbouncer | head -1 | sed 's|pod/||'
      ;;
    *)
      echo ""
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Execute psql in the Postgres container/pod
# ---------------------------------------------------------------------------
pg_exec() {
  local pg_name="$1"
  shift
  case "$RUNTIME" in
    docker)
      docker exec -i "$pg_name" "$@"
      ;;
    podman)
      podman exec -i "$pg_name" "$@"
      ;;
    k8s)
      kubectl exec -i -n "$K8S_NAMESPACE" "$pg_name" -- "$@"
      ;;
  esac
}

# ---------------------------------------------------------------------------
# List available backups
# ---------------------------------------------------------------------------
list_backups() {
  if [[ ! -d "$BACKUPS_DIR" ]]; then
    echo "No backups directory found at ${BACKUPS_DIR}"
    exit 1
  fi

  local backups
  backups=$(find "${BACKUPS_DIR}" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -r)
  if [[ -z "$backups" ]]; then
    echo "No backups found in ${BACKUPS_DIR}"
    exit 1
  fi

  printf "\n${C_BOLD}Available backups:${C_RESET}\n\n"
  local i=1
  while IFS= read -r dir; do
    local ts
    ts=$(basename "$dir")
    local has_secrets="no"
    local has_env="no"
    local has_db="no"
    local size="0K"
    [[ -d "${dir}/secrets" ]] && has_secrets="yes"
    [[ -f "${dir}/.env" ]] && has_env="yes"
    [[ -f "${dir}/postgres_dump.sql" ]] && has_db="yes"
    size=$(du -sh "$dir" 2>/dev/null | awk '{print $1}')
    printf "  %d) %s  [%s]  (secrets=%s, env=%s, db=%s)\n" "$i" "$ts" "$size" "$has_secrets" "$has_env" "$has_db"
    i=$((i + 1))
  done <<< "$backups"
  printf "\nUsage:\n"
  printf "  bash restore.sh <timestamp>            # restore a specific backup\n"
  printf "  bash restore.sh --latest               # restore the most recent\n"
  printf "  bash restore.sh --latest --k8s -n ns   # restore into Kubernetes\n\n"
}

# ---------------------------------------------------------------------------
# Validate backup integrity
# ---------------------------------------------------------------------------
validate_backup() {
  local backup_dir="$1"
  local errors=0

  # Hard fail: backup must have at minimum secrets/ AND .env
  if [[ ! -d "${backup_dir}/secrets" ]]; then
    log_error "Backup missing required directory: secrets/"
    errors=$((errors + 1))
  fi
  if [[ ! -f "${backup_dir}/.env" ]]; then
    log_error "Backup missing required file: .env"
    errors=$((errors + 1))
  fi

  # If structural fails, no point checking contents.
  if [[ "$errors" -gt 0 ]]; then
    return 1
  fi

  # Hard fail: v2.23.1-mtls backups MUST carry the CA keypair and at least
  # one service leaf key. Without these, restoring and then running install.sh
  # will regenerate a NEW CA that does not match any surviving leaves — every
  # mTLS peer breaks silently. See CLAUDE.md §4 Docker+Podman+Helm parity.
  for ca_file in ca_root.key ca_root.crt ca_intermediate.key ca_intermediate.crt; do
    if [[ ! -f "${backup_dir}/secrets/${ca_file}" ]]; then
      log_error "Backup missing required CA material: secrets/${ca_file}"
      errors=$((errors + 1))
    fi
  done
  # At least one *_client.key must exist (proves leaves were backed up)
  local leaf_count
  leaf_count=$(find "${backup_dir}/secrets" -maxdepth 1 -type f -name '*_client.key' 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$leaf_count" -lt 1 ]]; then
    log_error "Backup contains no *_client.key leaves — service mTLS certs missing"
    errors=$((errors + 1))
  fi

  # Hard fail: empty secret files indicate corruption.
  local empty_count
  empty_count=$(find "${backup_dir}/secrets" -maxdepth 1 -type f -empty 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$empty_count" -gt 0 ]]; then
    log_error "${empty_count} secret file(s) are empty — backup is corrupt"
    errors=$((errors + 1))
  fi

  # Hard fail: .env must carry the env keys the app NEEDs to boot.
  for key in YASHIGANI_TLS_DOMAIN POSTGRES_PASSWORD YASHIGANI_DB_AES_KEY; do
    if ! grep -q "^${key}=" "${backup_dir}/.env" 2>/dev/null; then
      log_error "Backup .env missing required key: ${key}"
      errors=$((errors + 1))
    fi
  done

  # Soft: postgres_dump.sql is optional (backup may predate DB data), but if
  # present it must be non-trivial (>100 bytes — empty file is suspicious).
  if [[ -f "${backup_dir}/postgres_dump.sql" ]]; then
    local dump_bytes
    dump_bytes=$(wc -c < "${backup_dir}/postgres_dump.sql" 2>/dev/null | tr -d ' ')
    if [[ -z "$dump_bytes" || "$dump_bytes" -lt 100 ]]; then
      log_error "postgres_dump.sql present but empty or truncated (${dump_bytes} bytes) — backup is corrupt"
      errors=$((errors + 1))
    fi
  else
    log_warn "No postgres_dump.sql in backup — DB will start empty post-restore"
  fi

  if [[ "$errors" -gt 0 ]]; then
    log_error "Backup validation: ${errors} failure(s) detected"
    return 1
  fi
  log_success "Backup validation passed"
  return 0
}

# ---------------------------------------------------------------------------
# Restore from a specific backup
# ---------------------------------------------------------------------------
restore_backup() {
  local backup_dir="$1"

  if [[ ! -d "$backup_dir" ]]; then
    log_error "Backup directory not found: ${backup_dir}"
    exit 1
  fi

  printf "\n${C_BOLD}Restoring from: $(basename "${backup_dir}")${C_RESET}\n"
  printf "  Runtime:     %s\n" "${RUNTIME}"
  if [[ "$K8S_MODE" == "true" ]]; then
    printf "  Namespace:   %s\n" "${K8S_NAMESPACE}"
  fi
  printf "\n"

  # Validate backup before restoring. --force bypasses validation for
  # genuine recovery scenarios (e.g. manually-assembled partial backup).
  if ! validate_backup "$backup_dir"; then
    if [[ "$FORCE" == "true" ]]; then
      log_warn "Backup validation failed but --force specified. Proceeding at operator risk."
    else
      log_error "Backup validation failed. Use --force to restore anyway (NOT recommended for production)."
      exit 1
    fi
  fi

  # Safety: snapshot current state before overwriting
  local pre_restore_dir="${BACKUPS_DIR}/pre-restore-$(date +%Y%m%d_%H%M%S)"
  if [[ -d "${WORK_DIR}/docker/secrets" ]]; then
    log_info "Saving current state to ${pre_restore_dir}..."
    mkdir -p "${pre_restore_dir}"
    cp -r "${WORK_DIR}/docker/secrets" "${pre_restore_dir}/secrets" 2>/dev/null || true
    cp "${WORK_DIR}/docker/.env" "${pre_restore_dir}/.env" 2>/dev/null || true
    log_success "Pre-restore snapshot saved"
  fi

  # 1. Restore secrets (preserve source mode; explicitly tighten CA private keys)
  if [[ -d "${backup_dir}/secrets" ]]; then
    log_info "Restoring secrets..."
    mkdir -p "${WORK_DIR}/docker/secrets"
    chmod 700 "${WORK_DIR}/docker/secrets"
    # cp -p preserves source mode/ownership timestamps; no blanket widen.
    # Pre-existing install.sh-written perms are preserved (container compat).
    if ! cp -rp "${backup_dir}/secrets/"* "${WORK_DIR}/docker/secrets/"; then
      log_error "Failed to copy secrets from backup"
      return 1
    fi
    # CA issuer private keys must NEVER be group/world readable (CWE-732).
    # They are only consumed by install.sh to sign leaves, never by containers
    # at runtime — so tighter-than-leaf perms are safe.
    for ca_key in ca_root.key ca_intermediate.key; do
      if [[ -f "${WORK_DIR}/docker/secrets/${ca_key}" ]]; then
        chmod 600 "${WORK_DIR}/docker/secrets/${ca_key}"
      fi
    done
    local secret_count
    secret_count=$(find "${backup_dir}/secrets" -maxdepth 1 -type f | wc -l | tr -d ' ')
    log_success "Secrets restored (${secret_count} files; CA keys forced 0600)"
  else
    log_warn "No secrets directory in backup — skipping"
  fi

  # 2. Restore .env
  if [[ -f "${backup_dir}/.env" ]]; then
    log_info "Restoring .env..."
    cp "${backup_dir}/.env" "${WORK_DIR}/docker/.env"
    log_success ".env restored"
  else
    log_warn "No .env file in backup — skipping"
  fi

  # 3. Restore Postgres dump
  if [[ -f "${backup_dir}/postgres_dump.sql" ]]; then
    _restore_postgres "${backup_dir}/postgres_dump.sql"
  else
    log_info "No Postgres dump in backup — skipping database restore"
  fi

  # 4. For K8s: update secrets in the cluster
  if [[ "$K8S_MODE" == "true" && -d "${backup_dir}/secrets" ]]; then
    _restore_k8s_secrets "${backup_dir}/secrets"
  fi

  printf "\n${C_GREEN}${C_BOLD}Restore complete.${C_RESET}\n\n"

  # Platform-specific next steps
  case "$RUNTIME" in
    docker)
      printf "  Next steps:\n"
      printf "    1. Restart services: docker compose -f docker/docker-compose.yml up -d\n"
      printf "    2. Verify: curl -sk https://\$(grep YASHIGANI_TLS_DOMAIN docker/.env | cut -d= -f2)/healthz\n"
      printf "    3. Log in to admin UI and verify credentials work\n"
      ;;
    podman)
      printf "  Next steps:\n"
      printf "    1. Restart services: podman compose -f docker/docker-compose.yml up -d\n"
      printf "    2. Verify: curl -sk https://\$(grep YASHIGANI_TLS_DOMAIN docker/.env | cut -d= -f2)/healthz\n"
      printf "    3. Log in to admin UI and verify credentials work\n"
      ;;
    k8s)
      printf "  Next steps:\n"
      printf "    1. Restart pods: kubectl rollout restart deployment -n ${K8S_NAMESPACE}\n"
      printf "    2. Verify: kubectl exec -n ${K8S_NAMESPACE} deploy/gateway -- curl -s http://localhost:8080/healthz\n"
      printf "    3. Log in to admin UI and verify credentials work\n"
      ;;
    *)
      printf "  Secrets and .env restored. Start your services manually.\n"
      ;;
  esac
  printf "\n"
  printf "  Pre-restore backup saved at: ${pre_restore_dir}\n"
  printf "  If something went wrong, restore from there.\n\n"
}

# ---------------------------------------------------------------------------
# Restore Postgres dump (runtime-aware)
# ---------------------------------------------------------------------------
_restore_postgres() {
  local dump_file="$1"
  local dump_size dump_bytes
  dump_size=$(du -h "$dump_file" 2>/dev/null | awk '{print $1}')
  dump_bytes=$(wc -c < "$dump_file" 2>/dev/null | tr -d ' ')
  if [[ -z "$dump_bytes" || "$dump_bytes" -lt 100 ]]; then
    log_error "Postgres dump is empty or truncated (${dump_bytes} bytes) — refusing to restore"
    return 1
  fi
  log_info "Postgres dump found (${dump_size}). Attempting restore..."

  # Read DB user/name from .env if available (preserve existing parse)
  local db_user="yashigani_app"
  local db_name="yashigani"
  if [[ -f "${WORK_DIR}/docker/.env" ]]; then
    local dsn
    dsn=$(grep "^YASHIGANI_DB_DSN=" "${WORK_DIR}/docker/.env" 2>/dev/null | head -1 || echo "")
    if [[ -n "$dsn" ]]; then
      # Extract user from postgresql://user:pass@host:port/db
      db_user=$(echo "$dsn" | sed -n 's|.*://\([^:]*\):.*|\1|p')
      db_name=$(echo "$dsn" | sed -n 's|.*/\([^?]*\).*|\1|p')
    fi
  fi

  # Read postgres superuser password from docker/secrets/postgres_password.
  # docker-compose.yml runs postgres as POSTGRES_USER=yashigani_app with
  # POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password, so yashigani_app
  # IS the superuser for this container — no separate super account.
  local pg_password=""
  if [[ -f "${WORK_DIR}/docker/secrets/postgres_password" ]]; then
    pg_password=$(<"${WORK_DIR}/docker/secrets/postgres_password")
  fi
  if [[ -z "$pg_password" ]]; then
    log_error "Cannot read docker/secrets/postgres_password — required for drop+recreate. Abort."
    return 1
  fi

  local pg_container
  pg_container=$(find_pg_container)

  if [[ -z "$pg_container" ]]; then
    log_warn "Postgres not running — dump saved for manual restore:"
    log_warn "  ${dump_file}"
    log_warn "  Manual (after 'compose up -d postgres'):"
    log_warn "    cat ${dump_file} | <runtime> exec -i <postgres_container> psql --single-transaction -v ON_ERROR_STOP=1 -U ${db_user} -d ${db_name}"
    return 0
  fi

  log_info "Found Postgres: ${pg_container}"
  log_info "Preparing target database '${db_name}' (terminate connections, drop, recreate)..."

  # Step 1: drop + recreate the target DB to guarantee clean schema-free state.
  # Connect to the 'postgres' system DB (always exists). Terminate any existing
  # connections to the target first, else DROP DATABASE hangs.
  #
  # Risk: this IS destructive — existing app state in "${db_name}" is wiped.
  # That is the intended semantics of a restore ("replace with backup").
  if ! pg_exec "$pg_container" env PGPASSWORD="$pg_password" \
        psql -U "$db_user" -d postgres -v ON_ERROR_STOP=1 -q <<EOF
SELECT pg_terminate_backend(pid) FROM pg_stat_activity
  WHERE datname = '${db_name}' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS "${db_name}";
CREATE DATABASE "${db_name}" OWNER "${db_user}";
EOF
  then
    log_error "Failed to drop+recreate '${db_name}'. Target DB may still have active connections from app containers."
    log_error "Remediation: stop app containers first (e.g. 'podman compose stop gateway backoffice'), then re-run restore."
    return 1
  fi
  log_success "Target database '${db_name}' recreated clean"

  # Step 2: feed dump with --single-transaction + ON_ERROR_STOP=1.
  # Any error aborts the whole transaction — no silent partial restore.
  # Do NOT swallow stderr with 2>/dev/null; surface errors to the operator.
  log_info "Loading dump into ${db_name} (single-transaction, fail-fast)..."
  if pg_exec "$pg_container" env PGPASSWORD="$pg_password" \
       psql --single-transaction -v ON_ERROR_STOP=1 \
            -U "$db_user" -d "$db_name" < "$dump_file"; then
    log_success "Postgres database restored (single-transaction, fail-fast)"
  else
    log_error "Postgres restore failed. Transaction was rolled back — database is back to the recreated-empty state."
    log_error "Review dump at: ${dump_file}"
    log_error "To investigate: cat ${dump_file} | <runtime> exec -i ${pg_container} psql -U ${db_user} -d ${db_name}"
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Restore K8s secrets
# ---------------------------------------------------------------------------
_restore_k8s_secrets() {
  local secrets_dir="$1"
  log_info "Updating Kubernetes secrets in namespace '${K8S_NAMESPACE}'..."

  # Build --from-file args for all secret files
  local from_files=()
  for f in "${secrets_dir}"/*; do
    [[ -f "$f" ]] && from_files+=("--from-file=$(basename "$f")=$f")
  done

  if [[ ${#from_files[@]} -eq 0 ]]; then
    log_warn "No secret files to restore"
    return 0
  fi

  # Delete and recreate the secret (kubectl create --dry-run + apply is cleaner
  # but some clusters don't support dry-run=client)
  if kubectl -n "$K8S_NAMESPACE" delete secret yashigani-secrets 2>/dev/null; then
    log_info "Deleted existing yashigani-secrets"
  fi

  if kubectl -n "$K8S_NAMESPACE" create secret generic yashigani-secrets "${from_files[@]}" 2>/dev/null; then
    log_success "Kubernetes secrets restored (${#from_files[@]} files)"
  else
    log_error "Failed to create Kubernetes secret — check permissions"
  fi
}

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
RESTORE_TARGET=""
FORCE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --k8s|--kubernetes)
      K8S_MODE=true
      shift
      ;;
    -n|--namespace)
      K8S_NAMESPACE="$2"
      shift 2
      ;;
    --latest)
      RESTORE_TARGET="--latest"
      shift
      ;;
    --force)
      FORCE=true
      shift
      ;;
    --help|-h)
      cat <<'EOF'
Yashigani Restore Script

Usage:
  bash restore.sh                              List available backups
  bash restore.sh <backup_dir>                 Restore from specific backup
  bash restore.sh --latest                     Restore most recent backup
  bash restore.sh --latest --k8s -n yashigani  Restore into Kubernetes

Options:
  --k8s, --kubernetes   Restore into a Kubernetes cluster
  -n, --namespace NS    Kubernetes namespace (default: yashigani)
  --latest              Use most recent backup
  --force               Skip validation warnings
  --help                Show this help

Supported platforms:
  - Docker Compose (Linux/macOS)
  - Podman Compose (Linux/macOS rootless)
  - Kubernetes (via kubectl)
EOF
      exit 0
      ;;
    *)
      RESTORE_TARGET="$1"
      shift
      ;;
  esac
done

detect_runtime

case "${RESTORE_TARGET}" in
  "")
    list_backups
    ;;
  --latest)
    latest=$(find "${BACKUPS_DIR}" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -r | head -1)
    if [[ -z "$latest" ]]; then
      log_error "No backups found"
      exit 1
    fi
    restore_backup "$latest"
    ;;
  *)
    if [[ -d "$RESTORE_TARGET" ]]; then
      restore_backup "$RESTORE_TARGET"
    elif [[ -d "${BACKUPS_DIR}/${RESTORE_TARGET}" ]]; then
      restore_backup "${BACKUPS_DIR}/${RESTORE_TARGET}"
    else
      log_error "Backup not found: ${RESTORE_TARGET}"
      list_backups
      exit 1
    fi
    ;;
esac
