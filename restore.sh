#!/usr/bin/env bash
set -euo pipefail
# Last updated: 2026-05-02T23:10:00+01:00 (fix RESTORE-4: BSD sed -i portability — use sed -i "" for macOS)

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

  if [[ ! -d "${backup_dir}/secrets" ]] && [[ ! -f "${backup_dir}/.env" ]]; then
    log_error "Backup is empty — no secrets directory and no .env file"
    return 1
  fi

  # Check secrets have content (not empty files)
  if [[ -d "${backup_dir}/secrets" ]]; then
    local empty_count
    empty_count=$(find "${backup_dir}/secrets" -maxdepth 1 -type f -empty 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$empty_count" -gt 0 ]]; then
      log_warn "${empty_count} secret file(s) are empty — may indicate a corrupt backup"
      errors=$((errors + 1))
    fi
  fi

  # Check .env has required keys
  if [[ -f "${backup_dir}/.env" ]]; then
    for key in YASHIGANI_TLS_DOMAIN POSTGRES_PASSWORD YASHIGANI_DB_AES_KEY; do
      if ! grep -q "^${key}=" "${backup_dir}/.env" 2>/dev/null; then
        log_warn "Missing ${key} in backup .env — may cause startup issues"
        errors=$((errors + 1))
      fi
    done
  fi

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

  # Validate backup before restoring
  validate_backup "$backup_dir" || {
    log_error "Backup validation failed. Use --force to restore anyway."
    exit 1
  }

  # Safety: snapshot current state before overwriting
  local pre_restore_dir="${BACKUPS_DIR}/pre-restore-$(date +%Y%m%d_%H%M%S)"
  if [[ -d "${WORK_DIR}/docker/secrets" ]]; then
    log_info "Saving current state to ${pre_restore_dir}..."
    mkdir -p "${pre_restore_dir}"
    cp -r "${WORK_DIR}/docker/secrets" "${pre_restore_dir}/secrets" 2>/dev/null || true
    cp "${WORK_DIR}/docker/.env" "${pre_restore_dir}/.env" 2>/dev/null || true
    log_success "Pre-restore snapshot saved"
  fi

  # 1. Restore secrets
  if [[ -d "${backup_dir}/secrets" ]]; then
    log_info "Restoring secrets..."
    mkdir -p "${WORK_DIR}/docker/secrets"

    # RESTORE-3 (v2.23.1 gate): the secrets dir may be owned by a subuid-range UID
    # left from a previous Podman rootless install (e.g. UID 363144 = container UID
    # 1001 in the PKI issuer's namespace). If the current user does not own it,
    # `chmod 751` below will fail with EPERM → restore aborts before touching any
    # secrets. Fix: if Podman rootless mode AND the dir is not owned by the current
    # user, use `podman unshare chown` (which maps the installer's UID to 0 inside
    # the user namespace, giving it root-equivalent privilege over the subuid range).
    # This mirrors the stale-install guard in install.sh.
    # Never sudo here — restore.sh runs zero sudo (P0-14).
    local _secrets_dir_owner
    _secrets_dir_owner=$(stat -c '%u' "${WORK_DIR}/docker/secrets" 2>/dev/null || echo "")
    if [[ -n "$_secrets_dir_owner" && "$_secrets_dir_owner" != "$(id -u)" ]]; then
      if [[ "${RUNTIME}" == "podman" ]] && command -v podman >/dev/null 2>&1; then
        log_info "Secrets dir owned by UID ${_secrets_dir_owner} (not current user $(id -u)) — resetting via podman unshare"
        # Chown dir to UID 0 inside the user namespace = current user on the host.
        if ! podman unshare chown 0:0 "${WORK_DIR}/docker/secrets" 2>/dev/null; then
          log_warn "podman unshare chown on secrets dir failed — chmod 751 may fail; pre-run: sudo chown $(id -un):$(id -gn) '${WORK_DIR}/docker/secrets'"
        fi
        # Also reset any existing files so cp -rp can overwrite them.
        find "${WORK_DIR}/docker/secrets" -maxdepth 1 -type f \
          -exec podman unshare chmod u+w {} \; 2>/dev/null || true
      else
        log_warn "Secrets dir owned by UID ${_secrets_dir_owner} (not current user $(id -u))."
        log_warn "  chmod 751 will fail unless you fix it first:"
        log_warn "    sudo chown $(id -un):$(id -gn) '${WORK_DIR}/docker/secrets'"
      fi
    fi

    # RC-6 (v2.23.1): secrets directory must be world-traversable (0751) so
    # container processes running as non-root UIDs (pgbouncer=70, redis=999,
    # etc.) can access individual files within it. restore.sh runs with
    # umask 077, which would create the directory as 0700 — override explicitly.
    # The outer home directory (/home/max) provides the primary access control;
    # making the inner secrets/ directory traversable is intentional and safe.
    chmod 751 "${WORK_DIR}/docker/secrets"
    # Ensure any pre-existing read-only files in the destination are writable
    # before we overwrite them. On macOS (BSD cp), cp -rp fails to overwrite
    # a 0400 file even when you own it — unlike GNU cp which can force-overwrite
    # owner-writable-by-permission.  The original filter was *.key/*.pem only,
    # but token files, hmac files, and password files are also installed 0400
    # by install.sh — all need u+w for the cp to succeed.  This is idempotent:
    # we restore canonical permissions in _pki_chown_client_keys immediately
    # after the copy.  Bug caught: R4 macOS Podman gate 2026-04-30.
    find "${WORK_DIR}/docker/secrets" -maxdepth 1 -type f \
      -exec chmod u+w {} \; 2>/dev/null || true
    # cp -p preserves source mode/ownership timestamps.
    if ! cp -rp "${backup_dir}/secrets/"* "${WORK_DIR}/docker/secrets/"; then
      log_error "Failed to copy secrets from backup"
      return 1
    fi
    local secret_count
    secret_count=$(find "${backup_dir}/secrets" -maxdepth 1 -type f | wc -l | tr -d ' ')
    log_success "Secrets copied from backup (${secret_count} files)"

    # BUG-58B-04a + BUG-58B-04b (v2.23.1): reapply canonical file modes and
    # re-own service private keys to the container UIDs that must read them.
    # Old backups (pre-fix) used 'chmod -R 600' which clobbered intentionally-
    # 0644 public secrets. New backups only tighten *.key to 0400. Either way,
    # calling _pki_chown_client_keys here normalises modes and ownership so that
    # every service container can read exactly the files it needs to.
    _pki_chown_client_keys
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
# BUG-58B-04b (v2.23.1): Re-own service private keys to container UIDs after
# PKI restore. install.sh's _backup_existing_data now only sets *.key to 0400
# (not a blanket chmod -R 600), but the backup still carries root:root ownership
# from the initial cp -rp. When restore.sh extracts keys, they land as root:root
# 0400; service containers (pgbouncer=UID70, redis=UID999, gateway/backoffice=
# UID1001) get EACCES on their own key.
#
# Same service→UID map as install.sh:_pki_chown_client_keys.
# Runs after secrets are restored on every supported runtime.
# ---------------------------------------------------------------------------
_pki_chown_client_keys() {
  local _secrets_dir="${WORK_DIR}/docker/secrets"

  # Canonical UID map: service name → container UID.
  local _uid_mapped_services=(
    "gateway:1001"
    "backoffice:1001"
    "redis:999"
    "budget-redis:999"
    "pgbouncer:70"
    "postgres:999"
  )

  # Determine chown mode: root can chown directly; non-root uses podman unshare
  # (Podman rootless user-namespace). Docker non-root: restore.sh never runs
  # sudo (P0-14) — warn with a copy-pasteable remediation block instead.
  # check_restore_preflight() has already verified docker group membership; the
  # key re-own step is the one operation that still requires host privilege when
  # backup keys land as root:root.
  local _chown_mode="direct"
  if [[ "$(id -u)" != "0" ]]; then
    if [[ "${RUNTIME}" == "podman" ]]; then
      _chown_mode="unshare"
    else
      # Docker non-root: warn-only — never sudo (P0-14 / feedback_security_company_no_shortcuts).
      _chown_mode="warn"
    fi
  fi

  log_info "Re-owning service private keys to container UIDs (mode: ${_chown_mode})"

  for _svc_uid in "${_uid_mapped_services[@]}"; do
    local _svc="${_svc_uid%%:*}"
    local _uid="${_svc_uid#*:}"
    local _keyfile="${_secrets_dir}/${_svc}_client.key"
    if [[ ! -f "$_keyfile" ]]; then
      continue
    fi
    case "$_chown_mode" in
      direct)
        if ! chown "${_uid}:${_uid}" "$_keyfile"; then
          log_warn "chown failed on ${_svc} key — container may fail to start"
        else
          chmod 0600 "$_keyfile" || log_warn "chmod 0600 failed on ${_svc} key (not fatal for direct mode)"
        fi
        ;;
      unshare)
        # RESTORE-1 (v2.23.1 gate): after `podman unshare chown ${_uid}:${_uid}`,
        # the file is owned by a subuid-range UID on the host. A subsequent
        # host-side `chmod` fails with EPERM because the calling user (su/UID 1004)
        # does not own the file. Fix: do the chmod INSIDE the podman unshare
        # namespace (where the chowned UID maps to 0 = the invoking user), alongside
        # the chown. This matches the pattern used in install.sh's _do_chown.
        local _key_basename
        _key_basename=$(basename "$_keyfile")
        local _key_dir
        _key_dir=$(dirname "$_keyfile")
        if ! podman unshare sh -c \
              "chown ${_uid}:${_uid} '${_keyfile}' && chmod 0600 '${_keyfile}'" 2>/dev/null; then
          log_warn "podman unshare chown/chmod failed on ${_svc} key — container may fail to start"
        fi
        ;;
      warn)
        log_warn "Non-root Docker: cannot chown ${_svc} key to UID ${_uid} without sudo."
        log_warn "  Run manually if ${_svc} fails to start:"
        log_warn "    sudo chown ${_uid}:${_uid} \"${_keyfile}\""
        ;;
    esac
  done

  # Reapply canonical cert modes: certs are public material (0644); keys are 0600.
  # Note: for 'unshare' mode, service keys were already chowned+chmod'd above
  # inside the user namespace. These host-side find commands will fail silently
  # on files owned by subuid-range UIDs (EPERM) — that is expected and harmless
  # because the correct mode was already applied inside unshare.
  find "${_secrets_dir}" -maxdepth 1 -type f \
    \( -name '*_client.crt' -o -name 'ca_*.crt' \) \
    -exec chmod 0644 {} \; 2>/dev/null || true
  find "${_secrets_dir}" -maxdepth 1 -type f -name '*.key' \
    -exec chmod 0600 {} \; 2>/dev/null || true
  # CA private keys are even tighter — only the PKI issuer (root/UID1001) reads
  # them. 0400 prevents accidental overwrite even by the owning UID.
  for _ca_key in ca_root.key ca_intermediate.key; do
    if [[ -f "${_secrets_dir}/${_ca_key}" ]]; then
      chmod 0400 "${_secrets_dir}/${_ca_key}" 2>/dev/null || true
    fi
  done

  # BUG-58B-04a: reapply 0644 to public password/token files that the backup's
  # per-file chmod may have tightened to 0400 (as of the BUG-58B-04a fix above,
  # backup only tightens *.key; but pre-fix backups on disk tightened everything
  # to 0600 via chmod -R 600). Reapply explicitly so restore is idempotent
  # against both old and new backup formats.
  local _public_secrets=(
    "admin_initial_password"
    "admin1_password"
    "admin1_username"
    "admin1_totp_secret"
    "admin2_password"
    "admin2_username"
    "admin2_totp_secret"
    "postgres_password"
    "redis_password"
    "grafana_admin_password"
    "openclaw_gateway_token"
    "wazuh_indexer_password"
    "wazuh_api_password"
    "wazuh_dashboard_password"
  )
  for _f in "${_public_secrets[@]}"; do
    if [[ -f "${_secrets_dir}/${_f}" ]]; then
      chmod 0644 "${_secrets_dir}/${_f}"
    fi
  done
  # bootstrap_token files (glob — one per service registered in manifest)
  find "${_secrets_dir}" -maxdepth 1 -type f -name '*_bootstrap_token' \
    -exec chmod 0644 {} \;

  log_success "Service key ownership + canonical file modes reapplied"

  # Defensive assertion: no world/group-readable private key files (S1 / CWE-732).
  if find "${_secrets_dir}" -maxdepth 1 -type f -name '*.key' \
        \( -perm -004 -o -perm -040 \) 2>/dev/null | grep -q .; then
    log_error "CWE-732: group/world-readable *.key file(s) under ${_secrets_dir} after chown step"
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# BUG-4 (v2.23.1): Refresh PGDATA-cached CA + server cert after PKI restore
# ---------------------------------------------------------------------------
# Postgres caches the CA root + server leaf inside PGDATA at first initdb
# (docker/postgres/05-enable-ssl.sh installs ca_root.crt -> ${PGDATA}/root.crt,
# postgres_client.crt -> server.crt, postgres_client.key -> server.key). On a
# fresh install the CA in PGDATA and the CA in /run/secrets/ca_root.crt are
# the same. After a restore, /run/secrets/ now carries the BACKUPs CA but
# PGDATA still has the in-place install CA -- every mTLS handshake against
# pgbouncer fails because pgbouncer presents a leaf signed by the restored CA
# while PGDATA root.crt only trusts the in-place CA.
#
# Fix: copy the restored CA + restored postgres leaf from /run/secrets into
# PGDATA, then pg_ctl reload (no restart needed -- TLS material is reloadable).
#
# Pattern-sweep result: ONLY postgres caches CA-in-volume. redis, pgbouncer,
# gateway, backoffice, caddy, grafana all read /run/secrets/ca_root.crt or
# bind-mounts at runtime and pick up the new CA on a normal compose restart.
# Helm chart equivalent runs the same 05-enable-ssl.sh logic in the postgres
# init job, so the K8s path uses the same install + reload sequence via
# kubectl exec.
# ---------------------------------------------------------------------------
_refresh_pgdata_ca() {
  local pg_target=""
  pg_target=$(find_pg_container)

  if [[ -z "$pg_target" ]]; then
    log_warn "Postgres not running -- PGDATA CA refresh deferred."
    log_warn "  After bringing postgres up, manually install"
    log_warn "  /run/secrets/ca_root.crt into \${PGDATA}/root.crt and the"
    log_warn "  postgres_client.{crt,key} into \${PGDATA}/server.{crt,key},"
    log_warn "  then pg_ctl reload."
    return 0
  fi

  log_info "Refreshing PGDATA-cached CA + server cert in ${pg_target}..."

  if ! pg_exec "$pg_target" sh -c '
    set -e
    PGDATA="${PGDATA:-/var/lib/postgresql/data/pgdata}"
    : "${PGDATA:?PGDATA env var unset in postgres container}"
    install -m 0644 -o postgres -g postgres /run/secrets/ca_root.crt         "${PGDATA}/root.crt"
    install -m 0644 -o postgres -g postgres /run/secrets/postgres_client.crt "${PGDATA}/server.crt"
    install -m 0600 -o postgres -g postgres /run/secrets/postgres_client.key "${PGDATA}/server.key"
    # pg_ctl cannot run as root. Use gosu if available (official postgres image),
    # fall back to su -s /bin/sh postgres for other distros. Both drop to the
    # postgres UID before invoking pg_ctl. Compose/VM paths exec as the postgres
    # user natively; only K8s kubectl exec arrives as root.
    if command -v gosu >/dev/null 2>&1; then
      gosu postgres pg_ctl -D "${PGDATA}" reload
    else
      su -s /bin/sh postgres -c "pg_ctl -D \"${PGDATA}\" reload"
    fi
  '; then
    log_error "PGDATA CA refresh failed. mTLS between pgbouncer and postgres may be broken."
    log_error "  Manual recovery: exec into postgres, copy"
    log_error "  /run/secrets/{ca_root.crt,postgres_client.crt,postgres_client.key} into"
    log_error "  \${PGDATA}/{root.crt,server.crt,server.key} (chown postgres:postgres),"
    log_error "  then run: pg_ctl -D \${PGDATA} reload"
    return 1
  fi

  log_success "PGDATA CA + server cert refreshed; postgres reloaded TLS material"
}

# ---------------------------------------------------------------------------
# BUG-58B-04d (v2.23.1): Update the live yashigani_app role password to match
# the restored postgres_password secret.
#
# Why this is needed:
#   * Fresh install creates the cluster with password A (random, generated).
#   * The cluster persists the SCRAM hash of A in pg_authid; the file
#     POSTGRES_PASSWORD_FILE is only consulted at initdb time.
#   * Restore overwrites docker/secrets/postgres_password with backup's
#     password B. pgbouncer's auto-generated userlist.txt regenerates with B
#     on its next container start; the app reads B from the same secret.
#   * But the live cluster still authenticates against A → every TCP
#     connection from pgbouncer/app fails with "password authentication
#     failed for user yashigani_app".
#
# Fix: ALTER ROLE on the live cluster, idempotently, via the local Unix
# socket inside the postgres container. pg_hba.conf entry installed by
# docker/postgres/05-enable-ssl.sh is 'local all all trust' so password-
# less auth is permitted there (and only there).
#
# SQL is fed via stdin so the password never appears in process args (ps).
# Single quotes inside the password are escaped by doubling
# (standard_conforming_strings is on by default in modern postgres).
# ---------------------------------------------------------------------------
_restore_pg_role_password() {
  local _secret_file="${WORK_DIR}/docker/secrets/postgres_password"
  if [[ ! -f "$_secret_file" ]]; then
    log_warn "postgres_password secret missing — skipping role password update"
    return 0
  fi
  local _new_pw
  _new_pw=$(<"$_secret_file")
  if [[ -z "$_new_pw" ]]; then
    log_warn "postgres_password is empty — skipping role password update"
    return 0
  fi

  local _pg_container
  _pg_container=$(find_pg_container)
  if [[ -z "$_pg_container" ]]; then
    log_warn "Postgres not running -- role password update deferred."
    log_warn "  After bringing postgres up, run inside the postgres container:"
    log_warn "    psql -U yashigani_app -d postgres"
    log_warn "    ALTER ROLE \"yashigani_app\" WITH PASSWORD '<contents of docker/secrets/postgres_password>';"
    return 0
  fi

  # Determine the DB role from the restored .env (default yashigani_app —
  # the same default install.sh writes).
  local _db_user="yashigani_app"
  if [[ -f "${WORK_DIR}/docker/.env" ]]; then
    local _dsn
    _dsn=$(grep "^YASHIGANI_DB_DSN=" "${WORK_DIR}/docker/.env" 2>/dev/null | head -1 || true)
    if [[ -n "$_dsn" ]]; then
      local _parsed
      _parsed=$(echo "$_dsn" | sed -n 's|.*://\([^:]*\):.*|\1|p')
      [[ -n "$_parsed" ]] && _db_user="$_parsed"
    fi
  fi

  # Escape single quotes in the password for SQL string literal.
  local _pw_escaped="${_new_pw//\'/\'\'}"

  log_info "Updating live ${_db_user} role password to match restored secret..."

  # Pipe SQL via stdin so the password never appears in process args.
  # Connect via local Unix socket → trust auth (per pg_hba.conf line 1
  # installed by docker/postgres/05-enable-ssl.sh).
  if ! printf '%s\n' "ALTER ROLE \"${_db_user}\" WITH PASSWORD '${_pw_escaped}';" \
        | pg_exec "$_pg_container" psql -U "$_db_user" -d postgres \
            -v ON_ERROR_STOP=1 -q --no-psqlrc >/dev/null; then
    log_error "Failed to update ${_db_user} role password on live cluster."
    log_error "  Manual recovery (run on host):"
    log_error "    ${RUNTIME} exec -it ${_pg_container} psql -U ${_db_user} -d postgres"
    log_error "    ALTER ROLE \"${_db_user}\" WITH PASSWORD '<contents of docker/secrets/postgres_password>';"
    return 1
  fi
  log_success "Role ${_db_user} password updated on live cluster"

  # RESTORE-2 (v2.23.1 gate): sync .env POSTGRES_PASSWORD + POSTGRES_PASSWORD_URLENC
  # to match the restored postgres_password secret.
  #
  # Root cause: install.sh generates an initial password, writes it to both .env and
  # docker/secrets/postgres_password. bootstrap_postgres.py (run by install.sh step 11)
  # regenerates the password and writes only to docker/secrets/postgres_password — .env
  # is NOT updated. After a restore, docker/secrets/postgres_password holds the backup's
  # final password but .env still has the initial install-time password. The backoffice
  # and gateway containers read YASHIGANI_DB_DSN from .env (which uses
  # POSTGRES_PASSWORD_URLENC), while pgbouncer's auto-generated userlist.txt reads from
  # the secrets file. These diverge → auth fails on every connection after compose up.
  #
  # Fix: after ALTER ROLE succeeds (live cluster authenticated against the secret),
  # update POSTGRES_PASSWORD and POSTGRES_PASSWORD_URLENC in .env to match.
  # URL-encode using Python (always available in backoffice image; or system python3).
  local _env_file="${WORK_DIR}/docker/.env"
  if [[ -f "$_env_file" ]]; then
    local _pw_urlenc
    _pw_urlenc=$(python3 -c \
      "import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1],safe=''))" \
      "$_new_pw" 2>/dev/null || echo "")
    if [[ -n "$_pw_urlenc" ]]; then
      # Update or append POSTGRES_PASSWORD
      if grep -q "^POSTGRES_PASSWORD=" "$_env_file"; then
        # macOS BSD sed requires an explicit backup-extension arg (can be empty string).
        # GNU sed accepts sed -i "..." but BSD sed treats the pattern as the extension.
        # Use sed -i "" for portability across both.
        sed -i "" "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${_new_pw}|" "$_env_file" 2>/dev/null || \
          sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${_new_pw}|" "$_env_file"
      else
        printf 'POSTGRES_PASSWORD=%s\n' "$_new_pw" >> "$_env_file"
      fi
      # Update or append POSTGRES_PASSWORD_URLENC
      if grep -q "^POSTGRES_PASSWORD_URLENC=" "$_env_file"; then
        sed -i "" "s|^POSTGRES_PASSWORD_URLENC=.*|POSTGRES_PASSWORD_URLENC=${_pw_urlenc}|" "$_env_file" 2>/dev/null || \
          sed -i "s|^POSTGRES_PASSWORD_URLENC=.*|POSTGRES_PASSWORD_URLENC=${_pw_urlenc}|" "$_env_file"
      else
        printf 'POSTGRES_PASSWORD_URLENC=%s\n' "$_pw_urlenc" >> "$_env_file"
      fi
      log_success ".env POSTGRES_PASSWORD[_URLENC] synced to match restored secret (RESTORE-2 fix)"
    else
      log_warn "Could not URL-encode postgres password — .env POSTGRES_PASSWORD_URLENC not updated."
      log_warn "  Manual fix: update POSTGRES_PASSWORD and POSTGRES_PASSWORD_URLENC in ${_env_file}"
      log_warn "  to match: $(cat "${_secret_file}" 2>/dev/null || echo '<read docker/secrets/postgres_password>')"
    fi
  fi

  # Note: ALTER ROLE on a missing role would have errored out via
  # ON_ERROR_STOP=1 above. A loopback verify (psql -h 127.0.0.1) would NOT
  # actually validate the new password because pg_hba.conf has
  # 'host all all 127.0.0.1/32 trust'. A meaningful TCP verify requires
  # an SSL+client-cert handshake — out of scope for this helper. Operators
  # can verify by restarting pgbouncer + the app and confirming successful
  # connections in the logs.
}

# ---------------------------------------------------------------------------
# Restore Postgres dump (runtime-aware)
# ---------------------------------------------------------------------------
_restore_postgres() {
  local dump_file="$1"
  local dump_size
  dump_size=$(du -h "$dump_file" 2>/dev/null | awk '{print $1}')
  log_info "Postgres dump found (${dump_size}). Attempting restore..."

  # Read DB user from .env if available
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

  local pg_container
  pg_container=$(find_pg_container)

  if [[ -z "$pg_container" ]]; then
    log_warn "Postgres not running — dump saved for manual restore:"
    log_warn "  ${dump_file}"
    log_warn "  Manual: cat ${dump_file} | docker exec -i <postgres_container> psql -U ${db_user} -d ${db_name}"
    return 0
  fi

  log_info "Found Postgres: ${pg_container}"
  log_info "Restoring as user '${db_user}' into database '${db_name}'..."

  if cat "$dump_file" | pg_exec "$pg_container" psql -U "$db_user" -d "$db_name" 2>/dev/null; then
    log_success "Postgres database restored"
  else
    log_warn "Postgres restore had errors — this may be normal if tables already exist"
    log_warn "Check manually: review ${dump_file} and compare with running database"
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
