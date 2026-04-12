#!/usr/bin/env bash
set -euo pipefail

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
#
# What gets restored:
#   - docker/secrets/    (admin passwords, TOTP secrets, service tokens)
#   - docker/.env        (environment variables, database passwords)
#   - postgres_dump.sql  (database — if available in backup)
#
# What does NOT get restored (by design):
#   - Container images (rebuilt from source)
#   - Docker volumes other than Postgres (recreated on startup)
#   - OPA policies (loaded from git)
# =============================================================================

C_GREEN="\033[0;32m"
C_RED="\033[0;31m"
C_YELLOW="\033[0;33m"
C_BOLD="\033[1m"
C_RESET="\033[0m"

WORK_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKUPS_DIR="${WORK_DIR}/backups"

log_info()    { printf "    --> %s\n" "$*"; }
log_success() { printf "    ${C_GREEN}ok${C_RESET}  %s\n" "$*"; }
log_error()   { printf "    ${C_RED}!!  ERROR: %s${C_RESET}\n" "$*" >&2; }
log_warn()    { printf "    ${C_YELLOW}!!  WARNING: %s${C_RESET}\n" "$*"; }

# List available backups
list_backups() {
    if [[ ! -d "$BACKUPS_DIR" ]]; then
        echo "No backups directory found at ${BACKUPS_DIR}"
        exit 1
    fi

    local backups
    backups=$(ls -1d "${BACKUPS_DIR}"/*/ 2>/dev/null | sort -r)
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
        [[ -d "${dir}secrets" ]] && has_secrets="yes"
        [[ -f "${dir}.env" ]] && has_env="yes"
        [[ -f "${dir}postgres_dump.sql" ]] && has_db="yes"
        printf "  %d) %s  (secrets=%s, env=%s, db=%s)\n" "$i" "$ts" "$has_secrets" "$has_env" "$has_db"
        i=$((i + 1))
    done <<< "$backups"
    printf "\nUsage: bash restore.sh <backup_dir>\n"
    printf "   or: bash restore.sh --latest\n\n"
}

# Restore from a specific backup
restore_backup() {
    local backup_dir="$1"

    if [[ ! -d "$backup_dir" ]]; then
        log_error "Backup directory not found: ${backup_dir}"
        exit 1
    fi

    printf "\n${C_BOLD}Restoring from: ${backup_dir}${C_RESET}\n\n"

    # 1. Restore secrets
    if [[ -d "${backup_dir}/secrets" ]]; then
        log_info "Restoring secrets..."
        cp -r "${backup_dir}/secrets/"* "${WORK_DIR}/docker/secrets/" 2>/dev/null || true
        chmod 600 "${WORK_DIR}/docker/secrets/"*
        log_success "Secrets restored"
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

    # 3. Restore Postgres dump (if available and Postgres is running)
    if [[ -f "${backup_dir}/postgres_dump.sql" ]]; then
        log_info "Postgres dump found. Attempting restore..."
        local compose_file="${WORK_DIR}/docker/docker-compose.yml"
        if command -v podman &>/dev/null; then
            local pg_container
            pg_container=$(podman ps --format '{{.Names}}' 2>/dev/null | grep postgres | head -1)
            if [[ -n "$pg_container" ]]; then
                cat "${backup_dir}/postgres_dump.sql" | podman exec -i "$pg_container" psql -U yashigani_app -d yashigani 2>/dev/null && \
                    log_success "Postgres database restored" || \
                    log_warn "Postgres restore failed — database may need manual recovery"
            else
                log_warn "Postgres container not running — save dump for manual restore later"
            fi
        else
            log_warn "Podman/Docker not available — save dump for manual restore"
        fi
    fi

    printf "\n${C_GREEN}${C_BOLD}Restore complete.${C_RESET}\n"
    printf "Next steps:\n"
    printf "  1. Restart services: podman compose -f docker/docker-compose.yml up -d\n"
    printf "  2. Verify: curl -sk https://yashigani.local/healthz\n"
    printf "  3. Log in to admin UI and verify credentials work\n\n"
}

# Main
case "${1:-}" in
    "")
        list_backups
        ;;
    --latest)
        latest=$(ls -1d "${BACKUPS_DIR}"/*/ 2>/dev/null | sort -r | head -1)
        if [[ -z "$latest" ]]; then
            log_error "No backups found"
            exit 1
        fi
        restore_backup "$latest"
        ;;
    *)
        if [[ -d "$1" ]]; then
            restore_backup "$1"
        elif [[ -d "${BACKUPS_DIR}/$1" ]]; then
            restore_backup "${BACKUPS_DIR}/$1"
        else
            log_error "Backup not found: $1"
            list_backups
            exit 1
        fi
        ;;
esac
