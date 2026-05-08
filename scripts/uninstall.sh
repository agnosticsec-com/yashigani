#!/usr/bin/env bash
# scripts/uninstall.sh — Yashigani v0.6.0
# Clean removal of Yashigani. Optionally preserves data volumes.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Parse flags
# ---------------------------------------------------------------------------
KEEP_DATA=0
FORCE=0

for arg in "$@"; do
  case "$arg" in
    --keep-data)  KEEP_DATA=1 ;;
    --force)      FORCE=1     ;;
    --yes|-y)     FORCE=1     ;;   # alias for --force; documented in --help
    --help|-h)
      cat <<'EOF'
Usage: scripts/uninstall.sh [OPTIONS]

Removes Yashigani containers, networks, secrets, and optionally data volumes.

Options:
  --keep-data     Preserve postgres_data, audit_data, and redis_data volumes
  --force         Skip confirmation prompts
  --yes, -y       Alias for --force; skip all confirmation prompts.
                  Use in CI / unattended removal. Operator accepts full
                  responsibility for data loss when --keep-data is not set.
  --help, -h      Print this message

What is removed:
  - All containers and networks (docker compose down)
  - All yashigani_* Docker volumes (unless --keep-data)
  - docker/secrets/ directory (generated secrets)
  - .env file (will prompt unless --force/--yes)

What is preserved with --keep-data:
  - yashigani_postgres_data
  - yashigani_audit_data
  - yashigani_redis_data
EOF
      exit 0
      ;;
    *) printf "Unknown option: %s\nRun with --help for usage.\n" "$arg" >&2; exit 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Source platform detection (for color vars)
# ---------------------------------------------------------------------------
# shellcheck source=scripts/platform-detect.sh
source "${SCRIPT_DIR}/platform-detect.sh"

# ---------------------------------------------------------------------------
# Color/print helpers
# ---------------------------------------------------------------------------
_info()  { printf "${YSG_BLUE}[INFO]${YSG_RESET}  %s\n"   "$*"; }
_ok()    { printf "${YSG_GREEN}[OK]${YSG_RESET}    %s\n"  "$*"; }
_warn()  { printf "${YSG_YELLOW}[WARN]${YSG_RESET}  %s\n" "$*"; }
_error() { printf "${YSG_RED}[ERROR]${YSG_RESET} %s\n"    "$*" >&2; }
_die()   { _error "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Step 1: Confirmation prompt
# ---------------------------------------------------------------------------
if [ "$FORCE" -eq 0 ]; then
  printf "${YSG_YELLOW}WARNING: This will remove Yashigani containers, networks,${YSG_RESET}\n"
  printf "${YSG_YELLOW}         secrets, and generated configuration.${YSG_RESET}\n"
  if [ "$KEEP_DATA" -eq 0 ]; then
    printf "${YSG_RED}         DATA VOLUMES WILL ALSO BE DELETED.${YSG_RESET}\n"
    printf "${YSG_RED}         Use --keep-data to preserve postgres/redis/audit data.${YSG_RESET}\n"
  else
    printf "${YSG_GREEN}         Data volumes will be preserved (--keep-data).${YSG_RESET}\n"
  fi
  printf "\n"
  printf "Type 'yes' to confirm uninstall: "
  CONFIRM=""
  IFS= read -r CONFIRM || true
  if [ "$CONFIRM" != "yes" ]; then
    _info "Uninstall cancelled."
    exit 0
  fi
fi

# ---------------------------------------------------------------------------
# Step 2: docker compose down
# ---------------------------------------------------------------------------
COMPOSE_FILE="${PROJECT_ROOT}/docker/docker-compose.yml"
if [ -f "$COMPOSE_FILE" ]; then
  _info "Stopping and removing containers and networks..."
  docker compose -f "$COMPOSE_FILE" down --remove-orphans 2>/dev/null || \
    _warn "docker compose down failed (containers may already be stopped)"
  _ok "Containers and networks removed."
else
  _warn "No docker-compose.yml found at ${COMPOSE_FILE} — skipping compose down"
fi

# ---------------------------------------------------------------------------
# Step 3: Remove data volumes (unless --keep-data)
# ---------------------------------------------------------------------------
DATA_VOLUMES=(
  yashigani_postgres_data
  yashigani_audit_data
  yashigani_redis_data
)

if [ "$KEEP_DATA" -eq 0 ]; then
  _info "Removing Yashigani data volumes..."
  # Remove data volumes explicitly
  for vol in "${DATA_VOLUMES[@]}"; do
    if docker volume inspect "$vol" >/dev/null 2>&1; then
      docker volume rm "$vol" && _ok "Removed volume: ${vol}" || \
        _warn "Could not remove volume: ${vol} (may be in use)"
    else
      _info "Volume not found (already gone): ${vol}"
    fi
  done

  # Remove any remaining yashigani_* volumes
  _info "Scanning for remaining yashigani_* volumes..."
  remaining="$(docker volume ls --filter "name=yashigani_" --format "{{.Name}}" 2>/dev/null || true)"
  if [ -n "$remaining" ]; then
    while IFS= read -r vol; do
      [ -z "$vol" ] && continue
      docker volume rm "$vol" && _ok "Removed volume: ${vol}" || \
        _warn "Could not remove volume: ${vol}"
    done <<< "$remaining"
  fi
else
  _info "Skipping data volume removal (--keep-data)."
fi

# ---------------------------------------------------------------------------
# Step 4: Remove docker/secrets/ directory
# ---------------------------------------------------------------------------
SECRETS_DIR="${PROJECT_ROOT}/docker/secrets"
if [ -d "$SECRETS_DIR" ]; then
  _info "Removing secrets directory: ${SECRETS_DIR}"
  rm -rf "$SECRETS_DIR"
  _ok "Secrets directory removed."
else
  _info "Secrets directory not found: ${SECRETS_DIR}"
fi

# ---------------------------------------------------------------------------
# Step 5: Remove .env (prompt unless --force)
# ---------------------------------------------------------------------------
ENV_FILE="${PROJECT_ROOT}/docker/.env"
if [ -f "$ENV_FILE" ]; then
  REMOVE_ENV=1
  if [ "$FORCE" -eq 0 ]; then
    printf "Remove %s? [y/N]: " "$ENV_FILE"
    CONFIRM_ENV=""
    IFS= read -r CONFIRM_ENV || true
    case "$CONFIRM_ENV" in
      [yY]|[yY][eE][sS]) REMOVE_ENV=1 ;;
      *) REMOVE_ENV=0 ;;
    esac
  fi

  if [ "$REMOVE_ENV" -eq 1 ]; then
    rm -f "$ENV_FILE"
    _ok ".env removed."
  else
    _info ".env preserved at ${ENV_FILE}"
  fi
else
  _info ".env not found — nothing to remove."
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf "\n"
if [ "$KEEP_DATA" -eq 1 ]; then
  PRESERVED_MSG="yes (postgres_data, audit_data, redis_data)"
else
  PRESERVED_MSG="no"
fi

printf "${YSG_GREEN}Yashigani uninstalled. Data volumes preserved: %s${YSG_RESET}\n" \
  "$PRESERVED_MSG"
