#!/usr/bin/env bash
# scripts/preflight.sh — Yashigani v0.6.0
# Pre-install requirement checks. Exits 1 if any REQUIRED check fails.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Parse flags
# ---------------------------------------------------------------------------
SKIP_DNS=0
SKIP_PORTS=0

for arg in "$@"; do
  case "$arg" in
    --skip-dns)   SKIP_DNS=1   ;;
    --skip-ports) SKIP_PORTS=1 ;;
    --help)
      cat <<'EOF'
Usage: scripts/preflight.sh [OPTIONS]

Pre-install requirement checks for Yashigani.

Options:
  --skip-dns    Skip DNS resolution check for YASHIGANI_TLS_DOMAIN
  --skip-ports  Skip port 80/443 availability checks
  --help        Print this help message

Environment variables read:
  TLS_MODE              If "acme", DNS check is performed unless --skip-dns
  YASHIGANI_TLS_DOMAIN  Domain to verify DNS for (required when TLS_MODE=acme)

Exit codes:
  0  All REQUIRED checks passed
  1  One or more REQUIRED checks failed
EOF
      exit 0
      ;;
    *) ;;
  esac
done

# ---------------------------------------------------------------------------
# Source platform detection
# ---------------------------------------------------------------------------
# shellcheck source=scripts/platform-detect.sh
source "${SCRIPT_DIR}/platform-detect.sh"

# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------
REQUIRED_FAILURES=0
declare -a RESULT_LINES=()

_pass() {
  local label="$1"
  local detail="${2:-}"
  RESULT_LINES+=("PASS|${label}|${detail}")
}

_fail() {
  local label="$1"
  local detail="${2:-}"
  RESULT_LINES+=("FAIL|${label}|${detail}")
  REQUIRED_FAILURES=$(( REQUIRED_FAILURES + 1 ))
}

_warn_check() {
  local label="$1"
  local detail="${2:-}"
  RESULT_LINES+=("WARN|${label}|${detail}")
}

# ---------------------------------------------------------------------------
# Check helpers
# ---------------------------------------------------------------------------

# 1. Shell version
_check_shell_version() {
  if [ -n "${BASH_VERSION:-}" ]; then
    local major
    major="${BASH_VERSION%%.*}"
    if [ "$major" -ge 4 ]; then
      _pass "Bash version" "bash ${BASH_VERSION}"
    else
      _fail "Bash version" "bash ${BASH_VERSION} — need >= 4"
    fi
  elif [ -n "${ZSH_VERSION:-}" ]; then
    local major
    major="${ZSH_VERSION%%.*}"
    if [ "$major" -ge 5 ]; then
      _pass "Shell version" "zsh ${ZSH_VERSION}"
    else
      _fail "Shell version" "zsh ${ZSH_VERSION} — need >= 5"
    fi
  else
    _fail "Shell version" "unknown shell — bash >= 4 or zsh >= 5 required"
  fi
}

# 2. curl
_check_curl() {
  if command -v curl >/dev/null 2>&1; then
    _pass "curl" "$(curl --version 2>/dev/null | head -1)"
  else
    _fail "curl" "not found — install curl"
  fi
}

# 3. Docker daemon
_check_docker_daemon() {
  if docker info >/dev/null 2>&1; then
    _pass "Docker daemon" "running"
  else
    _fail "Docker daemon" "not reachable — is Docker running?"
  fi
}

# 4. Docker Compose
_check_compose() {
  case "$YSG_COMPOSE" in
    plugin)
      local ver
      ver="$(docker compose version --short 2>/dev/null || echo "unknown")"
      _pass "Docker Compose" "plugin v${ver}"
      ;;
    standalone)
      local ver
      ver="$(docker-compose version --short 2>/dev/null || echo "unknown")"
      _pass "Docker Compose" "standalone v${ver}"
      ;;
    none)
      _fail "Docker Compose" "not found — install docker-compose-plugin"
      ;;
  esac
}

# 5. Ports 80 and 443
_check_port() {
  local port="$1"
  local in_use=0

  # Try ss first (most Linux)
  if command -v ss >/dev/null 2>&1; then
    if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
      in_use=1
    fi
  # Fall back to netstat
  elif command -v netstat >/dev/null 2>&1; then
    if netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
      in_use=1
    fi
  # Fall back to lsof
  elif command -v lsof >/dev/null 2>&1; then
    if lsof -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1; then
      in_use=1
    fi
  fi

  if [ "$in_use" -eq 0 ]; then
    _pass "Port ${port}" "free"
  else
    _fail "Port ${port}" "IN USE — stop the process using port ${port} first"
  fi
}

_check_ports() {
  if [ "$SKIP_PORTS" -eq 1 ]; then
    _pass "Port 80"  "skipped (--skip-ports)"
    _pass "Port 443" "skipped (--skip-ports)"
    return
  fi
  _check_port 80
  _check_port 443
}

# 6. Disk space
_check_disk() {
  local docker_root="/var/lib/docker"
  if docker info >/dev/null 2>&1; then
    docker_root="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || echo "/var/lib/docker")"
  fi
  # Use the mount point of docker root (or / on macOS)
  local mount_point="$docker_root"
  [ -d "$mount_point" ] || mount_point="/"

  local avail_gb
  avail_gb="$(df -BG "$mount_point" 2>/dev/null | awk 'NR==2 {gsub(/G/,"",$4); print $4}')"
  avail_gb="${avail_gb:-0}"

  if [ "$avail_gb" -ge 10 ]; then
    _pass "Disk space" "${avail_gb} GB available on ${mount_point}"
  else
    _fail "Disk space" "${avail_gb} GB available — need >= 10 GB on ${mount_point}"
  fi
}

# 7+8. RAM checks
_check_ram() {
  local ram_mb=0

  if [ "$YSG_OS" = "linux" ] && [ -r /proc/meminfo ]; then
    ram_mb="$(awk '/^MemTotal:/ { printf "%d", $2/1024 }' /proc/meminfo)"
  elif [ "$YSG_OS" = "macos" ]; then
    local ram_bytes
    ram_bytes="$(sysctl -n hw.memsize 2>/dev/null || echo 0)"
    ram_mb=$(( ram_bytes / 1024 / 1024 ))
  fi

  local ram_gb_display
  ram_gb_display="$(awk "BEGIN { printf \"%.1f\", ${ram_mb}/1024 }") GB"

  if [ "$ram_mb" -lt 512 ]; then
    _fail "RAM" "${ram_gb_display} — 512 MB absolute minimum not met"
  elif [ "$ram_mb" -lt 2048 ]; then
    _warn_check "RAM" "${ram_gb_display} (2 GB recommended)"
  else
    _pass "RAM" "${ram_gb_display}"
  fi

  if [ "$ram_mb" -lt 4096 ]; then
    _warn_check "RAM (Ollama)" "${ram_gb_display} (4 GB recommended for LLM inference)"
  else
    _pass "RAM (Ollama)" "${ram_gb_display} — sufficient for LLM inference"
  fi
}

# 9. /run/secrets writable
_check_secrets() {
  if [ -d /run/secrets ] && [ -w /run/secrets ]; then
    _pass "Docker secrets" "/run/secrets writable"
  elif docker info >/dev/null 2>&1; then
    # Docker daemon reachable — secrets mechanism available via swarm/compose
    _pass "Docker secrets" "Docker secrets mechanism available"
  else
    _fail "Docker secrets" "/run/secrets not writable and Docker not reachable"
  fi
}

# 10. DNS check (conditional on TLS_MODE=acme)
_check_dns() {
  local tls_mode="${TLS_MODE:-}"
  local domain="${YASHIGANI_TLS_DOMAIN:-}"

  if [ "$SKIP_DNS" -eq 1 ]; then
    _pass "DNS" "skipped (--skip-dns)"
    return
  fi

  if [ "$tls_mode" != "acme" ]; then
    _pass "DNS" "skipped (TLS_MODE is not 'acme')"
    return
  fi

  if [ -z "$domain" ]; then
    _fail "DNS" "TLS_MODE=acme but YASHIGANI_TLS_DOMAIN is not set"
    return
  fi

  local resolved=0
  if command -v dig >/dev/null 2>&1; then
    dig +short "$domain" 2>/dev/null | grep -qE '^[0-9]+\.' && resolved=1
  elif command -v nslookup >/dev/null 2>&1; then
    nslookup "$domain" >/dev/null 2>&1 && resolved=1
  elif command -v host >/dev/null 2>&1; then
    host "$domain" >/dev/null 2>&1 && resolved=1
  else
    _warn_check "DNS" "no dig/nslookup/host available — cannot verify ${domain}"
    return
  fi

  if [ "$resolved" -eq 1 ]; then
    _pass "DNS" "${domain} resolves"
  else
    _fail "DNS" "${domain} does not resolve — check your DNS records"
  fi
}

# ---------------------------------------------------------------------------
# Run all checks
# ---------------------------------------------------------------------------
_check_shell_version
_check_curl
_check_docker_daemon
_check_compose
_check_ports
_check_disk
_check_ram
_check_secrets
_check_dns

# ---------------------------------------------------------------------------
# Print summary table
# ---------------------------------------------------------------------------
printf "\n"
printf "%-4s %-26s %s\n" "   " "Check" "Result"
printf "%s\n" "------------------------------------------------------------"

for line in "${RESULT_LINES[@]}"; do
  IFS='|' read -r status label detail <<< "$line"
  case "$status" in
    PASS)
      icon="${YSG_GREEN}✓${YSG_RESET}"
      color="$YSG_RESET"
      ;;
    FAIL)
      icon="${YSG_RED}✗${YSG_RESET}"
      color="$YSG_RED"
      ;;
    WARN)
      icon="${YSG_YELLOW}⚠${YSG_RESET}"
      color="$YSG_YELLOW"
      ;;
    *)
      icon=" "
      color="$YSG_RESET"
      ;;
  esac
  printf " %b %-26s %b%s%b\n" "$icon" "$label" "$color" "$detail" "$YSG_RESET"
done

printf "\n"

# ---------------------------------------------------------------------------
# Exit
# ---------------------------------------------------------------------------
if [ "$REQUIRED_FAILURES" -gt 0 ]; then
  printf "${YSG_RED}Preflight failed: %d required check(s) did not pass.${YSG_RESET}\n" \
    "$REQUIRED_FAILURES" >&2
  exit 1
fi

printf "${YSG_GREEN}All required checks passed.${YSG_RESET}\n"
exit 0
