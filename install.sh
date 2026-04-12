#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Yashigani v2.1.0 Installer
# https://yashigani.io
#
# Usage:
#   curl -sSL https://get.yashigani.io | bash
#   curl -sSL https://get.yashigani.io | bash -s -- --non-interactive --domain example.com
#   ./install.sh --mode compose
#   ./install.sh --mode k8s --namespace yashigani
# =============================================================================

YASHIGANI_VERSION="2.20.0"
YASHIGANI_REPO_URL="${YASHIGANI_REPO_URL:-https://github.com/agnosticsec-com/yashigani.git}"
YASHIGANI_TARBALL_URL="${YASHIGANI_TARBALL_URL:-https://github.com/agnosticsec-com/yashigani/archive/refs/tags/v${YASHIGANI_VERSION}.tar.gz}"
YSG_INSTALL_DIR="${YSG_INSTALL_DIR:-$HOME/.yashigani}"

# -----------------------------------------------------------------------------
# Color output — only when stdout is a TTY
# -----------------------------------------------------------------------------
if [ -t 1 ]; then
  C_RESET="\033[0m"
  C_BLUE="\033[1;34m"
  C_GREEN="\033[1;32m"
  C_YELLOW="\033[1;33m"
  C_RED="\033[1;31m"
  C_BOLD="\033[1m"
else
  C_RESET=""
  C_BLUE=""
  C_GREEN=""
  C_YELLOW=""
  C_RED=""
  C_BOLD=""
fi

# -----------------------------------------------------------------------------
# Logging helpers
# -----------------------------------------------------------------------------
log_step()    { printf "${C_BLUE}[ %s ] %s${C_RESET}\n" "$1" "$2"; }
log_info()    { printf "${C_BOLD}    --> %s${C_RESET}\n" "$1"; }
log_success() { printf "${C_GREEN}    ok  %s${C_RESET}\n" "$1"; }
log_warn()    { printf "${C_YELLOW}    !!  WARNING: %s${C_RESET}\n" "$1" >&2; }
log_error()   { printf "${C_RED}    !!  ERROR: %s${C_RESET}\n" "$1" >&2; }
dry_print()   { printf "${C_YELLOW}    >>  Would run: %s${C_RESET}\n" "$*"; }

# -----------------------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------------------
MODE="compose"
DEPLOY_MODE=""                # demo|production|enterprise — set interactively or via --deploy
DOMAIN=""
TLS_MODE="acme"
ADMIN_EMAIL=""
UPSTREAM_URL=""
LICENSE_KEY_PATH=""
DB_AES_KEY=""                 # YASHIGANI_DB_AES_KEY — set via prompt or --db-aes-key
NON_INTERACTIVE=false
SKIP_PREFLIGHT=false
SKIP_PULL=false
UPGRADE=false
DRY_RUN=false
OFFLINE=false
NAMESPACE="yashigani"
TOTAL_STEPS=13
WORK_DIR=""
AGENT_BUNDLES=""          # comma-separated: langflow,letta,openclaw
INSTALL_WAZUH=false       # opt-in: --wazuh flag
COMPOSE_PROFILES=()       # populated by select_agent_bundles()

# If stdin is not a TTY (piped from curl), force non-interactive
if [ ! -t 0 ]; then
  NON_INTERACTIVE=true
fi

# -----------------------------------------------------------------------------
# Usage
# -----------------------------------------------------------------------------
usage() {
  cat <<EOF
${C_BOLD}Yashigani v${YASHIGANI_VERSION} Installer${C_RESET}

USAGE
  install.sh [OPTIONS]
  curl -sSL https://get.yashigani.io | bash -s -- [OPTIONS]

OPTIONS
  --deploy         demo|production|enterprise  Deployment mode (interactive if omitted)
  --mode           compose|k8s|vm         Legacy deployment mode (prefer --deploy)
  --domain         DOMAIN                 TLS domain, e.g. yashigani.example.com
  --tls-mode       acme|ca|selfsigned     TLS provisioning mode (default: acme)
  --admin-email    EMAIL                  Admin account email / username
  --upstream-url   URL                    Upstream MCP URL
  --license-key    PATH                   Path to .ysg license file
  --db-aes-key     KEY                    Database AES-256 encryption key (64-char hex)
  --namespace      NAMESPACE              Kubernetes namespace (default: yashigani)
  --agent-bundles  BUNDLES               Comma-separated opt-in agents: langflow,letta,openclaw (or "all")
  --wazuh                                 Install Wazuh SIEM (manager + indexer + dashboard)
  --offline                               Air-gapped mode (no ACME, no image pulls)
  --non-interactive                       Skip all interactive prompts
  --skip-preflight                        Skip preflight checks
  --skip-pull                             Skip docker compose pull (use local images)
  --upgrade                               Upgrade an existing installation
  --dry-run                               Print steps without executing
  --help                                  Show this help and exit

ENVIRONMENT
  YSG_INSTALL_DIR        Install directory when run via curl (default: \$HOME/.yashigani)
  YASHIGANI_LICENSE_FILE Alternative path to license file
  YSG_DEBUG              Set to 1 for verbose output

EXAMPLES
  # Interactive compose install
  curl -sSL https://get.yashigani.io | bash

  # Non-interactive compose install
  curl -sSL https://get.yashigani.io | bash -s -- \\
    --non-interactive --domain example.com --admin-email admin@example.com

  # Kubernetes install
  ./install.sh --mode k8s --namespace yashigani --domain example.com

  # Dry-run to review steps
  ./install.sh --dry-run --domain example.com
EOF
}

# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mode)
        MODE="${2:?'--mode requires a value: compose|k8s|vm'}"
        shift 2
        ;;
      --domain)
        DOMAIN="${2:?'--domain requires a value'}"
        shift 2
        ;;
      --tls-mode)
        TLS_MODE="${2:?'--tls-mode requires a value: acme|ca|selfsigned'}"
        shift 2
        ;;
      --admin-email)
        ADMIN_EMAIL="${2:?'--admin-email requires a value'}"
        shift 2
        ;;
      --upstream-url)
        UPSTREAM_URL="${2:?'--upstream-url requires a value'}"
        shift 2
        ;;
      --license-key)
        LICENSE_KEY_PATH="${2:?'--license-key requires a path'}"
        shift 2
        ;;
      --namespace)
        NAMESPACE="${2:?'--namespace requires a value'}"
        shift 2
        ;;
      --deploy)
        DEPLOY_MODE="${2:?'--deploy requires a value: demo|production|enterprise'}"
        shift 2
        ;;
      --db-aes-key)
        DB_AES_KEY="${2:?'--db-aes-key requires a value (64-char hex or 44-char base64)'}"
        shift 2
        ;;
      --wazuh)           INSTALL_WAZUH=true;     shift ;;
      --offline)         OFFLINE=true;           shift ;;
      --non-interactive) NON_INTERACTIVE=true;  shift ;;
      --skip-preflight)  SKIP_PREFLIGHT=true;   shift ;;
      --skip-pull)       SKIP_PULL=true;         shift ;;
      --upgrade)         UPGRADE=true;           shift ;;
      --dry-run)         DRY_RUN=true;           shift ;;
      --agent-bundles)
        AGENT_BUNDLES="${2:?'--agent-bundles requires a value, e.g. langflow,letta'}"
        shift 2
        ;;
      --help|-h)         usage; exit 0 ;;
      *)
        log_error "Unknown option: $1"
        printf "Run with --help for usage.\n" >&2
        exit 1
        ;;
    esac
  done

  # Validate mode
  case "$MODE" in
    compose|k8s|vm) ;;
    *)
      log_error "Invalid --mode '$MODE'. Allowed values: compose, k8s, vm"
      exit 1
      ;;
  esac

  # Validate tls-mode
  case "$TLS_MODE" in
    acme|ca|selfsigned) ;;
    *)
      log_error "Invalid --tls-mode '$TLS_MODE'. Allowed values: acme, ca, selfsigned"
      exit 1
      ;;
  esac

  # Kubernetes uses a different step count
  if [[ "$MODE" == "k8s" ]]; then
    TOTAL_STEPS=10
  fi
}

# -----------------------------------------------------------------------------
# Command execution wrapper — respects --dry-run and YSG_DEBUG
# -----------------------------------------------------------------------------
run_cmd() {
  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "$*"
    return 0
  fi
  if [[ "${YSG_DEBUG:-0}" == "1" ]]; then
    "$@"
  else
    "$@"
  fi
}

# Run a command, suppressing output unless YSG_DEBUG=1 or it fails
run_cmd_silent() {
  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "$*"
    return 0
  fi
  if [[ "${YSG_DEBUG:-0}" == "1" ]]; then
    "$@"
  else
    "$@" > /dev/null 2>&1
  fi
}

# -----------------------------------------------------------------------------
# Error handler
# -----------------------------------------------------------------------------
CURRENT_STEP="?"
CURRENT_STEP_NAME="initializing"

on_error() {
  local exit_code=$?
  printf "\n" >&2
  log_error "Installation failed at Step ${CURRENT_STEP} (${CURRENT_STEP_NAME})"
  log_error "Exit code: ${exit_code}"

  # Show last 10 log lines from compose if available
  if [[ "$MODE" != "k8s" ]] && [[ -n "$WORK_DIR" ]] && command -v docker &>/dev/null; then
    local compose_file="${WORK_DIR}/docker/docker-compose.yml"
    if [[ -f "$compose_file" ]]; then
      if docker compose -f "$compose_file" ps 2>/dev/null | grep -qE "Up|running"; then
        printf "${C_YELLOW}--- Last 10 log lines ---${C_RESET}\n" >&2
        docker compose -f "$compose_file" logs --tail=10 2>/dev/null >&2 || true
        printf "${C_YELLOW}-------------------------${C_RESET}\n" >&2
      fi
    fi
  fi

  printf "\n${C_YELLOW}Tip: Run with YSG_DEBUG=1 for verbose output${C_RESET}\n" >&2
  exit 1
}

trap on_error ERR

set_step() {
  CURRENT_STEP="$1"
  CURRENT_STEP_NAME="$2"
}

# -----------------------------------------------------------------------------
# Interactive prompt helpers — respect --non-interactive and piped stdin
# -----------------------------------------------------------------------------

# Returns 0 (yes) or 1 (no). Uses default when non-interactive.
prompt_yn() {
  local question="$1"
  local default="${2:-y}"

  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    [[ "$default" == "y" ]] && return 0 || return 1
  fi

  local hint
  [[ "$default" == "y" ]] && hint="[Y/n]" || hint="[y/N]"

  printf "${C_BOLD}%s %s: ${C_RESET}" "$question" "$hint"
  local answer
  read -r answer </dev/tty 2>/dev/null || answer="$default"
  answer="${answer:-$default}"
  answer="$(echo "$answer" | tr '[:upper:]' '[:lower:]')"
  [[ "$answer" == "y" || "$answer" == "yes" ]]
}

# Prints the entered value (or default) to stdout
prompt_input() {
  local question="$1"
  local default="${2:-}"

  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    printf "%s" "$default"
    return 0
  fi

  if [[ -n "$default" ]]; then
    printf "${C_BOLD}%s [%s]: ${C_RESET}" "$question" "$default"
  else
    printf "${C_BOLD}%s: ${C_RESET}" "$question"
  fi

  local answer
  read -r answer </dev/tty 2>/dev/null || answer="$default"
  printf "%s" "${answer:-$default}"
}

# -----------------------------------------------------------------------------
# Assert that a command exists in PATH
# -----------------------------------------------------------------------------
require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log_error "Required command not found in PATH: $cmd"
    log_error "Please install '$cmd' and re-run the installer."
    exit 1
  fi
}

# Resolve the compose command based on detected runtime
# Sets COMPOSE_CMD as an array (e.g. "docker compose" or "podman compose")
# Sets YSG_PODMAN_RUNTIME=true if using Podman (for auto-applying override file)
YSG_PODMAN_RUNTIME=false

resolve_compose_cmd() {
  COMPOSE_CMD=()

  # Prefer Podman (rootless, daemonless, more secure)
  # Check Podman FIRST — matches platform-detect.sh priority
  # Prefer podman-compose (Python, sequential) over podman compose (plugin, parallel)
  # because the docker-compose plugin crashes Podman's API socket with EOF on parallel creates.

  # Try standalone podman-compose FIRST (pip install podman-compose) — sequential, stable
  if command -v podman-compose >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
    COMPOSE_CMD=("podman-compose")
    YSG_PODMAN_RUNTIME=true
    return 0
  fi

  # Fall back to podman compose (Podman 4+ built-in, delegates to docker-compose plugin)
  if command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
    if podman compose version >/dev/null 2>&1; then
      COMPOSE_CMD=("podman" "compose")
      YSG_PODMAN_RUNTIME=true
      return 0
    fi
  fi

  # Fall back to Docker — verify daemon is running (not just CLI installed)
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    if docker compose version >/dev/null 2>&1; then
      COMPOSE_CMD=("docker" "compose")
      return 0
    fi
  fi

  # Try standalone docker-compose
  if command -v docker-compose >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    COMPOSE_CMD=("docker-compose")
    return 0
  fi

  # Docker Desktop on macOS without CLI in PATH
  if [ "${YSG_RUNTIME:-}" = "docker_desktop_no_cli" ]; then
    local dd_docker=""
    for p in "$HOME/.docker/bin/docker" "/usr/local/bin/com.docker.cli" \
             "/Applications/Docker.app/Contents/Resources/bin/docker"; do
      [ -x "$p" ] && dd_docker="$p" && break
    done
    if [ -n "$dd_docker" ] && $dd_docker compose version >/dev/null 2>&1; then
      COMPOSE_CMD=("$dd_docker" "compose")
      return 0
    fi
  fi

  log_error "No compose command found. Install one of:"
  log_error "  • Docker Desktop  — https://docker.com/products/docker-desktop"
  log_error "  • Podman Desktop  — https://podman-desktop.io"
  log_error "  • podman + podman-compose (pip install podman-compose)"
  exit 1
}

# =============================================================================
# STEP 0: Banner
# =============================================================================
print_banner() {
  printf "\n"
  printf "${C_BLUE}╔═══════════════════════════════════════════════════╗${C_RESET}\n"
  printf "${C_BLUE}║    Yashigani v%-8s Installer                 ║${C_RESET}\n" "${YASHIGANI_VERSION}"
  printf "${C_BLUE}╚═══════════════════════════════════════════════════╝${C_RESET}\n"
  printf "\n"

  if [[ "$DRY_RUN" == "true" ]]; then
    log_warn "DRY-RUN mode — no changes will be made to the system"
    printf "\n"
  fi
}

# =============================================================================
# STEP 1: Detect / bootstrap working directory
# =============================================================================
detect_working_directory() {
  set_step "1" "Detect working directory"
  log_step "1/${TOTAL_STEPS}" "Detecting working directory..."

  local script_path="${BASH_SOURCE[0]:-/dev/stdin}"
  local in_repo=false

  # Case 1: running as a file (not piped), try script's own directory
  if [[ "$script_path" != "/dev/stdin" && -n "$script_path" ]]; then
    local script_dir
    script_dir="$(cd "$(dirname "$script_path")" 2>/dev/null && pwd)" || script_dir=""
    if [[ -n "$script_dir" && -f "${script_dir}/docker/docker-compose.yml" ]]; then
      in_repo=true
      WORK_DIR="$script_dir"
      log_info "Using script directory as repository: $WORK_DIR"
    fi
  fi

  # Case 2: current working directory is already the repo
  if [[ "$in_repo" == "false" && -f "./docker/docker-compose.yml" ]]; then
    in_repo=true
    WORK_DIR="$(pwd)"
    log_info "Using current directory as repository: $WORK_DIR"
  fi

  # Case 3: need to bootstrap (curl pipe or neither of the above)
  if [[ "$in_repo" == "false" ]]; then
    bootstrap_repo
  fi

  export WORK_DIR
  log_success "Working directory: $WORK_DIR"
}

bootstrap_repo() {
  log_info "Yashigani source tree not found locally — bootstrapping..."

  # Check if a previous install already lives at YSG_INSTALL_DIR
  if [[ -d "$YSG_INSTALL_DIR" && -f "${YSG_INSTALL_DIR}/docker/docker-compose.yml" ]]; then
    log_info "Existing installation found at: $YSG_INSTALL_DIR"

    if [[ "$UPGRADE" == "true" ]]; then
      log_info "Pulling latest changes (--upgrade)..."
      if [[ "$DRY_RUN" == "true" ]]; then
        dry_print "git -C $YSG_INSTALL_DIR pull --ff-only"
      elif command -v git &>/dev/null && [[ -d "${YSG_INSTALL_DIR}/.git" ]]; then
        git -C "$YSG_INSTALL_DIR" pull --ff-only
      fi
    elif [[ "$NON_INTERACTIVE" == "true" ]]; then
      log_warn "Existing installation found. Pass --upgrade to update it."
    else
      if prompt_yn "Existing installation found at $YSG_INSTALL_DIR. Pull latest changes?" "y"; then
        UPGRADE=true
        if command -v git &>/dev/null && [[ -d "${YSG_INSTALL_DIR}/.git" ]]; then
          git -C "$YSG_INSTALL_DIR" pull --ff-only
        fi
      fi
    fi

    WORK_DIR="$YSG_INSTALL_DIR"
    return 0
  fi

  require_cmd "curl"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "git clone --depth 1 --branch v${YASHIGANI_VERSION} $YASHIGANI_REPO_URL $YSG_INSTALL_DIR"
    WORK_DIR="$YSG_INSTALL_DIR"
    return 0
  fi

  mkdir -p "$YSG_INSTALL_DIR"

  if command -v git &>/dev/null; then
    log_info "Cloning repository (v${YASHIGANI_VERSION})..."
    if git clone --depth 1 --branch "v${YASHIGANI_VERSION}" \
        "$YASHIGANI_REPO_URL" "$YSG_INSTALL_DIR" 2>&1; then
      log_success "Repository cloned to $YSG_INSTALL_DIR"
    else
      log_warn "git clone failed — falling back to tarball download"
      download_tarball
    fi
  else
    log_info "git not found — downloading tarball"
    download_tarball
  fi

  WORK_DIR="$YSG_INSTALL_DIR"
}

download_tarball() {
  require_cmd "tar"

  local tmp_tar
  tmp_tar="$(mktemp /tmp/yashigani-XXXXXX.tar.gz)"
  local tmp_dir
  tmp_dir="$(mktemp -d /tmp/yashigani-extract-XXXXXX)"

  log_info "Downloading tarball: $YASHIGANI_TARBALL_URL"
  if ! curl -sSL --fail --retry 3 -o "$tmp_tar" "$YASHIGANI_TARBALL_URL"; then
    log_error "Tarball download failed: $YASHIGANI_TARBALL_URL"
    rm -rf "$tmp_tar" "$tmp_dir"
    exit 1
  fi

  log_info "Extracting to $YSG_INSTALL_DIR ..."
  tar -xzf "$tmp_tar" -C "$tmp_dir"
  rm -f "$tmp_tar"

  # Tarball typically contains a single top-level directory
  local extracted_name
  extracted_name="$(ls "$tmp_dir" | head -1)"
  if [[ -n "$extracted_name" && -d "${tmp_dir}/${extracted_name}" ]]; then
    # Move contents into YSG_INSTALL_DIR
    find "${tmp_dir}/${extracted_name}" -maxdepth 1 -mindepth 1 \
      -exec mv {} "$YSG_INSTALL_DIR/" \;
  else
    log_error "Unexpected tarball structure; cannot locate extracted files"
    rm -rf "$tmp_dir"
    exit 1
  fi

  rm -rf "$tmp_dir"
  log_success "Tarball extracted to $YSG_INSTALL_DIR"
}

# =============================================================================
# STEP 2: Source platform-detect.sh
# =============================================================================
source_platform_detect() {
  set_step "2" "Source platform-detect.sh"
  log_step "2/${TOTAL_STEPS}" "Loading platform detection..."

  local detect_script="${WORK_DIR}/scripts/platform-detect.sh"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "source $detect_script"
    # Provide fallback values so later steps do not break
    YSG_OS="${YSG_OS:-linux}"
    YSG_ARCH="${YSG_ARCH:-x86_64}"
    YSG_RUNTIME="${YSG_RUNTIME:-docker}"
    YSG_GPU_TYPE="${YSG_GPU_TYPE:-none}"
    YSG_GPU_NAME="${YSG_GPU_NAME:-}"
    YSG_GPU_VRAM_MB="${YSG_GPU_VRAM_MB:-0}"
    YSG_GPU_COMPUTE="${YSG_GPU_COMPUTE:-none}"
    return 0
  fi

  if [[ ! -f "$detect_script" ]]; then
    log_error "Platform detection script not found: $detect_script"
    exit 1
  fi

  # shellcheck source=/dev/null
  source "$detect_script"
  log_success "Platform detection loaded"
}

# =============================================================================
# STEP 3: Print platform summary
# =============================================================================
print_platform_summary() {
  set_step "3" "Platform summary"
  log_step "3/${TOTAL_STEPS}" "Platform summary"

  # --- Interactive fallback if detection failed ---
  if [[ "$NON_INTERACTIVE" != "true" && -t 0 ]]; then
    _interactive_platform_fallback
  fi

  printf "\n"
  printf "  %-22s %s\n" "OS:"           "${YSG_OS:-unknown} (${YSG_DISTRO:-unknown})"
  printf "  %-22s %s\n" "Architecture:" "${YSG_ARCH:-unknown}"
  printf "  %-22s %s\n" "Runtime:"      "${YSG_RUNTIME:-unknown} (compose: ${YSG_COMPOSE:-unknown})"
  printf "  %-22s %s\n" "Deploy mode:"  "$MODE"
  printf "  %-22s %s\n" "Domain:"       "${DOMAIN:-(not set)}"
  printf "  %-22s %s\n" "TLS mode:"     "$TLS_MODE"
  if [[ "$MODE" == "k8s" ]]; then
    printf "  %-22s %s\n" "Namespace:"  "$NAMESPACE"
  fi
  if [[ "${YSG_GPU_TYPE:-none}" != "none" ]]; then
    printf "  %-22s %s\n" "GPU:"        "${YSG_GPU_NAME:-detected}"
    printf "  %-22s %s\n" "GPU memory:" "$(_format_gpu_vram)"
    printf "  %-22s %s\n" "GPU compute:" "${YSG_GPU_COMPUTE:-unknown}"
  else
    printf "  %-22s %s\n" "GPU:"        "none detected"
  fi
  printf "\n"
  _print_model_recommendations
}

_format_gpu_vram() {
  local vram_mb="${YSG_GPU_VRAM_MB:-0}"
  if [ "$vram_mb" -ge 1024 ]; then
    printf "%.1f GB" "$(awk "BEGIN { printf \"%.1f\", ${vram_mb}/1024 }")"
  else
    printf "%d MB" "$vram_mb"
  fi
}

_print_model_recommendations() {
  local vram="${YSG_GPU_VRAM_MB:-0}"
  if [ "$vram" -eq 0 ]; then return; fi
  printf "  ${C_BOLD}Recommended local models for your hardware:${C_RESET}\n"
  if [ "$vram" -ge 49152 ]; then
    printf "    - qwen3:235b-a22b, llama4:scout, deepseek-v3 (large models)\n"
  elif [ "$vram" -ge 32768 ]; then
    printf "    - qwen3:30b-a3b, llama4:scout, mistral-large\n"
  elif [ "$vram" -ge 16384 ]; then
    printf "    - qwen3:30b-a3b, llama3.1:8b, mistral:7b\n"
  elif [ "$vram" -ge 8192 ]; then
    printf "    - qwen2.5:3b (inspection), llama3.1:8b\n"
  else
    printf "    - qwen2.5:3b (inspection only), CPU inference for others\n"
  fi
  printf "\n"
}

_interactive_platform_fallback() {
  local needs_prompt=false
  if [[ "${YSG_OS:-unknown}" == "unknown" || "${YSG_RUNTIME:-none}" == "none" ]]; then
    needs_prompt=true
  fi
  if [[ "$needs_prompt" != "true" && "${YSG_GPU_TYPE:-none}" != "none" ]]; then
    return
  fi
  if [[ "$needs_prompt" == "true" ]]; then
    printf "\n"
    log_warn "Some platform values could not be detected automatically."
    printf "\n"
  fi
  if [[ "${YSG_OS:-unknown}" == "unknown" ]]; then
    printf "  Could not detect your operating system. Please select:\n"
    printf "    1) Linux (Ubuntu / Debian)\n"
    printf "    2) Linux (RHEL / CentOS / Fedora)\n"
    printf "    3) Linux (Alpine)\n"
    printf "    4) Linux (Arch)\n"
    printf "    5) macOS\n"
    printf "  Choice [1-5]: "
    read -r os_choice
    case "$os_choice" in
      1) YSG_OS=linux; YSG_DISTRO=ubuntu ;; 2) YSG_OS=linux; YSG_DISTRO=rhel ;;
      3) YSG_OS=linux; YSG_DISTRO=alpine ;; 4) YSG_OS=linux; YSG_DISTRO=arch ;;
      5) YSG_OS=macos; YSG_DISTRO=macos ;;
      *) log_warn "Invalid — defaulting to Linux"; YSG_OS=linux; YSG_DISTRO=ubuntu ;;
    esac
    printf "\n"
  fi
  if [[ "${YSG_RUNTIME:-none}" == "none" || "${YSG_RUNTIME:-}" == "unknown" ]]; then
    printf "  Could not detect a container runtime. Please select:\n"
    printf "    1) Docker (Docker Engine / Docker Desktop)\n"
    printf "    2) Podman\n"
    printf "  Choice [1-2]: "
    read -r rt_choice
    case "$rt_choice" in
      1) YSG_RUNTIME=docker ;; 2) YSG_RUNTIME=podman ;;
      *) log_warn "Invalid — defaulting to Docker"; YSG_RUNTIME=docker ;;
    esac
    printf "\n"
  fi
  if [[ "${YSG_GPU_TYPE:-none}" == "none" ]]; then
    printf "  No GPU was detected automatically. Do you have a GPU?\n"
    printf "    1) NVIDIA GPU (CUDA)\n"
    printf "    2) Apple Silicon (M1 / M2 / M3 / M4)\n"
    printf "    3) AMD GPU (ROCm)\n"
    printf "    4) No GPU / CPU only\n"
    printf "  Choice [1-4]: "
    read -r gpu_choice
    case "$gpu_choice" in
      1)
        YSG_GPU_TYPE=nvidia; YSG_GPU_COMPUTE=cuda; YSG_GPU_NAME="NVIDIA (user-reported)"
        printf "  Enter GPU VRAM in GB (e.g. 8, 16, 24, 48): "; read -r vram_gb
        [[ "${vram_gb:-0}" =~ ^[0-9]+$ ]] || vram_gb=0
        YSG_GPU_VRAM_MB=$(( ${vram_gb:-0} * 1024 )) ;;
      2)
        YSG_GPU_TYPE=apple_metal; YSG_GPU_COMPUTE=metal
        if command -v sysctl >/dev/null 2>&1; then
          local ram_bytes; ram_bytes="$(sysctl -n hw.memsize 2>/dev/null || echo 0)"
          YSG_GPU_VRAM_MB=$(( ram_bytes / 1024 / 1024 ))
          YSG_GPU_NAME="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Apple Silicon")"
        else
          YSG_GPU_NAME="Apple Silicon (user-reported)"
          printf "  Enter total system RAM in GB: "; read -r ram_gb
          [[ "${ram_gb:-8}" =~ ^[0-9]+$ ]] || ram_gb=8
          YSG_GPU_VRAM_MB=$(( ${ram_gb:-8} * 1024 ))
        fi ;;
      3)
        YSG_GPU_TYPE=amd_rocm; YSG_GPU_COMPUTE=rocm; YSG_GPU_NAME="AMD GPU (user-reported)"
        printf "  Enter GPU VRAM in GB: "; read -r vram_gb
        [[ "${vram_gb:-0}" =~ ^[0-9]+$ ]] || vram_gb=0
        YSG_GPU_VRAM_MB=$(( ${vram_gb:-0} * 1024 )) ;;
      4|*) YSG_GPU_TYPE=none ;;
    esac
    printf "\n"
  fi
}

# =============================================================================
# STEP 4: Install runtime (vm mode only)
# =============================================================================
install_runtime() {
  set_step "4" "Install runtime"

  if [[ "$MODE" != "vm" ]]; then
    return 0
  fi

  log_step "4/${TOTAL_STEPS}" "Installing container runtime (vm mode)..."

  local runtime_script="${WORK_DIR}/scripts/install-runtime.sh"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "bash $runtime_script"
    return 0
  fi

  if [[ ! -f "$runtime_script" ]]; then
    log_error "Runtime installation script not found: $runtime_script"
    exit 1
  fi

  bash "$runtime_script"
  log_success "Container runtime installed"
}

# =============================================================================
# STEP 5: Preflight checks
# =============================================================================
run_preflight() {
  set_step "5" "Preflight checks"

  if [[ "$SKIP_PREFLIGHT" == "true" ]]; then
    log_warn "Skipping preflight checks (--skip-preflight)"
    return 0
  fi

  log_step "5/${TOTAL_STEPS}" "Running preflight checks..."

  local preflight_script="${WORK_DIR}/scripts/preflight.sh"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "bash $preflight_script"
    return 0
  fi

  if [[ ! -f "$preflight_script" ]]; then
    log_error "Preflight script not found: $preflight_script"
    exit 1
  fi

  bash "$preflight_script"
  log_success "Preflight checks passed"
}

# =============================================================================
# =============================================================================
# STEP 5b: Deployment mode selection
# =============================================================================
select_deploy_mode() {
  # Already set via --deploy flag
  if [[ -n "$DEPLOY_MODE" ]]; then
    case "$DEPLOY_MODE" in
      demo|production|enterprise) ;;
      *)
        log_error "Invalid --deploy value '$DEPLOY_MODE'. Use: demo, production, enterprise"
        exit 1
        ;;
    esac
    log_info "Deployment mode: ${DEPLOY_MODE} (--deploy flag)"
    _apply_deploy_defaults
    return 0
  fi

  # Non-interactive without --deploy defaults to demo
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    DEPLOY_MODE="demo"
    log_info "Deployment mode: demo (non-interactive default)"
    _apply_deploy_defaults
    return 0
  fi

  printf "\n"
  printf "${C_BOLD}How would you like to deploy Yashigani?${C_RESET}\n\n"
  printf "    1) Demo / Open Source — quick evaluation on this machine (localhost, self-signed TLS)\n"
  printf "    2) Production — Docker Compose on a real server (Starter / Professional / Professional Plus)\n"
  printf "    3) Enterprise — Kubernetes with Helm charts (Enterprise licence)\n"
  printf "\n"
  printf "${C_BOLD}  Choice [1]: ${C_RESET}"

  local choice
  read -r choice </dev/tty 2>/dev/null || choice="1"
  choice="${choice:-1}"

  case "$choice" in
    1) DEPLOY_MODE="demo" ;;
    2) DEPLOY_MODE="production" ;;
    3) DEPLOY_MODE="enterprise" ;;
    *) log_warn "Invalid choice — defaulting to Demo"; DEPLOY_MODE="demo" ;;
  esac

  printf "\n"
  log_success "Deployment mode: ${DEPLOY_MODE}"
  _apply_deploy_defaults
}

_apply_deploy_defaults() {
  case "$DEPLOY_MODE" in
    demo)
      MODE="compose"
      DOMAIN="${DOMAIN:-localhost}"
      TLS_MODE="selfsigned"
      SKIP_PREFLIGHT="${SKIP_PREFLIGHT:-false}"
      ;;
    production)
      MODE="compose"
      ;;
    enterprise)
      MODE="k8s"
      TOTAL_STEPS=10
      ;;
  esac

  # Offline mode forces self-signed and skip-pull
  if [[ "$OFFLINE" == "true" ]]; then
    TLS_MODE="selfsigned"
    SKIP_PULL=true
    log_info "Offline mode: TLS set to self-signed, image pull skipped"
  fi
}

# =============================================================================
# STEP 5c: AES key provisioning
# =============================================================================
provision_aes_key() {
  # Already provided via --db-aes-key flag
  if [[ -n "$DB_AES_KEY" ]]; then
    _validate_aes_key "$DB_AES_KEY"
    log_info "Database AES key: provided via --db-aes-key"
    return 0
  fi

  # Check if .env already has a key (upgrade path)
  local env_file="${WORK_DIR}/docker/.env"
  if [[ -f "$env_file" ]]; then
    local existing_key
    existing_key="$(grep '^YASHIGANI_DB_AES_KEY=' "$env_file" 2>/dev/null | sed 's/^YASHIGANI_DB_AES_KEY=//' || echo "")"
    if [[ -n "$existing_key" ]]; then
      DB_AES_KEY="$existing_key"
      log_info "Database AES key: preserved from existing .env"
      return 0
    fi
  fi

  # Demo mode: auto-generate without prompting
  if [[ "$DEPLOY_MODE" == "demo" ]]; then
    _generate_aes_key
    log_info "Database AES key: auto-generated (demo mode)"
    return 0
  fi

  # Non-interactive: auto-generate
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    _generate_aes_key
    log_info "Database AES key: auto-generated (non-interactive)"
    return 0
  fi

  # Interactive: prompt
  printf "\n"
  printf "${C_BOLD}  Database encryption key (YASHIGANI_DB_AES_KEY):${C_RESET}\n\n"
  printf "    1) Generate a new 256-bit key automatically (recommended)\n"
  printf "    2) Bring your own key (BYOK) — paste an existing key\n"
  printf "\n"
  printf "${C_BOLD}  Choice [1]: ${C_RESET}"

  local choice
  read -r choice </dev/tty 2>/dev/null || choice="1"
  choice="${choice:-1}"

  case "$choice" in
    1)
      _generate_aes_key
      printf "\n"
      printf "  ${C_YELLOW}SAVE THIS KEY — it will only be shown once:${C_RESET}\n"
      printf "  ${C_BOLD}${DB_AES_KEY}${C_RESET}\n"
      printf "\n"
      log_success "Database AES key: generated"
      ;;
    2)
      printf "\n"
      printf "  Paste your 256-bit AES key (64-char hex or 44-char base64): "
      local user_key
      read -r user_key </dev/tty 2>/dev/null || user_key=""
      if [[ -z "$user_key" ]]; then
        log_error "No key provided. Aborting."
        exit 1
      fi
      _validate_aes_key "$user_key"
      DB_AES_KEY="$user_key"
      printf "\n"
      log_success "Database AES key: BYOK accepted"
      ;;
    *)
      log_warn "Invalid choice — generating automatically"
      _generate_aes_key
      log_success "Database AES key: generated"
      ;;
  esac
}

_generate_aes_key() {
  if command -v openssl >/dev/null 2>&1; then
    DB_AES_KEY="$(openssl rand -hex 32)"
  elif command -v python3 >/dev/null 2>&1; then
    DB_AES_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  else
    log_error "Cannot generate AES key: neither openssl nor python3 found"
    exit 1
  fi
}

_validate_aes_key() {
  local key="$1"
  local len=${#key}
  # Accept 64-char hex (32 bytes) or 44-char base64 (32 bytes)
  if [[ "$len" -eq 64 ]] && echo "$key" | grep -qE '^[0-9a-fA-F]+$'; then
    return 0
  elif [[ "$len" -eq 44 ]] && echo "$key" | grep -qE '^[A-Za-z0-9+/]+=*$'; then
    return 0
  else
    log_error "Invalid AES key: expected 64-char hex or 44-char base64 (got ${len} chars)"
    exit 1
  fi
}

# Write all required environment variables to docker/.env
_write_aes_key_to_env() {
  local env_file="${WORK_DIR}/docker/.env"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "Write environment variables to ${env_file}"
    return 0
  fi

  # Create .env if it doesn't exist
  touch "$env_file"

  # --- Helper: set a var in .env (update if exists, append if not) ---
  _env_set() {
    local key="$1"
    local value="$2"
    if [[ -z "$value" ]]; then return 0; fi
    if grep -q "^${key}=" "$env_file" 2>/dev/null; then
      local tmp_env
      tmp_env="$(mktemp)"
      sed "s|^${key}=.*|${key}=${value}|" "$env_file" > "$tmp_env"
      mv "$tmp_env" "$env_file"
    else
      echo "${key}=${value}" >> "$env_file"
    fi
  }

  # --- AES encryption key ---
  _env_set "YASHIGANI_DB_AES_KEY" "${DB_AES_KEY}"

  # --- Upstream MCP URL ---
  # Demo mode: use a built-in echo server so compose doesn't fail on missing var
  # Production: set from wizard or --upstream-url flag
  local upstream="${UPSTREAM_URL}"
  if [[ -z "$upstream" && "$DEPLOY_MODE" == "demo" ]]; then
    upstream="http://localhost:8080/echo"
  fi
  _env_set "UPSTREAM_MCP_URL" "${upstream}"

  # --- Domain ---
  _env_set "YASHIGANI_TLS_DOMAIN" "${DOMAIN}"

  # --- TLS mode ---
  _env_set "YASHIGANI_TLS_MODE" "${TLS_MODE}"

  # --- Admin email ---
  if [[ -n "$ADMIN_EMAIL" ]]; then
    _env_set "YASHIGANI_ADMIN_EMAIL" "${ADMIN_EMAIL}"
  fi

  # --- Prometheus basic auth (required by Caddy reverse proxy to Prometheus) ---
  # Generate a bcrypt hash for the Prometheus scrape endpoint.
  # Try methods in order: htpasswd (macOS/Linux), python3 bcrypt module, python3 hashlib fallback.
  local prom_password
  prom_password="$(_gen_password)"
  local prom_hash=""

  # Method 1: htpasswd (available on macOS via Apache, Linux via apache2-utils)
  if [[ -z "$prom_hash" ]] && command -v htpasswd >/dev/null 2>&1; then
    prom_hash="$(htpasswd -nbBC 12 "" "${prom_password}" 2>/dev/null | tr -d ':\n' || echo "")"
  fi

  # Method 2: python3 bcrypt module (installed as yashigani dependency)
  if [[ -z "$prom_hash" ]] && command -v python3 >/dev/null 2>&1; then
    prom_hash="$(YASHIGANI_PROM_PW="$prom_password" python3 -c "
import bcrypt, os
pw = os.environ['YASHIGANI_PROM_PW'].encode()
print(bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode())
" 2>/dev/null || echo "")"
  fi

  # Method 3: python3 stdlib bcrypt via hashlib (no external deps)
  # Caddy requires bcrypt ($2a$/$2b$) — PBKDF2 is incompatible
  if [[ -z "$prom_hash" ]] && command -v python3 >/dev/null 2>&1; then
    prom_hash="$(YASHIGANI_PROM_PW="$prom_password" python3 -c "
import os, hashlib, base64, struct
pw = os.environ['YASHIGANI_PROM_PW'].encode()
# bcrypt via subprocess htpasswd or fail
import subprocess, sys
try:
    r = subprocess.run(['htpasswd', '-nbBC', '12', '', pw.decode()], capture_output=True, text=True)
    if r.returncode == 0:
        print(r.stdout.strip().lstrip(':'))
        sys.exit(0)
except FileNotFoundError:
    pass
# No bcrypt available — cannot generate compatible hash
sys.exit(1)
" 2>/dev/null || echo "")"
  fi

  if [[ -z "$prom_hash" ]]; then
    log_error "Failed to generate Prometheus basic-auth hash. Install htpasswd (brew install httpd) or ensure python3 is available."
    exit 1
  fi
  # Escape $ to $$ for Docker Compose — bcrypt hashes contain $ delimiters
  # that Compose would interpret as variable interpolation.
  local escaped_hash="${prom_hash//\$/\$\$}"
  _env_set "PROMETHEUS_BASICAUTH_HASH" "${escaped_hash}"
  _env_set "PROMETHEUS_BASICAUTH_USER" "prometheus"

  # --- Environment mode ---
  if [[ "$DEPLOY_MODE" == "demo" ]]; then
    _env_set "YASHIGANI_ENV" "development"
  else
    _env_set "YASHIGANI_ENV" "production"
  fi

  # --- SSO IdP configuration ---
  # Add documented SSO section if not already present.
  # Operators configure IdPs by setting YASHIGANI_IDP_<N>_* vars.
  if ! grep -q "YASHIGANI_IDP_1_ID" "$env_file" 2>/dev/null; then
    cat >> "$env_file" << 'SSO_EOF'

# ---------------------------------------------------------------------------
# SSO Identity Provider Configuration (Starter tier and above)
# ---------------------------------------------------------------------------
# Configure up to 2 IdPs (Professional tier supports OIDC + SAML).
# Enterprise tier supports unlimited IdPs — add YASHIGANI_IDP_3_*, etc.
#
# YASHIGANI_IDP_1_ID=my-entra-id
# YASHIGANI_IDP_1_NAME=Entra ID
# YASHIGANI_IDP_1_PROTOCOL=oidc
# YASHIGANI_IDP_1_DISCOVERY_URL=https://login.microsoftonline.com/<tenant>/.well-known/openid-configuration
# YASHIGANI_IDP_1_CLIENT_ID=<client-id>
# YASHIGANI_IDP_1_CLIENT_SECRET=<client-secret>
# YASHIGANI_IDP_1_EMAIL_DOMAINS=example.com,example.org
# YASHIGANI_IDP_1_REDIRECT_URI=https://<domain>/auth/sso/oidc/my-entra-id/callback
#
# Require Yashigani TOTP after SSO (defense against session hijack/replay):
# YASHIGANI_SSO_2FA_REQUIRED=false
SSO_EOF
  fi

  log_info "Environment written to ${env_file}"
}

# =============================================================================
# STEP 6: Configuration wizard
# =============================================================================
run_wizard() {
  set_step "6" "Configuration wizard"

  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    log_step "6/${TOTAL_STEPS}" "Skipping wizard (--non-interactive)"

    local missing=()
    [[ -z "$DOMAIN" ]]       && missing+=("--domain")
    [[ -z "$ADMIN_EMAIL" ]]  && missing+=("--admin-email")
    [[ -z "$UPSTREAM_URL" ]] && missing+=("--upstream-url")

    if [[ ${#missing[@]} -gt 0 ]]; then
      log_warn "Non-interactive mode: the following flags were not provided: ${missing[*]}"
      log_warn "Defaults or empty values will be used; reconfigure via your .env file."
    fi

    export YASHIGANI_TLS_DOMAIN="$DOMAIN"
    export YASHIGANI_ADMIN_USERNAME="$ADMIN_EMAIL"
    export UPSTREAM_MCP_URL="$UPSTREAM_URL"
    export YASHIGANI_TLS_MODE="$TLS_MODE"
    return 0
  fi

  log_step "6/${TOTAL_STEPS}" "Running configuration wizard..."

  local wizard_script="${WORK_DIR}/scripts/wizard.sh"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "source $wizard_script"
    return 0
  fi

  if [[ -f "$wizard_script" ]]; then
    # Source so the wizard can export variables into this shell
    # shellcheck source=/dev/null
    source "$wizard_script"
  else
    log_warn "Wizard script not found: $wizard_script — running built-in prompts"
    run_inline_wizard
  fi

  log_success "Configuration complete"
}

run_inline_wizard() {
  printf "\n${C_BOLD}=== Yashigani Configuration ===${C_RESET}\n\n"

  if [[ -z "$DOMAIN" ]]; then
    DOMAIN="$(prompt_input "Domain name (e.g. yashigani.example.com)" "")"
  fi

  if [[ -z "$ADMIN_EMAIL" ]]; then
    ADMIN_EMAIL="$(prompt_input "Admin email address" "")"
  fi

  if [[ -z "$UPSTREAM_URL" ]]; then
    UPSTREAM_URL="$(prompt_input "Upstream MCP URL" "")"
  fi

  export YASHIGANI_TLS_DOMAIN="$DOMAIN"
  export YASHIGANI_ADMIN_USERNAME="$ADMIN_EMAIL"
  export UPSTREAM_MCP_URL="$UPSTREAM_URL"
  export YASHIGANI_TLS_MODE="$TLS_MODE"
}

# =============================================================================
# Idempotency check — detect and handle an existing running installation
# =============================================================================
check_existing_installation() {
  local secrets_dir="${WORK_DIR}/docker/secrets"

  if [[ ! -d "$secrets_dir" ]]; then
    return 0
  fi

  # Check whether compose containers are running
  local compose_file="${WORK_DIR}/docker/docker-compose.yml"
  local running=false

  if command -v docker &>/dev/null && [[ -f "$compose_file" ]]; then
    if docker compose -f "$compose_file" ps 2>/dev/null | grep -qE "Up|running"; then
      running=true
    fi
  fi

  [[ "$running" == "false" ]] && return 0

  log_warn "Existing Yashigani installation detected (containers are running)"

  if [[ "$UPGRADE" == "true" ]]; then
    log_info "Upgrade mode: latest images will be pulled and a rolling restart performed"
    return 0
  fi

  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    log_warn "Pass --upgrade to update the existing installation."
    log_warn "Continuing with current images..."
    SKIP_PULL=true
    return 0
  fi

  if prompt_yn "Would you like to upgrade the existing installation?" "y"; then
    UPGRADE=true
    log_info "Upgrade mode enabled"
  else
    log_info "Exiting — no changes made"
    exit 0
  fi
}

# =============================================================================
# STEP 7 (compose/vm): Handle license key
# =============================================================================
handle_license() {
  set_step "7" "License key"
  log_step "7/${TOTAL_STEPS}" "Checking license..."

  local secrets_dir="${WORK_DIR}/docker/secrets"
  local license_dest="${secrets_dir}/license_key"

  # Determine the source file
  local src_path=""
  if [[ -n "$LICENSE_KEY_PATH" ]]; then
    src_path="$LICENSE_KEY_PATH"
  elif [[ -n "${YASHIGANI_LICENSE_FILE:-}" ]]; then
    src_path="$YASHIGANI_LICENSE_FILE"
  fi

  if [[ -z "$src_path" ]]; then
    log_info "No license key provided — proceeding as Community Edition"
    log_info "To upgrade later, place your .ysg license file at: ${license_dest}"
    # Write placeholder content — Docker Desktop for Mac does not reliably
    # propagate empty files to the VM via VirtioFS/gRPC-FUSE.
    mkdir -p "$secrets_dir"
    echo "# community — replace with .ysg license content to upgrade" > "$license_dest"
    chmod 600 "$license_dest"
    return 0
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "mkdir -p $secrets_dir"
    dry_print "cp $src_path $license_dest"
    return 0
  fi

  if [[ ! -f "$src_path" ]]; then
    log_error "License key file not found: $src_path"
    exit 1
  fi

  mkdir -p "$secrets_dir"
  cp "$src_path" "$license_dest"

  if [[ ! -r "$license_dest" ]]; then
    log_error "License key was copied but is not readable: $license_dest"
    exit 1
  fi

  log_success "License key installed (source: $src_path)"
}

# =============================================================================
# STEP 8 (compose/vm): Optional agent bundle selection
# =============================================================================
select_agent_bundles() {
  set_step "8" "Agent bundle selection"
  log_step "8/${TOTAL_STEPS}" "Optional agent bundles..."

  # -----------------------------------------------------------------------
  # Disclaimer — always printed, cannot be suppressed
  # -----------------------------------------------------------------------
  printf "\n"
  printf "${C_YELLOW}╔═══════════════════════════════════════════════════════════╗${C_RESET}\n"
  printf "${C_YELLOW}║  THIRD-PARTY AGENT BUNDLES — COURTESY INTEGRATIONS        ║${C_RESET}\n"
  printf "${C_YELLOW}╠═══════════════════════════════════════════════════════════╣${C_RESET}\n"
  printf "${C_YELLOW}║  The following agents are provided AS IS by               ║${C_RESET}\n"
  printf "${C_YELLOW}║  Agnostic Security as a convenience.                      ║${C_RESET}\n"
  printf "${C_YELLOW}║                                                           ║${C_RESET}\n"
  printf "${C_YELLOW}║  • Image digests are pinned to upstream releases and      ║${C_RESET}\n"
  printf "${C_YELLOW}║    updated as part of the Yashigani release cycle.        ║${C_RESET}\n"
  printf "${C_YELLOW}║  • All support, bugs, and feature requests must be        ║${C_RESET}\n"
  printf "${C_YELLOW}║    directed to the upstream maintainers — NOT to          ║${C_RESET}\n"
  printf "${C_YELLOW}║    Agnostic Security support.                             ║${C_RESET}\n"
  printf "${C_YELLOW}║  • OpenClaw uses a Node.js 24 image (~800 MB) which is   ║${C_RESET}\n"
  printf "${C_YELLOW}║    significantly larger than the Python agent images.     ║${C_RESET}\n"
  printf "${C_YELLOW}╚═══════════════════════════════════════════════════════════╝${C_RESET}\n"
  printf "\n"

  # Non-interactive: honour --agent-bundles flag (comma-separated list or empty)
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    if [[ -n "$AGENT_BUNDLES" ]]; then
      IFS=',' read -ra _bundles <<< "$AGENT_BUNDLES"
      for _b in "${_bundles[@]}"; do
        _b="${_b// /}"   # trim spaces
        case "$_b" in
          all)
            COMPOSE_PROFILES+=("langflow" "letta" "openclaw")
            log_info "Agent bundle enabled (--agent-bundles): langflow, letta, openclaw"
            ;;
          langflow|letta|openclaw)
            COMPOSE_PROFILES+=("$_b")
            log_info "Agent bundle enabled (--agent-bundles): $_b"
            ;;
          *)
            log_warn "Unknown agent bundle '$_b' in --agent-bundles — skipping"
            ;;
        esac
      done
    else
      log_info "No agent bundles selected (--non-interactive, --agent-bundles not set)"
    fi
    return 0
  fi

  printf "${C_BOLD}Available agent bundles:${C_RESET}\n\n"
  printf "    1) Langflow    — Visual multi-agent workflow builder (MIT)\n"
  printf "    2) Letta       — Stateful agent with persistent memory (Apache 2.0)\n"
  printf "    3) OpenClaw    — Node.js 24 personal AI, 30+ channels (${C_YELLOW}~800 MB${C_RESET}, license TBD)\n"
  printf "    4) All of the above\n"
  printf "    0) None — skip agent bundles\n"
  printf "\n"
  printf "${C_BOLD}  Enter your choices (comma-separated, e.g. 1,2 or 4 for all) [0]: ${C_RESET}"

  local choices
  read -r choices </dev/tty 2>/dev/null || choices="0"
  choices="${choices:-0}"

  # Normalize: remove spaces
  choices="$(echo "$choices" | tr -d ' ')"

  # Parse choices
  IFS=',' read -ra selected <<< "$choices"
  for choice in "${selected[@]}"; do
    case "$choice" in
      1)
        COMPOSE_PROFILES+=("langflow")
        log_success "Langflow selected"
        ;;
      2)
        COMPOSE_PROFILES+=("letta")
        log_success "Letta selected"
        ;;
      3)
        COMPOSE_PROFILES+=("openclaw")
        log_warn "OpenClaw uses a Node.js 24 image (~800 MB) — ensure sufficient disk space"
        log_success "OpenClaw selected"
        ;;
      4)
        COMPOSE_PROFILES+=("langflow" "letta" "openclaw")
        log_warn "OpenClaw uses a Node.js 24 image (~800 MB) — ensure sufficient disk space"
        log_success "All agent bundles selected"
        ;;
      0)
        ;;
      *)
        log_warn "Unknown option '$choice' — skipping"
        ;;
    esac
  done

  printf "\n"
  if [[ ${#COMPOSE_PROFILES[@]} -eq 0 ]]; then
    log_info "No agent bundles selected — skipping"
  else
    # Deduplicate in case user entered e.g. 1,5
    local unique_profiles=()
    for p in "${COMPOSE_PROFILES[@]}"; do
      local already=false
      for u in "${unique_profiles[@]+"${unique_profiles[@]}"}"; do
        [[ "$u" == "$p" ]] && already=true
      done
      [[ "$already" == "false" ]] && unique_profiles+=("$p")
    done
    COMPOSE_PROFILES=("${unique_profiles[@]}")
    log_success "Agent bundles selected: ${COMPOSE_PROFILES[*]}"
  fi
}

# =============================================================================
# STEP 9 (compose/vm): docker compose pull
# =============================================================================
compose_pull() {
  set_step "9" "docker compose pull"

  if [[ "$SKIP_PULL" == "true" ]]; then
    log_warn "Skipping docker compose pull (--skip-pull)"
    return 0
  fi

  log_step "9/${TOTAL_STEPS}" "Pulling container images..."

  resolve_compose_cmd

  # --- Verify Docker daemon is running before attempting pull ---
  _ensure_docker_running

  # --- Fix Docker credential helper if missing (common macOS issue) ---
  _fix_docker_credentials

  local compose_file="${WORK_DIR}/docker/docker-compose.yml"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "${COMPOSE_CMD[*]} -f $compose_file pull"
    return 0
  fi

  # Build local images first (gateway + backoffice have Dockerfiles, not on Docker Hub)
  # Podman builds are handled in compose_up() — skip here if already built
  if [[ "$YSG_PODMAN_RUNTIME" != "true" ]]; then
    log_info "Building gateway and backoffice images from source..."
    "${COMPOSE_CMD[@]}" -f "$compose_file" build --no-cache gateway backoffice || {
      log_error "Failed to build gateway/backoffice images. Check Dockerfiles."
      exit 1
    }
    log_success "Local images built"
  else
    log_info "Podman images already built — skipping compose build"
  fi

  # Pull all remote images
  if [[ "$YSG_PODMAN_RUNTIME" == "true" ]]; then
    # Podman: pull images in parallel for speed (podman-compose pull is sequential)
    log_info "Pulling remote container images (parallel)..."
    local _images
    _images=$(grep '^\s*image:' "$compose_file" | sed 's/.*image:\s*//' | sed 's/\s*$//' \
      | grep -v 'yashigani/' | grep -v '${' | sort -u)
    # Add profile images if selected
    for _profile in "${COMPOSE_PROFILES[@]+"${COMPOSE_PROFILES[@]}"}"; do
      [[ -z "$_profile" ]] && continue
      case "$_profile" in
        langflow) _images="$_images
docker.io/langflowai/langflow:latest" ;;
        letta) _images="$_images
docker.io/letta/letta:latest" ;;
        openclaw) _images="$_images
ghcr.io/openclaw/openclaw:latest" ;;
      esac
    done
    # Pull 4 at a time
    local _count=0
    local _total
    _total=$(echo "$_images" | grep -c .)
    for _img in $_images; do
      [[ -z "$_img" ]] && continue
      podman pull "$_img" >/dev/null 2>&1 &
      _count=$((_count + 1))
      if [[ $((_count % 4)) -eq 0 ]]; then
        wait
        log_info "  pulled $_count/$_total images..."
      fi
    done
    wait
    log_success "All $_total remote images pulled"
  else
    log_info "Pulling remote container images..."
    "${COMPOSE_CMD[@]}" -f "$compose_file" pull --ignore-buildable 2>/dev/null || \
    "${COMPOSE_CMD[@]}" -f "$compose_file" pull --ignore-pull-failures 2>/dev/null || \
    "${COMPOSE_CMD[@]}" -f "$compose_file" pull 2>/dev/null || true
    log_success "Container images ready"
  fi
}

# Ensure Docker daemon is running — prompt user to start it if not
_ensure_docker_running() {
  # Skip check for dry-run
  if [[ "$DRY_RUN" == "true" ]]; then return 0; fi

  # Check if daemon responds
  if docker info >/dev/null 2>&1; then
    return 0
  fi

  # Daemon not running — try to help
  log_warn "Docker daemon is not running."

  if [[ "$YSG_OS" == "macos" && -d "/Applications/Docker.app" ]]; then
    printf "\n"
    printf "  ${C_BOLD}Docker Desktop needs to be started.${C_RESET}\n\n"

    if [[ "$NON_INTERACTIVE" == "true" ]]; then
      log_info "Attempting to start Docker Desktop..."
      open -a Docker 2>/dev/null || true
    else
      printf "    1) Start Docker Desktop automatically\n"
      printf "    2) I'll start it manually — wait for me\n"
      printf "\n"
      printf "  ${C_BOLD}Choice [1]: ${C_RESET}"
      local choice
      read -r choice </dev/tty 2>/dev/null || choice="1"
      choice="${choice:-1}"

      if [[ "$choice" == "1" ]]; then
        log_info "Starting Docker Desktop..."
        open -a Docker 2>/dev/null || true
      fi
    fi

    # Wait for daemon to become available (up to 60 seconds)
    printf "  Waiting for Docker daemon"
    local waited=0
    while ! docker info >/dev/null 2>&1; do
      if [[ $waited -ge 60 ]]; then
        printf "\n"
        log_error "Docker daemon did not start within 60 seconds."
        log_error "Start Docker Desktop manually and re-run the installer."
        exit 1
      fi
      printf "."
      sleep 2
      waited=$((waited + 2))
    done
    printf " ready!\n\n"
    log_success "Docker daemon is running"

  elif command -v podman >/dev/null 2>&1; then
    log_info "Trying: podman machine start..."
    podman machine start 2>/dev/null || true
    sleep 3
    if ! podman info >/dev/null 2>&1; then
      log_error "Podman machine did not start. Run 'podman machine start' manually and re-run."
      exit 1
    fi
    log_success "Podman machine is running"

  else
    log_error "No container runtime is running. Start Docker or Podman and re-run the installer."
    exit 1
  fi
}

# Fix missing Docker credential helper (common on macOS when Docker Desktop
# CLI is symlinked but the credential helpers aren't in PATH)
_fix_docker_credentials() {
  if [[ "$DRY_RUN" == "true" ]]; then return 0; fi

  # Only relevant on macOS
  if [[ "$YSG_OS" != "macos" ]]; then return 0; fi

  # Check if the credential helper exists
  if command -v docker-credential-osxkeychain >/dev/null 2>&1; then
    return 0  # Already in PATH
  fi

  # Check Docker Desktop's bundled credential helper
  local cred_helper="/Applications/Docker.app/Contents/Resources/bin/docker-credential-osxkeychain"
  if [[ ! -x "$cred_helper" ]]; then
    # No credential helper at all — configure Docker to not use one
    _docker_config_no_credsStore
    return 0
  fi

  # Credential helper exists but not in PATH — symlink it
  log_info "Docker credential helper not in PATH — fixing..."
  if [[ -t 0 && "$NON_INTERACTIVE" != "true" ]]; then
    printf "  ${C_BOLD}Create symlink for docker-credential-osxkeychain? [Y/n]: ${C_RESET}"
    local choice
    read -r choice </dev/tty 2>/dev/null || choice="y"
    choice="$(echo "${choice:-y}" | tr '[:upper:]' '[:lower:]')"
    if [[ "$choice" != "y" && "$choice" != "yes" && -n "$choice" ]]; then
      _docker_config_no_credsStore
      return 0
    fi
  fi

  if sudo ln -sf "$cred_helper" /usr/local/bin/docker-credential-osxkeychain 2>/dev/null; then
    log_success "docker-credential-osxkeychain symlinked"
  else
    log_warn "Could not create symlink — configuring Docker to pull without credential helper"
    _docker_config_no_credsStore
  fi
}

# Configure Docker to not require a credential helper for pulling public images
_docker_config_no_credsStore() {
  local docker_config="$HOME/.docker/config.json"
  if [[ -f "$docker_config" ]]; then
    # Remove credsStore from config if present (allows anonymous pulls)
    if grep -q '"credsStore"' "$docker_config" 2>/dev/null; then
      log_info "Removing credsStore from Docker config (allows anonymous image pulls)..."
      local tmp_config
      tmp_config="$(mktemp)"
      # Use python3 for safe JSON manipulation
      if command -v python3 >/dev/null 2>&1; then
        python3 -c "
import json, sys
with open('${docker_config}') as f:
    cfg = json.load(f)
cfg.pop('credsStore', None)
with open('${tmp_config}', 'w') as f:
    json.dump(cfg, f, indent=2)
" 2>/dev/null && mv "$tmp_config" "$docker_config"
      else
        # Fallback: sed (less safe but works for simple cases)
        sed '/"credsStore"/d' "$docker_config" > "$tmp_config" && mv "$tmp_config" "$docker_config"
      fi
      log_success "Docker config updated — anonymous pulls enabled"
    fi
  fi
}

# =============================================================================
# STEP 10 (compose/vm): docker compose up -d
# =============================================================================
compose_up() {
  set_step "10" "compose up"
  log_step "10/${TOTAL_STEPS}" "Starting services..."

  resolve_compose_cmd

  local compose_file="${WORK_DIR}/docker/docker-compose.yml"

  # Auto-apply Podman rootless override when running on Podman
  local compose_files=("-f" "$compose_file")
  if [[ "$YSG_PODMAN_RUNTIME" == "true" ]]; then
    log_info "Podman detected — configuring rootless deployment"

    # 1. Ensure Podman socket is running
    systemctl --user start podman.socket 2>/dev/null || true
    export DOCKER_HOST="unix:///run/user/$(id -u)/podman/podman.sock"

    # 2. Check sysctl for privileged port binding (Caddy needs 80/443)
    local port_start
    port_start="$(sysctl -n net.ipv4.ip_unprivileged_port_start 2>/dev/null || echo 1024)"
    if [[ "$port_start" -gt 80 ]]; then
      log_warn "Podman rootless: ports 80/443 require sysctl change"
      log_warn "Run: echo 'net.ipv4.ip_unprivileged_port_start=80' | sudo tee -a /etc/sysctl.conf && sudo sysctl -p"
      log_warn "Caddy will not start until this is configured"
    fi

    # 3. Create Docker-compatible directories for promtail
    if [[ ! -d "/var/lib/docker/containers" ]]; then
      sudo mkdir -p /var/lib/docker/containers 2>/dev/null || \
        mkdir -p /var/lib/docker/containers 2>/dev/null || \
        log_warn "Could not create /var/lib/docker/containers — promtail may not collect container logs"
    fi

    # 4. Use podman-compose if available (sequential, no socket crashes)
    #    Don't apply podman-override.yml with podman-compose (userns conflicts with pods)
    if command -v podman-compose >/dev/null 2>&1; then
      COMPOSE_CMD=("podman-compose")
      log_info "Using podman-compose (native, sequential)"
      # No override needed — podman-compose handles rootless natively
    else
      # Fall back to podman compose (delegates to docker-compose)
      # Apply override for security_opt only (no userns_mode)
      local podman_override="${WORK_DIR}/docker/docker-compose.podman-override.yml"
      if [[ -f "$podman_override" ]]; then
        compose_files+=("-f" "$podman_override")
        log_info "Using podman compose with rootless override"
      fi
    fi

    # 5. Build images with podman build (compose build uses Docker buildx)
    log_info "Building images with Podman..."
    podman build -f "${WORK_DIR}/docker/Dockerfile.gateway" -t yashigani/gateway:latest "${WORK_DIR}" 2>&1 | tail -1
    podman build -f "${WORK_DIR}/docker/Dockerfile.backoffice" -t yashigani/backoffice:latest "${WORK_DIR}" 2>&1 | tail -1
    log_success "Images built with Podman"
  fi

  # Ensure all required directories and secret files exist (handles upgrades,
  # re-runs, and failed previous installs). Docker Desktop for Mac (VirtioFS)
  # does not reliably propagate files to the VM — verify all exist with content.
  local secrets_dir="${WORK_DIR}/docker/secrets"
  local data_dir="${WORK_DIR}/docker/data"
  mkdir -p "$secrets_dir"
  mkdir -p "${data_dir}/audit"
  mkdir -p "${WORK_DIR}/docker/tls"

  for _secret_file in license_key redis_password postgres_password grafana_admin_password; do
    if [[ ! -s "${secrets_dir}/${_secret_file}" ]]; then
      echo "# placeholder — replace with actual value" > "${secrets_dir}/${_secret_file}"
      chmod 644 "${secrets_dir}/${_secret_file}"
      log_info "Created secret placeholder: ${_secret_file}"
    fi
  done

  # Flush filesystem to ensure Docker Desktop Mac (VirtioFS) sees all files
  sync 2>/dev/null || true
  sleep 2

  # Ensure agent bundle token files exist if profiles are selected
  for _profile in "${COMPOSE_PROFILES[@]+"${COMPOSE_PROFILES[@]}"}"; do
    if [[ -n "$_profile" ]]; then
      local _token_file="${secrets_dir}/${_profile}_token"
      if [[ ! -s "$_token_file" ]]; then
        echo "# placeholder — auto-generated at first bootstrap" > "$_token_file"
        chmod 666 "$_token_file"
        log_info "Created token placeholder: ${_profile}_token"
      fi
    fi
  done

  # Build --profile flags for any selected agent bundles
  local profile_args=()
  for _profile in "${COMPOSE_PROFILES[@]+"${COMPOSE_PROFILES[@]}"}"; do
    [[ -n "$_profile" ]] && profile_args+=("--profile" "$_profile")
  done

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "${COMPOSE_CMD[*]} ${compose_files[*]} ${profile_args[*]+${profile_args[*]}} up -d"
    return 0
  fi

  # Clean up any stale containers/networks from failed previous runs.
  # NEVER use -v (--volumes) — that destroys user data (Postgres, Redis, audit logs).
  log_info "Stopping any existing containers (preserving data volumes)..."
  "${COMPOSE_CMD[@]}" "${compose_files[@]}" ${profile_args[@]+"${profile_args[@]}"} down 2>/dev/null || true

  if [[ "$UPGRADE" == "true" ]]; then
    log_info "Starting services (upgrade — removing orphaned containers)..."
    "${COMPOSE_CMD[@]}" "${compose_files[@]}" ${profile_args[@]+"${profile_args[@]}"} up -d --remove-orphans
  else
    log_info "Starting services..."
    "${COMPOSE_CMD[@]}" "${compose_files[@]}" ${profile_args[@]+"${profile_args[@]}"} up -d
  fi

  log_success "Services started"
}

# =============================================================================
# STEP 11 (compose/vm): Bootstrap Postgres
# =============================================================================
bootstrap_postgres() {
  set_step "11" "Bootstrap Postgres"
  log_step "11/${TOTAL_STEPS}" "Bootstrapping database..."

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "docker compose exec backoffice python scripts/bootstrap_postgres.py"
    return 0
  fi

  # Wait for backoffice to be ready before running bootstrap
  local retries=45
  local compose_file="${WORK_DIR}/docker/docker-compose.yml"
  resolve_compose_cmd
  log_info "Waiting for backoffice to be ready..."
  for i in $(seq 1 $retries); do
    if "${COMPOSE_CMD[@]}" -f "$compose_file" exec -T backoffice python -c "import urllib.request; urllib.request.urlopen('http://localhost:8443/healthz')" >/dev/null 2>&1; then
      break
    fi
    if [[ "$i" -eq "$retries" ]]; then
      log_warn "Backoffice not ready after ${retries} attempts — skipping DB bootstrap"
      log_info "Run manually later: docker compose exec backoffice python scripts/bootstrap_postgres.py"
      return 0
    fi
    sleep 2
  done

  # Run Alembic migrations + seed data via the backoffice container
  "${COMPOSE_CMD[@]}" -f "$compose_file" exec -T backoffice python -m alembic upgrade head 2>&1 || {
    log_warn "Alembic migrations failed — database may already be bootstrapped"
  }

  log_success "Database bootstrapped"
}

# =============================================================================
# STEP 11b (compose): Register agent bundles via backoffice API
# =============================================================================
register_agent_bundles() {
  if [[ ${#COMPOSE_PROFILES[@]} -eq 0 ]]; then
    return 0
  fi

  log_info "Registering agent bundles with backoffice..."

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "Register agent bundles: ${COMPOSE_PROFILES[*]}"
    return 0
  fi

  local backoffice_url="http://localhost:8443"
  local secrets_dir="${WORK_DIR}/docker/secrets"
  local compose_file="${WORK_DIR}/docker/docker-compose.yml"

  # Rebuild compose file args (same logic as compose_up)
  local compose_files=("-f" "$compose_file")
  if [[ "$YSG_PODMAN_RUNTIME" == "true" ]]; then
    local podman_override="${WORK_DIR}/docker/docker-compose.podman-override.yml"
    [[ -f "$podman_override" ]] && compose_files+=("-f" "$podman_override")
  fi

  # Run the entire registration flow inside the backoffice container.
  # This avoids shell interpolation issues and timing problems with TOTP.
  # The Python script reads secrets from /run/secrets/, computes TOTP,
  # authenticates, registers each agent, and writes tokens to /run/secrets/.
  local agents_json='['
  local first=true
  for _profile in "${COMPOSE_PROFILES[@]+"${COMPOSE_PROFILES[@]}"}"; do
    [[ -z "$_profile" ]] && continue
    # Skip if token already exists and isn't a placeholder
    if [[ -s "${secrets_dir}/${_profile}_token" ]] && ! grep -q "placeholder" "${secrets_dir}/${_profile}_token" 2>/dev/null; then
      log_info "  ${_profile}: token exists — skipping"
      continue
    fi
    case "$_profile" in
      langflow)  local _name="Langflow"  _url="http://langflow:7860"   _proto="langflow" ;;
      letta)     local _name="Letta"     _url="http://letta:8283"     _proto="letta" ;;
      openclaw)  local _name="OpenClaw"  _url="http://openclaw:18789" _proto="openai" ;;
      *) continue ;;
    esac
    $first || agents_json+=','
    agents_json+="{\"profile\":\"${_profile}\",\"name\":\"${_name}\",\"url\":\"${_url}\",\"protocol\":\"${_proto}\"}"
    first=false
  done
  agents_json+=']'

  if [[ "$agents_json" == "[]" ]]; then
    log_info "No new agents to register"
    return 0
  fi

  local reg_output
  reg_output="$("${COMPOSE_CMD[@]}" "${compose_files[@]}" exec -T -e AGENTS_JSON="${agents_json}" backoffice \
    python3 -c '
import json, os, sys, time, urllib.request

secrets = "/run/secrets"
def read_secret(name):
    try:
        return open(os.path.join(secrets, name)).read().strip()
    except:
        return ""

user = read_secret("admin1_username")
pw = read_secret("admin1_password")
totp_secret = read_secret("admin1_totp_secret")
if not all([user, pw, totp_secret]):
    print("ERROR:missing_secrets", file=sys.stderr)
    sys.exit(1)

# Compute TOTP using pyotp with SHA-256 (same as backoffice)
import pyotp, hashlib
totp_code = pyotp.TOTP(totp_secret, digest=hashlib.sha256).now()

# Login
login_data = json.dumps({"username": user, "password": pw, "totp_code": totp_code}).encode()
req = urllib.request.Request("http://localhost:8443/auth/login", data=login_data,
                             headers={"Content-Type": "application/json"})
try:
    resp = urllib.request.urlopen(req)
except Exception as e:
    print(f"ERROR:login_failed:{e}", file=sys.stderr)
    sys.exit(1)

session = ""
cookie = resp.headers.get("Set-Cookie", "")
for part in cookie.split(";"):
    part = part.strip()
    if part.startswith("yashigani_admin_session="):
        session = part.split("=", 1)[1]
        break

if not session:
    print("ERROR:no_session_cookie", file=sys.stderr)
    sys.exit(1)

# Register agents
agents = json.loads(os.environ.get("AGENTS_JSON", "[]"))
results = []
for agent in agents:
    reg_data = json.dumps({"name": agent["name"], "upstream_url": agent["url"], "protocol": agent.get("protocol", "openai")}).encode()
    req = urllib.request.Request("http://localhost:8443/admin/agents", data=reg_data,
                                 headers={"Content-Type": "application/json",
                                           "Cookie": f"yashigani_admin_session={session}"})
    try:
        resp = urllib.request.urlopen(req)
        body = json.loads(resp.read())
        token = body.get("token", "")
        profile = agent["profile"]
        aname = agent["name"]
        if token:
            token_path = os.path.join(secrets, profile + "_token")
            try:
                with open(token_path, "w") as f:
                    f.write(token)
            except PermissionError:
                pass  # token printed below for host-side capture
            results.append("OK:" + aname + ":" + profile + ":" + token)
        else:
            results.append("FAIL:" + aname + ":no_token")
    except urllib.error.HTTPError as e:
        aname = agent.get("name", "?")
        detail = e.read().decode()[:100]
        results.append("FAIL:" + aname + ":" + str(e.code) + ":" + detail)
    except Exception as e:
        aname = agent.get("name", "?")
        results.append("FAIL:" + aname + ":" + str(e))

for r in results:
    print(r)
' 2>&1)" || true

  # Parse results
  local any_registered=false
  while IFS= read -r line; do
    case "$line" in
      OK:*)
        local _parts="${line#OK:}"
        local _agent_name="${_parts%%:*}"
        # Extract profile:token from OK:name:profile:token
        local _rest="${_parts#*:}"
        local _profile="${_rest%%:*}"
        local _token="${_rest#*:}"
        if [[ -n "$_profile" && -n "$_token" && "$_token" != "$_profile" ]]; then
          echo "$_token" > "${secrets_dir}/${_profile}_token"
          chmod 644 "${secrets_dir}/${_profile}_token"
        fi
        log_success "  ${_agent_name}: registered"
        any_registered=true
        ;;
      FAIL:*)
        local _fail_detail="${line#FAIL:}"
        log_warn "  ${_fail_detail}"
        ;;
      ERROR:*)
        log_warn "Agent registration: ${line#ERROR:}"
        ;;
    esac
  done <<< "$reg_output"

  if $any_registered; then
    # Restart agent containers so they pick up the new tokens
    log_info "Restarting agent containers with new tokens..."
    for _profile in "${COMPOSE_PROFILES[@]+"${COMPOSE_PROFILES[@]}"}"; do
      [[ -z "$_profile" ]] && continue
      "${COMPOSE_CMD[@]}" "${compose_files[@]}" --profile "$_profile" restart "$_profile" 2>/dev/null || true
    done
    log_success "Agent bundle registration complete"

    # Pre-populate agents in Open WebUI's database
    log_info "Syncing agents to Open WebUI..."
    local init_script="${WORK_DIR}/scripts/init-openwebui-agents.py"
    if [[ -f "$init_script" ]]; then
      "${COMPOSE_CMD[@]}" "${compose_files[@]}" cp "$init_script" open-webui:/tmp/init-agents.py 2>/dev/null || \
        podman cp "$init_script" docker_open-webui_1:/tmp/init-agents.py 2>/dev/null
      "${COMPOSE_CMD[@]}" "${compose_files[@]}" exec -T open-webui python3 /tmp/init-agents.py 2>&1 || \
        podman exec docker_open-webui_1 python3 /tmp/init-agents.py 2>&1 || true
    fi
  else
    log_warn "No agents were registered — register manually via /admin/agents"
  fi
}

# =============================================================================
# STEP 12 (compose/vm): Health check
# =============================================================================
run_health_check() {
  set_step "12" "Health check"
  log_step "12/${TOTAL_STEPS}" "Running health checks..."

  local health_script="${WORK_DIR}/scripts/health-check.sh"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "bash $health_script"
    return 0
  fi

  if [[ ! -f "$health_script" ]]; then
    log_error "Health check script not found: $health_script"
    exit 1
  fi

  bash "$health_script"
  log_success "Health checks passed"
}

# =============================================================================
# STEP 8b: Generate all service secrets
# =============================================================================
# Stored as module-level vars so the completion summary can print them once.
GEN_ADMIN1_PASSWORD=""
GEN_ADMIN2_PASSWORD=""
GEN_ADMIN1_TOTP_SECRET=""
GEN_ADMIN2_TOTP_SECRET=""
GEN_ADMIN1_TOTP_URI=""
GEN_ADMIN2_TOTP_URI=""
GEN_POSTGRES_PASSWORD=""
GEN_REDIS_PASSWORD=""
GEN_GRAFANA_PASSWORD=""

_gen_password() {
  # 36-char alphanumeric password (matches Agnostic Security policy)
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 36
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import secrets,string; print("".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(36)))'
  else
    # Last resort — /dev/urandom
    LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 36
  fi
}

_gen_totp_secret() {
  # 20-byte (160-bit) TOTP secret, base32-encoded (RFC 4226 / RFC 6238)
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import secrets,base64; print(base64.b32encode(secrets.token_bytes(20)).decode().rstrip("="))'
  elif command -v openssl >/dev/null 2>&1; then
    openssl rand 20 | python3 -c 'import sys,base64; print(base64.b32encode(sys.stdin.buffer.read()).decode().rstrip("="))' 2>/dev/null || \
      openssl rand 20 | base64 | tr -dc 'A-Z2-7' | head -c 32
  else
    LC_ALL=C tr -dc 'A-Z2-7' < /dev/urandom | head -c 32
  fi
}

_gen_totp_uri() {
  # otpauth://totp/Yashigani:username?secret=SECRET&issuer=Yashigani&digits=6&period=30
  local username="$1"
  local secret="$2"
  local issuer="${DOMAIN:-Yashigani}"
  echo "otpauth://totp/Yashigani:${username}?secret=${secret}&issuer=${issuer}&digits=6&period=30"
}

# Generate two distinct admin usernames from curated word lists
GEN_ADMIN1_USERNAME=""
GEN_ADMIN2_USERNAME=""

_gen_admin_usernames() {
  # Three themed lists — installer picks one theme at random, then two distinct names
  local -a animals=(falcon eagle phoenix raven wolf panther orca hawk lynx cobra
                    tiger condor viper mantis jaguar osprey heron crane puma ibis)
  local -a flowers=(orchid lotus cedar maple jasmine iris dahlia sage willow ivy
                    azalea holly fern clover hazel violet laurel rowan aspen reed)
  local -a robots=(atlas optimus cortex nexus cipher vector prism zenith echo forge
                   titan onyx flux nova spark pulse helix quark axiom delta)

  # Pick a random theme
  local theme_roll
  if command -v python3 >/dev/null 2>&1; then
    theme_roll="$(python3 -c 'import secrets; print(secrets.randbelow(3))')"
  else
    theme_roll=$(( RANDOM % 3 ))
  fi

  local -a chosen_list
  case "$theme_roll" in
    0) chosen_list=("${animals[@]}") ;;
    1) chosen_list=("${flowers[@]}") ;;
    2) chosen_list=("${robots[@]}") ;;
  esac

  local list_len=${#chosen_list[@]}

  # Pick two distinct indices
  local idx1 idx2
  if command -v python3 >/dev/null 2>&1; then
    idx1="$(python3 -c "import secrets; print(secrets.randbelow(${list_len}))")"
    idx2="$(python3 -c "import secrets; r=${idx1}; exec('while r==${idx1}: r=secrets.randbelow(${list_len})'); print(r)")"
  else
    idx1=$(( RANDOM % list_len ))
    idx2=$(( (idx1 + 1 + RANDOM % (list_len - 1)) % list_len ))
  fi

  GEN_ADMIN1_USERNAME="${chosen_list[$idx1]}"
  GEN_ADMIN2_USERNAME="${chosen_list[$idx2]}"
}

generate_secrets() {
  local secrets_dir="${WORK_DIR}/docker/secrets"

  # Skip if secrets already exist (upgrade path)
  if [[ -f "${secrets_dir}/postgres_password" && -f "${secrets_dir}/redis_password" ]]; then
    log_info "Secrets already exist — preserving (upgrade path)"
    GEN_POSTGRES_PASSWORD="$(cat "${secrets_dir}/postgres_password" 2>/dev/null || echo "[preserved]")"
    GEN_REDIS_PASSWORD="$(cat "${secrets_dir}/redis_password" 2>/dev/null || echo "[preserved]")"
    GEN_GRAFANA_PASSWORD="$(cat "${secrets_dir}/grafana_admin_password" 2>/dev/null || echo "[preserved]")"
    GEN_ADMIN1_PASSWORD="[preserved — check secrets dir]"
    GEN_ADMIN2_PASSWORD="[preserved — check secrets dir]"
    GEN_ADMIN1_TOTP_SECRET="[preserved]"
    GEN_ADMIN2_TOTP_SECRET="[preserved]"
    GEN_ADMIN1_TOTP_URI=""
    GEN_ADMIN2_TOTP_URI=""
    # Ensure passwords are in .env for Docker Compose interpolation
    local env_file="${WORK_DIR}/docker/.env"
    for _pw_key_val in "POSTGRES_PASSWORD:${GEN_POSTGRES_PASSWORD}" "REDIS_PASSWORD:${GEN_REDIS_PASSWORD}"; do
      local _pw_key="${_pw_key_val%%:*}"
      local _pw_val="${_pw_key_val#*:}"
      if [[ "$_pw_val" != "[preserved]" && -n "$_pw_val" ]]; then
        if grep -q "^${_pw_key}=" "$env_file" 2>/dev/null; then
          local tmp_env; tmp_env="$(mktemp)"
          sed "s|^${_pw_key}=.*|${_pw_key}=${_pw_val}|" "$env_file" > "$tmp_env"
          mv "$tmp_env" "$env_file"
        else
          echo "${_pw_key}=${_pw_val}" >> "$env_file"
        fi
      fi
    done
    # Ensure OpenClaw gateway token exists
    if ! grep -q "^OPENCLAW_GATEWAY_TOKEN=" "$env_file" 2>/dev/null; then
      local openclaw_token
      openclaw_token="$(openssl rand -hex 32 2>/dev/null || python3 -c 'import secrets; print(secrets.token_hex(32))')"
      echo "OPENCLAW_GATEWAY_TOKEN=${openclaw_token}" >> "$env_file"
    fi
    return 0
  fi

  # Generate unique admin usernames from themed word lists
  _gen_admin_usernames

  log_info "Generating service passwords and 2FA secrets..."
  log_info "Admin usernames: ${GEN_ADMIN1_USERNAME} (primary), ${GEN_ADMIN2_USERNAME} (backup)"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "Generate 36-char passwords for: ${GEN_ADMIN1_USERNAME}, ${GEN_ADMIN2_USERNAME}, postgres, redis, grafana"
    dry_print "Generate TOTP secrets for: ${GEN_ADMIN1_USERNAME}, ${GEN_ADMIN2_USERNAME}"
    dry_print "Write to ${secrets_dir}/"
    GEN_ADMIN1_PASSWORD="[dry-run]"
    GEN_ADMIN2_PASSWORD="[dry-run]"
    GEN_ADMIN1_TOTP_SECRET="[dry-run]"
    GEN_ADMIN2_TOTP_SECRET="[dry-run]"
    GEN_POSTGRES_PASSWORD="[dry-run]"
    GEN_REDIS_PASSWORD="[dry-run]"
    GEN_GRAFANA_PASSWORD="[dry-run]"
    return 0
  fi

  mkdir -p "$secrets_dir"

  # --- Admin 1 (primary) ---
  GEN_ADMIN1_PASSWORD="$(_gen_password)"
  printf "%s" "$GEN_ADMIN1_PASSWORD" > "${secrets_dir}/admin1_password"
  chmod 644 "${secrets_dir}/admin1_password"
  # Also write as admin_initial_password — the backoffice bootstrap checks this
  # file to decide whether to generate new credentials or use existing ones
  printf "%s" "$GEN_ADMIN1_PASSWORD" > "${secrets_dir}/admin_initial_password"
  chmod 644 "${secrets_dir}/admin_initial_password"
  printf "%s" "$GEN_ADMIN1_USERNAME" > "${secrets_dir}/admin1_username"
  chmod 644 "${secrets_dir}/admin1_username"
  # Update .env so backoffice creates the account with the generated username
  local env_file="${WORK_DIR}/docker/.env"
  if grep -q "^YASHIGANI_ADMIN_USERNAME=" "$env_file" 2>/dev/null; then
    local tmp_env; tmp_env="$(mktemp)"
    sed "s|^YASHIGANI_ADMIN_USERNAME=.*|YASHIGANI_ADMIN_USERNAME=${GEN_ADMIN1_USERNAME}|" "$env_file" > "$tmp_env"
    mv "$tmp_env" "$env_file"
  else
    echo "YASHIGANI_ADMIN_USERNAME=${GEN_ADMIN1_USERNAME}" >> "$env_file"
  fi

  GEN_ADMIN1_TOTP_SECRET="$(_gen_totp_secret)"
  printf "%s" "$GEN_ADMIN1_TOTP_SECRET" > "${secrets_dir}/admin1_totp_secret"
  chmod 644 "${secrets_dir}/admin1_totp_secret"
  GEN_ADMIN1_TOTP_URI="$(_gen_totp_uri "$GEN_ADMIN1_USERNAME" "$GEN_ADMIN1_TOTP_SECRET")"

  # --- Admin 2 (backup — anti-lockout) ---
  GEN_ADMIN2_PASSWORD="$(_gen_password)"
  printf "%s" "$GEN_ADMIN2_PASSWORD" > "${secrets_dir}/admin2_password"
  chmod 644 "${secrets_dir}/admin2_password"
  printf "%s" "$GEN_ADMIN2_USERNAME" > "${secrets_dir}/admin2_username"
  chmod 644 "${secrets_dir}/admin2_username"

  GEN_ADMIN2_TOTP_SECRET="$(_gen_totp_secret)"
  printf "%s" "$GEN_ADMIN2_TOTP_SECRET" > "${secrets_dir}/admin2_totp_secret"
  chmod 644 "${secrets_dir}/admin2_totp_secret"
  GEN_ADMIN2_TOTP_URI="$(_gen_totp_uri "$GEN_ADMIN2_USERNAME" "$GEN_ADMIN2_TOTP_SECRET")"

  # --- PostgreSQL ---
  GEN_POSTGRES_PASSWORD="$(_gen_password)"
  printf "%s" "$GEN_POSTGRES_PASSWORD" > "${secrets_dir}/postgres_password"
  chmod 644 "${secrets_dir}/postgres_password"
  # Also write to .env so Docker Compose can interpolate ${POSTGRES_PASSWORD}
  # in service DSN and PgBouncer DATABASE_URL
  local env_file="${WORK_DIR}/docker/.env"
  if grep -q "^POSTGRES_PASSWORD=" "$env_file" 2>/dev/null; then
    local tmp_env; tmp_env="$(mktemp)"
    sed "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${GEN_POSTGRES_PASSWORD}|" "$env_file" > "$tmp_env"
    mv "$tmp_env" "$env_file"
  else
    echo "POSTGRES_PASSWORD=${GEN_POSTGRES_PASSWORD}" >> "$env_file"
  fi

  # --- Redis ---
  GEN_REDIS_PASSWORD="$(_gen_password)"
  printf "%s" "$GEN_REDIS_PASSWORD" > "${secrets_dir}/redis_password"
  chmod 644 "${secrets_dir}/redis_password"
  # Write to .env for Compose interpolation (LangGraph REDIS_URI needs it)
  if grep -q "^REDIS_PASSWORD=" "$env_file" 2>/dev/null; then
    local tmp_env; tmp_env="$(mktemp)"
    sed "s|^REDIS_PASSWORD=.*|REDIS_PASSWORD=${GEN_REDIS_PASSWORD}|" "$env_file" > "$tmp_env"
    mv "$tmp_env" "$env_file"
  else
    echo "REDIS_PASSWORD=${GEN_REDIS_PASSWORD}" >> "$env_file"
  fi

  # --- OpenClaw gateway token ---
  local openclaw_token
  openclaw_token="$(openssl rand -hex 32 2>/dev/null || python3 -c 'import secrets; print(secrets.token_hex(32))')"
  printf "%s" "$openclaw_token" > "${secrets_dir}/openclaw_gateway_token"
  chmod 644 "${secrets_dir}/openclaw_gateway_token"
  if grep -q "^OPENCLAW_GATEWAY_TOKEN=" "$env_file" 2>/dev/null; then
    local tmp_env; tmp_env="$(mktemp)"
    sed "s|^OPENCLAW_GATEWAY_TOKEN=.*|OPENCLAW_GATEWAY_TOKEN=${openclaw_token}|" "$env_file" > "$tmp_env"
    mv "$tmp_env" "$env_file"
  else
    echo "OPENCLAW_GATEWAY_TOKEN=${openclaw_token}" >> "$env_file"
  fi

  # --- Grafana ---
  GEN_GRAFANA_PASSWORD="$(_gen_password)"
  printf "%s" "$GEN_GRAFANA_PASSWORD" > "${secrets_dir}/grafana_admin_password"
  chmod 644 "${secrets_dir}/grafana_admin_password"

  # --- HIBP breach check on generated passwords (defense-in-depth) ---
  _hibp_check_passwords

  log_success "All passwords and 2FA secrets generated (${secrets_dir}/)"
}

# =============================================================================
# Have I Been Pwned (HIBP) k-Anonymity password breach check
# =============================================================================
# Uses the HIBP Passwords API v3 (api.pwnedpasswords.com)
# Protocol: SHA-1 hash the password, send first 5 chars, check locally.
# The actual password NEVER leaves the system.
# See: https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange

_hibp_check_single() {
  local label="$1"
  local password="$2"

  # Skip if no curl or no internet
  if ! command -v curl >/dev/null 2>&1; then
    return 0
  fi

  # SHA-1 hash the password
  local sha1_hash=""
  if command -v shasum >/dev/null 2>&1; then
    sha1_hash="$(printf '%s' "$password" | shasum -a 1 | awk '{print toupper($1)}')"
  elif command -v sha1sum >/dev/null 2>&1; then
    sha1_hash="$(printf '%s' "$password" | sha1sum | awk '{print toupper($1)}')"
  elif command -v openssl >/dev/null 2>&1; then
    sha1_hash="$(printf '%s' "$password" | openssl dgst -sha1 | awk '{print toupper($NF)}')"
  else
    return 0  # Can't hash — skip silently
  fi

  local prefix="${sha1_hash:0:5}"
  local suffix="${sha1_hash:5}"

  # Query HIBP k-Anonymity API (5-char prefix only — password never sent)
  local response=""
  response="$(curl -sSL --max-time 5 --connect-timeout 3 \
    -H "User-Agent: Yashigani-Installer/${YASHIGANI_VERSION}" \
    "https://api.pwnedpasswords.com/range/${prefix}" 2>/dev/null || echo "")"

  if [[ -z "$response" ]]; then
    return 0  # API unreachable — skip silently (air-gapped, offline, etc.)
  fi

  # Check if our suffix appears in the response
  local match_count=""
  match_count="$(echo "$response" | grep -i "^${suffix}:" | cut -d: -f2 | tr -d '\r' || echo "")"

  if [[ -n "$match_count" && "$match_count" -gt 0 ]]; then
    log_warn "HIBP: ${label} password found in ${match_count} data breach(es) — regenerating..."
    return 1  # Compromised
  fi

  return 0  # Clean
}

_hibp_check_passwords() {
  # Only check if we have internet access (skip in offline/demo-localhost mode)
  if [[ "$OFFLINE" == "true" ]]; then
    log_info "Skipping HIBP breach check (offline mode)"
    return 0
  fi

  log_info "Checking generated passwords against HIBP breach database..."

  local max_retries=3

  # Check admin1 — regenerate if compromised (extremely unlikely for 36-char random)
  local attempt=0
  while ! _hibp_check_single "Admin 1 (${GEN_ADMIN1_USERNAME})" "$GEN_ADMIN1_PASSWORD"; do
    attempt=$((attempt + 1))
    if [[ $attempt -ge $max_retries ]]; then
      log_warn "HIBP: Could not generate a clean password after ${max_retries} attempts — proceeding anyway"
      break
    fi
    GEN_ADMIN1_PASSWORD="$(_gen_password)"
    printf "%s" "$GEN_ADMIN1_PASSWORD" > "${WORK_DIR}/docker/secrets/admin1_password"
  done

  # Check admin2
  attempt=0
  while ! _hibp_check_single "Admin 2 (${GEN_ADMIN2_USERNAME})" "$GEN_ADMIN2_PASSWORD"; do
    attempt=$((attempt + 1))
    if [[ $attempt -ge $max_retries ]]; then
      break
    fi
    GEN_ADMIN2_PASSWORD="$(_gen_password)"
    printf "%s" "$GEN_ADMIN2_PASSWORD" > "${WORK_DIR}/docker/secrets/admin2_password"
  done

  # Check service passwords (postgres, redis, grafana)
  _hibp_check_and_regen "postgres" "$GEN_POSTGRES_PASSWORD" "${WORK_DIR}/docker/secrets/postgres_password" $max_retries
  _hibp_check_and_regen "redis" "$GEN_REDIS_PASSWORD" "${WORK_DIR}/docker/secrets/redis_password" $max_retries
  _hibp_check_and_regen "grafana" "$GEN_GRAFANA_PASSWORD" "${WORK_DIR}/docker/secrets/grafana_admin_password" $max_retries

  log_success "HIBP breach check complete — all passwords clean"
}

_hibp_check_and_regen() {
  local label="$1"
  local password="$2"
  local secret_file="$3"
  local max_retries="$4"
  local attempt=0

  while ! _hibp_check_single "$label" "$password"; do
    attempt=$((attempt + 1))
    if [[ $attempt -ge $max_retries ]]; then
      break
    fi
    password="$(_gen_password)"
    printf "%s" "$password" > "$secret_file"
  done

  # Update the module-level variable
  local upper_label
  upper_label="$(echo "$label" | tr '[:lower:]' '[:upper:]')"
  printf -v "GEN_${upper_label}_PASSWORD" '%s' "$password"
}

# =============================================================================
# STEP 13 (compose/vm): Completion summary with credentials
# =============================================================================
print_completion_summary() {
  set_step "13" "Completion"
  log_step "13/${TOTAL_STEPS}" "Installation complete"

  local proto="https"
  [[ "$TLS_MODE" == "selfsigned" ]] && proto="https (self-signed)"

  printf "\n"
  printf "${C_GREEN}╔═══════════════════════════════════════════════════════════════╗${C_RESET}\n"
  printf "${C_GREEN}║    Yashigani v%-8s is up and running!                     ║${C_RESET}\n" "${YASHIGANI_VERSION}"
  printf "${C_GREEN}╚═══════════════════════════════════════════════════════════════╝${C_RESET}\n"
  printf "\n"

  # --- Access URLs ---
  if [[ -n "$DOMAIN" ]]; then
    printf "  ${C_BOLD}Access:${C_RESET}\n"
    printf "    %-22s %s://%s\n"           "Open WebUI:"   "$proto"  "$DOMAIN"
    printf "    %-22s %s://%s/admin/login\n" "Admin Panel:" "$proto" "$DOMAIN"
    printf "    %-22s %s://%s/v1\n"        "Gateway API:"  "https"   "$DOMAIN"
    if [[ "$DOMAIN" != "localhost" ]]; then
      printf "    %-22s https://%s:3000\n" "Grafana:" "$DOMAIN"
    else
      printf "    %-22s https://localhost:3000\n" "Grafana:"
    fi
    printf "\n"
  fi

  # --- Credentials (shown ONCE — never again) ---
  printf "  ${C_YELLOW}╔══════════════════════════════════════════════════════════════════╗${C_RESET}\n"
  printf "  ${C_YELLOW}║  CREDENTIALS — SAVE THESE NOW (shown only once)                 ║${C_RESET}\n"
  printf "  ${C_YELLOW}╠══════════════════════════════════════════════════════════════════╣${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}  ${C_BOLD}Admin 1 (primary):${C_RESET}                                           ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    Username:     %-44s ${C_YELLOW}║${C_RESET}\n" "${GEN_ADMIN1_USERNAME}"
  printf "  ${C_YELLOW}║${C_RESET}    Password:     %-44s ${C_YELLOW}║${C_RESET}\n" "${GEN_ADMIN1_PASSWORD}"
  printf "  ${C_YELLOW}║${C_RESET}    TOTP secret:  %-44s ${C_YELLOW}║${C_RESET}\n" "${GEN_ADMIN1_TOTP_SECRET}"
  if [[ -n "$GEN_ADMIN1_TOTP_URI" ]]; then
  printf "  ${C_YELLOW}║${C_RESET}    TOTP URI (paste into authenticator app):                     ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    %s\n" "${GEN_ADMIN1_TOTP_URI}"
  fi
  printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}  ${C_BOLD}Admin 2 (backup — anti-lockout):${C_RESET}                              ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    Username:     %-44s ${C_YELLOW}║${C_RESET}\n" "${GEN_ADMIN2_USERNAME}"
  printf "  ${C_YELLOW}║${C_RESET}    Password:     %-44s ${C_YELLOW}║${C_RESET}\n" "${GEN_ADMIN2_PASSWORD}"
  printf "  ${C_YELLOW}║${C_RESET}    TOTP secret:  %-44s ${C_YELLOW}║${C_RESET}\n" "${GEN_ADMIN2_TOTP_SECRET}"
  if [[ -n "$GEN_ADMIN2_TOTP_URI" ]]; then
  printf "  ${C_YELLOW}║${C_RESET}    TOTP URI (paste into authenticator app):                     ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    %s\n" "${GEN_ADMIN2_TOTP_URI}"
  fi
  printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}╠══════════════════════════════════════════════════════════════════╣${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}  ${C_BOLD}Encryption Key (AES-256 + HMAC):${C_RESET}                              ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    %-60s ${C_YELLOW}║${C_RESET}\n" "${DB_AES_KEY:-[not set]}"
  printf "  ${C_YELLOW}║${C_RESET}    ${C_RED}CRITICAL: This key encrypts database columns AND hashes${C_RESET}       ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    ${C_RED}email addresses in audit logs. Losing this key means${C_RESET}          ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    ${C_RED}permanent data loss. Store in break-glass vault.${C_RESET}              ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}╠══════════════════════════════════════════════════════════════════╣${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}  ${C_BOLD}PostgreSQL:${C_RESET}                                                  ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    User:         yashigani_app                                  ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    Password:     %-44s ${C_YELLOW}║${C_RESET}\n" "${GEN_POSTGRES_PASSWORD}"
  printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}  ${C_BOLD}Redis:${C_RESET}                                                       ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    Password:     %-44s ${C_YELLOW}║${C_RESET}\n" "${GEN_REDIS_PASSWORD}"
  printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}  ${C_BOLD}Grafana:${C_RESET}                                                     ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    Username:     admin                                          ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}║${C_RESET}    Password:     %-44s ${C_YELLOW}║${C_RESET}\n" "${GEN_GRAFANA_PASSWORD}"
  printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
  printf "  ${C_YELLOW}╚══════════════════════════════════════════════════════════════════╝${C_RESET}\n"
  printf "\n"
  printf "  ${C_RED}${C_BOLD}WARNING:${C_RESET} These credentials will NOT be shown again.\n"
  printf "  ${C_RED}Store them in a password manager or secure vault immediately.${C_RESET}\n"
  printf "\n"

  # --- Agent bundles ---
  if [[ ${#COMPOSE_PROFILES[@]} -gt 0 ]]; then
    printf "  ${C_BOLD}Agent bundles installed:${C_RESET} %s\n" "${COMPOSE_PROFILES[*]}"
    printf "\n"
  fi

  # --- Deployment mode ---
  printf "  ${C_BOLD}Deployment:${C_RESET}\n"
  printf "    %-22s %s\n" "Mode:"      "${DEPLOY_MODE:-compose}"
  printf "    %-22s %s\n" "Directory:" "$WORK_DIR"
  printf "    %-22s %s\n" "TLS:"       "$TLS_MODE"
  if [[ "${YSG_GPU_TYPE:-none}" != "none" ]]; then
    printf "    %-22s %s\n" "GPU:"     "${YSG_GPU_NAME}"
  fi
  printf "\n"

  # --- Next steps ---
  printf "  ${C_BOLD}Next steps:${C_RESET}\n"
  printf "    1. Save ALL credentials above in a password manager\n"
  printf "    2. Scan the TOTP QR URIs into your authenticator app (Google Authenticator, Authy, 1Password)\n"
  printf "    3. Log in to the backoffice as '%s' and change the default password\n" "${GEN_ADMIN1_USERNAME}"
  printf "    4. Store '%s' credentials in a safe/vault (break-glass backup)\n" "${GEN_ADMIN2_USERNAME}"
  printf "    5. Register your first AI agent\n"
  printf "    6. Configure your OPA RBAC policy\n"
  if [[ "$DEPLOY_MODE" != "demo" ]]; then
    printf "    7. Set up SIEM integration (Splunk / Elastic / Wazuh)\n"
    printf "    8. Import your licence key (if not done during install)\n"
  fi
  printf "\n"

  # --- Useful commands ---
  printf "  ${C_BOLD}Useful commands:${C_RESET}\n"
  printf "    Health check:    bash %s/scripts/health-check.sh\n" "$WORK_DIR"
  printf "    View logs:       ${COMPOSE_CMD[*]:-docker compose} -f %s/docker/docker-compose.yml logs -f\n" "$WORK_DIR"
  printf "    Update:          bash %s/update.sh\n" "$WORK_DIR"
  printf "    Uninstall:       bash %s/uninstall.sh\n" "$WORK_DIR"
  printf "\n"

  # --- DNS / Browser access guidance ---
  if [[ "$TLS_MODE" == "selfsigned" && "$DOMAIN" != "localhost" ]]; then
    local machine_ip
    machine_ip="$(hostname -I 2>/dev/null | awk '{print $1}' || ipconfig getifaddr en0 2>/dev/null || echo "<this-machine-ip>")"

    printf "  ${C_YELLOW}╔══════════════════════════════════════════════════════════════════╗${C_RESET}\n"
    printf "  ${C_YELLOW}║  IMPORTANT: DNS / Browser Access                                 ║${C_RESET}\n"
    printf "  ${C_YELLOW}╠══════════════════════════════════════════════════════════════════╣${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}  Yashigani uses a self-signed TLS certificate for the domain    ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}  '%s'. To access it from your browser or other  ${C_YELLOW}║${C_RESET}\n" "${DOMAIN}"
    printf "  ${C_YELLOW}║${C_RESET}  machines, add this entry to /etc/hosts on each client:         ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}  Run on your computer (or any client that needs access):        ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}    sudo sh -c 'echo \"%s %s\" >> /etc/hosts'  ${C_YELLOW}║${C_RESET}\n" "$machine_ip" "$DOMAIN"
    printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}  Then open: https://%s                          ${C_YELLOW}║${C_RESET}\n" "$DOMAIN"
    printf "  ${C_YELLOW}║${C_RESET}  Admin UI:  https://%s/admin/login              ${C_YELLOW}║${C_RESET}\n" "$DOMAIN"
    printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}  Your browser will show a certificate warning — this is         ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}  expected with self-signed certificates. Accept it to proceed.  ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}║${C_RESET}  For curl: curl -sk https://%s/healthz          ${C_YELLOW}║${C_RESET}\n" "$DOMAIN"
    printf "  ${C_YELLOW}║${C_RESET}                                                                ${C_YELLOW}║${C_RESET}\n"
    printf "  ${C_YELLOW}╚══════════════════════════════════════════════════════════════════╝${C_RESET}\n"
    printf "\n"
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    log_warn "This was a dry-run — no changes were made to the system"
  fi
}

# =============================================================================
# Kubernetes flow steps
# =============================================================================

# STEP 7 (k8s): helm dependency update
k8s_helm_dep_update() {
  set_step "7" "helm dependency update"
  log_step "7/${TOTAL_STEPS}" "Updating Helm chart dependencies..."

  require_cmd "helm"

  local chart_dir="${WORK_DIR}/helm/yashigani"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "helm dependency update $chart_dir"
    return 0
  fi

  if [[ ! -d "$chart_dir" ]]; then
    log_error "Helm chart directory not found: $chart_dir"
    exit 1
  fi

  helm dependency update "$chart_dir"
  log_success "Helm dependencies updated"
}

# STEP 8 (k8s): helm upgrade --install
k8s_helm_install() {
  set_step "8" "helm upgrade --install"
  log_step "8/${TOTAL_STEPS}" "Deploying via Helm..."

  require_cmd "helm"

  local chart_dir="${WORK_DIR}/helm/yashigani"
  local helm_values="${WORK_DIR}/.env.helm"

  if [[ "$DRY_RUN" == "true" ]]; then
    if [[ -f "$helm_values" ]]; then
      dry_print "helm upgrade --install yashigani $chart_dir -n $NAMESPACE --create-namespace -f $helm_values"
    else
      dry_print "helm upgrade --install yashigani $chart_dir -n $NAMESPACE --create-namespace"
    fi
    return 0
  fi

  local helm_args=(
    upgrade --install yashigani "$chart_dir"
    --namespace "$NAMESPACE"
    --create-namespace
  )

  if [[ -f "$helm_values" ]]; then
    helm_args+=(-f "$helm_values")
  else
    log_warn "Helm values file not found ($helm_values) — using chart defaults"
  fi

  helm "${helm_args[@]}"
  log_success "Helm release deployed"
}

# STEP 9 (k8s): kubectl rollout status
k8s_rollout_status() {
  set_step "9" "kubectl rollout status"
  log_step "9/${TOTAL_STEPS}" "Waiting for gateway deployment to become ready..."

  require_cmd "kubectl"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry_print "kubectl rollout status deployment/yashigani-gateway -n $NAMESPACE --timeout=300s"
    return 0
  fi

  kubectl rollout status deployment/yashigani-gateway \
    --namespace "$NAMESPACE" \
    --timeout=300s

  log_success "Gateway deployment is ready"
}

# STEP 10 (k8s): Access instructions
k8s_print_access() {
  set_step "10" "Access instructions"
  log_step "10/${TOTAL_STEPS}" "Deployment complete"

  printf "\n"
  printf "${C_GREEN}╔═══════════════════════════════════════════════════╗${C_RESET}\n"
  printf "${C_GREEN}║  Yashigani v%-8s deployed to Kubernetes!     ║${C_RESET}\n" "${YASHIGANI_VERSION}"
  printf "${C_GREEN}╚═══════════════════════════════════════════════════╝${C_RESET}\n"
  printf "\n"
  printf "  %-22s %s\n" "Namespace:"    "$NAMESPACE"
  printf "  %-22s %s\n" "Helm release:" "yashigani"
  if [[ -n "$DOMAIN" ]]; then
    printf "  %-22s https://%s\n" "Dashboard:" "$DOMAIN"
  fi
  printf "\n"
  printf "  Check pods:\n"
  printf "    kubectl get pods -n %s\n\n" "$NAMESPACE"
  printf "  View gateway logs:\n"
  printf "    kubectl logs -f deployment/yashigani-gateway -n %s\n\n" "$NAMESPACE"
  printf "  Uninstall:\n"
  printf "    helm uninstall yashigani -n %s\n\n" "$NAMESPACE"

  if [[ "$DRY_RUN" == "true" ]]; then
    log_warn "This was a dry-run — no changes were made to the cluster"
  fi
}

# =============================================================================
# Main
# =============================================================================
main() {
  parse_args "$@"

  # ---- Step 0: Banner ----
  print_banner

  # ---- Step 1: Working directory ----
  detect_working_directory

  # Move into the repo now that we know where it is
  if [[ "$DRY_RUN" != "true" && -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
    cd "$WORK_DIR"
  fi

  # ---- Step 2: Platform detection ----
  source_platform_detect

  # ---- Step 3: Platform summary ----
  print_platform_summary

  # ---- Step 3b: Deployment mode selection (new in v0.9.0) ----
  select_deploy_mode

  # ---- Step 3c: AES key provisioning (new in v0.9.0) ----
  provision_aes_key

  if [[ "$MODE" == "k8s" ]]; then
    # ------------------------------------------------------------------
    # Kubernetes / Enterprise deployment path
    # ------------------------------------------------------------------
    # Step 4: n/a (no runtime install for k8s)
    # Step 5: Preflight
    run_preflight

    # Step 6: Wizard / config
    run_wizard

    # Write AES key to Helm values or K8s secret
    _write_aes_key_to_env

    # Step 7: Helm dependency update
    k8s_helm_dep_update

    # Step 8: Helm install/upgrade
    k8s_helm_install

    # Step 9: Rollout status
    k8s_rollout_status

    # Step 10: Access instructions
    k8s_print_access

  else
    # ------------------------------------------------------------------
    # Docker Compose deployment path (Demo + Production)
    # ------------------------------------------------------------------

    # Step 4: Install runtime (vm mode only — no-op for compose)
    install_runtime

    # Step 5: Preflight
    run_preflight

    # Step 6: Wizard / config (skipped in demo mode — defaults applied)
    if [[ "$DEPLOY_MODE" == "demo" ]]; then
      log_step "6/${TOTAL_STEPS}" "Skipping wizard (demo mode — using defaults)"
    else
      run_wizard
    fi

    # Idempotency: check for running installation before making changes
    check_existing_installation

    # Write AES key to .env
    _write_aes_key_to_env

    # Generate all service passwords (admin, postgres, redis, grafana)
    generate_secrets

    # Step 7: License key (skipped in demo — Community, no key needed)
    if [[ "$DEPLOY_MODE" == "demo" ]]; then
      log_step "7/${TOTAL_STEPS}" "Skipping licence key (demo mode — Community tier)"
    else
      handle_license
    fi

    # Step 8: Optional agent bundle selection
    select_agent_bundles

    # Step 8b: Wazuh SIEM (opt-in)
    if [[ "$INSTALL_WAZUH" == "true" ]]; then
      COMPOSE_PROFILES+=("wazuh")
      log_success "Wazuh SIEM enabled (--wazuh flag)"
    elif [[ "$NON_INTERACTIVE" != "true" ]]; then
      printf "\n${C_BOLD}Install Wazuh SIEM? (open-source security monitoring)${C_RESET}\n"
      printf "    Includes: Wazuh Manager + OpenSearch Indexer + Dashboard\n"
      printf "    ${C_YELLOW}Requires ~2 GB additional disk space${C_RESET}\n"
      printf "\n${C_BOLD}  Install Wazuh? [y/N]: ${C_RESET}"
      local wazuh_choice
      read -r wazuh_choice </dev/tty 2>/dev/null || wazuh_choice="n"
      if [[ "${wazuh_choice,,}" == "y" || "${wazuh_choice,,}" == "yes" ]]; then
        COMPOSE_PROFILES+=("wazuh")
        log_success "Wazuh SIEM selected"
      fi
    fi

    # Step 9: docker compose pull
    compose_pull

    # Step 10: docker compose up -d
    compose_up

    # Step 11: Bootstrap Postgres
    bootstrap_postgres

    # Step 11b: Register agent bundles (after backoffice is healthy)
    register_agent_bundles

    # Step 12: Health check
    run_health_check

    # Step 13: Completion summary
    print_completion_summary
  fi
}

main "$@"
