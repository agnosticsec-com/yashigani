#!/usr/bin/env bash
# scripts/install-runtime.sh — Yashigani v0.6.0
# Install Docker Engine + Compose plugin if not already present.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--help" ]; then
  cat <<'EOF'
Usage: scripts/install-runtime.sh [--help]

Installs Docker Engine and the Compose plugin for the current platform.
Skips installation if Docker is already running (docker info succeeds).

Supported platforms:
  ubuntu, debian   — Docker apt repository
  rhel, fedora     — Docker dnf repository
  amzn             — amazon-linux-extras (AL2) or dnf (AL2023)
  alpine           — apk
  macos            — Homebrew cask (Docker Desktop)

If Docker is unavailable and Podman is present, installs podman-compose
and creates a /usr/local/bin/docker symlink to podman.

Must be run as root (or with sudo) on Linux.
EOF
  exit 0
fi

# ---------------------------------------------------------------------------
# Source platform detection
# ---------------------------------------------------------------------------
# shellcheck source=scripts/platform-detect.sh
source "${SCRIPT_DIR}/platform-detect.sh"

# ---------------------------------------------------------------------------
# Color helpers (already exported by platform-detect.sh, but guard here)
# ---------------------------------------------------------------------------
_info()    { printf "${YSG_BLUE}[INFO]${YSG_RESET}  %s\n"    "$*"; }
_ok()      { printf "${YSG_GREEN}[OK]${YSG_RESET}    %s\n"   "$*"; }
_warn()    { printf "${YSG_YELLOW}[WARN]${YSG_RESET}  %s\n"  "$*"; }
_error()   { printf "${YSG_RED}[ERROR]${YSG_RESET} %s\n"     "$*" >&2; }
_die()     { _error "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Check if Docker is already running — skip if so
# ---------------------------------------------------------------------------
if docker info >/dev/null 2>&1; then
  _ok "Docker daemon is already running. Skipping installation."
  exit 0
fi

_info "Docker not running. Starting installation for distro: ${YSG_DISTRO}, arch: ${YSG_ARCH}"

# ---------------------------------------------------------------------------
# Must be root on Linux
# ---------------------------------------------------------------------------
if [ "$YSG_OS" = "linux" ] && [ "$(id -u)" -ne 0 ]; then
  _die "This script must be run as root (or via sudo) on Linux."
fi

# ---------------------------------------------------------------------------
# Install helpers
# ---------------------------------------------------------------------------
_install_ubuntu_debian() {
  local distro="$YSG_DISTRO"
  _info "Installing Docker via official apt repository for ${distro}..."

  apt-get update -y
  apt-get install -y ca-certificates curl gnupg lsb-release

  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/${distro}/gpg" \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg

  local arch_deb
  arch_deb="$(dpkg --print-architecture)"
  local codename
  codename="$(. /etc/os-release && echo "${VERSION_CODENAME:-$(lsb_release -cs)}")"

  echo \
    "deb [arch=${arch_deb} signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/${distro} ${codename} stable" \
    > /etc/apt/sources.list.d/docker.list

  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
}

_install_rhel_fedora() {
  local distro="$YSG_DISTRO"
  _info "Installing Docker via dnf for ${distro}..."

  # Both RHEL/CentOS-family and Fedora use the centos repo for now
  dnf -y install dnf-plugins-core
  dnf config-manager --add-repo \
    https://download.docker.com/linux/centos/docker-ce.repo
  dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
}

_install_amzn() {
  _info "Detecting Amazon Linux version..."
  local amzn_version
  amzn_version="$(. /etc/os-release && echo "${VERSION_ID:-2}")"

  if echo "$amzn_version" | grep -q '^2$'; then
    _info "Amazon Linux 2 — using amazon-linux-extras..."
    amazon-linux-extras install docker -y
  else
    _info "Amazon Linux 2023+ — using dnf..."
    dnf install -y docker
  fi
}

_install_alpine() {
  _info "Installing Docker via apk..."
  apk add --update docker docker-cli-compose
  rc-update add docker boot
  service docker start || true
}

_install_macos() {
  _info "Installing Docker Desktop via Homebrew..."
  if ! command -v brew >/dev/null 2>&1; then
    _die "Homebrew is not installed. Please install it from https://brew.sh first."
  fi
  brew install --cask docker
  if [ "$YSG_ARCH" = "arm64" ]; then
    _warn "Apple Silicon detected. Please open Docker Desktop manually once after" \
          "this install to complete the VM setup before using docker commands."
  fi
  _info "Docker Desktop installed. Launch it from /Applications or Spotlight."
}

_install_podman_fallback() {
  _warn "Docker is not available and Podman is present. Setting up Podman compatibility layer..."
  if [ "$YSG_OS" = "linux" ]; then
    case "$YSG_DISTRO" in
      ubuntu|debian)
        apt-get install -y podman-compose 2>/dev/null || pip3 install podman-compose
        ;;
      rhel|fedora)
        dnf install -y podman-compose 2>/dev/null || pip3 install podman-compose
        ;;
      alpine)
        apk add --update podman-compose 2>/dev/null || pip3 install podman-compose
        ;;
      *)
        pip3 install podman-compose || _warn "Could not install podman-compose automatically."
        ;;
    esac
  else
    brew install podman-compose 2>/dev/null || pip3 install podman-compose || \
      _warn "Could not install podman-compose automatically."
  fi

  if [ ! -e /usr/local/bin/docker ]; then
    _info "Creating /usr/local/bin/docker symlink -> $(command -v podman)"
    ln -sf "$(command -v podman)" /usr/local/bin/docker
  fi
  _ok "Podman compatibility layer configured."
}

# ---------------------------------------------------------------------------
# Main install dispatch
# ---------------------------------------------------------------------------
case "$YSG_DISTRO" in
  ubuntu|debian) _install_ubuntu_debian ;;
  rhel|fedora)   _install_rhel_fedora   ;;
  amzn)          _install_amzn          ;;
  alpine)        _install_alpine        ;;
  macos)         _install_macos         ;;
  *)
    if [ "$YSG_RUNTIME" = "podman" ]; then
      _install_podman_fallback
    else
      _die "Unsupported distro '${YSG_DISTRO}'. Install Docker manually: https://docs.docker.com/engine/install/"
    fi
    ;;
esac

# ---------------------------------------------------------------------------
# Post-install steps (Linux only)
# ---------------------------------------------------------------------------
if [ "$YSG_OS" = "linux" ]; then
  _info "Enabling and starting Docker daemon..."
  systemctl enable --now docker

  if [ -n "${SUDO_USER:-}" ]; then
    _info "Adding ${SUDO_USER} to the docker group..."
    usermod -aG docker "$SUDO_USER"
    _warn "Group membership change requires a re-login to take effect."
  elif [ "$(id -u)" -eq 0 ]; then
    _warn "Running as root — skipping usermod. Add your user to the docker group manually:"
    _warn "  sudo usermod -aG docker YOUR_USERNAME"
  fi

  _info "Verifying Docker installation with hello-world..."
  if docker run --rm hello-world >/dev/null 2>&1; then
    _ok "Docker hello-world ran successfully."
  else
    _warn "hello-world test failed. Docker may need a moment to start."
    _warn "Try: docker run --rm hello-world"
  fi
fi

_ok "Docker Engine + Compose plugin installation complete."
