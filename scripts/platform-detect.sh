#!/usr/bin/env bash
# scripts/platform-detect.sh — Yashigani v0.6.0
# Full platform detection. Source this script; exports YSG_* environment variables.

set -euo pipefail

# ---------------------------------------------------------------------------
# Color helpers (only when stdout is a TTY)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  YSG_RED='\033[0;31m'
  YSG_GREEN='\033[0;32m'
  YSG_YELLOW='\033[1;33m'
  YSG_BLUE='\033[0;34m'
  YSG_RESET='\033[0m'
else
  YSG_RED=''
  YSG_GREEN=''
  YSG_YELLOW=''
  YSG_BLUE=''
  YSG_RESET=''
fi
export YSG_RED YSG_GREEN YSG_YELLOW YSG_BLUE YSG_RESET

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--help" ]; then
  cat <<'EOF'
Usage: source scripts/platform-detect.sh [--help]

Detects the current platform and exports the following variables:

  YSG_OS       — "linux" | "macos"
  YSG_DISTRO   — "ubuntu" | "debian" | "rhel" | "fedora" | "amzn" | "alpine" | "arch" | "macos"
  YSG_ARCH     — "amd64" | "arm64"
  YSG_CLOUD    — "aws" | "gcp" | "azure" | "digitalocean" | "hetzner" | "none"
  YSG_VM       — "kvm" | "vmware" | "virtualbox" | "hyperv" | "none"
  YSG_RUNTIME  — "docker" | "podman" | "none"
  YSG_COMPOSE  — "plugin" | "standalone" | "none"
  YSG_K8S      — "true" | "false"

Set YSG_DETECT_VERBOSE=1 before sourcing to print detected values.
EOF
  exit 0
fi

# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------
_detect_os() {
  case "$(uname -s)" in
    Linux*)  echo "linux" ;;
    Darwin*) echo "macos" ;;
    *)       echo "linux" ;;
  esac
}

# ---------------------------------------------------------------------------
# Distro detection
# ---------------------------------------------------------------------------
_detect_distro() {
  local os="$1"
  if [ "$os" = "macos" ]; then
    echo "macos"
    return
  fi
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    local id
    id="$(. /etc/os-release && echo "${ID:-unknown}")"
    case "$id" in
      ubuntu)  echo "ubuntu"  ;;
      debian)  echo "debian"  ;;
      rhel|centos|rocky|almalinux) echo "rhel" ;;
      fedora)  echo "fedora"  ;;
      amzn)    echo "amzn"    ;;
      alpine)  echo "alpine"  ;;
      arch)    echo "arch"    ;;
      *)       echo "$id"     ;;
    esac
    return
  fi
  if [ -f /etc/debian_version ]; then echo "debian"; return; fi
  if [ -f /etc/redhat-release ]; then echo "rhel";   return; fi
  if [ -f /etc/alpine-release ]; then echo "alpine"; return; fi
  echo "unknown"
}

# ---------------------------------------------------------------------------
# Architecture detection
# ---------------------------------------------------------------------------
_detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo "amd64"  ;;
    aarch64|arm64) echo "arm64"  ;;
    *)             echo "amd64"  ;;
  esac
}

# ---------------------------------------------------------------------------
# Cloud detection (curl with 1s timeout, no auth required)
# ---------------------------------------------------------------------------
_curl_probe() {
  # $1 = url, remaining args passed to curl
  curl --silent --max-time 1 --connect-timeout 1 -o /dev/null -w "%{http_code}" "$@" 2>/dev/null || echo "000"
}

_detect_cloud() {
  local code

  # AWS — try IMDSv2 token first, fall back to plain IMDSv1 probe
  local aws_token
  aws_token="$(curl --silent --max-time 1 --connect-timeout 1 \
    -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 10" 2>/dev/null || true)"
  if [ -n "$aws_token" ]; then
    code="$(_curl_probe "http://169.254.169.254/latest/meta-data/" \
      -H "X-aws-ec2-metadata-token: ${aws_token}")"
    [ "$code" = "200" ] && echo "aws" && return
  fi
  code="$(_curl_probe "http://169.254.169.254/latest/meta-data/")"
  [ "$code" = "200" ] && echo "aws" && return

  # GCP
  code="$(_curl_probe "http://metadata.google.internal/computeMetadata/v1/" \
    -H "Metadata-Flavor: Google")"
  [ "$code" = "200" ] && echo "gcp" && return

  # Azure
  code="$(_curl_probe \
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
    -H "Metadata: true")"
  [ "$code" = "200" ] && echo "azure" && return

  # DigitalOcean
  code="$(_curl_probe "http://169.254.169.254/metadata/v1/id")"
  [ "$code" = "200" ] && echo "digitalocean" && return

  # Hetzner — check response headers for "server: hetzner"
  local hetzner_header
  hetzner_header="$(curl --silent --max-time 1 --connect-timeout 1 \
    -D - -o /dev/null "http://169.254.169.254/" 2>/dev/null | \
    tr '[:upper:]' '[:lower:]' | grep -i '^server:' || true)"
  if echo "$hetzner_header" | grep -qi 'hetzner'; then
    echo "hetzner" && return
  fi

  echo "none"
}

# ---------------------------------------------------------------------------
# VM detection
# ---------------------------------------------------------------------------
_detect_vm() {
  # Try systemd-detect-virt first
  if command -v systemd-detect-virt >/dev/null 2>&1; then
    local virt
    virt="$(systemd-detect-virt 2>/dev/null || echo "none")"
    case "$virt" in
      kvm|qemu)     echo "kvm"        && return ;;
      vmware)       echo "vmware"     && return ;;
      oracle)       echo "virtualbox" && return ;;
      microsoft)    echo "hyperv"     && return ;;
      none)         echo "none"       && return ;;
      *)            ;;
    esac
  fi

  # Fall back to DMI strings
  local dmi_product=""
  for f in /sys/class/dmi/id/product_name /sys/class/dmi/id/sys_vendor \
            /sys/class/dmi/id/board_vendor; do
    [ -r "$f" ] && dmi_product="$dmi_product $(cat "$f" 2>/dev/null || true)"
  done
  dmi_product="$(echo "$dmi_product" | tr '[:upper:]' '[:lower:]')"

  case "$dmi_product" in
    *kvm*|*qemu*)        echo "kvm"        && return ;;
    *vmware*)            echo "vmware"     && return ;;
    *virtualbox*)        echo "virtualbox" && return ;;
    *"microsoft corporation"*) echo "hyperv" && return ;;
  esac

  # Fall back to /proc/cpuinfo
  if [ -r /proc/cpuinfo ]; then
    local cpuinfo
    cpuinfo="$(tr '[:upper:]' '[:lower:]' < /proc/cpuinfo)"
    echo "$cpuinfo" | grep -qi 'kvm\|qemu'      && echo "kvm"        && return
    echo "$cpuinfo" | grep -qi 'vmware'          && echo "vmware"     && return
    echo "$cpuinfo" | grep -qi 'virtualbox\|vbox' && echo "virtualbox" && return
  fi

  echo "none"
}

# ---------------------------------------------------------------------------
# Container runtime detection
# ---------------------------------------------------------------------------
_detect_runtime() {
  if command -v docker >/dev/null 2>&1; then
    if docker info >/dev/null 2>&1; then
      echo "docker" && return
    fi
  fi
  if command -v podman >/dev/null 2>&1; then
    echo "podman" && return
  fi
  echo "none"
}

# ---------------------------------------------------------------------------
# Compose detection
# ---------------------------------------------------------------------------
_detect_compose() {
  if docker compose version >/dev/null 2>&1; then
    echo "plugin" && return
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    echo "standalone" && return
  fi
  echo "none"
}

# ---------------------------------------------------------------------------
# Kubernetes detection
# ---------------------------------------------------------------------------
_detect_k8s() {
  if command -v kubectl >/dev/null 2>&1 && command -v helm >/dev/null 2>&1; then
    echo "true"
  else
    echo "false"
  fi
}

# ---------------------------------------------------------------------------
# Run all detections
# ---------------------------------------------------------------------------
YSG_OS="$(_detect_os)"
YSG_DISTRO="$(_detect_distro "$YSG_OS")"
YSG_ARCH="$(_detect_arch)"
YSG_CLOUD="$(_detect_cloud)"
YSG_VM="$(_detect_vm)"
YSG_RUNTIME="$(_detect_runtime)"
YSG_COMPOSE="$(_detect_compose)"
YSG_K8S="$(_detect_k8s)"

export YSG_OS YSG_DISTRO YSG_ARCH YSG_CLOUD YSG_VM YSG_RUNTIME YSG_COMPOSE YSG_K8S

# ---------------------------------------------------------------------------
# Verbose output
# ---------------------------------------------------------------------------
if [ "${YSG_DETECT_VERBOSE:-0}" = "1" ]; then
  printf "${YSG_BLUE}Platform detection results:${YSG_RESET}\n"
  printf "  %-20s %s\n" "YSG_OS"      "$YSG_OS"
  printf "  %-20s %s\n" "YSG_DISTRO"  "$YSG_DISTRO"
  printf "  %-20s %s\n" "YSG_ARCH"    "$YSG_ARCH"
  printf "  %-20s %s\n" "YSG_CLOUD"   "$YSG_CLOUD"
  printf "  %-20s %s\n" "YSG_VM"      "$YSG_VM"
  printf "  %-20s %s\n" "YSG_RUNTIME" "$YSG_RUNTIME"
  printf "  %-20s %s\n" "YSG_COMPOSE" "$YSG_COMPOSE"
  printf "  %-20s %s\n" "YSG_K8S"     "$YSG_K8S"
fi
