#!/usr/bin/env bash
# detect-platform.sh — Detect hardware arch, virtualization, and cloud provider.
# Source this file: . scripts/detect-platform.sh
# Exports: ARCH, PLATFORM, CLOUD_PROVIDER, GPU_AVAILABLE, IS_VM

set -euo pipefail

# Architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)        ARCH="x86_64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *)             ARCH="unknown" ;;
esac
export ARCH

# Cloud provider detection (1s timeout, non-blocking)
CLOUD_PROVIDER="none"
IS_VM="false"

detect_aws() {
    local token
    token=$(curl -sf -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 10" \
        --connect-timeout 1 --max-time 1 2>/dev/null) || return 1
    local instance_type
    instance_type=$(curl -sf -H "X-aws-ec2-metadata-token: $token" \
        "http://169.254.169.254/latest/meta-data/instance-type" \
        --connect-timeout 1 --max-time 1 2>/dev/null) || return 1
    export CLOUD_INSTANCE_TYPE="$instance_type"
    return 0
}

detect_azure() {
    curl -sf \
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
        -H "Metadata: true" \
        --connect-timeout 1 --max-time 1 2>/dev/null | grep -q '"azEnvironment"' || return 1
}

detect_gcp() {
    curl -sf \
        "http://metadata.google.internal/computeMetadata/v1/instance/machine-type" \
        -H "Metadata-Flavor: Google" \
        --connect-timeout 1 --max-time 1 2>/dev/null | grep -q "projects/" || return 1
}

detect_vm() {
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        local virt
        virt=$(systemd-detect-virt 2>/dev/null || echo "none")
        [ "$virt" != "none" ] && return 0
    fi
    grep -qi "hypervisor" /proc/cpuinfo 2>/dev/null && return 0
    return 1
}

if detect_aws 2>/dev/null; then
    CLOUD_PROVIDER="aws"
    IS_VM="true"
    # Detect GPU instance families
    case "${CLOUD_INSTANCE_TYPE:-}" in
        p3.*|p4.*|g4.*|g5.*) GPU_AVAILABLE="true" ;;
        *)                    GPU_AVAILABLE="false" ;;
    esac
elif detect_azure 2>/dev/null; then
    CLOUD_PROVIDER="azure"
    IS_VM="true"
    GPU_AVAILABLE="false"   # Would need additional IMDS query; default to false
elif detect_gcp 2>/dev/null; then
    CLOUD_PROVIDER="gcp"
    IS_VM="true"
    GPU_AVAILABLE="false"   # GCP GPU detection via metadata /accelerators
elif detect_vm 2>/dev/null; then
    CLOUD_PROVIDER="none"
    IS_VM="true"
    GPU_AVAILABLE="false"
else
    CLOUD_PROVIDER="none"
    IS_VM="false"
    # Local GPU detection
    if command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi >/dev/null 2>&1; then
        GPU_AVAILABLE="true"
    else
        GPU_AVAILABLE="false"
    fi
fi

# Platform summary
if [ "$IS_VM" = "true" ]; then
    PLATFORM="vm_${CLOUD_PROVIDER}"
else
    PLATFORM="local_${ARCH}"
fi

export CLOUD_PROVIDER IS_VM GPU_AVAILABLE PLATFORM
