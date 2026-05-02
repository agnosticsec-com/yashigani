#!/usr/bin/env bash
# sign_image.sh — Sign container images with cosign and attach SBOM attestation
# Last updated: 2026-04-25T21:43:38+01:00
#
# Usage:
#   bash scripts/sign_image.sh IMAGE [IMAGE ...]
#
# Examples:
#   bash scripts/sign_image.sh ghcr.io/agnosticsec-com/yashigani-gateway:2.23.1 ghcr.io/agnosticsec-com/yashigani-backoffice:2.23.1
#
# Signing modes (detected automatically):
#   1. Keyless  — OIDC token available (GitHub Actions / Workload Identity)
#                 Uses Fulcio CA + Rekor transparency log.
#                 No key material required; recommended for CI.
#   2. Local key — COSIGN_PRIVATE_KEY env var or cosign.key file present.
#                 Key passphrase in COSIGN_PASSWORD env var.
#
# SBOM attestation:
#   If dist/sbom-yashigani-*.cdx.json exists, the newest matching file is
#   attached as a CycloneDX attestation via `cosign attest`.
#
# Verification (print-only, no network call):
#   After signing, this script prints the `cosign verify` command for docs.

set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[0;33m'
NC='\033[0m'

info()  { echo -e "${GRN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YLW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

if [[ $# -eq 0 ]]; then
    echo "Usage: bash scripts/sign_image.sh IMAGE [IMAGE ...]" >&2
    echo "Example: bash scripts/sign_image.sh ghcr.io/agnosticsec-com/yashigani-gateway:2.23.1" >&2
    exit 1
fi

if ! command -v cosign &>/dev/null; then
    error "cosign not found in PATH.
Install it:
  # Linux / macOS (Homebrew)
  brew install cosign

  # Linux binary
  curl -sLO https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
  chmod +x cosign-linux-amd64 && sudo mv cosign-linux-amd64 /usr/local/bin/cosign

  # GitHub Actions
  uses: sigstore/cosign-installer@v3"
fi

COSIGN_VERSION=$(cosign version 2>/dev/null | grep -E '^GitVersion' | awk '{print $2}' || cosign version 2>&1 | head -1)
info "cosign detected: ${COSIGN_VERSION}"

# ---------------------------------------------------------------------------
# Signing mode detection
# ---------------------------------------------------------------------------

KEYLESS=false
LOCAL_KEY=false
KEY_FLAGS=()
SIGN_ENV=()

if [[ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]] || \
   [[ -n "${GOOGLE_SERVICE_ACCOUNT_NAME:-}" ]] || \
   [[ "${COSIGN_EXPERIMENTAL:-0}" == "1" ]]; then
    # GitHub Actions OIDC or explicit keyless mode
    KEYLESS=true
    info "Signing mode: KEYLESS (Fulcio + Rekor)"

elif [[ -n "${COSIGN_PRIVATE_KEY:-}" ]]; then
    LOCAL_KEY=true
    KEY_FLAGS+=(--key env://COSIGN_PRIVATE_KEY)
    SIGN_ENV+=("COSIGN_PRIVATE_KEY=${COSIGN_PRIVATE_KEY}")
    [[ -n "${COSIGN_PASSWORD:-}" ]] && SIGN_ENV+=("COSIGN_PASSWORD=${COSIGN_PASSWORD}")
    info "Signing mode: LOCAL KEY (env var COSIGN_PRIVATE_KEY)"

elif [[ -f cosign.key ]]; then
    LOCAL_KEY=true
    KEY_FLAGS+=(--key cosign.key)
    info "Signing mode: LOCAL KEY (cosign.key file)"
    warn "Set COSIGN_PASSWORD env var if the key has a passphrase."

else
    warn "No signing credentials detected. Attempting keyless as default."
    warn "Set COSIGN_PRIVATE_KEY or ensure OIDC token is available."
    KEYLESS=true
fi

# ---------------------------------------------------------------------------
# Locate SBOM (newest match wins)
# ---------------------------------------------------------------------------

SBOM_FILE=""
if [[ -d dist ]]; then
    SBOM_FILE=$(ls -t dist/sbom-yashigani-*.cdx.json 2>/dev/null | head -1 || true)
fi

if [[ -n "${SBOM_FILE}" ]]; then
    info "SBOM found: ${SBOM_FILE}"
else
    warn "No dist/sbom-yashigani-*.cdx.json found. Run scripts/generate_sbom.py first."
    warn "SBOM attestation will be skipped."
fi

# ---------------------------------------------------------------------------
# Sign and attest each image
# ---------------------------------------------------------------------------

IMAGES=("$@")
VERIFY_CMDS=()

for IMAGE in "${IMAGES[@]}"; do
    info "Processing: ${IMAGE}"

    # -- Sign --
    SIGN_CMD=(cosign sign --yes)

    if $LOCAL_KEY; then
        SIGN_CMD+=("${KEY_FLAGS[@]}")
    fi
    # For keyless: no --key flag; cosign uses ambient OIDC credentials

    SIGN_CMD+=("${IMAGE}")

    info "Running: ${SIGN_CMD[*]}"
    if $LOCAL_KEY && [[ -n "${COSIGN_PRIVATE_KEY:-}" ]]; then
        env "${SIGN_ENV[@]}" "${SIGN_CMD[@]}"
    else
        "${SIGN_CMD[@]}"
    fi
    info "Signed: ${IMAGE}"

    # -- Attest SBOM --
    if [[ -n "${SBOM_FILE}" ]]; then
        ATTEST_CMD=(cosign attest --yes --predicate "${SBOM_FILE}" --type cyclonedx)
        if $LOCAL_KEY; then
            ATTEST_CMD+=("${KEY_FLAGS[@]}")
        fi
        ATTEST_CMD+=("${IMAGE}")

        info "Attaching SBOM attestation: ${SBOM_FILE}"
        if $LOCAL_KEY && [[ -n "${COSIGN_PRIVATE_KEY:-}" ]]; then
            env "${SIGN_ENV[@]}" "${ATTEST_CMD[@]}"
        else
            "${ATTEST_CMD[@]}"
        fi
        info "SBOM attestation attached: ${IMAGE}"
    fi

    # -- Build verify command for documentation --
    if $KEYLESS; then
        # Keyless: caller must supply the expected OIDC issuer and identity
        VERIFY_CMDS+=("cosign verify \\
    --certificate-identity-regexp='https://github.com/.*' \\
    --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \\
    ${IMAGE}")
    else
        VERIFY_CMDS+=("cosign verify --key cosign.pub ${IMAGE}")
    fi
done

# ---------------------------------------------------------------------------
# Print verification commands
# ---------------------------------------------------------------------------

echo ""
echo "========================================================"
echo " Verification commands (copy into docs or README)"
echo "========================================================"
echo ""
for CMD in "${VERIFY_CMDS[@]}"; do
    echo "# Verify image signature"
    echo "${CMD}"
    echo ""
done

if [[ -n "${SBOM_FILE}" ]]; then
    for IMAGE in "${IMAGES[@]}"; do
        if $KEYLESS; then
            ATTEST_VERIFY="cosign verify-attestation \\
    --type cyclonedx \\
    --certificate-identity-regexp='https://github.com/.*' \\
    --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \\
    ${IMAGE} | jq '.[0].payload | @base64d | fromjson'"
        else
            ATTEST_VERIFY="cosign verify-attestation \\
    --type cyclonedx \\
    --key cosign.pub \\
    ${IMAGE} | jq '.[0].payload | @base64d | fromjson'"
        fi
        echo "# Extract SBOM attestation from ${IMAGE}"
        echo "${ATTEST_VERIFY}"
        echo ""
    done
fi

echo "========================================================"
info "Done."
