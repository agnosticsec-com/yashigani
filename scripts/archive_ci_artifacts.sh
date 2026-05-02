#!/usr/bin/env bash
# Last updated: 2026-05-02T06:58:47+01:00
# archive_ci_artifacts.sh — Download CI gate evidence and archive it for release.
#
# Usage:
#   scripts/archive_ci_artifacts.sh <commit-sha> <version>
#
# Examples:
#   scripts/archive_ci_artifacts.sh ec46ab4 2.23.1
#   scripts/archive_ci_artifacts.sh abc1234 2.24.0
#
# Prerequisites:
#   - gh CLI installed and authenticated (gh auth status must show logged-in)
#   - PAT must have: repo, read:packages  (workflow scope NOT needed for download)
#   - Run from inside the yashigani repo directory
#
# Output:
#   /Users/max/Documents/Claude/Internal/Compliance/yashigani/v<version>/ci-evidence/<sha>/
#   ├── unit-tests-py3.12-<sha>/
#   │   ├── test-results-3.12.xml
#   │   └── verdict-3.12.txt          # grep: "Unit tests: PASS"
#   ├── unit-tests-py3.13-<sha>/
#   │   ├── test-results-3.13.xml
#   │   └── verdict-3.13.txt          # grep: "Unit tests: PASS"
#   ├── mypy-<sha>/
#   │   ├── mypy-xml/index.xml
#   │   ├── mypy-output.txt
#   │   └── mypy-summary.txt          # grep: "Type check: PASS"
#   ├── opengrep-<sha>/
#   │   ├── opengrep-results.json
#   │   └── opengrep-summary.txt      # grep: "Opengrep: PASS"
#   └── archive-manifest.txt          # summary of all downloaded artifacts
#
# Pre-flight grep-check (run before tagging a release):
# NOTE: artifact dirs embed the full SHA; use glob to match regardless of
# whether COMMIT_SHA is short or full.
#
#   SHA=$(git rev-parse ec46ab4) VER=2.23.1
#   BASE=/Users/max/Documents/Claude/Internal/Compliance/yashigani/v${VER}/ci-evidence/${SHA}
#   grep -q "Unit tests: PASS" "${BASE}"/unit-tests-py3.12-*/verdict-3.12.txt \
#     && grep -q "Unit tests: PASS" "${BASE}"/unit-tests-py3.13-*/verdict-3.13.txt \
#     && grep -q "Type check: PASS" "${BASE}"/mypy-*/mypy-summary.txt \
#     && grep -q "Opengrep: PASS"   "${BASE}"/opengrep-*/opengrep-summary.txt \
#     && echo "ALL CI GATES PASS — safe to tag" \
#     || echo "FAIL — one or more gates not green"

set -euo pipefail

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------
if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <commit-sha> <version>" >&2
    echo "  e.g. $0 ec46ab4 2.23.1" >&2
    exit 1
fi

COMMIT_SHA_INPUT="$1"
VERSION="$2"

# ---------------------------------------------------------------------------
# Resolve full SHA (GitHub artifact names embed the full 40-char SHA)
# ---------------------------------------------------------------------------
# Accept either short (7+) or full (40) SHA. Expand to full via git rev-parse
# so artifact directory matching works regardless of input length.
COMMIT_SHA=$(git rev-parse "${COMMIT_SHA_INPUT}" 2>/dev/null) || {
    echo "[WARN] git rev-parse failed for '${COMMIT_SHA_INPUT}' — using as-is" >&2
    COMMIT_SHA="${COMMIT_SHA_INPUT}"
}
COMMIT_SHA_SHORT="${COMMIT_SHA:0:7}"
echo "[info] Commit: ${COMMIT_SHA} (short: ${COMMIT_SHA_SHORT})"

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
# Archive directory uses the full SHA to match artifact names from CI.
ARCHIVE_BASE="/Users/max/Documents/Claude/Internal/Compliance/yashigani/v${VERSION}/ci-evidence/${COMMIT_SHA}"
DOWNLOAD_TMP="/Users/max/Documents/Claude/Internal/Compliance/yashigani/v${VERSION}/ci-evidence/.tmp-download-${COMMIT_SHA_SHORT}"

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
echo "[preflight] Checking gh CLI..."
if ! command -v gh &>/dev/null; then
    echo "[ERROR] gh CLI not found. Install with: brew install gh (macOS) or see https://cli.github.com" >&2
    exit 1
fi

echo "[preflight] Checking gh auth..."
if ! gh auth status &>/dev/null; then
    echo "[ERROR] gh CLI not authenticated. Run: gh auth login" >&2
    exit 1
fi

echo "[preflight] Resolving repo from git remote..."
REPO=$(gh repo view --json nameWithOwner -q '.nameWithOwner' 2>/dev/null) || {
    echo "[ERROR] Could not resolve repo. Run from inside the yashigani git repository." >&2
    exit 1
}
echo "[preflight] Repo: ${REPO}"

# ---------------------------------------------------------------------------
# Find CI runs for this commit
# ---------------------------------------------------------------------------
echo "[info] Looking up workflow runs for commit ${COMMIT_SHA}..."

# List runs matching the commit; both 'CI' and 'Security Scan' workflows are
# needed. gh run list returns JSON with runDatabaseId.
RUNS_JSON=$(gh run list \
    --repo "${REPO}" \
    --commit "${COMMIT_SHA}" \
    --json databaseId,workflowName,status,conclusion,url \
    --limit 20)

echo "[info] Runs found:"
echo "${RUNS_JSON}" | python3 -c "
import json, sys
runs = json.load(sys.stdin)
for r in runs:
    print(f\"  [{r.get('conclusion','pending')}] {r['workflowName']} (id={r['databaseId']}) {r['url']}\")
"

# ---------------------------------------------------------------------------
# Verify runs completed
# ---------------------------------------------------------------------------
INCOMPLETE=$(echo "${RUNS_JSON}" | python3 -c "
import json, sys
runs = json.load(sys.stdin)
incomplete = [r for r in runs if r.get('status') not in ('completed',)]
for r in incomplete:
    print(f\"{r['workflowName']} status={r.get('status')}\")
")
if [[ -n "${INCOMPLETE}" ]]; then
    echo "[WARN] Some runs are not yet completed:" >&2
    echo "${INCOMPLETE}" >&2
    echo "[WARN] Proceeding — artifacts from completed jobs may still be downloadable." >&2
fi

# ---------------------------------------------------------------------------
# Download artifacts
# ---------------------------------------------------------------------------
mkdir -p "${DOWNLOAD_TMP}"
mkdir -p "${ARCHIVE_BASE}"

# Extract run IDs that have succeeded or completed
RUN_IDS=$(echo "${RUNS_JSON}" | python3 -c "
import json, sys
runs = json.load(sys.stdin)
# Download from all completed runs regardless of conclusion (FAIL runs still
# have artifacts — that is the whole point of 'if: always()' upload steps).
ids = [str(r['databaseId']) for r in runs if r.get('status') == 'completed']
print('\n'.join(ids))
")

if [[ -z "${RUN_IDS}" ]]; then
    echo "[ERROR] No completed runs found for commit ${COMMIT_SHA}." >&2
    echo "        Trigger CI on this commit, wait for completion, then re-run." >&2
    exit 1
fi

DOWNLOAD_COUNT=0
while IFS= read -r RUN_ID; do
    [[ -z "${RUN_ID}" ]] && continue
    echo "[download] Run ${RUN_ID}..."
    RUN_DOWNLOAD_DIR="${DOWNLOAD_TMP}/${RUN_ID}"
    mkdir -p "${RUN_DOWNLOAD_DIR}"
    # gh run download extracts each artifact into a subdirectory named after
    # the artifact. We capture all artifacts from the run; the evidence
    # selection step below picks only the three gate artifacts.
    if gh run download "${RUN_ID}" \
        --repo "${REPO}" \
        --dir "${RUN_DOWNLOAD_DIR}" 2>&1; then
        echo "[download] Run ${RUN_ID} OK"
        DOWNLOAD_COUNT=$((DOWNLOAD_COUNT + 1))
    else
        echo "[WARN] Run ${RUN_ID} download failed or had no artifacts" >&2
    fi
done <<< "${RUN_IDS}"

if [[ "${DOWNLOAD_COUNT}" -eq 0 ]]; then
    echo "[ERROR] No artifacts downloaded. Verify CI ran with artifact upload steps." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Move gate artifacts into the canonical evidence path
# ---------------------------------------------------------------------------
echo "[archive] Selecting gate artifacts..."

ARTIFACTS_FOUND=0

# Walk all downloaded artifact directories and copy named gate artifacts.
find "${DOWNLOAD_TMP}" -mindepth 2 -maxdepth 2 -type d | while IFS= read -r ADIR; do
    ANAME=$(basename "${ADIR}")
    case "${ANAME}" in
        unit-tests-py3.12-*)
            DEST="${ARCHIVE_BASE}/${ANAME}"
            mkdir -p "${DEST}"
            cp -r "${ADIR}/." "${DEST}/"
            echo "[archive] Captured: ${ANAME}"
            ;;
        unit-tests-py3.13-*)
            DEST="${ARCHIVE_BASE}/${ANAME}"
            mkdir -p "${DEST}"
            cp -r "${ADIR}/." "${DEST}/"
            echo "[archive] Captured: ${ANAME}"
            ;;
        mypy-*)
            DEST="${ARCHIVE_BASE}/${ANAME}"
            mkdir -p "${DEST}"
            cp -r "${ADIR}/." "${DEST}/"
            echo "[archive] Captured: ${ANAME}"
            ;;
        opengrep-*)
            DEST="${ARCHIVE_BASE}/${ANAME}"
            mkdir -p "${DEST}"
            cp -r "${ADIR}/." "${DEST}/"
            echo "[archive] Captured: ${ANAME}"
            ;;
        *)
            # Other artifacts (bandit, pip-audit, etc.) are NOT copied here.
            # They live in separate evidence paths. This script is gate-specific.
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Emit archive manifest
# ---------------------------------------------------------------------------
MANIFEST="${ARCHIVE_BASE}/archive-manifest.txt"
{
    echo "Archive: ci-evidence for ${COMMIT_SHA}"
    echo "Version: ${VERSION}"
    echo "Repo: ${REPO}"
    echo "Generated: $(date -Iseconds)"
    echo ""
    echo "Files:"
    find "${ARCHIVE_BASE}" -type f | sort | sed "s|${ARCHIVE_BASE}/||"
} > "${MANIFEST}"
echo "[archive] Manifest written: ${MANIFEST}"

# ---------------------------------------------------------------------------
# Validate gate verdicts
# ---------------------------------------------------------------------------
echo ""
echo "=== Gate Verdict Check ==="

GATE_PASS=true

check_verdict() {
    local label="$1"
    local glob_pattern="$2"
    local grep_pattern="$3"
    # Use glob expansion — artifact dirs embed full SHA which may differ from
    # the COMMIT_SHA variable if the caller passed a short SHA that resolved.
    local match
    match=$(find "${ARCHIVE_BASE}" -path "${glob_pattern}" -type f 2>/dev/null | head -1)
    if [[ -n "${match}" ]] && grep -q "${grep_pattern}" "${match}"; then
        echo "  [PASS] ${label} (${match##${ARCHIVE_BASE}/})"
    else
        echo "  [FAIL] ${label} — file not found or verdict not PASS"
        echo "         Expected pattern: ${grep_pattern}"
        echo "         Expected glob: ${glob_pattern}"
        GATE_PASS=false
    fi
}

check_verdict "Unit tests (py3.12)" \
    "${ARCHIVE_BASE}/unit-tests-py3.12-*/verdict-3.12.txt" \
    "Unit tests: PASS"

check_verdict "Unit tests (py3.13)" \
    "${ARCHIVE_BASE}/unit-tests-py3.13-*/verdict-3.13.txt" \
    "Unit tests: PASS"

check_verdict "Type check (mypy)" \
    "${ARCHIVE_BASE}/mypy-*/mypy-summary.txt" \
    "Type check: PASS"

check_verdict "Opengrep" \
    "${ARCHIVE_BASE}/opengrep-*/opengrep-summary.txt" \
    "Opengrep: PASS"

echo ""
if [[ "${GATE_PASS}" == "true" ]]; then
    echo "ALL CI GATES PASS — archive complete at:"
    echo "  ${ARCHIVE_BASE}"
    echo ""
    echo "Pre-flight one-liner for tagging:"
    cat <<ONELINER
  SHA=${COMMIT_SHA} VER=${VERSION}
  BASE=/Users/max/Documents/Claude/Internal/Compliance/yashigani/v\${VER}/ci-evidence/\${SHA}
  grep -q "Unit tests: PASS" "\${BASE}"/unit-tests-py3.12-*/verdict-3.12.txt \\
    && grep -q "Unit tests: PASS" "\${BASE}"/unit-tests-py3.13-*/verdict-3.13.txt \\
    && grep -q "Type check: PASS" "\${BASE}"/mypy-*/mypy-summary.txt \\
    && grep -q "Opengrep: PASS"   "\${BASE}"/opengrep-*/opengrep-summary.txt \\
    && echo "ALL CI GATES PASS — safe to tag" \\
    || echo "FAIL — one or more gates not green"
ONELINER
else
    echo "[FAIL] One or more gates did not pass. Review artifacts above." >&2
    echo "       Archive still written to: ${ARCHIVE_BASE}" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
rm -rf "${DOWNLOAD_TMP}"
echo "[cleanup] Temporary download directory removed."
