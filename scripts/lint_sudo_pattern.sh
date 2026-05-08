#!/usr/bin/env bash
# Last updated: 2026-05-02T01:00:00+01:00
#
# lint_sudo_pattern.sh — Fail if any committed file introduces forbidden
# sudo patterns.  Two classes are detected:
#
# CLASS A — piping a password into sudo via echo or printf:
#   echo 'PASSWORD' | sudo -S ...
#   printf 'PASSWORD' | sudo -S ...
#   This pattern leaks credentials into process listings and shell history.
#   The correct approach is an interactive sudo prompt or the vm_sudo() SSH
#   helper (remote ephemeral shell, macOS Keychain password, tests/upgrade/).
#
# CLASS B — sudo -n (non-interactive NOPASSWD assumption):
#   sudo -n chown ...    <- assumes NOPASSWD sudoers; fails silently otherwise
#   sudo -n systemctl ...
#   Installer bodies must run zero sudo (feedback_audience_sysadmins.md).
#   Pre-flight and operator-side scripts must use interactive sudo, not -n.
#   Retro #3bi (v2.23.1): sudo -n chown in Docker install path caused silent
#   EACCES in PKI issuer container on non-NOPASSWD sysadmin accounts.
#
# Exclusions
# ----------
# *.md files     — may show forbidden patterns as documented BAD examples.
# tests/upgrade/ — contains vm_sudo(): heredoc-wrapped remote commands that
#                  pipe a password into sudo on a *remote* VM over SSH. This
#                  is the only safe use-site (no local PTY, no NOPASSWD
#                  alternative for unprivileged remote user, password from
#                  macOS Keychain, never hardcoded). Review changes manually.
#
# Usage
#   bash scripts/lint_sudo_pattern.sh [path ...]
#   (no args = scan entire repo from CWD)

set -euo pipefail

# -- Colour helpers -----------------------------------------------------------
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[0;33m'
NC='\033[0m'

info()  { printf "${GRN}[lint-sudo]${NC} %s\n" "$*"; }
warn()  { printf "${YLW}[lint-sudo]${NC} %s\n" "$*"; }
error() { printf "${RED}[lint-sudo]${NC} %s\n" "$*" >&2; }

# -- Configuration ------------------------------------------------------------
# Class A: forbidden pipe-to-sudo pattern
PATTERN_A='(echo|printf)[^|]*\|[^|]*sudo -S'

# Class B: sudo -n (non-interactive, NOPASSWD assumption)
PATTERN_B='sudo[[:space:]]+-n[[:space:]]'

# Paths to exclude from scanning.
EXCLUDE_DIRS=(
    "tests/upgrade"
    ".git"
)

EXCLUDE_FILE_GLOBS=(
    "*.md"
    "lint_sudo_pattern.sh"
)

# -- Argument handling --------------------------------------------------------
SCAN_ROOTS=("${@:-.}")

# -- Build grep exclusion flags -----------------------------------------------
GREP_ARGS=()
for dir in "${EXCLUDE_DIRS[@]}"; do
    GREP_ARGS+=(--exclude-dir="$(basename "$dir")")
done
for glob in "${EXCLUDE_FILE_GLOBS[@]}"; do
    GREP_ARGS+=(--exclude="$glob")
done

# -- Helper: run one pattern scan, apply dir-prefix filters -------------------
run_scan() {
    local pattern="$1"
    local raw_findings

    raw_findings=$(
        grep -rEn "${GREP_ARGS[@]}" \
            "$pattern" \
            "${SCAN_ROOTS[@]}" 2>/dev/null || true
    )

    # Further filter excluded dir prefixes (--exclude-dir misses mid-path hits).
    for excl_dir in "${EXCLUDE_DIRS[@]}"; do
        raw_findings=$(printf '%s\n' "$raw_findings" | grep -v "/${excl_dir}/" || true)
        raw_findings=$(printf '%s\n' "$raw_findings" | grep -v "^${excl_dir}/" || true)
    done

    # Strip empty lines.
    printf '%s\n' "$raw_findings" | grep -v '^$' || true
}

# -- Scan ---------------------------------------------------------------------
info "Scanning for forbidden sudo patterns..."
info "Roots   : ${SCAN_ROOTS[*]}"
info "Excluded dirs  : ${EXCLUDE_DIRS[*]}"
info "Excluded globs : ${EXCLUDE_FILE_GLOBS[*]}"

FOUND_A=$(run_scan "$PATTERN_A")
FOUND_B=$(run_scan "$PATTERN_B")

EXIT_CODE=0

# -- Report -------------------------------------------------------------------
if [[ -n "$FOUND_A" ]]; then
    error "CLASS A -- forbidden echo/printf pipe-to-sudo pattern:"
    error "  (leaks credentials into process listings and shell history)"
    error ""
    while IFS= read -r line; do
        error "  $line"
    done <<< "$FOUND_A"
    error ""
    error "Fix: use an interactive sudo prompt or vm_sudo() for remote-VM calls."
    EXIT_CODE=1
fi

if [[ -n "$FOUND_B" ]]; then
    error "CLASS B -- sudo -n (NOPASSWD assumption -- retro #3bi, CWE-250):"
    error "  (sudo -n fails silently when operator has password-required sudoers)"
    error ""
    while IFS= read -r line; do
        error "  $line"
    done <<< "$FOUND_B"
    error ""
    error "Fix: installer body must use zero sudo (feedback_audience_sysadmins)."
    error "     Pre-flight operator scripts must use interactive sudo, not -n."
    EXIT_CODE=1
fi

if [[ "$EXIT_CODE" -eq 0 ]]; then
    info "No forbidden sudo patterns found. Clean."
fi

exit "$EXIT_CODE"
