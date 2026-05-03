#!/usr/bin/env bash
# Last updated: 2026-05-02T00:00:00+01:00
#
# lint_sudo_pattern.sh — Fail if any committed file introduces the forbidden
# pattern: piping a password into sudo via echo or printf.
#
#   echo 'PASSWORD' | sudo -S ...
#   printf 'PASSWORD' | sudo -S ...
#
# This pattern leaks credentials into process listings and shell history.
# The correct approach is to require an interactive sudo prompt or to use
# the dedicated vm_sudo() SSH helper which scopes the pattern to remote
# ephemeral shells.
#
# BAD (detected and rejected by this script):
#   echo 'SECRET' [pipe] sudo -S service restart      ← forbidden
#   printf '%s\n' "$PASS" [pipe] sudo -S apt install  ← forbidden
#
# Exclusions
# ----------
# *.md files     — may show the forbidden pattern as a documented BAD example.
# tests/upgrade/ — contains vm_sudo() and heredoc-wrapped remote commands that
#                  pipe a password into sudo on a *remote* VM over SSH. This is
#                  the only safe use-site: there is no local PTY, no NOPASSWD
#                  alternative for an unprivileged remote user, and the password
#                  originates from the macOS Keychain (never hardcoded).
#                  Review any change to these files manually.
#
# Usage
#   bash scripts/lint_sudo_pattern.sh [path ...]
#   (no args = scan entire repo from CWD)

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[0;33m'
NC='\033[0m'

info()  { printf "${GRN}[lint-sudo]${NC} %s\n" "$*"; }
warn()  { printf "${YLW}[lint-sudo]${NC} %s\n" "$*"; }
error() { printf "${RED}[lint-sudo]${NC} %s\n" "$*" >&2; }

# ── Configuration ─────────────────────────────────────────────────────────────
# Regex passed to grep -E; matches the forbidden pipe-to-sudo pattern.
PATTERN='(echo|printf)[^|]*\|[^|]*sudo -S'

# Paths to exclude from scanning (space-separated globs / prefix strings).
# grep --exclude-dir and --exclude handle these.
EXCLUDE_DIRS=(
    "tests/upgrade"
    ".git"
)

EXCLUDE_FILE_GLOBS=(
    "*.md"
    "lint_sudo_pattern.sh"
)

# ── Argument handling ──────────────────────────────────────────────────────────
SCAN_ROOTS=("${@:-.}")

# ── Build grep exclusion flags ─────────────────────────────────────────────────
GREP_ARGS=()
for dir in "${EXCLUDE_DIRS[@]}"; do
    GREP_ARGS+=(--exclude-dir="$(basename "$dir")")
done
for glob in "${EXCLUDE_FILE_GLOBS[@]}"; do
    GREP_ARGS+=(--exclude="$glob")
done

# ── Scan ───────────────────────────────────────────────────────────────────────
info "Scanning for forbidden sudo pipe pattern…"
info "Pattern : ${PATTERN}"
info "Roots   : ${SCAN_ROOTS[*]}"
info "Excluded dirs  : ${EXCLUDE_DIRS[*]}"
info "Excluded globs : ${EXCLUDE_FILE_GLOBS[*]}"

FINDINGS=$(
    grep -rEn "${GREP_ARGS[@]}" \
        "$PATTERN" \
        "${SCAN_ROOTS[@]}" 2>/dev/null || true
)

# Further filter out excluded dir prefixes that --exclude-dir may miss when
# scanning absolute paths or when the dir appears mid-path.
for excl_dir in "${EXCLUDE_DIRS[@]}"; do
    FINDINGS=$(printf '%s\n' "$FINDINGS" | grep -v "/${excl_dir}/" || true)
    FINDINGS=$(printf '%s\n' "$FINDINGS" | grep -v "^${excl_dir}/" || true)
done

# Strip empty lines.
FINDINGS=$(printf '%s\n' "$FINDINGS" | grep -v '^$' || true)

# ── Report ─────────────────────────────────────────────────────────────────────
if [[ -z "$FINDINGS" ]]; then
    info "No forbidden sudo pipe patterns found. Clean."
    exit 0
fi

error "Forbidden sudo pipe pattern detected in the following locations:"
error ""
while IFS= read -r line; do
    error "  $line"
done <<< "$FINDINGS"
error ""
error "Do not pipe passwords into sudo via echo/printf."
error "Use an interactive sudo prompt or the vm_sudo() SSH helper for remote calls."
error "See scripts/lint_sudo_pattern.sh for exclusion policy."
exit 1
