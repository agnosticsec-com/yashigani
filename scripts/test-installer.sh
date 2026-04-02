#!/usr/bin/env bash
# scripts/test-installer.sh — Yashigani v2.0.0
# Local installer test suite. Runs on the developer's machine to verify
# install.sh, platform-detect.sh, and preflight.sh work correctly.
#
# Usage:
#   bash scripts/test-installer.sh              # Run all tests
#   bash scripts/test-installer.sh --quick       # Platform detection only
#   bash scripts/test-installer.sh --preflight   # Preflight only
#   bash scripts/test-installer.sh --install     # Full install dry-run

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Colors
if [ -t 1 ]; then
  GREEN='\033[1;32m'; RED='\033[1;31m'; YELLOW='\033[1;33m'
  BLUE='\033[1;34m'; BOLD='\033[1m'; RESET='\033[0m'
else
  GREEN=''; RED=''; YELLOW=''; BLUE=''; BOLD=''; RESET=''
fi

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

_pass() { PASS_COUNT=$((PASS_COUNT + 1)); printf "  ${GREEN}PASS${RESET}  %s\n" "$1"; }
_fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); printf "  ${RED}FAIL${RESET}  %s\n" "$1"; }
_warn() { WARN_COUNT=$((WARN_COUNT + 1)); printf "  ${YELLOW}WARN${RESET}  %s\n" "$1"; }
_info() { printf "  ${BLUE}....${RESET}  %s\n" "$1"; }

# =========================================================================
# TEST 1: Platform detection
# =========================================================================
test_platform_detection() {
  printf "\n${BOLD}=== Test 1: Platform Detection ===${RESET}\n\n"

  # Source platform-detect.sh
  (
    source "${REPO_DIR}/scripts/platform-detect.sh" 2>/dev/null

    # OS detection
    if [ -n "$YSG_OS" ] && [ "$YSG_OS" != "unknown" ]; then
      _pass "OS detected: ${YSG_OS}"
    else
      _fail "OS not detected (YSG_OS=${YSG_OS:-unset})"
    fi

    # Distro
    if [ -n "$YSG_DISTRO" ] && [ "$YSG_DISTRO" != "unknown" ]; then
      _pass "Distro detected: ${YSG_DISTRO}"
    else
      _warn "Distro not detected (YSG_DISTRO=${YSG_DISTRO:-unset})"
    fi

    # Architecture
    if [ -n "$YSG_ARCH" ] && [ "$YSG_ARCH" != "unknown" ]; then
      _pass "Architecture detected: ${YSG_ARCH}"
    else
      _fail "Architecture not detected (YSG_ARCH=${YSG_ARCH:-unset})"
    fi

    # Runtime
    if [ -n "$YSG_RUNTIME" ] && [ "$YSG_RUNTIME" != "none" ]; then
      _pass "Runtime detected: ${YSG_RUNTIME}"
    else
      _fail "Runtime not detected (YSG_RUNTIME=${YSG_RUNTIME:-unset})"
    fi

    # Compose
    if [ "$YSG_COMPOSE" != "none" ]; then
      _pass "Compose detected: ${YSG_COMPOSE}"
    else
      _warn "Compose not detected (YSG_COMPOSE=${YSG_COMPOSE:-unset})"
    fi

    # GPU
    if [ -n "$YSG_GPU_TYPE" ] && [ "$YSG_GPU_TYPE" != "none" ]; then
      _pass "GPU detected: ${YSG_GPU_TYPE} — ${YSG_GPU_NAME}"
      local _vram_gb
      _vram_gb="$(awk "BEGIN { printf \"%.1f\", ${YSG_GPU_VRAM_MB} / 1024 }")"
      _pass "GPU VRAM: ${YSG_GPU_VRAM_MB} MB (${_vram_gb} GB)"
      _pass "GPU compute: ${YSG_GPU_COMPUTE}"
    else
      _warn "No GPU detected (YSG_GPU_TYPE=${YSG_GPU_TYPE:-unset})"
    fi

    # Cloud
    _info "Cloud: ${YSG_CLOUD} (expected 'none' on local machine)"

    # VM
    _info "VM: ${YSG_VM} (expected 'none' on bare metal)"
  )
}

# =========================================================================
# TEST 2: Bash 3.2 compatibility
# =========================================================================
test_bash_compat() {
  printf "\n${BOLD}=== Test 2: Bash 3.2 Compatibility ===${RESET}\n\n"

  # Check for bash 4+ syntax in install.sh
  local bad_syntax=0

  # ${var,,} and ${var^^} — bash 4+ case conversion
  if grep -nE '\$\{[a-zA-Z_]+,,\}|\$\{[a-zA-Z_]+\^\^\}' "${REPO_DIR}/install.sh" 2>/dev/null; then
    _fail "install.sh contains \${var,,} or \${var^^} (bash 4+ only)"
    bad_syntax=1
  else
    _pass "No \${var,,} / \${var^^} syntax in install.sh"
  fi

  # declare -A — bash 4+ associative arrays
  if grep -nE 'declare\s+-A' "${REPO_DIR}/install.sh" 2>/dev/null; then
    _fail "install.sh uses declare -A (bash 4+ associative arrays)"
    bad_syntax=1
  else
    _pass "No associative arrays in install.sh"
  fi

  # readarray / mapfile — bash 4+
  if grep -nE '\breadarray\b|\bmapfile\b' "${REPO_DIR}/install.sh" 2>/dev/null; then
    _fail "install.sh uses readarray/mapfile (bash 4+)"
    bad_syntax=1
  else
    _pass "No readarray/mapfile in install.sh"
  fi

  # &>> — bash 4+ redirect
  if grep -nE '&>>' "${REPO_DIR}/install.sh" 2>/dev/null; then
    _fail "install.sh uses &>> (bash 4+)"
    bad_syntax=1
  else
    _pass "No &>> redirects in install.sh"
  fi

  # Check scripts too
  for script in preflight.sh platform-detect.sh; do
    if grep -nE '\$\{[a-zA-Z_]+,,\}|\$\{[a-zA-Z_]+\^\^\}|declare\s+-A|\breadarray\b|\bmapfile\b' "${REPO_DIR}/scripts/${script}" 2>/dev/null; then
      _fail "${script} contains bash 4+ syntax"
      bad_syntax=1
    else
      _pass "${script} — no bash 4+ syntax"
    fi
  done

  if [ "$bad_syntax" -eq 0 ]; then
    _pass "All scripts compatible with bash 3.2 (macOS default)"
  fi
}

# =========================================================================
# TEST 3: Variable name consistency
# =========================================================================
test_variable_names() {
  printf "\n${BOLD}=== Test 3: Variable Name Consistency ===${RESET}\n\n"

  # Check install.sh does NOT reference old DETECTED_* vars
  if grep -nE 'DETECTED_OS|DETECTED_ARCH|DETECTED_RUNTIME' "${REPO_DIR}/install.sh" 2>/dev/null; then
    _fail "install.sh still references DETECTED_* variables (should use YSG_*)"
  else
    _pass "install.sh uses YSG_* variables (no DETECTED_* references)"
  fi

  # Check install.sh DOES reference YSG_* vars
  if grep -q 'YSG_OS' "${REPO_DIR}/install.sh" 2>/dev/null; then
    _pass "install.sh references YSG_OS"
  else
    _fail "install.sh does not reference YSG_OS"
  fi

  if grep -q 'YSG_GPU_TYPE' "${REPO_DIR}/install.sh" 2>/dev/null; then
    _pass "install.sh references YSG_GPU_TYPE"
  else
    _fail "install.sh does not reference YSG_GPU_TYPE"
  fi
}

# =========================================================================
# TEST 4: Preflight checks
# =========================================================================
test_preflight() {
  printf "\n${BOLD}=== Test 4: Preflight Checks ===${RESET}\n\n"

  local result
  if result="$(bash "${REPO_DIR}/scripts/preflight.sh" --skip-ports --skip-dns 2>&1)"; then
    _pass "Preflight passed"
    # Show the output
    echo "$result" | grep -E '✓|✗|⚠' | while IFS= read -r line; do
      _info "$line"
    done
  else
    local exit_code=$?
    _warn "Preflight exited with code ${exit_code}"
    echo "$result" | grep -E '✓|✗|⚠' | while IFS= read -r line; do
      _info "$line"
    done
    # Check if only warnings (not hard failures)
    local fail_count
    fail_count="$(echo "$result" | grep -c '✗' || echo 0)"
    if [ "$fail_count" -eq 0 ]; then
      _pass "No hard failures — only warnings"
    else
      _fail "${fail_count} hard failure(s) in preflight"
    fi
  fi
}

# =========================================================================
# TEST 5: Install dry-run
# =========================================================================
test_install_dryrun() {
  printf "\n${BOLD}=== Test 5: Install Dry-Run ===${RESET}\n\n"

  local result
  if result="$(bash "${REPO_DIR}/install.sh" --dry-run --non-interactive --skip-preflight 2>&1)"; then
    _pass "install.sh --dry-run completed without errors"

    # Check version displayed
    if echo "$result" | grep -q "2.0.0"; then
      _pass "Version 2.0.0 displayed in banner"
    else
      _fail "Version 2.0.0 not found in output"
    fi

    # Check platform summary is present
    if echo "$result" | grep -q "Platform summary"; then
      _pass "Platform summary step ran"
    else
      _fail "Platform summary step not found"
    fi

    # In dry-run + non-interactive mode, OS defaults to "linux" (not "unknown")
    if echo "$result" | grep "OS:" | grep -q "unknown (unknown)"; then
      _fail "OS shows 'unknown (unknown)' in platform summary"
    else
      _pass "OS has a value in summary (dry-run defaults to linux)"
    fi

  else
    _fail "install.sh --dry-run failed with exit code $?"
    echo "$result" | tail -10
  fi
}

# =========================================================================
# TEST 6: File integrity
# =========================================================================
test_file_integrity() {
  printf "\n${BOLD}=== Test 6: File Integrity ===${RESET}\n\n"

  local files=(
    "install.sh"
    "update.sh"
    "scripts/platform-detect.sh"
    "scripts/preflight.sh"
    "docker/docker-compose.yml"
    "docker/Dockerfile.gateway"
    "docker/Dockerfile.backoffice"
  )

  for f in "${files[@]}"; do
    if [ -f "${REPO_DIR}/${f}" ]; then
      _pass "${f} exists"
    else
      _fail "${f} missing"
    fi
  done

  # Check executability
  for f in install.sh update.sh; do
    if [ -x "${REPO_DIR}/${f}" ]; then
      _pass "${f} is executable"
    else
      _warn "${f} not executable — run: chmod +x ${f}"
    fi
  done

  # Version consistency
  local install_ver
  install_ver="$(grep -oE 'YASHIGANI_VERSION="[^"]+"' "${REPO_DIR}/install.sh" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "?")"
  local update_ver
  update_ver="$(grep -oE 'CURRENT_VERSION="[^"]+"' "${REPO_DIR}/update.sh" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "?")"

  if [ "$install_ver" = "$update_ver" ]; then
    _pass "Version consistent across install.sh and update.sh: ${install_ver}"
  else
    _fail "Version mismatch: install.sh=${install_ver}, update.sh=${update_ver}"
  fi
}

# =========================================================================
# TEST 7: Agent bundle menu (non-interactive)
# =========================================================================
test_agent_bundles() {
  printf "\n${BOLD}=== Test 7: Agent Bundle Selection ===${RESET}\n\n"

  # Test --agent-bundles flag in non-interactive mode
  local result
  result="$(bash "${REPO_DIR}/install.sh" --dry-run --non-interactive --skip-preflight --agent-bundles langgraph,crewai 2>&1)"

  if echo "$result" | grep -qi "langgraph"; then
    _pass "LangGraph selected via --agent-bundles flag"
  else
    _fail "LangGraph not recognised from --agent-bundles"
  fi

  if echo "$result" | grep -qi "crewai"; then
    _pass "CrewAI selected via --agent-bundles flag"
  else
    _fail "CrewAI not recognised from --agent-bundles"
  fi

  # Test with invalid bundle name
  result="$(bash "${REPO_DIR}/install.sh" --dry-run --non-interactive --skip-preflight --agent-bundles invalidbundle 2>&1)"
  if echo "$result" | grep -qi "unknown\|skipping"; then
    _pass "Invalid bundle name handled gracefully"
  else
    _warn "Could not verify invalid bundle handling"
  fi
}

# =========================================================================
# Summary
# =========================================================================
print_summary() {
  printf "\n${BOLD}═══════════════════════════════════════════════${RESET}\n"
  printf "${BOLD}  Test Results: ${GREEN}${PASS_COUNT} passed${RESET}"
  if [ "$FAIL_COUNT" -gt 0 ]; then
    printf "  ${RED}${FAIL_COUNT} failed${RESET}"
  fi
  if [ "$WARN_COUNT" -gt 0 ]; then
    printf "  ${YELLOW}${WARN_COUNT} warnings${RESET}"
  fi
  printf "\n${BOLD}═══════════════════════════════════════════════${RESET}\n\n"

  if [ "$FAIL_COUNT" -gt 0 ]; then
    printf "${RED}  Some tests failed. Fix issues before releasing.${RESET}\n\n"
    return 1
  elif [ "$WARN_COUNT" -gt 0 ]; then
    printf "${YELLOW}  All tests passed with warnings. Review before releasing.${RESET}\n\n"
    return 0
  else
    printf "${GREEN}  All tests passed. Ready to release.${RESET}\n\n"
    return 0
  fi
}

# =========================================================================
# Main
# =========================================================================
MODE="${1:---all}"

printf "\n${BLUE}╔═══════════════════════════════════════════════╗${RESET}\n"
printf "${BLUE}║  Yashigani Installer Test Suite v2.0.0         ║${RESET}\n"
printf "${BLUE}╚═══════════════════════════════════════════════╝${RESET}\n"

case "$MODE" in
  --quick)
    test_platform_detection
    ;;
  --preflight)
    test_preflight
    ;;
  --install)
    test_install_dryrun
    ;;
  --all|*)
    test_platform_detection
    test_bash_compat
    test_variable_names
    test_preflight
    test_install_dryrun
    test_file_integrity
    test_agent_bundles
    ;;
esac

print_summary
