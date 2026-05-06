#!/usr/bin/env bash
# tests/upgrade/test_auto_rollback_wiring.sh — Yashigani v2.23.2
# last-updated: 2026-05-04T00:00:00+01:00 (new — retro #59)
#
# Wiring test for update.sh auto-rollback path.
#
# Proves that update.sh main():
#   1. Calls verify_health AFTER restart_services and BEFORE print_summary.
#   2. On health-check failure WITHOUT --no-auto-rollback, calls do_rollback
#      and exits non-zero.
#   3. On health-check failure WITH --no-auto-rollback, does NOT call
#      do_rollback, prints the inspection message, and exits non-zero.
#   4. On health-check success, does NOT call do_rollback and proceeds to
#      print_summary cleanly.
#
# Strategy:
#   Source update.sh under YSG_UPDATE_NO_AUTORUN=1 so main() doesn't fire on
#   load. Stub the network/git/restart functions so we never touch the real
#   environment. Stub health-check.sh to return whatever the test wants.
#   Stub do_rollback so we observe whether it was invoked.
#
# This is a wiring test — it verifies that update.sh ROUTES correctly through
# verify_health → do_rollback. Real upgrade+rollback against running services
# is covered by tests/upgrade/n_minus_one.sh on a VM.
#
# Usage: ./tests/upgrade/test_auto_rollback_wiring.sh
# Exit:  0 = all assertions pass; 1 = any assertion fails.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
UPDATE_SH="${REPO_ROOT}/update.sh"

if [[ ! -f "$UPDATE_SH" ]]; then
  echo "ERROR: cannot find update.sh at ${UPDATE_SH}" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Test harness — minimal assert helpers
# ---------------------------------------------------------------------------
PASS=0
FAIL=0

assert_contains() {
  local haystack="$1" needle="$2" name="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    printf "  PASS  %s\n" "$name"
    PASS=$((PASS + 1))
  else
    printf "  FAIL  %s\n         expected to contain: %s\n" "$name" "$needle"
    FAIL=$((FAIL + 1))
  fi
}

assert_not_contains() {
  local haystack="$1" needle="$2" name="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    printf "  PASS  %s\n" "$name"
    PASS=$((PASS + 1))
  else
    printf "  FAIL  %s\n         expected NOT to contain: %s\n" "$name" "$needle"
    FAIL=$((FAIL + 1))
  fi
}

assert_eq() {
  local actual="$1" expected="$2" name="$3"
  if [[ "$actual" == "$expected" ]]; then
    printf "  PASS  %s\n" "$name"
    PASS=$((PASS + 1))
  else
    printf "  FAIL  %s (expected=%s actual=%s)\n" "$name" "$expected" "$actual"
    FAIL=$((FAIL + 1))
  fi
}

# ---------------------------------------------------------------------------
# Build a fake INSTALL_DIR with stubbed health-check.sh and a backup the
# rollback path can find.
# ---------------------------------------------------------------------------
mk_fake_install() {
  local root="$1" hc_exit_code="$2"
  mkdir -p "${root}/scripts" "${root}/docker" "${root}/backups/pre-update-v0.0.0-19700101-000000"

  cat >"${root}/docker/docker-compose.yml" <<'EOF'
services:
  gateway:
    image: yashigani/gateway:test
EOF

  echo "0.0.0" >"${root}/backups/pre-update-v0.0.0-19700101-000000/VERSION"

  # Health-check stub — exits with whatever exit code the test asked for.
  cat >"${root}/scripts/health-check.sh" <<EOF
#!/usr/bin/env bash
echo "[stub-health-check] args=\$* exit=${hc_exit_code}"
exit ${hc_exit_code}
EOF
  chmod +x "${root}/scripts/health-check.sh"
}

# ---------------------------------------------------------------------------
# Hermetic harness — sources update.sh, replaces network/git/restart steps
# with no-ops, observes do_rollback invocation, runs main() under env-driven
# config. Flags are passed via env (not argv) to sidestep update.sh's own
# arg parser that runs at source-time.
# Writes "[main exit] N" as the last line so the parent can capture status.
#
# Env contract:
#   YSG_TEST_INSTALL_DIR      — path to fixture install dir
#   YSG_TEST_UPDATE_SH        — path to update.sh under test
#   YSG_TEST_NO_AUTO_ROLLBACK — "1" to set NO_AUTO_ROLLBACK=true
#   YSG_TEST_HEALTH_TIMEOUT   — integer to set HEALTH_TIMEOUT
# ---------------------------------------------------------------------------
HARNESS="$(mktemp)"
cat >"$HARNESS" <<'HARNESS_EOF'
#!/usr/bin/env bash
set +e

YSG_UPDATE_NO_AUTORUN=1
export YSG_UPDATE_NO_AUTORUN

# Source with empty positional args so update.sh's own parser is a no-op.
set --
# shellcheck source=/dev/null
source "$YSG_TEST_UPDATE_SH"

# Re-disable -e/-u (update.sh's `set -euo pipefail` is now active).
set +eu

# Apply test config AFTER source so it overrides the sourced defaults.
TARGET_VERSION="9.9.9"
INSTALL_DIR="$YSG_TEST_INSTALL_DIR"
NO_AUTO_ROLLBACK=false
HEALTH_TIMEOUT=120
[[ "${YSG_TEST_NO_AUTO_ROLLBACK:-0}" == "1" ]] && NO_AUTO_ROLLBACK=true
[[ -n "${YSG_TEST_HEALTH_TIMEOUT:-}" ]] && HEALTH_TIMEOUT="$YSG_TEST_HEALTH_TIMEOUT"

# Stubs — make detect/check/backup/pull/restart no-ops so we exercise only
# the verify_health → auto-rollback wiring.
detect_install_dir()    { :; }
detect_current_version(){ CURRENT_VERSION="0.0.0"; }
check_latest_version()  { :; }
backup_current()        { echo "[stub] backup_current called"; }
pull_update()            { :; }
pull_images()            { :; }
restart_services()       { echo "[stub] restart_services called"; }

# Observable do_rollback stub. Echo a sentinel and return so we can inspect
# whether main() reached this path.
do_rollback() {
  echo "[stub] do_rollback called"
  return 0
}

# Run main in a subshell so its `exit` calls don't kill THIS harness.
# Capture exit code via short-circuit so set -e (re-enabled by main()'s
# `set -euo pipefail` in the sourced file) can't terminate us early.
( main ) && rc=$? || rc=$?
echo "[main exit] $rc"
HARNESS_EOF
chmod +x "$HARNESS"

run_harness() {
  local install_dir="$1"; shift
  YSG_TEST_INSTALL_DIR="$install_dir" \
  YSG_TEST_UPDATE_SH="$UPDATE_SH" \
  YSG_TEST_NO_AUTO_ROLLBACK="${YSG_TEST_NO_AUTO_ROLLBACK:-0}" \
  YSG_TEST_HEALTH_TIMEOUT="${YSG_TEST_HEALTH_TIMEOUT:-}" \
    bash "$HARNESS" 2>&1
}

# ---------------------------------------------------------------------------
# Case 1: health check FAILS, default behavior → auto-rollback engaged
# ---------------------------------------------------------------------------
echo ""
echo "── Case 1: health FAIL + default → auto-rollback engaged ──"
T1="$(mktemp -d)"
mk_fake_install "$T1" 1
out_1="$(run_harness "$T1")"
assert_contains     "$out_1" "Verifying service health"      "case1: verify_health step ran"
assert_contains     "$out_1" "Health check FAILED"           "case1: health failure logged"
assert_contains     "$out_1" "Auto-rollback engaged"         "case1: auto-rollback message"
assert_contains     "$out_1" "[stub] do_rollback called"     "case1: do_rollback invoked"
assert_contains     "$out_1" "Upgrade to v9.9.9 aborted"     "case1: abort message logged"
assert_not_contains "$out_1" "Update complete: v"            "case1: print_summary NOT reached"
assert_contains     "$out_1" "[main exit] 1"                 "case1: main exits non-zero"
rm -rf "$T1"

# ---------------------------------------------------------------------------
# Case 2: health check FAILS, --no-auto-rollback → rollback skipped
# ---------------------------------------------------------------------------
echo ""
echo "── Case 2: health FAIL + --no-auto-rollback → manual inspection ──"
T2="$(mktemp -d)"
mk_fake_install "$T2" 1
out_2="$(YSG_TEST_NO_AUTO_ROLLBACK=1 run_harness "$T2")"
assert_contains     "$out_2" "Health check FAILED"           "case2: health failure logged"
assert_contains     "$out_2" "--no-auto-rollback set"        "case2: manual-inspection message"
assert_not_contains "$out_2" "[stub] do_rollback called"     "case2: do_rollback NOT invoked"
assert_not_contains "$out_2" "Auto-rollback engaged"         "case2: auto-rollback NOT engaged"
assert_not_contains "$out_2" "Update complete: v"            "case2: print_summary NOT reached"
assert_contains     "$out_2" "[main exit] 1"                 "case2: main exits non-zero"
rm -rf "$T2"

# ---------------------------------------------------------------------------
# Case 3: health check PASSES → no rollback, summary reached
# ---------------------------------------------------------------------------
echo ""
echo "── Case 3: health PASS → no rollback, summary reached ──"
T3="$(mktemp -d)"
mk_fake_install "$T3" 0
out_3="$(run_harness "$T3")"
assert_contains     "$out_3" "Health check PASSED"           "case3: health success logged"
assert_not_contains "$out_3" "[stub] do_rollback called"     "case3: do_rollback NOT invoked"
assert_not_contains "$out_3" "Auto-rollback engaged"         "case3: no rollback message"
assert_contains     "$out_3" "Update complete: v"            "case3: print_summary reached"
assert_contains     "$out_3" "[main exit] 0"                 "case3: main exits zero"
rm -rf "$T3"

# ---------------------------------------------------------------------------
# Case 4: --health-timeout pass-through
# ---------------------------------------------------------------------------
echo ""
echo "── Case 4: --health-timeout passed to health-check.sh ──"
T4="$(mktemp -d)"
mk_fake_install "$T4" 0
out_4="$(YSG_TEST_HEALTH_TIMEOUT=47 run_harness "$T4")"
assert_contains "$out_4" "[stub-health-check] args=--timeout 47" "case4: --timeout 47 passed through"
rm -rf "$T4"

rm -f "$HARNESS"

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------
echo ""
printf "── Verdict ── PASS=%d FAIL=%d\n" "$PASS" "$FAIL"
if [[ "$FAIL" -gt 0 ]]; then
  echo "auto-rollback wiring: FAIL"
  exit 1
fi
echo "auto-rollback wiring: PASS"
exit 0
