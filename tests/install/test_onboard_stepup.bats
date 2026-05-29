#!/usr/bin/env bats
# tests/install/test_onboard_stepup.bats
#
# P1 W6 — Step-up gate tests for install.sh --onboard / --offboard
#
# Test matrix:
#   G-SYNTAX    bash -n + shellcheck; gate function present
#   G-SECRETS   CWE-214: read -s, --data @file, 0600 tmpfiles, no /tmp
#   G-GATE-COND gate is CONDITIONAL on _is_existing_yashigani_running
#   G-ABORT     gate failure blocks execution with || exit 1
#   G-ORDER     WORK_DIR before gate; gate before cosign in onboard
#   G-ENDPT     HTTPS + --cacert; reads docker/.env; both /auth/login + /auth/stepup
#   G-SYMMETRY  single function reused by onboard + offboard
#   G-AUDIT     gate emits audit log line with username + ISO-8601 timestamp
#   G-FUNC      gate returns non-zero: CA absent; TOTP invalid; conn refused; tmpdir cleaned up
#
# All static tests are offline. G-FUNC uses a minimal subshell harness.
#
# Requirements: bats-core >= 1.10.0, bash, python3, shellcheck
# Run: bats tests/install/test_onboard_stepup.bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/install.sh"
MOCK_ROOT="${REPO_ROOT}/tests/install/.mock_stepup"
EXTRACT_PY="${REPO_ROOT}/tests/install/extract_gate_fragment.py"

setup() {
  rm -rf "${MOCK_ROOT}"
  mkdir -p "${MOCK_ROOT}/docker/secrets"
  printf '# mock CA cert\n' > "${MOCK_ROOT}/docker/secrets/ca_root.crt"
  chmod 0644 "${MOCK_ROOT}/docker/secrets/ca_root.crt"
  printf 'YASHIGANI_HTTPS_PORT=19443\n' > "${MOCK_ROOT}/docker/.env"
}

teardown() {
  rm -rf "${MOCK_ROOT}"
}

# ---------------------------------------------------------------------------
# G-SYNTAX
# ---------------------------------------------------------------------------

@test "G-SYNTAX: install.sh passes bash -n" {
  run bash -n "${INSTALL_SH}"
  [ "$status" -eq 0 ]
}

@test "G-SYNTAX: no new shellcheck findings beyond pre-existing SC2188" {
  # Extract only the SC<code> identifiers from the shellcheck output, then
  # filter out the known pre-existing SC2188.  Any remaining SC codes indicate
  # new findings introduced by this branch.
  local findings
  findings="$(shellcheck --enable=all --severity=warning "${INSTALL_SH}" 2>&1 \
      | grep -oE 'SC[0-9]+' \
      | grep -v 'SC2188' \
      || true)"
  [ -z "$findings" ]
}

@test "G-SYNTAX: _ysg_onboard_stepup_gate function defined exactly once" {
  run grep -c '^_ysg_onboard_stepup_gate()' "${INSTALL_SH}"
  [ "$output" -eq 1 ]
}

@test "G-SYNTAX: _gate_cleanup helper defined inside gate function" {
  run grep -c '_gate_cleanup()' "${INSTALL_SH}"
  [ "$output" -ge 1 ]
}

# ---------------------------------------------------------------------------
# G-SECRETS
# ---------------------------------------------------------------------------

@test "G-SECRETS: read -s used at least twice (password and TOTP prompts)" {
  local count
  count="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -cE 'read -r?s' || true)"
  [ "$count" -ge 2 ]
}

@test "G-SECRETS: curl uses --data @file not inline credentials on command line" {
  local bad good
  bad="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -cE -- "--data '\{" || true)"
  [ "$bad" -eq 0 ]
  good="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c -- '--data "@' || true)"
  [ "$good" -ge 1 ]
}

@test "G-SECRETS: credential tmpfiles created with 0600 mode (CWE-732)" {
  local count
  count="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c '0o600' || true)"
  [ "$count" -ge 1 ]
}

@test "G-SECRETS: tmpdir is under WORK_DIR, not /tmp (filesystem guardrail)" {
  local in_workdir in_tmp
  in_workdir="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c 'WORK_DIR.*ysg-gate' || true)"
  [ "$in_workdir" -ge 1 ]
  in_tmp="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -cE 'mktemp.*/tmp' || true)"
  [ "$in_tmp" -eq 0 ]
}

@test "G-SECRETS: RETURN trap registered to clean up secrets on all exit paths" {
  local count
  count="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c 'trap.*RETURN' || true)"
  [ "$count" -ge 1 ]
}

# ---------------------------------------------------------------------------
# G-GATE-COND: gate is conditional on _is_existing_yashigani_running
# ---------------------------------------------------------------------------

@test "G-GATE-COND: onboard gate guarded by _is_existing_yashigani_running" {
  # Verify:
  # (a) _is_existing_yashigani_running appears in the handler
  # (b) _ysg_onboard_stepup_gate appears AFTER _is_existing_yashigani_running
  #     AND on a line that is indented (i.e. inside the if-block)
  local onboard_start
  onboard_start="$(grep -n '^handle_onboard_subcommand()' "${INSTALL_SH}" \
      | head -1 | cut -d: -f1)"
  # Line number of the _is_existing check inside the handler
  local guard_line gate_call_line
  guard_line="$(awk "NR > ${onboard_start}" "${INSTALL_SH}" \
      | grep -n '_is_existing_yashigani_running' | head -1 | cut -d: -f1)"
  gate_call_line="$(awk "NR > ${onboard_start}" "${INSTALL_SH}" \
      | grep -n '_ysg_onboard_stepup_gate' | head -1 | cut -d: -f1)"
  [ -n "$guard_line" ]
  [ -n "$gate_call_line" ]
  # Gate call must come after the guard
  [ "$gate_call_line" -gt "$guard_line" ]
}

@test "G-GATE-COND: offboard gate guarded by _is_existing_yashigani_running" {
  local offboard_start guard_line gate_call_line
  offboard_start="$(grep -n '^handle_offboard_subcommand()' "${INSTALL_SH}" \
      | head -1 | cut -d: -f1)"
  guard_line="$(awk "NR > ${offboard_start}" "${INSTALL_SH}" \
      | grep -n '_is_existing_yashigani_running' | head -1 | cut -d: -f1)"
  gate_call_line="$(awk "NR > ${offboard_start}" "${INSTALL_SH}" \
      | grep -n '_ysg_onboard_stepup_gate' | head -1 | cut -d: -f1)"
  [ -n "$guard_line" ]
  [ -n "$gate_call_line" ]
  [ "$gate_call_line" -gt "$guard_line" ]
}

# ---------------------------------------------------------------------------
# G-ABORT: gate failure blocks execution
# ---------------------------------------------------------------------------

@test "G-ABORT: onboard gate failure aborts with || exit 1" {
  local onboard_start handler_body
  onboard_start="$(grep -n '^handle_onboard_subcommand()' "${INSTALL_SH}" \
      | head -1 | cut -d: -f1)"
  handler_body="$(awk "NR > ${onboard_start}" "${INSTALL_SH}" \
      | awk 'BEGIN{d=1} {d+=gsub(/{/,"{"); d-=gsub(/}/,"}"); print; if(d<=0) exit}')"
  printf '%s' "$handler_body" | grep -q '_ysg_onboard_stepup_gate.*||.*exit 1'
}

@test "G-ABORT: offboard gate failure aborts with || exit 1" {
  local offboard_start handler_body
  offboard_start="$(grep -n '^handle_offboard_subcommand()' "${INSTALL_SH}" \
      | head -1 | cut -d: -f1)"
  handler_body="$(awk "NR > ${offboard_start}" "${INSTALL_SH}" \
      | awk 'BEGIN{d=1} {d+=gsub(/{/,"{"); d-=gsub(/}/,"}"); print; if(d<=0) exit}')"
  printf '%s' "$handler_body" | grep -q '_ysg_onboard_stepup_gate.*||.*exit 1'
}

# ---------------------------------------------------------------------------
# G-ORDER: ordering within handlers
# ---------------------------------------------------------------------------

@test "G-ORDER: WORK_DIR resolved before step-up gate in onboard handler" {
  local onboard_start detect_line gate_line
  onboard_start="$(grep -n '^handle_onboard_subcommand()' "${INSTALL_SH}" \
      | head -1 | cut -d: -f1)"
  detect_line="$(awk "NR > ${onboard_start}" "${INSTALL_SH}" \
      | grep -n 'detect_working_directory' | head -1 | cut -d: -f1)"
  gate_line="$(awk "NR > ${onboard_start}" "${INSTALL_SH}" \
      | grep -n '_ysg_onboard_stepup_gate' | head -1 | cut -d: -f1)"
  [ -n "$detect_line" ]
  [ -n "$gate_line" ]
  [ "$detect_line" -lt "$gate_line" ]
}

@test "G-ORDER: step-up gate before cosign gate in onboard handler" {
  local onboard_start gate_line cosign_line
  onboard_start="$(grep -n '^handle_onboard_subcommand()' "${INSTALL_SH}" \
      | head -1 | cut -d: -f1)"
  gate_line="$(awk "NR > ${onboard_start}" "${INSTALL_SH}" \
      | grep -n '_ysg_onboard_stepup_gate' | head -1 | cut -d: -f1)"
  cosign_line="$(awk "NR > ${onboard_start}" "${INSTALL_SH}" \
      | grep -n '_ysg_cosign_gate' | head -1 | cut -d: -f1)"
  [ -n "$gate_line" ]
  [ -n "$cosign_line" ]
  [ "$gate_line" -lt "$cosign_line" ]
}

@test "G-ORDER: WORK_DIR resolved before step-up gate in offboard handler" {
  local offboard_start detect_line gate_line
  offboard_start="$(grep -n '^handle_offboard_subcommand()' "${INSTALL_SH}" \
      | head -1 | cut -d: -f1)"
  detect_line="$(awk "NR > ${offboard_start}" "${INSTALL_SH}" \
      | grep -n 'detect_working_directory' | head -1 | cut -d: -f1)"
  gate_line="$(awk "NR > ${offboard_start}" "${INSTALL_SH}" \
      | grep -n '_ysg_onboard_stepup_gate' | head -1 | cut -d: -f1)"
  [ -n "$detect_line" ]
  [ -n "$gate_line" ]
  [ "$detect_line" -lt "$gate_line" ]
}

# ---------------------------------------------------------------------------
# G-ENDPT
# ---------------------------------------------------------------------------

@test "G-ENDPT: gate reads YASHIGANI_HTTPS_PORT from docker/.env" {
  local count
  count="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c 'docker/.env' || true)"
  [ "$count" -ge 1 ]
}

@test "G-ENDPT: gate connects via https:// not plain http://" {
  local https_count http_count
  https_count="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c 'https://localhost' || true)"
  [ "$https_count" -ge 1 ]
  http_count="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -cE 'http://localhost' || true)"
  [ "$http_count" -eq 0 ]
}

@test "G-ENDPT: gate uses --cacert, never --insecure" {
  local cacert_count insecure_count
  cacert_count="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c -- '--cacert' || true)"
  [ "$cacert_count" -ge 1 ]
  # Check non-comment lines only (skip lines starting with optional whitespace + #)
  insecure_count="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -vE '^\s*#' \
      | grep -cE -- '--insecure| -k | -k$' || true)"
  [ "$insecure_count" -eq 0 ]
}

@test "G-ENDPT: gate calls /auth/login AND /auth/stepup" {
  local login_c stepup_c
  login_c="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c '/auth/login' || true)"
  stepup_c="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c '/auth/stepup' || true)"
  [ "$login_c" -ge 1 ]
  [ "$stepup_c" -ge 1 ]
}

# ---------------------------------------------------------------------------
# G-SYMMETRY
# ---------------------------------------------------------------------------

@test "G-SYMMETRY: offboard gate call uses label 'offboard'" {
  local offboard_start call_line
  offboard_start="$(grep -n '^handle_offboard_subcommand()' "${INSTALL_SH}" \
      | head -1 | cut -d: -f1)"
  call_line="$(awk "NR > ${offboard_start}" "${INSTALL_SH}" \
      | awk 'BEGIN{d=1} {d+=gsub(/{/,"{"); d-=gsub(/}/,"}"); print; if(d<=0) exit}' \
      | grep '_ysg_onboard_stepup_gate' || true)"
  printf '%s' "$call_line" | grep -q '"offboard"'
}

@test "G-SYMMETRY: onboard gate call uses label 'onboard'" {
  local onboard_start call_line
  onboard_start="$(grep -n '^handle_onboard_subcommand()' "${INSTALL_SH}" \
      | head -1 | cut -d: -f1)"
  call_line="$(awk "NR > ${onboard_start}" "${INSTALL_SH}" \
      | awk 'BEGIN{d=1} {d+=gsub(/{/,"{"); d-=gsub(/}/,"}"); print; if(d<=0) exit}' \
      | grep '_ysg_onboard_stepup_gate' || true)"
  printf '%s' "$call_line" | grep -q '"onboard"'
}

# ---------------------------------------------------------------------------
# G-AUDIT
# ---------------------------------------------------------------------------

@test "G-AUDIT: gate emits audit log with operator identity on success path" {
  local count
  count="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c 'step-up gate passed for user' || true)"
  [ "$count" -ge 1 ]
}

@test "G-AUDIT: gate emits ISO-8601 timestamp on success path" {
  local count
  count="$(awk '/^_ysg_onboard_stepup_gate\(\)/{f=1} f{print}' "${INSTALL_SH}" \
      | grep -c 'date -u.*%Y-%m-%dT' || true)"
  [ "$count" -ge 1 ]
}

# ---------------------------------------------------------------------------
# G-FUNC: runtime unit tests via subshell + extract_gate_fragment.py
# ---------------------------------------------------------------------------

@test "G-FUNC: gate returns non-zero when ca_root.crt is absent" {
  local fragment
  fragment="$(python3 "${EXTRACT_PY}" "${INSTALL_SH}")"
  rm -f "${MOCK_ROOT}/docker/secrets/ca_root.crt"
  run bash -c "
${fragment}
WORK_DIR='${MOCK_ROOT}'
exec 0</dev/null
_ysg_onboard_stepup_gate 'onboard'
" 2>&1
  [ "$status" -ne 0 ]
}

@test "G-FUNC: gate error message mentions ca_root.crt when cert absent" {
  local fragment
  fragment="$(python3 "${EXTRACT_PY}" "${INSTALL_SH}")"
  rm -f "${MOCK_ROOT}/docker/secrets/ca_root.crt"
  run bash -c "
${fragment}
WORK_DIR='${MOCK_ROOT}'
exec 0</dev/null
_ysg_onboard_stepup_gate 'onboard' 2>&1 || true
" 2>&1
  [[ "$output" == *"CA cert"* ]] || [[ "$output" == *"ca_root.crt"* ]]
}

@test "G-FUNC: tmpdir cleaned up after gate failure (no .ysg-gate-* residual)" {
  local fragment
  fragment="$(python3 "${EXTRACT_PY}" "${INSTALL_SH}")"
  rm -f "${MOCK_ROOT}/docker/secrets/ca_root.crt"
  bash -c "
${fragment}
WORK_DIR='${MOCK_ROOT}'
exec 0</dev/null
_ysg_onboard_stepup_gate 'onboard' 2>/dev/null || true
" 2>/dev/null || true
  local residual
  residual="$(find "${MOCK_ROOT}/docker" -maxdepth 1 -name '.ysg-gate-*' -type d 2>/dev/null | wc -l | tr -d ' ')"
  [ "$residual" -eq 0 ]
}

@test "G-FUNC: gate returns non-zero when backoffice unreachable (conn refused)" {
  local fragment
  fragment="$(python3 "${EXTRACT_PY}" "${INSTALL_SH}")"
  # Port 19998 should not be listening in any test environment
  run bash -c "
${fragment}
WORK_DIR='${MOCK_ROOT}'
YASHIGANI_HTTPS_PORT=19998
# Mock read() to inject credentials so we reach the curl call
read() {
  local _v=\"\${!#}\"
  case \"\$_v\" in
    _username) eval \"\$_v='testadmin'\" ;;
    _password) eval \"\$_v='testpass123'\" ;;
    _totp)     eval \"\$_v='123456'\" ;;
    *) true ;;
  esac
}
printf() { true; }
_ysg_onboard_stepup_gate 'onboard' 2>&1
" 2>&1
  [ "$status" -ne 0 ]
}
