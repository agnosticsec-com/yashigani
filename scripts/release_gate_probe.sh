#!/usr/bin/env bash
# release_gate_probe.sh — Yashigani SOP 4 canonical release-gate probe.
#
# CONTRACT (binding, see feedback_test_harness_no_fake_green.md):
#   * Probes documented endpoints with documented payloads only.
#   * First non-2xx is FAIL — exits non-zero. No retry, no downgrade clauses.
#   * Emits literal lines "Admin1 login HTTP: <code>" and "Admin2 login HTTP: <code>"
#     to stdout (SOP 5 grep contract — feedback_evidence_bound_task_closure.md).
#   * Uses TOTP secrets from --secrets-dir (admin1_totp_secret, admin2_totp_secret).
#   * The verdict line "RESTORE TEST GREEN" MUST NOT be emitted by callers unless
#     this script exits 0 AND both 200 lines are in the same log file.
#
# Last-Updated: 2026-04-27T10:00:00Z

set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 --base-url URL --secrets-dir DIR [--ssh-prefix CMD] [--cat-prefix CMD]

  --base-url     Backoffice base URL (e.g. https://localhost or https://127.0.0.1)
  --secrets-dir  Directory containing admin1_username, admin1_password,
                 admin1_totp_secret, admin2_* (mode 0400 expected)
  --ssh-prefix   Optional command prefix to wrap probe (e.g. "ssh max@vm")
  --cat-prefix   Optional command prefix for reading secret files
                 (default: "cat"; use "sudo -S cat" for root-owned post-restore)

Exit codes:
  0  Both admins authenticated (HTTP 200)
  1  Argument or setup error
  2  Admin1 non-200
  3  Admin2 non-200
  4  Transport / decode / TOTP error
EOF
  exit 1
}

BASE_URL=""
SECRETS_DIR=""
SSH_PREFIX=""
CAT_PREFIX="cat"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-url) BASE_URL="$2"; shift 2 ;;
    --secrets-dir) SECRETS_DIR="$2"; shift 2 ;;
    --ssh-prefix) SSH_PREFIX="$2"; shift 2 ;;
    --cat-prefix) CAT_PREFIX="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown arg: $1" >&2; usage ;;
  esac
done

[[ -n "$BASE_URL" && -n "$SECRETS_DIR" ]] || usage

read_secret() {
  local name="$1"
  local out
  if [[ -n "$SSH_PREFIX" ]]; then
    out=$($SSH_PREFIX "$CAT_PREFIX ${SECRETS_DIR}/${name}" 2>/dev/null | tr -d '\n')
  else
    out=$($CAT_PREFIX "${SECRETS_DIR}/${name}" 2>/dev/null | tr -d '\n')
  fi
  if [[ -z "$out" ]]; then
    echo "FATAL: secret ${name} empty or unreadable from ${SECRETS_DIR}" >&2
    exit 1
  fi
  printf '%s' "$out"
}

probe_admin() {
  local label="$1" user="$2" pass="$3" totp_secret="$4"
  local totp_code resp status
  totp_code=$(python3 -c "import pyotp,hashlib,sys; print(pyotp.TOTP('${totp_secret}',digest=hashlib.sha256).now())" 2>/dev/null) || {
    echo "${label} login HTTP: TOTP_ERR"
    return 4
  }
  resp=$(python3 - "$BASE_URL" "$user" "$pass" "$totp_code" <<'PYEOF'
import json, ssl, sys, urllib.request, urllib.error
base, user, pw, code = sys.argv[1:5]
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
body = json.dumps({"username": user, "password": pw, "totp_code": code}).encode()
req = urllib.request.Request(f"{base}/auth/login", data=body,
                              headers={"Content-Type": "application/json"}, method="POST")
try:
    r = urllib.request.urlopen(req, context=ctx, timeout=15)
    print(json.dumps({"status": r.status}))
except urllib.error.HTTPError as e:
    print(json.dumps({"status": e.code}))
except Exception as ex:
    print(json.dumps({"status": "ERR", "err": str(ex)}))
PYEOF
)
  status=$(python3 -c "import json,sys; d=json.loads(sys.argv[1]); print(d.get('status','unknown'))" "$resp" 2>/dev/null || echo "unknown")
  echo "${label} login HTTP: ${status}"
  [[ "$status" == "200" ]]
}

A1_USER=$(read_secret admin1_username)
A1_PASS=$(read_secret admin1_password)
A1_TOTP=$(read_secret admin1_totp_secret)
A2_USER=$(read_secret admin2_username)
A2_PASS=$(read_secret admin2_password)
A2_TOTP=$(read_secret admin2_totp_secret)

probe_admin "Admin1" "$A1_USER" "$A1_PASS" "$A1_TOTP" || exit 2
probe_admin "Admin2" "$A2_USER" "$A2_PASS" "$A2_TOTP" || exit 3

exit 0
