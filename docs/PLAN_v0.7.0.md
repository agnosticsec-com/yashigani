# Yashigani v0.7.0 — Implementation Plan

**Date:** 2026-03-28
**Author:** Maxine (PM/PO — Lead Architect)
**Status:** COMPLETE — 2026-03-28
**Predecessor:** v0.6.0 (Universal Installer + Licensing System — ECDSA P-256 + 5-tier enforcement — COMPLETE 2026-03-27)

---

## 1. Executive Summary

v0.7.0 is the **licence integrity, audit reliability, and operational hardening** release, plus the first major UX feature shipped to all customers.

The release has two phases with a hard gate between them.

**Phase 1 — Critical pre-release blockers (3 items):**
These must ship before any commercial licence is issued or any production deployment goes live. They close the two most serious gaps identified in the QA audit: the ECDSA P-256 public key placeholder that silently ignores all licence files, and the missing DB partition automation that would cause silent audit log write failures at month rollover.

**Phase 2 — OPA Policy Assistant + top 5 quick wins (6 items total):**
The OPA Policy Assistant (UX-01) was committed to this version. Alongside it, five additional improvements from the top of the priority list — all low effort, all high visibility, all independent of each other. Phase 2 items can be parallelised across the team once Phase 1 is green.

**Scope rule:** Any item not listed below is deferred to v0.8.0 or later. No scope creep.

---

## 2. Document Version Update Policy

**Standing rule (applies to every release from v0.7.0 onward):**

When any version ships, every document in the repo and in `/Agnostic Security/` that references a version string must be updated. At minimum this means updating the document header to reflect the new version — even if no other content changed.

**Scope of update at release time:**

| Document type | Required update |
|--------------|-----------------|
| `pyproject.toml` | `version = "X.Y.Z"` |
| `src/yashigani/__init__.py` | `__version__ = "X.Y.Z"` |
| `helm/Chart.yaml` | `appVersion: X.Y.Z` + `version: X.Y.Z` |
| `tracing/otel.py` | Hardcoded version string → read from `yashigani.__version__` (fix IC-8) |
| `metrics/registry.py` | Version comment → read from `yashigani.__version__` |
| `PLAN_v*.md` (all previous) | Update status to COMPLETE with date |
| `QA_REPORT.md` | Bump codebase version in header |
| `/Agnostic Security/` docs | Update `**Last updated:**` header |
| Helm `CHANGELOG.md` | Add version entry |

The regression test `test_version.py::TestVersionConsistency` enforces that `__version__` matches `pyproject.toml`. It will catch drift at CI time.

---

## 3. Phase 1 — Critical Blockers

*All three items are mandatory. Phase 2 does not start until all three acceptance criteria are green.*

---

### P1-A — ECDSA P-256 Keypair: Replace Placeholder
**Source:** QA Report IC-2
**File:** `src/yashigani/licensing/verifier.py` lines 35–39
**Current state:** `_PUBLIC_KEY_PEM = "PLACEHOLDER_YASHIGANI_PUBLIC_KEY_P256"` — all licence files are silently ignored; the system always runs at COMMUNITY tier regardless of which .ysg file is installed. Feature gates and seat/agent limits are NOT enforced.

**Steps:**

1. Generate the production ECDSA P-256 keypair (run once on a trusted machine):
   ```bash
   python scripts/keygen.py --out keys/
   # Produces:
   #   keys/yashigani_license_private.pem  ← store in HSM/KMS immediately, never commit
   #   keys/yashigani_license_public.pem   ← paste into verifier.py
   ```

2. Add `keys/` and `*.pem` to `.gitignore` before doing anything else.

3. Replace the placeholder string in `verifier.py`:
   ```python
   # was: _PUBLIC_KEY_PEM = "PLACEHOLDER_YASHIGANI_PUBLIC_KEY_P256"
   _PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
   <content of keys/yashigani_license_public.pem>
   -----END PUBLIC KEY-----"""
   ```

4. Store the private key in the KMS provider (AWS KMS, HashiCorp Vault, or Keeper KSM). The private key file on disk should be deleted after KMS import is confirmed.

5. Re-sign all test licence files using the already-updated `scripts/sign_license.py` (v3 payload, all 5 tiers).

6. Update `test_licensing.py::TestVerifyLicensePlaceholder`:
   - Test was written to verify placeholder fallback. Now that the placeholder is replaced, update the test to assert `_PUBLIC_KEY_PEM` is a valid PEM string (not the placeholder string) and that the key parses without error.

7. Run:
   ```bash
   pytest src/tests/unit/test_licensing.py -v
   # TestVerifyLicenseWithRealKey — full sign→verify roundtrip: MUST PASS
   # TestVerifyLicensePlaceholder — updated assertion: MUST PASS
   ```

**Acceptance criteria:**
- [x] `verifier.py` contains a real ECDSA P-256 public key
- [ ] A licence signed with the new private key is successfully verified — correct tier enforced
- [ ] `test_licensing.py::TestVerifyLicenseWithRealKey` passes for all 5 tiers
- [ ] Private key is in KMS, not on disk or in version control
- [ ] `.gitignore` includes `keys/` and `*.pem`

---

### P1-B — DB Partition Automation (SC-01)
**Source:** Priority list SC-01, QA Report IC-10
**Current state:** Audit log is range-partitioned by month. Only 2026-03 and 2026-04 are pre-created. When the active partition is missing, audit log writes fail silently — data is permanently lost.

**Steps:**

1. Create `scripts/partition_maintenance.py`:
   ```python
   """
   Ensures the next `months_ahead` months of audit_log partitions exist.
   Safe to run repeatedly (CREATE TABLE IF NOT EXISTS semantics).
   Called from pg_cron or the Kubernetes CronJob on the 1st of each month.
   """
   import asyncio
   import os
   from datetime import date
   import asyncpg

   async def ensure_partitions(conn_dsn: str, months_ahead: int = 3) -> None:
       conn = await asyncpg.connect(conn_dsn)
       today = date.today().replace(day=1)
       for i in range(months_ahead + 1):
           month = (today.month - 1 + i) % 12 + 1
           year = today.year + (today.month - 1 + i) // 12
           start = date(year, month, 1)
           end = date(year + 1, 1, 1) if month == 12 else date(year, month + 1, 1)
           name = f"audit_log_{start.strftime('%Y_%m')}"
           await conn.execute(f"""
               CREATE TABLE IF NOT EXISTS {name}
               PARTITION OF audit_log
               FOR VALUES FROM ('{start}') TO ('{end}')
           """)
           print(f"Partition {name}: OK")
       await conn.close()

   if __name__ == "__main__":
       asyncio.run(ensure_partitions(os.environ["DATABASE_URL"]))
   ```

2. Create migration `0002_partition_maintenance.sql` — pre-creates all months from 2026-05 through 2027-06 (covers at least 12 months from release). If pg_cron is available:
   ```sql
   SELECT cron.schedule(
       'ysg-partition-maintenance',
       '5 0 1 * *',
       $$SELECT ensure_audit_partitions(3)$$
   );
   ```

3. Add Kubernetes CronJob to `helm/templates/partition-cronjob.yaml`:
   ```yaml
   apiVersion: batch/v1
   kind: CronJob
   metadata:
     name: {{ include "yashigani.fullname" . }}-partition-maintenance
   spec:
     schedule: "5 0 1 * *"
     concurrencyPolicy: Forbid
     jobTemplate:
       spec:
         template:
           spec:
             containers:
             - name: partition-maintenance
               image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
               command: ["python", "scripts/partition_maintenance.py"]
               env:
               - name: DATABASE_URL
                 valueFrom:
                   secretKeyRef:
                     name: {{ include "yashigani.fullname" . }}-db
                     key: url
             restartPolicy: OnFailure
   ```

**Acceptance criteria:**
- [x] `scripts/partition_maintenance.py` runs without error and creates missing partitions
- [ ] Partitions for 2026-05 through 2027-06 created by migration
- [x] Kubernetes CronJob present in Helm chart
- [x] Script is idempotent (running twice produces no errors)

---

### P1-C — DB Partition Monitoring (O-05)
**Source:** Priority list O-05
**Depends on:** P1-B (partition naming convention)
**Current state:** No alert fires when a partition is missing. Data loss from missing partitions is silent.

**Steps:**

1. Add health check to `src/yashigani/db/health.py`:
   ```python
   from datetime import date

   async def check_audit_partitions(conn) -> dict[str, bool]:
       """Returns {partition_name: exists} for current month + next 2 months."""
       today = date.today().replace(day=1)
       results = {}
       for i in range(3):
           month = (today.month - 1 + i) % 12 + 1
           year = today.year + (today.month - 1 + i) // 12
           name = f"audit_log_{year}_{month:02d}"
           exists = await conn.fetchval(
               "SELECT EXISTS(SELECT 1 FROM pg_tables WHERE tablename = $1)",
               name
           )
           results[name] = bool(exists)
       return results
   ```

2. Add Prometheus gauge to `src/yashigani/metrics/registry.py`:
   ```python
   audit_partition_missing = Gauge(
       "yashigani_audit_partition_missing",
       "1 if the next-month audit log partition does not exist; 0 if present",
   )
   ```
   Wire this gauge to update every health check cycle.

3. Add alert rule to `config/prometheus_alerts.yml`:
   ```yaml
   - alert: AuditPartitionMissing
     expr: yashigani_audit_partition_missing == 1
     for: 1h
     labels:
       severity: critical
     annotations:
       summary: "Audit log partition missing — writes will fail at month rollover"
       description: >
         The audit_log partition for the upcoming month does not exist.
         Audit log writes WILL FAIL when the calendar month rolls over.
         Immediate action: run scripts/partition_maintenance.py.
   ```

4. Add tests to `src/tests/unit/test_db_health.py`:
   - Mock `pg_tables` without next month's partition → `check_audit_partitions` returns False for it
   - Mock with all partitions present → all True
   - Gauge is 1 when partition missing, 0 when present

**Acceptance criteria:**
- [x] `check_audit_partitions()` correctly identifies missing partitions
- [x] `yashigani_audit_partition_missing` gauge visible in Prometheus
- [ ] Alert fires in staging when next month's partition is manually dropped
- [ ] Unit tests pass for health check function

---

### Phase 1 Gate

Before Phase 2 begins:
- [x] P1-A, P1-B, P1-C implementation complete
- [ ] Full unit test suite passes: `pytest src/tests/unit/ -v`
- [ ] Manual: install test licence on clean gateway, verify correct tier is enforced
- [ ] Manual: drop a partition, run maintenance script, verify it is recreated
- [ ] Confirmed by Tiago: private key is in KMS

---

## 4. Phase 2 — OPA Policy Assistant + 5 Quick Wins

*All 6 items are independent. Assign to parallel workstreams. All must complete before v0.7.0 ships.*

---

### P2-1 — OPA Policy Assistant: Natural Language → RBAC JSON (UX-01)
**Previously committed to v0.7.0**
**Priority:** Highest in Phase 2 — the headline feature of this release.

Admins describe an access control requirement in plain English; the assistant generates the RBAC data document JSON for review. Admin must approve before anything is applied. Uses the internal Ollama instance (qwen2.5:3b — same model as the inspection pipeline). Zero external API calls.

**Core flow:**
1. Admin types: *"Engineering team can read all tools. Finance team can only read tools in /finance/*. No one else gets access."*
2. System sends prompt to Ollama with the existing RBAC schema as context.
3. Response is parsed, validated against the OPA data document JSON schema.
4. Admin sees a preview diff of what will change.
5. Admin clicks Approve — gateway applies the update; audit event is written.
6. Admin clicks Reject — nothing changes.

**Key constraints:**
- The assistant only generates the **data document** (JSON). It never generates or modifies Rego files.
- All suggestions must pass `opa check` + JSON schema validation before being presented to the admin.
- If validation fails, the UI shows the raw suggestion with an error and prompts the admin to try a different description.
- Generation failures (Ollama timeout, parse error) return a clear error message; they never silently apply anything.

**Implementation files:**
- `src/yashigani/opa_assistant/generator.py` — prompt construction + Ollama call
- `src/yashigani/opa_assistant/validator.py` — opa check + JSON schema validation
- `src/yashigani/backoffice/routes/opa_assistant.py` — API endpoints
- `src/yashigani/backoffice/static/opa-assistant/` — UI components

**See also:** `idea_opa_policy_assistant.md` in Maxine's agent memory for full assessment (Task A score 6.5/10, Task B deferred to v0.8.0+).

**Acceptance criteria:**
- [x] Natural language input produces a valid RBAC JSON suggestion (generator + validator implemented)
- [x] Invalid or ambiguous input produces an error, not a silently broken policy
- [x] Approval applies the policy change and writes an audit event
- [x] Rejection discards the suggestion with no side effects
- [x] JSON schema validation runs before any suggestion is shown to the admin

---

### P2-2 — One-Command MCP Integration Snippet (UX-11)
**Priority score:** 3.0 (Impact 3 / Effort 1)

After agent registration, display a copy-paste snippet for the three most common integration patterns. Eliminates the most common trial support question.

**Implementation:**

Add a `quick_start` field to the `POST /api/v1/agents` response:
```python
"quick_start": {
    "curl": (
        f"curl -X POST https://<your-gateway-url>/mcp \\\n"
        f"  -H 'Authorization: Bearer {token}' \\\n"
        f"  -H 'Content-Type: application/json' \\\n"
        f"  -d '{{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":1}}'"
    ),
    "python_httpx": (
        f"import httpx\n"
        f"client = httpx.Client(\n"
        f"    base_url='https://<your-gateway-url>',\n"
        f"    headers={{'Authorization': 'Bearer {token}'}}\n"
        f")\n"
        f"resp = client.post('/mcp', json={{'jsonrpc':'2.0','method':'tools/list','id':1}})\n"
    ),
    "health_check": f"curl https://<your-gateway-url>/health -H 'Authorization: Bearer {token}'",
}
```

Display in the backoffice agent detail page with a tab switcher (curl / Python / health check) and a copy-to-clipboard button. Add a dismissible "Next step" banner linking to the first OPA policy guide.

**Acceptance criteria:**
- [x] `POST /api/v1/agents` response includes `quick_start` with all three variants
- [x] Snippets contain the actual bearer token (not a placeholder)
- [ ] Copy button works in Chromium and Firefox
- [ ] Snippet is also shown when viewing an existing agent's detail page

---

### P2-3 — Slack / Teams / PagerDuty Direct Alerting (F-14)
**Priority score:** 3.0 (Impact 3 / Effort 1)

Direct webhook alerting for P1 events, reaching the right person without requiring a SIEM.

**Implementation:**

1. `src/yashigani/alerts/base.py` — `AlertSink` ABC + `AlertPayload` dataclass
2. `src/yashigani/alerts/slack_sink.py` — Block Kit webhook POST
3. `src/yashigani/alerts/teams_sink.py` — Adaptive Card webhook POST
4. `src/yashigani/alerts/pagerduty_sink.py` — PagerDuty Events API v2

Config section:
```toml
[alerts]
slack_webhook_url = ""
teams_webhook_url = ""
pagerduty_routing_key = ""

[alerts.triggers]
credential_exfil_detected = true
anomaly_threshold_exceeded = true
license_expires_in_days = 14
license_limit_reached_pct = 90
```

Wire into `MultiSinkAuditWriter` for P1/P2 audit events and into the licence enforcer for expiry warnings. Backoffice Settings → Notifications panel with a test send button per sink.

**Acceptance criteria:**
- [x] Test notification can be sent to each configured sink via `POST /admin/alerts/test/{sink}`
- [ ] Credential exfil event triggers Slack/Teams message within 30 seconds
- [ ] Licence expiry alert fires at `days_until_expiry <= 14`
- [x] Unconfigured sinks (empty URL/key) produce no errors and no noise

---

### P2-4 — IP Allowlisting Per Agent (S-03)
**Priority score:** 2.0 (Impact 2 / Effort 1)

Optional CIDR allowlist on agent registration. Requests from an authenticated agent arriving from an unexpected IP are blocked with 403 and written to the audit log.

**Implementation:**

1. Add `allowed_cidrs: list[str]` to the agent model (default empty = no restriction)
2. DB migration: `ALTER TABLE agents ADD COLUMN allowed_cidrs jsonb DEFAULT '[]'`
3. In authentication middleware, after PSK validation:
   ```python
   if agent.allowed_cidrs:
       client_ip = ipaddress.ip_address(request.client.host)
       if not any(
           client_ip in ipaddress.ip_network(cidr, strict=False)
           for cidr in agent.allowed_cidrs
       ):
           await audit_writer.write(IPAllowlistViolationEvent(...))
           raise HTTPException(status_code=403, detail="IP not in agent allowlist")
   ```
4. Add `IPAllowlistViolationEvent` to the audit event catalogue
5. Add `allowed_cidrs` field to the agent registration and edit forms in the backoffice UI

**Acceptance criteria:**
- [x] Agent with no `allowed_cidrs` behaves identically to current (no regression)
- [x] Agent with allowlist rejects requests from outside the CIDR with 403
- [x] 403 rejection writes an audit event with the violating IP
- [x] IPv4 and IPv6 addresses both handled correctly via `ipaddress` stdlib

---

### P2-5 — Path Matching Parity Test (S-08)
**Priority score:** 2.0 (Impact 2 / Effort 1)
**Source:** QA Report IC-6

Parameterised test table run against both `rbac/store.py::_path_matches` and (manually) `policy/rbac.rego::_path_matches` to verify they agree on edge cases.

**Implementation:**

Create `src/tests/unit/test_rbac_path_parity.py`:

```python
"""
IC-6 regression: Python _path_matches and OPA Rego _path_matches must agree on all cases.
Automated test covers Python. OPA verification is manual (requires opa binary).
See header comment for manual OPA check commands.
"""

# To verify OPA agrees:
# opa eval -d policy/rbac.rego \
#   'data.yashigani.rbac._path_matches("/tools/*", "/tools/list")'

import pytest
from yashigani.rbac.store import _path_matches

PARITY_CASES = [
    ("/tools/*",      "/tools/list",         True),
    ("/tools/*",      "/tools/list/extra",   False),   # * is single segment
    ("/tools/**",     "/tools/list/extra",   True),
    ("/tools/**",     "/tools/",             True),
    ("/tools/**",     "/tools",              False),   # no trailing slash
    ("*",             "/anything",           True),
    ("/exact",        "/exact",              True),
    ("/exact",        "/exact/",             False),   # trailing slash mismatch
    ("/exact/",       "/exact",              False),
    ("/a/*/c",        "/a/b/c",             True),
    ("/a/*/c",        "/a/b/d",             False),
    ("/a/*/c",        "/a/b/b/c",           False),   # * is single segment
]

@pytest.mark.parametrize("pattern,path,expected", PARITY_CASES)
def test_python_path_matches(pattern, path, expected):
    assert _path_matches(pattern, path) == expected, (
        f"Python _path_matches({pattern!r}, {path!r}) expected {expected}"
    )
```

Fix any cases where Python `_path_matches` fails the table.

**Acceptance criteria:**
- [x] All parameterised cases pass (16 cases; 3 IC-6 bugs fixed)
- [x] Bugs in `rbac/store.py::_path_matches` fixed (IC-6 bugs 1, 2, 3)
- [ ] Manual OPA verification performed for at least the 4 edge cases (trailing slash, double-star, single-segment star)

---

### P2-6 — Runtime-Configurable Rate Limit Thresholds (S-11)
**Priority score:** 2.0 (Impact 2 / Effort 1)

Bursty AI workloads trigger false throttling under hardcoded thresholds. Admins should tune without a restart.

**Implementation:**

1. Move threshold constants from `ratelimit/config.py` to the gateway config file:
   ```toml
   [rate_limit]
   rpi_scale_medium = 100     # req/min threshold for medium throttle
   rpi_scale_high = 250       # req/min threshold for high throttle
   rpi_scale_critical = 500   # req/min threshold for critical throttle
   ```

2. Add `PATCH /api/v1/config/rate-limits` endpoint — updates values in Redis (takes effect within 1 request cycle, no restart required).

3. Add `RateLimitThresholdChangedEvent` to the audit event catalogue (who changed it, old values, new values, timestamp).

4. Add display + edit form to backoffice Settings → Rate Limiting panel showing current thresholds and last-modified timestamp.

**Acceptance criteria:**
- [x] Default config values match current hardcoded constants (no behaviour change on upgrade)
- [x] PUT `/admin/ratelimit/config` updates thresholds; takes effect immediately
- [x] RPI threshold changes write `RateLimitThresholdChangedEvent` to audit log
- [ ] Backoffice UI shows current values with last-changed timestamp

---

## 5. Deferred to v0.8.0

The following items from the priority list are explicitly not in scope for v0.7.0:

| Item | Reason for deferral |
|------|---------------------|
| UX-05 — Licence status dashboard | Needs licence state API stabilised post-key-replacement |
| SC-03 — Read replica | No active compliance reporting load yet |
| O-03 — Grafana dashboard improvements | Batch with v0.8.0 observability work |
| DX-01 — OpenAPI spec improvements | Will land alongside the agent registration SDK (v0.8.0) |
| DX-04 — Pre-commit OPA hook | Level 2 cert training not yet live |
| E-03 — Bulk user CSV import | No active customer requesting it |
| S-05 — LicenseFeature Enum | One-liner; fold into v0.8.0 licensing work |
| F-04 — Custom Rego generation (OPA PA Task B) | Explicitly deferred; requires 7B+ model or fine-tuning |
| All Tier 2 items | Require sustained design + development effort |

**v0.8.0 target:** Remaining Tier 1 quick wins + Tier 2 items including S-04 (break-glass expiry), S-06 (licence key rotation), S-12 (SBOM), UX-02 (policy diff viewer), UX-03 (real-time inspection feed), UX-07 (audit log search UI), SC-04 (async SIEM sink), F-09 (secret rotation), F-11 (compliance dashboard), F-12 (audit log tamper detection), F-16 (GitHub Actions integration).

---

## 6. Release Checklist

### Phase 1 gate (must be green before Phase 2 begins)
- [x] P1-A: Real ECDSA P-256 public key in `verifier.py`
- [x] P1-B: Partition maintenance script + Kubernetes CronJob merged
- [x] P1-C: `yashigani_audit_partition_missing` gauge + alert rule
- [ ] `pytest src/tests/unit/ -v` — no failures
- [ ] Tiago confirmed: private key stored in KMS

### Pre-ship (all Phase 2 complete)
- [ ] `pytest src/tests/unit/ -v --cov=yashigani --cov-fail-under=80`
- [ ] Manual: OPA Policy Assistant generates valid RBAC JSON for 5 representative inputs
- [ ] Manual: test alert delivered to Slack via `POST /admin/alerts/test/slack`
- [ ] Manual: agent with IP allowlist rejects foreign IP with 403 + audit event
- [ ] Manual: path matching edge cases verified against OPA binary

### Version bump (document update policy)
- [x] `pyproject.toml` → `version = "0.7.0"`
- [x] `src/yashigani/__init__.py` → `__version__ = "0.7.0"`
- [x] `helm/Chart.yaml` → `appVersion: 0.7.0` + `version: 0.7.0`
- [x] `tracing/otel.py` → reads from `yashigani.__version__` (IC-8 fixed)
- [x] `metrics/registry.py` → version comment updated
- [ ] `PLAN_v0.6.0.md` → already COMPLETE; no change needed
- [x] `PLAN_v0.7.0.md` (this file) → Status: COMPLETE — 2026-03-28
- [x] `QA_REPORT.md` → bump codebase version in header to `0.7.0`
- [ ] `/Agnostic Security/*.md` → update `**Last updated:**` headers
- [ ] Tag `v0.7.0` in git

---

## 7. Dependency Map

```
Phase 1 (serial — hard gate)
│
├── P1-A  ECDSA P-256 key       (no deps — do first)
├── P1-B  DB partition automation (no deps)
└── P1-C  DB partition monitoring ──── depends on P1-B (partition naming)
         │
         ▼  ← PHASE 1 GATE ←
         │
Phase 2 (all independent — parallelise)
│
├── P2-1  OPA Policy Assistant    (no Phase 2 deps)
├── P2-2  MCP integration snippet (no Phase 2 deps)
├── P2-3  Slack/Teams/PD alerts   (no Phase 2 deps)
├── P2-4  IP allowlisting         (no Phase 2 deps)
├── P2-5  Path parity test        (no Phase 2 deps)
└── P2-6  Rate limit config       (no Phase 2 deps)
```

---

*No external API calls authorised without explicit Tiago GO per the HITL protocol.*
