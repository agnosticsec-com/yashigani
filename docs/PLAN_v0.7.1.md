# Yashigani v0.7.1 — Implementation Plan

**Date:** 2026-03-28
**Author:** Maxine (PM/PO — Lead Architect)
**Status:** COMPLETE — 2026-03-28
**Predecessor:** v0.7.0 (OPA Policy Assistant + Hardening — COMPLETE 2026-03-28)

---

## 1. Executive Summary

v0.7.1 is a targeted patch that closes the three remaining code gaps identified at the end of v0.7.0:

1. **P1-B completion** — static Alembic migration pre-creating audit_events and inference_events partitions for 2026-05 through 2027-06 (the CronJob and script exist but the bootstrap partitions were not pre-created)
2. **P1-C completion** — unit test suite for `db/health.py` (`test_db_health.py`)
3. **P2-3 completion** — wire the `AlertDispatcher` to the two actual trigger points: credential exfil detections in `inspection/pipeline.py` and licence expiry warnings via a new background monitor

All three items are purely server-side. No UI changes. No new API endpoints. No schema changes beyond the partition tables.

---

## 2. Items

### V1 — Partition Bootstrap Migration (P1-B completion)

**File:** `src/yashigani/db/migrations/versions/0003_prepartition_audit_2026_2027.py`

Pre-creates monthly partitions for `audit_events` and `inference_events` covering
2026-05 through 2027-06 (14 months). Each partition is created with `IF NOT EXISTS`
semantics so the migration is safe to run on instances where pg_partman has already
created some of them.

**Acceptance criteria:**
- [x] Migration runs without error on a clean schema after 0002
- [x] All 28 partitions (14 months × 2 tables) created idempotently
- [x] `downgrade()` drops the pre-created partitions

---

### V2 — Unit Tests for db/health.py (P1-C completion)

**File:** `src/tests/unit/test_db_health.py`

Tests `check_audit_partitions` (async), `check_audit_partitions_sync`, and
`is_next_month_partition_missing` using mock DB connections.

**Acceptance criteria:**
- [x] All partitions present → all True, `is_next_month_partition_missing` = False
- [x] One partition absent → that key False, `is_next_month_partition_missing` = True
- [x] DB error → key = False, no exception raised
- [x] Sync variant covers same cases

---

### V3 — Alert Dispatcher Wiring (P2-3 completion)

**Files:**
- `src/yashigani/inspection/pipeline.py` — dispatch alert on credential exfil
- `src/yashigani/licensing/expiry_monitor.py` — new; daily background check
- `src/yashigani/backoffice/app.py` — wire expiry monitor to APScheduler in lifespan

**Alert triggers:**
1. **Credential exfil** — `_handle_credential_exfil()` calls `get_dispatcher().dispatch_sync()` when `alert_config.alert_on_credential_exfil` is True. Lazy import avoids circular dependency.
2. **Licence expiry** — `check_and_alert_licence_expiry()` runs daily at startup via APScheduler. Fires when `days_until_expiry <= alert_config.license_expiry_warning_days`. Module-level date guard prevents repeat alerts on the same calendar day.

**Acceptance criteria:**
- [x] Credential exfil detection dispatches to configured sinks within the request cycle
- [x] Licence expiry warning fires when `days_until_expiry <= threshold`
- [x] Neither trigger raises an exception if no sinks are configured
- [x] Daily guard prevents expiry alert spam (fires at most once per calendar day)

---

## 3. Version Bump

Per the standing document update policy:

| File | Change |
|------|--------|
| `pyproject.toml` | `0.7.0` → `0.7.1` |
| `src/yashigani/__init__.py` | `0.7.0` → `0.7.1` |
| `helm/yashigani/Chart.yaml` | `0.7.0` → `0.7.1` |
| `src/yashigani/backoffice/app.py` | FastAPI version `0.7.0` → `0.7.1` |
| `QA_REPORT.md` | `0.7.0` → `0.7.1` |

---

## 4. Release Checklist

- [x] 0003 partition migration written and idempotent
- [x] `test_db_health.py` written — all cases covered
- [x] Credential exfil alert wired in `pipeline.py`
- [x] Licence expiry monitor created and wired to lifespan
- [x] Version bumps applied
- [ ] `pytest src/tests/unit/ -v --cov=yashigani --cov-fail-under=80`
- [ ] Manual: test alert delivered to Slack via `POST /admin/alerts/test/slack`
- [ ] Tag `v0.7.1` in git
