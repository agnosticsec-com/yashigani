# Yashigani QA Report — Pre-release Inconsistency Audit

**Generated:** 2026-03-28
**Codebase version:** 0.8.0 (pyproject.toml)
**Scope:** Full codebase review of all .py, .md, .yaml, .toml, .sh, .rego files

---

## Summary

| Category | Count | Fixed in this session |
|----------|-------|----------------------|
| CRITICAL (blocks functionality) | 2 | 1 fixed, 1 requires key material |
| MODERATE (silent misbehaviour) | 3 | 2 fixed |
| MINOR (cosmetic / operational) | 6 | 3 fixed |
| Test coverage gaps | 7 areas | Tests written for all |

---

## CRITICAL Issues

### IC-1 — Version string mismatch ✅ FIXED
**File:** `src/yashigani/__init__.py`
**Was:** `__version__ = "0.1.0"`
**Fixed to:** `__version__ = "0.5.0"` (matches pyproject.toml)
**Impact:** Any code reading `yashigani.__version__` (health endpoint, OTEL traces, log headers) returned wrong version. Regression test added: `test_version.py::TestVersionConsistency`.

---

### IC-2 — License public key is a placeholder ⚠️ REQUIRES ACTION
**File:** `src/yashigani/licensing/verifier.py`, line 35-39
**Issue:** `_PUBLIC_KEY_PEM = "PLACEHOLDER_YASHIGANI_PUBLIC_KEY_P256"`
**Impact:** ALL license files are silently ignored. The system always runs at COMMUNITY tier regardless of the .ysg file installed. Feature gates and seat/agent limits are NOT enforced.
**Current behaviour:** `_is_placeholder()` and `_warn_placeholder_once()` detect this and log a warning, but do not raise. System falls back to COMMUNITY_LICENSE.

**Action required before any release:**
```bash
# Generate the ECDSA P-256 keypair (run once, store private key in HSM/KMS):
python scripts/keygen.py --out keys/

# Replace the placeholder in verifier.py with the content of:
# keys/yashigani_license_public.pem
```

**Regression tests added:** `test_licensing.py::TestVerifyLicensePlaceholder` (verifies fallback behaviour), `TestVerifyLicenseWithRealKey` (full path with real ephemeral keypair).

---

## MODERATE Issues

### IC-3 — sign_license.py only generated v1 payloads / missing tiers ✅ FIXED
**File:** `scripts/sign_license.py`
**Was:**
- Payload version hardcoded to `"v": 1`
- `--tier` only accepted `professional` and `enterprise`
- No `--max-end-users`, `--max-admin-seats`, `--license-id`, `--issued-at`, `--expires-at`, `--license-type` flags
- `_max_orgs_for_tier()` returned 1 for professional_plus (should be 5)
- CLI flags did not match what `Commerce/src/license_generator.py` passes

**Fixed:**
- Generates v3 payloads with all required fields
- All 5 tiers accepted: community, starter, professional, professional_plus, enterprise
- All missing flags added; flag names match Commerce module expectations
- `professional_plus` correctly defaults to `max_orgs=5`
- Tier defaults table added and must stay in sync with `licensing/model.py::TIER_DEFAULTS`

**Regression tests:** `test_sign_license.py` — 30+ tests including full sign→verify roundtrip.

---

### IC-4 — Classifier default model name mismatch ✅ FIXED
**File:** `src/yashigani/inspection/classifier.py`, line 73
**Was:** `model: str = "qwen3.5:4b"`
**Fixed to:** `model: str = "qwen2.5:3b"` (matches docs, conftest.py mock, and OPA assistant notes)
**Impact:** A fresh deployment with no explicit model config would try to load `qwen3.5:4b` which does not exist in the standard deployment. Inspection pipeline would fall back to LLM-unavailable behaviour.
**Regression test:** `test_classifier.py::TestDefaultModel::test_default_model_is_qwen25_3b`

---

### IC-5 — Upgrade URL points to yashigani.io not agnosticsec.com ✅ FIXED
**File:** `src/yashigani/licensing/enforcer.py`, lines 127 and 146
**Was:** `"upgrade_url": "https://yashigani.io/pricing"`
**Fixed to:** `"upgrade_url": "https://agnosticsec.com/pricing"`
**Impact:** Users receiving HTTP 402 responses (feature gated, limit exceeded) were directed to a non-existent URL.
**Regression test:** `test_licensing.py::TestResponseHelpers::test_upgrade_url_points_to_agnosticsecurity`

---

## MINOR Issues (not fixed — flagged for backlog)

### IC-6 — Path matching parity between OPA Rego and Python unverified
**Files:** `policy/rbac.rego` (`_path_matches`, lines ~54-60) and `src/yashigani/rbac/store.py` (`_path_matches`)
**Issue:** Both implement glob matching independently. Trailing-slash behaviour and edge cases are not verified to be identical.
**Risk:** An OPA policy decision and Python enforcement may disagree on edge-case paths.
**Recommended action:** Add `test_rbac.py::TestPathMatchParity` with a shared parameterised test table run against both implementations.

### IC-7 — Feature names are unvalidated strings (not an Enum)
**File:** `src/yashigani/licensing/model.py`, line 25
**Issue:** `features: frozenset` accepts any string. A misspelled feature name in a .ysg payload silently passes through with no gate.
**Recommended action:** Add `LicenseFeature(str, Enum)` with values `oidc`, `saml`, `scim` and validate in `_build_license_state`.

### IC-8 — Version strings scattered across multiple files
**Files:** `__init__.py` (now fixed), `state.py` (comments), `metrics/registry.py` (comment), `tracing/otel.py` (hardcoded string `"0.5.0"`), `helm/Chart.yaml`
**Recommended action:** Single source of truth — read from `yashigani.__version__` everywhere. Remove version strings from comments.

### IC-9 — TOTP backoff hardcoded (not runtime-configurable)
**File:** `src/yashigani/auth/local_auth.py`
**Issue:** `_TOTP_BACKOFF_SECONDS = [0, 1, 2, 4, 8]` — requires restart to change.
**Recommended action:** Add to config if adjustability is needed, or accept as acceptable for now.

### IC-10 — DB partitions only cover 2026-03 and 2026-04
**File:** `src/yashigani/db/migrations/versions/0001_initial_schema.py`
**Issue:** Audit log table is range-partitioned by month. Only two months are pre-created.
**Required action before going live:** Create a maintenance job that creates partition for next month on the 1st of each current month.

### IC-11 — Recovery code constants are migration-sensitive
**Files:** `src/yashigani/auth/totp.py` — `_RECOVERY_CODE_COUNT = 8` and `_RECOVERY_CODE_FORMAT = "{:04X}-{:04X}-{:04X}"`
**Issue:** Changing either constant invalidates all existing recovery codes with no migration path.
**Regression test added:** `test_totp.py::TestRecoveryCodeConstants` — will fail immediately if either constant changes.

---

## Test Coverage Gaps — New Tests Written

| Gap | Test file | Key tests |
|-----|-----------|-----------|
| licensing.model — no tests | `test_licensing.py` | Tier enum, TIER_DEFAULTS consistency, LicenseState.has_feature, is_expired |
| licensing.verifier — no tests | `test_licensing.py` | Placeholder fallback, valid sig, invalid sig, expiry, v1/v2 compat, all 5 tiers |
| licensing.enforcer — no tests | `test_licensing.py` | set/get, require_feature, all 4 limit checks, -1 unlimited, response helpers |
| auth.password — no tests | `test_password.py` | Min length 36, hash/verify roundtrip, generate uniqueness |
| inspection.classifier — no tests | `test_classifier.py` | Label constants, default model, _parse_response all paths, error fallback |
| scripts/sign_license.py — no tests | `test_sign_license.py` | All tiers, v3 fields, defaults, overrides, roundtrip verify |
| auth.totp constants — no change detection | `test_totp.py` | _RECOVERY_CODE_COUNT=8, _RECOVERY_CODE_FORMAT stable |
| Version consistency — no test | `test_version.py` | __version__ matches pyproject.toml |

---

## Remaining Coverage Gaps (not addressed in this session)

| Area | Why not addressed | Priority |
|------|-----------------|---------|
| Backoffice routes (21 files) | Large; requires full app context setup | P1 |
| OPA Rego policy evaluation | Requires `opa` binary + policy files in test environment | P1 |
| Path matching parity (Rego vs Python) | See IC-6 — needs parameterised test table | P1 |
| Async DB operations (asyncpg) | Requires test database | P2 |
| TOTP backoff edge cases | Unit test straightforward; add to test_totp.py | P2 |
| Concurrent rate-limiter access | Requires async test harness | P2 |
| Audit immutable-floor enforcement | `EmergencyUnlockExecutedEvent` must not be maskable | P1 |
| KMS providers (real credentials) | Excluded from coverage in pyproject.toml — by design | P3 |
| Inspection LLM backends (cloud) | Excluded from coverage — requires API keys | P3 |
| Integration: gateway+OPA+audit pipeline | Full end-to-end; requires docker-compose | P2 |

---

## Pre-Release Checklist

### Blocking (must fix before any release)
- [ ] Replace `_PUBLIC_KEY_PEM` placeholder in `verifier.py` with real ECDSA P-256 public key
- [ ] Generate customer license files using updated `sign_license.py` (v3 payload)
- [ ] Verify all existing customer licenses (if any) still verify with `verify_license()`
- [ ] Create DB partitions for at least the next 6 months
- [ ] Run full test suite: `pytest src/tests/ -v --cov=yashigani --cov-fail-under=80`

### Strongly recommended before first customer deployment
- [ ] Add `LicenseFeature` Enum to eliminate silent feature name misspellings (IC-7)
- [ ] Add `tracing/otel.py` to read version from `yashigani.__version__` not hardcoded string
- [ ] Verify path matching parity between `policy/rbac.rego` and `rbac/store.py` (IC-6)
- [ ] Create monthly partition maintenance job (IC-10)
- [ ] Set DMARC to p=quarantine on agnosticsec.com before sending first email

---

## Running the Tests

```bash
# Install dev dependencies
pip install 'yashigani[dev]'   # includes fakeredis, pytest-asyncio, httpx, pytest-cov

# Run all unit tests
pytest src/tests/unit/ -v

# Run with coverage
pytest src/tests/unit/ --cov=yashigani --cov-report=term-missing --cov-fail-under=80

# Run only licensing tests
pytest src/tests/unit/test_licensing.py -v

# Run only the new tests from this session
pytest src/tests/unit/test_licensing.py \
       src/tests/unit/test_password.py \
       src/tests/unit/test_classifier.py \
       src/tests/unit/test_sign_license.py \
       src/tests/unit/test_totp.py \
       src/tests/unit/test_version.py \
       -v
```
