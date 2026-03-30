# Yashigani v0.6.1 — Implementation Plan

**Date:** 2026-03-27
**Author:** Maxine (PM/PO — Lead Architect)
**Status:** SUPERSEDED — content merged into v0.7.0
**Predecessor:** v0.6.0 (Universal installer · 3-tier licensing · ECDSA P-256 · install.sh)

---

## 1. Executive Summary

v0.6.1 is a **tier restructuring** release with two parallel tracks:

**Track A — Tier Limits Redesign**
Replaces the v0.6.0 tier model with four tiers that reflect real commercial segment sizing:

| Tier | Agents / MCPs | Users | Orgs | SAML / OIDC / SCIM | Key Required |
|------|--------------|-------|------|---------------------|--------------|
| **Community** | 20 | 5 | 1 | ✗ | No |
| **Professional** | 500 | 500 | 1 | ✓ | Yes |
| **Professional Plus** | 2,000 | 1,000 | 3 | ✓ | Yes |
| **Enterprise** | Unlimited | Unlimited | Unlimited | ✓ | Yes |

Key changes vs v0.6.0:
- Community raised from 10 → **20 agents**, adds **5-user cap** (was unlimited users in v0.6.0 — now explicitly bounded)
- Professional raised from unlimited → **500 agents**, adds **500-user cap**, still 1 org
- **Professional Plus** is a new tier: 2,000 agents, 1,000 users, up to 3 orgs
- Enterprise remains unlimited on all axes

**Track B — Community Licensing Model**
Formally adopt a community open-source license that maximises contribution velocity while ensuring Yashigani can incorporate contributions into all commercial tiers without legal exposure.

**Recommendation: Apache License 2.0 + Contributor License Agreement (CLA)**

---

## 2. Track A — Tier Limits Redesign

### 2A.1 Code Changes

#### `src/yashigani/licensing/model.py`

Add `PROFESSIONAL_PLUS` to `LicenseTier` enum. Add `max_users: int` to `LicenseState`. Add per-tier convenience constants.

```python
class LicenseTier(str, Enum):
    COMMUNITY         = "community"
    PROFESSIONAL      = "professional"
    PROFESSIONAL_PLUS = "professional_plus"
    ENTERPRISE        = "enterprise"

@dataclass(frozen=True)
class LicenseState:
    tier: LicenseTier
    org_domain: str
    max_agents: int       # -1 = unlimited
    max_users: int        # -1 = unlimited  ← NEW
    max_orgs: int         # -1 = unlimited
    features: frozenset[str]
    issued_at: datetime
    expires_at: datetime | None
    license_id: str | None
    valid: bool
    error: str | None

# Hardcoded Community defaults (no key needed)
COMMUNITY_LICENSE = LicenseState(
    tier=LicenseTier.COMMUNITY,
    org_domain="*",
    max_agents=20,          # raised from 10
    max_users=5,            # NEW limit
    max_orgs=1,
    features=frozenset(),
    issued_at=datetime.min,
    expires_at=None,
    license_id=None,
    valid=True,
    error=None,
)
```

#### `src/yashigani/licensing/enforcer.py`

Add `check_user_limit()` and `LicenseUserLimitExceeded` to mirror the existing `check_agent_limit()` / `LicenseLimitExceeded` pattern.

```python
def check_user_limit(current_count: int) -> None:
    """Raise LicenseLimitExceeded(402) if count >= max_users and not unlimited."""
    lic = get_license()
    if lic.max_users != -1 and current_count >= lic.max_users:
        raise LicenseLimitExceeded(
            limit_type="users",
            current=current_count,
            maximum=lic.max_users,
            tier=lic.tier.value,
        )
```

HTTP 402 response body:
```json
{
  "error": "LICENSE_LIMIT_EXCEEDED",
  "limit_type": "users",
  "current": 5,
  "maximum": 5,
  "tier": "community",
  "upgrade_url": "https://yashigani.io/pricing",
  "message": "User limit reached. Community tier allows up to 5 users."
}
```

#### `src/yashigani/backoffice/routes/users.py`

Wire `check_user_limit()` to user creation endpoint:

```python
from yashigani.licensing.enforcer import check_user_limit

@router.post("/admin/users")
async def create_user(...):
    current_count = auth_service.count_users()
    check_user_limit(current_count)
    # ... rest of user creation
```

#### `src/yashigani/licensing/verifier.py`

License payload format bumped to `"v": 2`. New field `max_users` added. Backwards compat: if `max_users` absent in payload (v1 license), infer from tier:

| Tier string | max_users default (v1 fallback) |
|-------------|--------------------------------|
| community | 5 |
| professional | 500 |
| professional_plus | 1000 |
| enterprise | -1 |

Updated payload JSON schema (v2):
```json
{
  "v": 2,
  "tier": "professional_plus",
  "org_domain": "example.com",
  "max_agents": 2000,
  "max_users": 1000,
  "max_orgs": 3,
  "features": ["saml", "oidc", "scim"],
  "issued_at": "2026-04-01T00:00:00Z",
  "expires_at": "2027-04-01T00:00:00Z",
  "license_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

#### `src/yashigani/backoffice/routes/license.py`

Update `GET /admin/license` to include user usage:

```json
{
  "tier": "professional_plus",
  "valid": true,
  "expires_at": "2027-04-01T00:00:00Z",
  "limits": {
    "agents": { "current": 47, "maximum": 2000, "unlimited": false },
    "users":  { "current": 12, "maximum": 1000, "unlimited": false },
    "orgs":   { "current": 1,  "maximum": 3,    "unlimited": false }
  },
  "features": ["saml", "oidc", "scim"],
  "upgrade_url": "https://yashigani.io/pricing"
}
```

#### `scripts/sign_license.py`

Add `--max-users` CLI flag. Add `--tier professional_plus` support. Emit v2 payload.

### 2A.2 Modified Files

```
src/yashigani/licensing/model.py          (max_users field, PROFESSIONAL_PLUS tier, updated COMMUNITY_LICENSE)
src/yashigani/licensing/verifier.py       (v2 payload schema, backwards-compat v1 fallback)
src/yashigani/licensing/enforcer.py       (check_user_limit, LicenseLimitExceeded user variant)
src/yashigani/backoffice/routes/users.py  (wire check_user_limit on POST /admin/users)
src/yashigani/backoffice/routes/license.py (user count in GET /admin/license response)
scripts/sign_license.py                   (--max-users flag, v2 payload)
```

### 2A.3 No Changes Required

- `src/yashigani/licensing/loader.py` — resolution order unchanged
- `docker/docker-compose.yml` — no structural change
- `policy/*.rego` — OPA policy unchanged; user limit is enforced at the application layer
- `install.sh` / `scripts/wizard.sh` — no change; license step unchanged
- `scripts/health-check.sh` — no change

---

## 3. Track B — Community Licensing Model

### 3.1 The Problem

Without a formal license and a Contributor License Agreement (CLA):

1. Every contributor retains full copyright to their contribution.
2. Yashigani can incorporate contributions into the community edition (because they share the same license), but **cannot** incorporate them into the Professional or Enterprise commercial versions without the contributor's separate explicit consent.
3. Even if the community license is MIT, a contributor could later assert that their code was used in a commercial product in a way they did not consent to, creating legal uncertainty.
4. In a jurisdiction without a signed agreement, even a "I submitted a PR" can create copyright entanglement.

### 3.2 Recommendation: Apache 2.0 + CLA

#### Community License: Apache License 2.0

**Why Apache 2.0 over MIT:**

| Criterion | MIT | Apache 2.0 |
|-----------|-----|-----------|
| Patent grant | No explicit grant | Yes — contributors explicitly grant patent rights |
| Attribution requirement | Minimal | Requires NOTICE file preservation |
| OSI-approved open source | Yes | Yes |
| Enterprise familiarity | High | Very high (Linux Foundation standard) |
| Compatibility with copyleft | GPL 3, LGPL 3 | GPL 3, LGPL 3 |
| Contributor patent trap prevention | No | Yes |

For a **security product** where contributors may have patents on specific techniques (detection algorithms, crypto schemes), Apache 2.0's explicit patent grant protects all users of the community version from patent claims by contributors. This is a hard requirement for enterprise adoption.

**Why not AGPL v3:**

AGPL v3 requires that anyone who modifies Yashigani and uses it as a network service must release their modifications under AGPL. This would:
- Deter security-conscious enterprise customers from contributing (they cannot contribute without disclosing modifications)
- Require Yashigani to dual-license (AGPL community + commercial license) which is valid but adds legal complexity at every customer conversation
- Not materially prevent forking since Yashigani's commercial value is in ongoing development, support, and managed distribution — not just the code

Apache 2.0 is the right choice at this stage of growth.

**Why not BUSL (Business Source License):**

BUSL is not an open-source license (not OSI-approved). It limits production commercial use. This would block legitimate self-hosted community deployments and reduce contribution velocity.

#### Contributor License Agreement (CLA)

The CLA is the critical mechanism. It must be signed **before any pull request is merged**.

**What the CLA grants to Yashigani:**
1. A perpetual, irrevocable, worldwide copyright license to reproduce, prepare derivative works, publicly display, publicly perform, sublicense, and distribute the contribution.
2. An explicit patent license covering any patents the contributor holds that are necessarily infringed by the contribution.
3. A representation that the contributor has the right to submit the contribution (no third-party IP encumbrance).
4. Moral rights waiver (jurisdictions that have them: France, Germany, etc.).

**What the CLA does NOT do:**
- Does not transfer copyright ownership (contributor retains it)
- Does not prevent the contributor from using their own contribution elsewhere
- Does not impose any license on the contributor's other work

**CLA variants needed:**
- **Individual CLA (ICLA):** For contributors acting on their own behalf
- **Corporate CLA (CCLA):** For contributors acting on behalf of an employer (covers employer's IP claims)

**Implementation via CLA Assistant:**

CLA Assistant (https://cla-assistant.io) is a free GitHub App that:
1. Adds a status check to every PR
2. Comments on the PR asking unsigned contributors to sign
3. Stores signed CLAs in a GitHub Gist
4. Blocks merge until all contributors have signed
5. Remembers past signers (one-time signing per contributor)

```yaml
# .github/cla.yml (CLA Assistant configuration)
name: CLA Assistant
on:
  issue_comment:
    types: [created]
  pull_request_target:
    types: [opened, closed, synchronize]

permissions:
  actions: write
  contents: write
  pull-requests: write
  statuses: write

jobs:
  CLAssistant:
    runs-on: ubuntu-latest
    steps:
      - name: CLA Assistant
        uses: contributor-assistant/github-action@v2.4.0
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          PERSONAL_ACCESS_TOKEN: ${{ secrets.PERSONAL_ACCESS_TOKEN }}
        with:
          path-to-signatures: 'signatures/version1/cla.json'
          path-to-document: 'CLA.md'
          branch: 'cla-signatures'
          allowlist: 'bot*,dependabot*'
```

**CLA text key clauses** (to be drafted with legal counsel — summary only):
```
1. Grant of Copyright License: You grant Yashigani a perpetual, worldwide,
   non-exclusive, royalty-free copyright license to reproduce, prepare
   derivative works of, publicly display, sublicense, and distribute your
   Contributions and such derivative works in any form.

2. Grant of Patent License: You grant Yashigani a perpetual, worldwide,
   non-exclusive, royalty-free patent license under Your patent claims
   necessarily infringed by your Contribution or by the combination of your
   Contribution with the Project.

3. You represent that you are legally entitled to grant the above license.

4. You represent that each of Your Contributions is Your original creation.
```

### 3.3 Files to Create

```
LICENSE                   (Apache 2.0 full text)
CLA.md                    (CLA text — draft with legal counsel)
CONTRIBUTING.md           (How to contribute, CLA requirement, PR process)
.github/cla.yml           (CLA Assistant workflow)
signatures/               (CLA signature store — auto-managed by CLA Assistant)
.gitignore                (add signatures/ if desired — but best to commit them)
```

### 3.4 CONTRIBUTING.md Key Sections

1. **CLA requirement** — Must sign before any PR is merged. Individual or Corporate.
2. **License agreement** — All contributions are licensed under Apache 2.0.
3. **PR process** — Branch from `main`, one feature per PR, tests required.
4. **Code of conduct** — Reference to CODE_OF_CONDUCT.md.
5. **Security vulnerability reporting** — `security@yashigani.io` (not GitHub issues).

### 3.5 How This Protects Yashigani

| Risk | Mitigation |
|------|-----------|
| Contributor claims royalties for code in Professional tier | CLA: perpetual commercial license granted at time of contribution |
| Contributor files patent suit on their own contribution | CLA: explicit patent license granted |
| Contributor's employer claims ownership | CCLA: employer signs away rights before contribution merged |
| Contributor submits GPLv2 code (license-incompatible) | CLA: contributor represents they have right to submit; GPL code caught in code review |
| Forker builds competing product using community code | Apache 2.0 allows this — acceptable; competitive moat is pace of development + commercial features |

---

## 4. Phase Breakdown

| Phase | Track | Scope |
|-------|-------|-------|
| 1 | A | `model.py` — `max_users`, `PROFESSIONAL_PLUS`, updated `COMMUNITY_LICENSE` |
| 2 | A | `verifier.py` — v2 payload, backwards-compat v1 fallback |
| 3 | A | `enforcer.py` — `check_user_limit()`, 402 response body |
| 4 | A | `routes/users.py` — wire `check_user_limit()` on user creation |
| 5 | A | `routes/license.py` — user count in GET /admin/license |
| 6 | A | `scripts/sign_license.py` — `--max-users` flag, v2 payload |
| 7 | B | `LICENSE` (Apache 2.0), `CLA.md`, `CONTRIBUTING.md` |
| 8 | B | `.github/cla.yml` (CLA Assistant GitHub Action) |
| 9 | A+B | Documentation updates (objectives, owasp, install_config, preflight_check) |

---

## 5. Metrics / Success Criteria

**Track A:**
- Community tier: 21st agent registration returns 402 `LICENSE_LIMIT_EXCEEDED` (agent)
- Community tier: 6th user creation returns 402 `LICENSE_LIMIT_EXCEEDED` (users)
- Professional license: 501st agent returns 402; 501st user returns 402
- Professional Plus license: 2,001st agent returns 402; 1,001st user returns 402
- Enterprise license: no limits enforced
- v1 license file (no `max_users` field) loads with tier-default user limit (backward compat)
- `GET /admin/license` returns `limits.users.current` and `limits.users.maximum`

**Track B:**
- `LICENSE` file present at repo root (Apache 2.0)
- `CLA.md` present (draft)
- CLA Assistant blocks merge for unsigned contributors
- `CONTRIBUTING.md` references CLA requirement

---

## 6. Open Questions

None.

- **Q1 (Professional Plus max_orgs):** 3 orgs — confirmed by spec ✓
- **Q2 (Community user limit):** 5 users — confirmed ✓
- **Q3 (v1 license backward compat):** infer max_users from tier — approved approach ✓
- **Q4 (CLA tool):** CLA Assistant (free, GitHub-native) — confirmed ✓
- **Q5 (community license):** Apache 2.0 — confirmed ✓

---

*Awaiting GO to implement all 9 phases.*
