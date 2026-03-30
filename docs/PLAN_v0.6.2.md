# Yashigani v0.6.2 — Implementation Plan

**Date:** 2026-03-28
**Author:** Maxine (PM/PO — Lead Architect)
**Status:** SUPERSEDED — content merged into v0.7.0
**Predecessor:** v0.6.1 (4-tier model · max_users · PROFESSIONAL_PLUS · Apache 2.0 + CLA)

---

## 1. Executive Summary

v0.6.2 completes the licensing model with three changes:

1. **Starter tier** — $1,200/year. Fills the gap between Community and Professional for small teams with an SSO mandate (OIDC only, 100 agents, 250 end users, 25 admin seats). Designed to convert Community users who hit the SSO wall without charging them Professional prices.

2. **Three-dimensional limits** — Split the single `max_users` field (planned in v0.6.1) into two independent limits: `max_end_users` (people using AI tools through the gateway) and `max_admin_seats` (people managing the Yashigani control plane). These are fundamentally different populations with different scaling dynamics and must be licensed separately.

3. **v3 license payload** — Updated `.ysg` payload schema carrying all three limit dimensions. Backwards-compatible: v1/v2 license files load with per-tier defaults inferred from the `tier` field.

---

## 2. Final Tier Model

| Tier | Agents | End Users | Admin Seats | Orgs | SSO | Price |
|------|--------|-----------|-------------|------|-----|-------|
| **Community** | 20 | 50 | 10 | 1 | None | Free |
| **Starter** | 100 | 250 | 25 | 1 | OIDC only | $1,200/yr |
| **Professional** | 500 | 1,000 | 50 | 1 | Full (SAML+OIDC+SCIM) | $4,800/yr |
| **Professional Plus** | 2,000 | 10,000 | 200 | 5 | Full | $14,400/yr |
| **Enterprise** | ∞ | ∞ | ∞ | ∞ | Full | $48,000+/yr |

**Why Starter unlocks OIDC but not SAML/SCIM:**
- OIDC is the SSO protocol used by Google Workspace, Okta (personal tier), GitHub — what small teams actually have
- SAML is an enterprise IdP protocol (Okta enterprise, Azure AD ADFS, PingFederate) — not needed at Starter scale
- SCIM requires an enterprise IdP that supports automated provisioning — out of scope at Starter

---

## 3. Code Changes

### 3.1 `src/yashigani/licensing/model.py`

**What changes:**
- Add `STARTER` and `PROFESSIONAL_PLUS` to `LicenseTier`
- Add `max_end_users: int` and `max_admin_seats: int` to `LicenseState`
- Remove the `max_users` field (never shipped to production — was a v0.6.1 plan item)
- Update `COMMUNITY_LICENSE` with all five tier defaults
- Add per-tier limit constants for use by verifier backwards-compat

```python
class LicenseTier(str, Enum):
    COMMUNITY         = "community"
    STARTER           = "starter"
    PROFESSIONAL      = "professional"
    PROFESSIONAL_PLUS = "professional_plus"
    ENTERPRISE        = "enterprise"

@dataclass(frozen=True)
class LicenseState:
    tier: LicenseTier
    org_domain: str
    max_agents: int        # -1 = unlimited
    max_end_users: int     # end users proxied through gateway, -1 = unlimited
    max_admin_seats: int   # backoffice admin accounts, -1 = unlimited
    max_orgs: int          # -1 = unlimited
    features: frozenset
    issued_at: datetime
    expires_at: Optional[datetime]
    license_id: Optional[str]
    valid: bool
    error: Optional[str]

# Tier-default limits — used by verifier for v1/v2 backwards compat
_TIER_DEFAULTS: dict[str, dict] = {
    "community":         {"max_agents": 20,    "max_end_users": 50,     "max_admin_seats": 10,  "max_orgs": 1},
    "starter":           {"max_agents": 100,   "max_end_users": 250,    "max_admin_seats": 25,  "max_orgs": 1},
    "professional":      {"max_agents": 500,   "max_end_users": 1000,   "max_admin_seats": 50,  "max_orgs": 1},
    "professional_plus": {"max_agents": 2000,  "max_end_users": 10000,  "max_admin_seats": 200, "max_orgs": 5},
    "enterprise":        {"max_agents": -1,    "max_end_users": -1,     "max_admin_seats": -1,  "max_orgs": -1},
}

COMMUNITY_LICENSE = LicenseState(
    tier=LicenseTier.COMMUNITY,
    org_domain="*",
    max_agents=20,
    max_end_users=50,
    max_admin_seats=10,
    max_orgs=1,
    features=frozenset(),
    issued_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    expires_at=None,
    license_id=None,
    valid=True,
    error=None,
)
```

### 3.2 `src/yashigani/licensing/enforcer.py`

**What changes:**
- Add `check_end_user_limit(current_count: int) -> None`
- Add `check_admin_seat_limit(current_count: int) -> None`
- Update `license_feature_gated_response` to correctly name the tier that unlocks each feature
- Update `license_limit_exceeded_response` to include tier context and human message

```python
def check_end_user_limit(current_count: int) -> None:
    """Raise LicenseLimitExceeded if current_count >= max_end_users (and max != -1)."""
    if _license.max_end_users == -1:
        return
    if current_count >= _license.max_end_users:
        raise LicenseLimitExceeded(
            limit_name="max_end_users",
            current=current_count,
            max_val=_license.max_end_users,
        )

def check_admin_seat_limit(current_count: int) -> None:
    """Raise LicenseLimitExceeded if current_count >= max_admin_seats (and max != -1)."""
    if _license.max_admin_seats == -1:
        return
    if current_count >= _license.max_admin_seats:
        raise LicenseLimitExceeded(
            limit_name="max_admin_seats",
            current=current_count,
            max_val=_license.max_admin_seats,
        )
```

402 response body for limit exceeded:
```json
{
  "error": "LICENSE_LIMIT_EXCEEDED",
  "limit": "max_end_users",
  "current": 50,
  "maximum": 50,
  "tier": "community",
  "upgrade_url": "https://yashigani.io/pricing",
  "message": "End user limit reached (50/50). Upgrade to Starter or higher."
}
```

Feature gate upgrade message mapping:
| Feature | Required tier | Message |
|---------|--------------|---------|
| `oidc` | Starter | "OIDC SSO requires Starter or higher" |
| `saml` | Professional | "SAML SSO requires Professional or higher" |
| `scim` | Professional | "SCIM provisioning requires Professional or higher" |

### 3.3 `src/yashigani/licensing/verifier.py`

**What changes:**
- `_build_license_state()`: pull `max_end_users` and `max_admin_seats` from payload; fall back to `_TIER_DEFAULTS[tier_str]` if absent (v1/v2 compat)
- `verify_license()` expired-license rebuild: copy new fields
- Invalid-signature fallback `LicenseState(...)`: use `_TIER_DEFAULTS["community"]`

**v3 payload schema:**
```json
{
  "v": 3,
  "tier": "starter",
  "org_domain": "example.com",
  "max_agents": 100,
  "max_end_users": 250,
  "max_admin_seats": 25,
  "max_orgs": 1,
  "features": ["oidc"],
  "issued_at": "2026-04-01T00:00:00Z",
  "expires_at": "2027-04-01T00:00:00Z",
  "license_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Backwards compat (v1/v2 missing new fields):**
```python
defaults = _TIER_DEFAULTS.get(tier_str, _TIER_DEFAULTS["community"])
max_end_users  = int(payload.get("max_end_users",  defaults["max_end_users"]))
max_admin_seats = int(payload.get("max_admin_seats", defaults["max_admin_seats"]))
```

### 3.4 `src/yashigani/backoffice/routes/license.py`

**What changes:**
- `GET /admin/license` returns structured `limits` object with all four dimensions
- Count current end_users from auth_service, current admin_seats from auth_service admin count

```json
{
  "tier": "starter",
  "valid": true,
  "org_domain": "example.com",
  "expires_at": "2027-04-01T00:00:00Z",
  "license_id": "550e8400-...",
  "limits": {
    "agents":       { "current": 12,  "maximum": 100,  "unlimited": false },
    "end_users":    { "current": 47,  "maximum": 250,  "unlimited": false },
    "admin_seats":  { "current": 3,   "maximum": 25,   "unlimited": false },
    "orgs":         { "current": 1,   "maximum": 1,    "unlimited": false }
  },
  "features": { "oidc": true, "saml": false, "scim": false },
  "upgrade_url": "https://yashigani.io/pricing"
}
```

### 3.5 `src/yashigani/backoffice/routes/users.py`

**What changes:**
- Wire `check_admin_seat_limit(auth_service.count_admin_users())` on `POST /admin/users`

### 3.6 `scripts/sign_license.py`

**What changes:**
- Add `--max-end-users` and `--max-admin-seats` flags
- Add `--tier starter` support
- Emit v3 payload with all fields
- Default values for each tier if flags are omitted (use `_TIER_DEFAULTS`)

---

## 4. Files Modified

```
src/yashigani/licensing/model.py           (STARTER tier, max_end_users, max_admin_seats, _TIER_DEFAULTS)
src/yashigani/licensing/enforcer.py        (check_end_user_limit, check_admin_seat_limit, updated messages)
src/yashigani/licensing/verifier.py        (v3 payload, backwards compat, new fields in all LicenseState builds)
src/yashigani/backoffice/routes/license.py (structured limits response)
src/yashigani/backoffice/routes/users.py   (check_admin_seat_limit on POST /admin/users)
scripts/sign_license.py                    (--max-end-users, --max-admin-seats, v3 payload)
```

## 5. Files NOT Changed

```
src/yashigani/licensing/loader.py          (resolution order unchanged)
src/yashigani/licensing/__init__.py        (re-exports unchanged)
src/yashigani/agents/registry.py           (check_agent_limit already wired in v0.6.0)
src/yashigani/sso/saml.py                  (require_feature("saml") already wired)
src/yashigani/sso/oidc.py                  (require_feature("oidc") already wired)
src/yashigani/backoffice/routes/scim.py    (require_feature("scim") already wired)
docker/docker-compose.yml                  (no structural change)
policy/*.rego                              (limits enforced at application layer)
install.sh / scripts/wizard.sh             (license step unchanged)
```

---

## 6. Phase Breakdown

| Phase | Scope |
|-------|-------|
| 1 | `model.py` — all five tiers, three limit fields, `_TIER_DEFAULTS`, updated `COMMUNITY_LICENSE` |
| 2 | `enforcer.py` — `check_end_user_limit`, `check_admin_seat_limit`, updated error messages |
| 3 | `verifier.py` — v3 schema, backwards compat for v1/v2, new fields in all LicenseState builds |
| 4 | `routes/license.py` — structured limits object in GET response |
| 5 | `routes/users.py` — wire `check_admin_seat_limit` |
| 6 | `scripts/sign_license.py` — new flags, v3 payload, tier defaults |
| 7 | Documentation updates (objectives, owasp, install_config, preflight_check) |

---

## 7. Success Criteria

- Community: 21st agent → 402; 51st end user → 402; 11th admin seat → 402
- Starter: 101st agent → 402; 251st end user → 402; 26th admin seat → 402; SAML → 402 (OIDC allowed)
- Professional: 501st agent → 402; 1,001st end user → 402; 51st admin seat → 402
- Enterprise: no limits enforced on any dimension
- v1 `.ysg` file (no `max_end_users` / `max_admin_seats`) loads successfully with tier-default values
- `GET /admin/license` returns `limits.end_users.current` and `limits.admin_seats.current`

---

*Awaiting GO to implement all 7 phases.*
