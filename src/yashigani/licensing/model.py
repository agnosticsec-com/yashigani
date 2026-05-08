"""License model — tiers, state, community defaults."""
# Last updated: 2026-05-06T00:00:00+01:00 (retro #42 website-truth alignment + LIC-001..007 hardening rebased)
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Union


class LicenseTier(str, Enum):
    COMMUNITY          = "community"
    IGNITER            = "igniter"
    STARTER            = "starter"
    PROFESSIONAL       = "professional"
    PROFESSIONAL_PLUS  = "professional_plus"
    ENTERPRISE         = "enterprise"
    ACADEMIC_NONPROFIT = "academic_nonprofit"
    # v2.23.2 GROUP-5-3: canary sentinel — never issued to customers.
    # If verify_license() accepts a CANARY token, the verifier has been patched
    # to remove tier filtering. Tested by canary-token integration test.
    CANARY             = "canary"


class LicenseFeature(str, Enum):
    OIDC       = "oidc"
    SAML       = "saml"
    SCIM       = "scim"
    # v2.2 — PII detection (Professional Plus+)
    PII_LOG    = "pii_log"      # LOG mode: detect and record findings only
    PII_REDACT = "pii_redact"   # REDACT and BLOCK modes: mutate or block payloads


@dataclass(frozen=True)
class LicenseState:
    tier: LicenseTier
    org_domain: str                       # "*" means any domain (community)
    max_agents: int                       # -1 = unlimited
    max_end_users: int                    # end users proxied through gateway, -1 = unlimited
    max_admin_seats: int                  # backoffice admin accounts, -1 = unlimited
    max_orgs: int                         # -1 = unlimited
    features: frozenset[LicenseFeature]   # typed feature set; verifier coerces strings on load
    issued_at: datetime
    expires_at: Optional[datetime]
    license_id: Optional[str]
    valid: bool
    error: Optional[str]

    def has_feature(self, feature: Union[LicenseFeature, str]) -> bool:
        if isinstance(feature, str):
            try:
                feature = LicenseFeature(feature)
            except ValueError:
                return False
        return feature in self.features

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at


# Per-tier limit defaults — used by verifier for backwards-compat with
# v1/v2 license payloads that pre-date the max_end_users / max_admin_seats fields.
# Source of truth: README §8 Feature Matrix by Tier (mirrors agnosticsec.com/pricing).
TIER_DEFAULTS: dict[str, dict] = {
    "community":          {"max_agents": 20,    "max_end_users": 5,      "max_admin_seats": 2,   "max_orgs": 1},
    "igniter":            {"max_agents": 200,   "max_end_users": 50,     "max_admin_seats": 5,   "max_orgs": 1},
    "starter":            {"max_agents": 400,   "max_end_users": 100,    "max_admin_seats": 10,  "max_orgs": 1},
    "professional":       {"max_agents": 2000,  "max_end_users": 500,    "max_admin_seats": 25,  "max_orgs": 1},
    "professional_plus":  {"max_agents": 16000, "max_end_users": 4000,   "max_admin_seats": 100, "max_orgs": 5},
    "enterprise":         {"max_agents": -1,    "max_end_users": -1,     "max_admin_seats": -1,  "max_orgs": -1},
    # Per README §8 / pricing page: Non-profit & Education = Unlimited everything.
    "academic_nonprofit": {"max_agents": -1,    "max_end_users": -1,     "max_admin_seats": -1,  "max_orgs": -1},
    # canary: community limits (this tier is never legitimately issued)
    "canary":             {"max_agents": 20,    "max_end_users": 5,      "max_admin_seats": 2,   "max_orgs": 1},
}


# Community hardcoded defaults — no license file needed
# v2.23.2 canonical: 20 agents / 5 end users / 2 admin seats / 1 org
COMMUNITY_LICENSE = LicenseState(
    tier=LicenseTier.COMMUNITY,
    org_domain="*",
    max_agents=20,
    max_end_users=5,
    max_admin_seats=2,
    max_orgs=1,
    features=frozenset(),
    issued_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    expires_at=None,
    license_id=None,
    valid=True,
    error=None,
)

# Academic / non-profit hardcoded defaults — requires a signed license file.
# Per README §8 / pricing page: Non-profit & Education has Unlimited everything.
ACADEMIC_NONPROFIT_LICENSE = LicenseState(
    tier=LicenseTier.ACADEMIC_NONPROFIT,
    org_domain="*",
    max_agents=-1,
    max_end_users=-1,
    max_admin_seats=-1,
    max_orgs=-1,
    features=frozenset(),
    issued_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    expires_at=None,
    license_id=None,
    valid=True,
    error=None,
)
