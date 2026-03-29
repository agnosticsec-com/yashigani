"""
Feature gate enforcement.

The active license is loaded once at startup and cached in module state.
All gate functions are synchronous — called from FastAPI route handlers.
"""
from __future__ import annotations

from yashigani.licensing.model import COMMUNITY_LICENSE, LicenseState, LicenseTier

# ---------------------------------------------------------------------------
# Module-level license state
# ---------------------------------------------------------------------------

_license: LicenseState = COMMUNITY_LICENSE


def set_license(lic: LicenseState) -> None:
    """Set the active license. Called once at startup."""
    global _license
    _license = lic


def get_license() -> LicenseState:
    """Return the currently active license."""
    return _license


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class LicenseFeatureGated(Exception):
    def __init__(self, feature: str, tier: LicenseTier) -> None:
        self.feature = feature
        self.tier = tier
        super().__init__(f"Feature '{feature}' is not available on {tier.value} tier")


class LicenseLimitExceeded(Exception):
    def __init__(self, limit_name: str, current: int, max_val: int) -> None:
        self.limit_name = limit_name
        self.current = current
        self.max_val = max_val
        super().__init__(
            f"License limit exceeded: {limit_name} ({current}/{max_val})"
        )


# ---------------------------------------------------------------------------
# Gate functions
# ---------------------------------------------------------------------------

def require_feature(feature: str) -> None:
    """Raise LicenseFeatureGated if feature not in active license."""
    if not _license.has_feature(feature):
        raise LicenseFeatureGated(feature=feature, tier=_license.tier)


def check_agent_limit(current_count: int) -> None:
    """Raise LicenseLimitExceeded if current_count >= max_agents (and max != -1)."""
    if _license.max_agents == -1:
        return
    if current_count >= _license.max_agents:
        raise LicenseLimitExceeded(
            limit_name="max_agents",
            current=current_count,
            max_val=_license.max_agents,
        )


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


def check_org_limit(current_count: int) -> None:
    """Raise LicenseLimitExceeded if current_count >= max_orgs (and max != -1)."""
    if _license.max_orgs == -1:
        return
    if current_count >= _license.max_orgs:
        raise LicenseLimitExceeded(
            limit_name="max_orgs",
            current=current_count,
            max_val=_license.max_orgs,
        )


# ---------------------------------------------------------------------------
# FastAPI exception handler helpers
# ---------------------------------------------------------------------------

# Which tier unlocks each feature — used in upgrade messages
_FEATURE_UPGRADE_TIER: dict[str, str] = {
    "oidc": "Starter",
    "saml": "Professional",
    "scim": "Professional",
}


def license_feature_gated_response(exc: LicenseFeatureGated) -> dict:
    upgrade_tier = _FEATURE_UPGRADE_TIER.get(exc.feature, "Professional")
    return {
        "error": "LICENSE_FEATURE_GATED",
        "feature": exc.feature,
        "tier": exc.tier.value,
        "upgrade_url": "https://agnosticsec.com/pricing",
        "message": f"{exc.feature.upper()} requires {upgrade_tier} or higher",
    }


def license_limit_exceeded_response(exc: LicenseLimitExceeded) -> dict:
    tier = _license.tier.value
    limit_label = {
        "max_agents":      "Agent",
        "max_end_users":   "End user",
        "max_admin_seats": "Admin seat",
        "max_orgs":        "Organization",
    }.get(exc.limit_name, exc.limit_name)
    return {
        "error": "LICENSE_LIMIT_EXCEEDED",
        "limit": exc.limit_name,
        "current": exc.current,
        "maximum": exc.max_val,
        "tier": tier,
        "upgrade_url": "https://agnosticsec.com/pricing",
        "message": (
            f"{limit_label} limit reached ({exc.current}/{exc.max_val}). "
            f"Upgrade your license at yashigani.io/pricing."
        ),
    }
