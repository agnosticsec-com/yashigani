"""
Yashigani Auth — Multi-IdP Identity Broker.

Yashigani IS the identity broker (Decision 11). Supports OIDC and SAML v2
with multiple IdPs per deployment. Caddy delegates auth to the backoffice,
which resolves identity and sets session cookies.

Tier gating:
  Community:         Local auth + API keys only
  Starter:           1 OIDC
  Professional:      1 OIDC + 1 SAML
  Professional Plus: 5 IdPs (any mix)
  Enterprise:        Unlimited
  Academic:          1 OIDC

Login flow:
  1. User hits /chat/* -> Caddy redirects unauthenticated to /auth/sso/select
  2. User selects IdP (or auto-detected by email domain)
  3. Redirect to IdP (OIDC authorization endpoint or SAML SSO URL)
  4. IdP callback -> backoffice validates token/assertion
  5. Backoffice resolves/creates Yashigani identity
  6. Sets session cookie
  7. Caddy reads session -> injects X-Forwarded-* headers
  8. Open WebUI/Gateway receive pre-authenticated identity
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class IdPConfig:
    """Configuration for an identity provider."""
    id: str
    name: str                      # Display name ("Entra ID Germany")
    protocol: str                  # "oidc" or "saml"
    metadata_url: str = ""         # OIDC discovery or SAML metadata URL
    client_id: str = ""            # OIDC client ID or SAML entity ID
    client_secret: str = ""        # Stored encrypted in KMS
    entity_id: str = ""            # SAML entity ID
    group_mapping: dict = field(default_factory=dict)  # IdP group -> Yashigani group
    org_id: str = ""               # Which org this IdP serves
    default_sensitivity: str = "INTERNAL"
    email_domains: list[str] = field(default_factory=list)  # For auto-detection
    enabled: bool = True


@dataclass
class SSOResult:
    """Result of SSO authentication."""
    success: bool
    identity_id: str = ""
    email: str = ""
    name: str = ""
    groups: list[str] = field(default_factory=list)
    idp_name: str = ""
    error: str = ""


# Tier limits for IdP count
_TIER_IDP_LIMITS = {
    "community": 0,
    "starter": 1,
    "professional": 2,
    "professional_plus": 5,
    "enterprise": 999,
    "academic": 1,
}


class IdentityBroker:
    """
    Multi-IdP identity broker.

    Manages IdP configurations and handles SSO authentication flows.
    """

    def __init__(self, tier: str = "community") -> None:
        self._idps: dict[str, IdPConfig] = {}
        self._tier = tier
        self._limit = _TIER_IDP_LIMITS.get(tier, 0)
        logger.info("IdentityBroker: tier=%s, idp_limit=%d", tier, self._limit)

    def add_idp(self, config: IdPConfig) -> None:
        """Register an IdP. Raises if tier limit exceeded."""
        if len(self._idps) >= self._limit:
            raise ValueError(
                f"IdP limit reached for tier '{self._tier}' "
                f"({self._limit} max, {len(self._idps)} configured)"
            )
        self._idps[config.id] = config
        logger.info("IdentityBroker: added IdP %s (%s, %s)", config.id, config.name, config.protocol)

    def remove_idp(self, idp_id: str) -> None:
        """Remove an IdP configuration."""
        self._idps.pop(idp_id, None)

    def list_idps(self) -> list[IdPConfig]:
        """List all configured IdPs."""
        return [idp for idp in self._idps.values() if idp.enabled]

    def get_idp(self, idp_id: str) -> Optional[IdPConfig]:
        """Get a specific IdP configuration."""
        return self._idps.get(idp_id)

    def detect_idp_by_email(self, email: str) -> Optional[IdPConfig]:
        """Auto-detect IdP from email domain."""
        domain = email.split("@")[-1].lower() if "@" in email else ""
        for idp in self._idps.values():
            if idp.enabled and domain in idp.email_domains:
                return idp
        return None

    def get_oidc_auth_url(self, idp_id: str, redirect_uri: str, state: str) -> Optional[str]:
        """
        Generate OIDC authorization URL for a specific IdP.

        Returns the URL to redirect the user to, or None if IdP not found.
        """
        idp = self._idps.get(idp_id)
        if not idp or idp.protocol != "oidc" or not idp.enabled:
            return None

        # In production, this would use authlib to construct the URL
        # from the IdP's .well-known/openid-configuration
        auth_endpoint = f"{idp.metadata_url.rstrip('/')}/authorize"
        params = (
            f"?client_id={idp.client_id}"
            f"&redirect_uri={redirect_uri}"
            f"&response_type=code"
            f"&scope=openid+email+profile+groups"
            f"&state={state}"
        )
        return auth_endpoint + params

    def handle_oidc_callback(
        self,
        idp_id: str,
        code: str,
        redirect_uri: str,
    ) -> SSOResult:
        """
        Handle OIDC authorization code callback.

        In production, this exchanges the code for tokens, validates the
        ID token, and extracts the user's email, name, and groups.
        """
        idp = self._idps.get(idp_id)
        if not idp:
            return SSOResult(success=False, error="IdP not found")

        # Placeholder — authlib integration in full implementation
        # This would:
        # 1. Exchange code for tokens at IdP's token endpoint
        # 2. Validate ID token JWT (signature, expiry, audience)
        # 3. Extract claims (email, name, groups)
        # 4. Map IdP groups to Yashigani groups
        # 5. Create/update identity in registry

        logger.info("OIDC callback for IdP %s — code exchange pending implementation", idp.name)
        return SSOResult(
            success=False,
            error="OIDC code exchange not yet implemented — use API keys for v1.0 beta",
        )

    def handle_saml_response(
        self,
        idp_id: str,
        saml_response: str,
    ) -> SSOResult:
        """
        Handle SAML v2 assertion response.

        In production, this validates the SAML assertion and extracts
        the user's attributes.
        """
        idp = self._idps.get(idp_id)
        if not idp:
            return SSOResult(success=False, error="IdP not found")

        logger.info("SAML response for IdP %s — assertion validation pending implementation", idp.name)
        return SSOResult(
            success=False,
            error="SAML assertion validation not yet implemented — use API keys for v1.0 beta",
        )

    def map_groups(self, idp_id: str, idp_groups: list[str]) -> list[str]:
        """Map IdP group names to Yashigani group slugs."""
        idp = self._idps.get(idp_id)
        if not idp:
            return []
        return [
            idp.group_mapping.get(g, g)  # Pass through if no mapping
            for g in idp_groups
        ]
