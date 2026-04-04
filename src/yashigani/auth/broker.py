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

from yashigani.sso.oidc import OIDCConfig, OIDCProvider, OIDCUserInfo

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
        self._oidc_providers: dict[str, OIDCProvider] = {}
        self._tier = tier
        self._limit = _TIER_IDP_LIMITS.get(tier, 0)
        logger.info("IdentityBroker: tier=%s, idp_limit=%d", tier, self._limit)

    def add_idp(self, config: IdPConfig, redirect_uri: str = "") -> None:
        """
        Register an IdP. Raises if tier limit exceeded.

        For OIDC IdPs, an OIDCProvider is created immediately so that
        get_oidc_auth_url() and handle_oidc_callback() can delegate to it.
        ``redirect_uri`` is required for OIDC; if omitted the provider is
        constructed without one (callers must pass it at exchange time).
        """
        if len(self._idps) >= self._limit:
            raise ValueError(
                f"IdP limit reached for tier '{self._tier}' "
                f"({self._limit} max, {len(self._idps)} configured)"
            )
        self._idps[config.id] = config

        if config.protocol == "oidc":
            oidc_cfg = OIDCConfig(
                client_id=config.client_id,
                client_secret=config.client_secret,
                discovery_url=config.metadata_url,
                redirect_uri=redirect_uri,
                scopes=["openid", "email", "profile", "groups"],
            )
            self._oidc_providers[config.id] = OIDCProvider(oidc_cfg)

        logger.info("IdentityBroker: added IdP %s (%s, %s)", config.id, config.name, config.protocol)

    def remove_idp(self, idp_id: str) -> None:
        """Remove an IdP configuration."""
        self._idps.pop(idp_id, None)
        self._oidc_providers.pop(idp_id, None)

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

    def get_oidc_auth_url(self, idp_id: str, redirect_uri: str, state: str, nonce: str = "") -> Optional[str]:
        """
        Generate OIDC authorization URL for a specific IdP.

        Delegates to OIDCProvider.get_authorization_url() which performs a
        real OIDC discovery fetch and uses authlib to build the URL.
        Returns the redirect URL, or None if IdP not found/disabled.
        """
        idp = self._idps.get(idp_id)
        if not idp or idp.protocol != "oidc" or not idp.enabled:
            return None

        provider = self._oidc_providers.get(idp_id)
        if provider is None:
            # Lazily create provider if it was somehow missing (e.g., added
            # before redirect_uri was known).  The caller must supply it here.
            oidc_cfg = OIDCConfig(
                client_id=idp.client_id,
                client_secret=idp.client_secret,
                discovery_url=idp.metadata_url,
                redirect_uri=redirect_uri,
                scopes=["openid", "email", "profile", "groups"],
            )
            provider = OIDCProvider(oidc_cfg)
            self._oidc_providers[idp_id] = provider
        else:
            # Stamp the redirect_uri onto the provider config — it may differ
            # per-request when the host/scheme changes across environments.
            provider._config.redirect_uri = redirect_uri

        return provider.get_authorization_url(state=state, nonce=nonce or state)

    def handle_oidc_callback(
        self,
        idp_id: str,
        code: str,
        redirect_uri: str,
        state: str = "",
    ) -> SSOResult:
        """
        Handle OIDC authorization code callback.

        Delegates to OIDCProvider.exchange_code(), validates the ID token,
        maps IdP groups, and returns a populated SSOResult.
        """
        idp = self._idps.get(idp_id)
        if not idp:
            return SSOResult(success=False, error="IdP not found")

        provider = self._oidc_providers.get(idp_id)
        if provider is None:
            return SSOResult(success=False, error=f"No OIDC provider configured for IdP '{idp_id}'")

        # Keep redirect_uri in sync — same value used during authorization.
        provider._config.redirect_uri = redirect_uri

        try:
            user_info: OIDCUserInfo = provider.exchange_code(code=code, state=state)
        except ValueError as exc:
            logger.warning("OIDC code exchange failed for IdP %s: %s", idp.name, exc)
            return SSOResult(success=False, error=str(exc))
        except Exception as exc:
            logger.error("OIDC provider error for IdP %s: %s", idp.name, exc)
            return SSOResult(success=False, error="OIDC token exchange failed")

        # Extract raw groups claim from ID token (Entra: groups, Okta: groups, etc.)
        raw_groups: list[str] = []
        for claim_name in ("groups", "roles", "cognito:groups"):
            val = user_info.raw_claims.get(claim_name)
            if isinstance(val, list):
                raw_groups = [str(g) for g in val]
                break

        mapped_groups = self.map_groups(idp_id, raw_groups)

        logger.info(
            "OIDC callback success: idp=%s sub=%s email=%s groups=%s",
            idp.name, user_info.subject, user_info.email, mapped_groups,
        )
        return SSOResult(
            success=True,
            identity_id=user_info.subject,
            email=user_info.email or "",
            name=user_info.name or "",
            groups=mapped_groups,
            idp_name=idp.name,
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
