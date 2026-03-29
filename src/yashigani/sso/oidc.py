"""
Yashigani SSO — OpenID Connect (OIDC) relying party.
Validates ID tokens and resolves user identity from claims.
YASHIGANI_AUTH_MODE=sso with OIDC discovery.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional

from yashigani.licensing.enforcer import require_feature

logger = logging.getLogger(__name__)


def _import_authlib():
    try:
        from authlib.integrations.requests_client import OAuth2Session
        from authlib.jose import jwt, JWTClaims
        from authlib.jose.errors import JoseError
        return OAuth2Session, jwt, JWTClaims, JoseError
    except ImportError as exc:
        raise ImportError(
            "authlib is required for OIDC. Install with: pip install authlib"
        ) from exc


@dataclass
class OIDCConfig:
    client_id: str
    client_secret: str
    discovery_url: str          # e.g. https://accounts.google.com/.well-known/openid-configuration
    redirect_uri: str
    scopes: list[str] = None

    def __post_init__(self):
        if self.scopes is None:
            self.scopes = ["openid", "email", "profile"]


@dataclass
class OIDCUserInfo:
    subject: str                # IdP-stable user identifier
    email: Optional[str]
    name: Optional[str]
    raw_claims: dict


class OIDCProvider:
    """
    OIDC Relying Party.
    Handles authorization redirect, callback token exchange, and ID token validation.
    """

    def __init__(self, config: OIDCConfig) -> None:
        self._config = config
        self._metadata: Optional[dict] = None
        self._jwks: Optional[dict] = None

    def get_authorization_url(self, state: str, nonce: str) -> str:
        """Build the IdP authorization redirect URL."""
        require_feature("oidc")
        OAuth2Session, *_ = _import_authlib()
        meta = self._get_metadata()
        session = OAuth2Session(
            client_id=self._config.client_id,
            redirect_uri=self._config.redirect_uri,
            scope=" ".join(self._config.scopes),
        )
        url, _ = session.create_authorization_url(
            meta["authorization_endpoint"],
            state=state,
            nonce=nonce,
        )
        return url

    def exchange_code(self, code: str, state: str) -> OIDCUserInfo:
        """
        Exchange authorization code for tokens.
        Validates ID token signature and claims.
        Returns OIDCUserInfo on success.
        """
        require_feature("oidc")
        OAuth2Session, jwt_lib, _, JoseError = _import_authlib()
        meta = self._get_metadata()
        session = OAuth2Session(
            client_id=self._config.client_id,
            client_secret=self._config.client_secret,
            redirect_uri=self._config.redirect_uri,
        )
        token = session.fetch_token(
            meta["token_endpoint"],
            code=code,
            grant_type="authorization_code",
        )
        id_token = token.get("id_token")
        if not id_token:
            raise ValueError("No id_token in token response")

        jwks = self._get_jwks()
        try:
            claims = jwt_lib.decode(id_token, jwks)
            claims.validate(
                now=int(time.time()),
                leeway=30,
            )
        except JoseError as exc:
            raise ValueError(f"ID token validation failed: {exc}") from exc

        return OIDCUserInfo(
            subject=claims["sub"],
            email=claims.get("email"),
            name=claims.get("name"),
            raw_claims=dict(claims),
        )

    # -- Internal ------------------------------------------------------------

    def _get_metadata(self) -> dict:
        if self._metadata:
            return self._metadata
        import urllib.request, json
        with urllib.request.urlopen(self._config.discovery_url, timeout=10) as resp:
            self._metadata = json.loads(resp.read())
        return self._metadata

    def _get_jwks(self) -> dict:
        if self._jwks:
            return self._jwks
        import urllib.request, json
        meta = self._get_metadata()
        with urllib.request.urlopen(meta["jwks_uri"], timeout=10) as resp:
            self._jwks = json.loads(resp.read())
        return self._jwks
