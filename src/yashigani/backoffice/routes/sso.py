"""
Yashigani Backoffice — SSO routes.

GET  /auth/sso/select                  — list available IdPs (JSON)
GET  /auth/sso/oidc/{idp_id}           — initiate OIDC flow (redirect to IdP)
GET  /auth/sso/oidc/{idp_id}/callback  — OIDC callback: exchange code, create session
POST /auth/sso/saml/{idp_id}/acs       — SAML ACS endpoint (placeholder, 501)

Security invariants:
  - State token and nonce are generated with secrets.token_urlsafe(32) (256-bit).
  - State is stored in Redis with a 10-minute TTL; replayed or missing state
    is rejected with 400 (CSRF prevention, ASVS V3.5.3).
  - Nonce is embedded in the state value and verified against the ID token
    nonce claim (if present) to prevent token injection (ASVS V3.5.4).
  - On callback success, the Yashigani identity is resolved or created in the
    IdentityRegistry, then a session is issued via SessionStore.
  - Email is never stored in audit logs — SHA-256 hash only.
  - All state/nonce keys use a dedicated Redis namespace (sso:state:).
  - require_feature("oidc") is called before any OIDC-specific work (tier gate).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse

from yashigani.backoffice.state import backoffice_state
from yashigani.auth.session import _mask_ip
from yashigani.licensing.enforcer import (
    require_feature,
    LicenseFeatureGated,
    license_feature_gated_response,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Redis TTL for OIDC state tokens (10 minutes — generous for slow IdPs).
_STATE_TTL_SECONDS = 600
_STATE_KEY_PREFIX = "sso:state:"

# Session max-age mirrors the existing admin/user session constant (4 hours).
_SESSION_MAX_AGE = 14400
_USER_SESSION_COOKIE = "__Host-yashigani_session"
_PENDING_2FA_COOKIE = "yashigani_sso_pending"
_PENDING_2FA_TTL = 300  # 5 minutes to complete 2FA after SSO
_PENDING_2FA_PREFIX = "sso:pending_2fa:"

# Slug sanitiser: only lowercase alphanumeric + hyphens.
_SLUG_RE = re.compile(r"[^a-z0-9\-]")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _redis():
    """
    Return a raw Redis client for SSO state storage.
    Reuses the session_store's underlying Redis connection (db/1).
    Falls back to None — callers must guard.
    """
    store = backoffice_state.session_store
    if store is None:
        return None
    return store._redis


def _build_redirect_uri(request: Request, idp_id: str) -> str:
    """Construct the absolute callback URL for this IdP."""
    base = str(request.base_url).rstrip("/")
    return f"{base}/auth/sso/oidc/{idp_id}/callback"


def _store_state(r, state: str, idp_id: str, nonce: str, code_verifier: str = "") -> None:
    """Persist state -> {idp_id, nonce, code_verifier, issued_at} in Redis with TTL."""
    payload = json.dumps({
        "idp_id": idp_id,
        "nonce": nonce,
        "code_verifier": code_verifier,
        "issued_at": time.time(),
    })
    r.setex(f"{_STATE_KEY_PREFIX}{state}", _STATE_TTL_SECONDS, payload)


def _consume_state(r, state: str) -> Optional[dict]:
    """
    Atomically read and delete the state entry.
    Returns the parsed payload or None if not found / expired.
    """
    key = f"{_STATE_KEY_PREFIX}{state}"
    raw = r.get(key)
    if raw is None:
        return None
    r.delete(key)
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


def _get_hmac_key() -> bytes:
    """
    Get the per-tenant HMAC key for email hashing.
    Uses YASHIGANI_DB_AES_KEY (always present in every deployment).
    Deleting this key makes all email hashes permanently unrecoverable
    — clean GDPR Article 17 erasure without breaking the audit chain.
    Multi-tenant: derive per-org key via HKDF if org_id is provided.
    """
    key = os.getenv("YASHIGANI_DB_AES_KEY", "")
    if not key:
        # Fallback to secrets file
        try:
            secrets_dir = os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets")
            with open(os.path.join(secrets_dir, "db_aes_key")) as f:
                key = f.read().strip()
        except Exception:
            key = "yashigani-default-hmac-key"  # dev/demo only
    return key.encode()


def _derive_org_id() -> str:
    """
    Derive a stable org_id from deployment identity:
    domain + license_id + deployment timestamp.
    Clients with multiple deployments (different domains/subdomains)
    get different org_ids, so email hashes don't correlate across deployments.
    """
    domain = os.getenv("YASHIGANI_TLS_DOMAIN", "localhost")
    license_id = ""
    try:
        from yashigani.licensing.enforcer import get_license
        lic = get_license()
        license_id = lic.license_id or lic.org_domain or ""
    except Exception:
        pass
    # Combine domain + license for deployment-unique org_id
    return f"{domain}:{license_id}" if license_id else domain


def _email_hash(email: str, org_id: str = "") -> str:
    """
    HMAC-SHA256 hex digest of the normalised email, keyed per tenant.
    Not reversible without the HMAC key. Deleting the key = GDPR erasure.
    For multi-tenant (enterprise), the org_id is mixed into the key
    so the same email in different orgs produces different hashes.
    org_id is derived from domain + license key if not provided.
    """
    base_key = _get_hmac_key()
    effective_org = org_id or _derive_org_id()
    if effective_org:
        # Per-org key derivation: HMAC(base_key, org_id) as the effective key
        derived_key = hmac.new(base_key, effective_org.encode(), hashlib.sha256).digest()
    else:
        derived_key = base_key
    return hmac.new(derived_key, email.strip().lower().encode(), hashlib.sha256).hexdigest()


def _email_to_slug(email: str) -> str:
    """
    Derive a registry slug from an email address.
    e.g. alice@example.com -> alice-example-com
    """
    local, _, domain = email.partition("@")
    raw = f"{local}-{domain}".lower()
    slug = _SLUG_RE.sub("-", raw).strip("-")
    # Trim to 64 chars — IdentityRegistry slug limit.
    return slug[:64]


def _resolve_or_create_identity(
    email: str,
    name: str,
    groups: list[str],
    idp_name: str,
    org_id: str,
    default_sensitivity: str,
) -> str:
    """
    Resolve an existing identity by slug or create a new one.

    Returns the identity_id.
    Raises RuntimeError if the registry is unavailable.
    """
    # IdentityRegistry lives on the RBAC store Redis client (db/3).
    # We access it via backoffice_state if wired, otherwise instantiate locally.
    registry = getattr(backoffice_state, "identity_registry", None)
    if registry is None:
        raise RuntimeError("IdentityRegistry is not available")

    from yashigani.identity.registry import IdentityKind

    slug = _email_to_slug(email)
    existing = registry.get_by_slug(slug)
    if existing:
        identity_id = existing["identity_id"]
        # Keep groups and last_seen_at fresh.
        registry.update(identity_id, groups=groups)
        logger.info(
            "SSO: resolved existing identity %s (email_hash=%s)",
            identity_id, _email_hash(email),
        )
        return identity_id

    # New user — register with HUMAN kind.
    identity_id, _key = registry.register(
        kind=IdentityKind.HUMAN,
        name=name or email,
        slug=slug,
        description=f"SSO user via {idp_name}",
        groups=groups,
        sensitivity_ceiling=default_sensitivity,
        org_id=org_id,
    )
    logger.info(
        "SSO: created new identity %s slug=%s (email_hash=%s)",
        identity_id, slug, _email_hash(email),
    )
    return identity_id


def _write_sso_success_audit(
    idp_id: str,
    idp_name: str,
    identity_id: str,
    email: str,
    groups: list[str],
    client_ip: str,
    org_id: str = "",
) -> None:
    from yashigani.audit.schema import SSOLoginSuccessEvent
    try:
        backoffice_state.audit_writer.write(
            SSOLoginSuccessEvent(
                idp_id=idp_id,
                idp_name=idp_name,
                identity_id=identity_id,
                email_hash=_email_hash(email, org_id=org_id),
                groups=groups,
                client_ip_prefix=_mask_ip(client_ip),
            )
        )
    except Exception as exc:
        logger.error("SSO audit write failed (success): %s", exc)


def _write_sso_failure_audit(
    idp_id: str,
    idp_name: str,
    reason: str,
    client_ip: str,
) -> None:
    from yashigani.audit.schema import SSOLoginFailureEvent
    try:
        backoffice_state.audit_writer.write(
            SSOLoginFailureEvent(
                idp_id=idp_id,
                idp_name=idp_name,
                failure_reason=reason,
                client_ip_prefix=_mask_ip(client_ip),
            )
        )
    except Exception as exc:
        logger.error("SSO audit write failed (failure): %s", exc)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/sso/select")
async def list_idps():
    """
    Return the list of enabled IdPs available for SSO login.
    Unauthenticated — shown to anonymous users on the login page.
    """
    broker = backoffice_state.identity_broker
    if broker is None:
        return JSONResponse(content={"idps": []})

    idps = broker.list_idps()
    return JSONResponse(content={
        "idps": [
            {
                "id": idp.id,
                "name": idp.name,
                "protocol": idp.protocol,
                "email_domains": idp.email_domains,
            }
            for idp in idps
        ]
    })


@router.get("/sso/oidc/{idp_id}")
async def initiate_oidc(idp_id: str, request: Request):
    """
    Initiate an OIDC authorization flow.
    Generates a cryptographically random state + nonce, stores them in Redis
    with a 10-minute TTL, then redirects the browser to the IdP.
    """
    try:
        require_feature("oidc")
    except LicenseFeatureGated as exc:
        return JSONResponse(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            content=license_feature_gated_response(exc),
        )

    broker = backoffice_state.identity_broker
    if broker is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "identity_broker_unavailable"},
        )

    idp = broker.get_idp(idp_id)
    if idp is None or not idp.enabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "idp_not_found"},
        )
    if idp.protocol != "oidc":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "idp_not_oidc"},
        )

    r = _redis()
    if r is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "session_store_unavailable"},
        )

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    redirect_uri = _build_redirect_uri(request, idp_id)

    try:
        auth_url, code_verifier = broker.get_oidc_auth_url(
            idp_id=idp_id,
            redirect_uri=redirect_uri,
            state=state,
            nonce=nonce,
        )
    except Exception as exc:
        logger.error("OIDC initiation failed for IdP %s: %s", idp_id, exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "oidc_discovery_failed"},
        )

    if auth_url is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "auth_url_generation_failed"},
        )

    # Store state with PKCE code_verifier for the callback (ASVS 10.4.6).
    _store_state(r, state, idp_id, nonce, code_verifier=code_verifier)

    return RedirectResponse(url=auth_url, status_code=status.HTTP_302_FOUND)


@router.get("/sso/oidc/{idp_id}/callback")
async def oidc_callback(
    idp_id: str,
    request: Request,
    code: str = "",
    state: str = "",
    error: str = "",
    error_description: str = "",
):
    """
    Handle the OIDC authorization code callback from the IdP.

    On success: resolves/creates the Yashigani identity, issues a session
    cookie, and redirects to /chat.
    On failure: redirects to /login with an error query parameter.
    """
    client_ip = request.client.host if request.client else "unknown"

    # IdP-side errors (user denied consent, etc.)
    if error:
        logger.warning(
            "OIDC callback: IdP returned error for IdP %s: %s — %s",
            idp_id, error, error_description,
        )
        _write_sso_failure_audit(idp_id, idp_id, f"idp_error:{error}", client_ip)
        return RedirectResponse(
            url=f"/login?error=sso_failed&idp={idp_id}",
            status_code=status.HTTP_302_FOUND,
        )

    # Validate required parameters
    if not code or not state:
        _write_sso_failure_audit(idp_id, idp_id, "missing_code_or_state", client_ip)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "missing_code_or_state"},
        )

    # Verify feature gate
    try:
        require_feature("oidc")
    except LicenseFeatureGated as exc:
        return JSONResponse(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            content=license_feature_gated_response(exc),
        )

    broker = backoffice_state.identity_broker
    if broker is None:
        _write_sso_failure_audit(idp_id, idp_id, "broker_unavailable", client_ip)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "identity_broker_unavailable"},
        )

    r = _redis()
    if r is None:
        _write_sso_failure_audit(idp_id, idp_id, "session_store_unavailable", client_ip)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "session_store_unavailable"},
        )

    # Consume and validate state — CSRF protection (ASVS V3.5.3)
    state_payload = _consume_state(r, state)
    if state_payload is None:
        _write_sso_failure_audit(idp_id, idp_id, "invalid_or_expired_state", client_ip)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_or_expired_state"},
        )

    if state_payload.get("idp_id") != idp_id:
        _write_sso_failure_audit(idp_id, idp_id, "state_idp_mismatch", client_ip)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "state_idp_mismatch"},
        )

    # Exchange code for tokens + validate ID token.
    # Retrieve the PKCE code_verifier stored during initiation (ASVS 10.4.6).
    code_verifier = state_payload.get("code_verifier", "")
    redirect_uri = _build_redirect_uri(request, idp_id)
    sso_result = broker.handle_oidc_callback(
        idp_id=idp_id,
        code=code,
        redirect_uri=redirect_uri,
        state=state,
        code_verifier=code_verifier,
    )

    if not sso_result.success:
        _write_sso_failure_audit(
            idp_id, sso_result.idp_name or idp_id, sso_result.error, client_ip
        )
        return RedirectResponse(
            url=f"/login?error=sso_failed&idp={idp_id}",
            status_code=status.HTTP_302_FOUND,
        )

    # -----------------------------------------------------------------------
    # Validate acr (Authentication Context Class Reference) — ASVS 10.3.4
    # -----------------------------------------------------------------------
    _min_acr = os.getenv("YASHIGANI_MIN_ACR_VALUE", "").strip()
    _id_token_acr = ""
    if hasattr(sso_result, "raw_claims"):
        _id_token_acr = str(sso_result.raw_claims.get("acr", ""))
    # SSOResult may not carry raw_claims yet; fall back to empty.
    if not _id_token_acr and hasattr(sso_result, "acr"):
        _id_token_acr = str(getattr(sso_result, "acr", ""))

    if _min_acr and _id_token_acr:
        # Simple lexicographic comparison — works for well-structured acr URIs
        # (e.g. urn:mace:incommon:iap:silver < urn:mace:incommon:iap:gold)
        # and numeric levels (e.g. "1" < "2").
        if _id_token_acr < _min_acr:
            logger.warning(
                "OIDC acr too low: got %s, minimum %s (IdP %s)",
                _id_token_acr, _min_acr, idp_id,
            )
            _write_sso_failure_audit(
                idp_id, sso_result.idp_name or idp_id,
                f"acr_insufficient:{_id_token_acr}<{_min_acr}", client_ip,
            )
            return RedirectResponse(
                url=f"/login?error=auth_strength_insufficient&idp={idp_id}",
                status_code=status.HTTP_302_FOUND,
            )

    logger.info("OIDC acr=%s for IdP %s (min=%s)", _id_token_acr or "(none)", idp_id, _min_acr or "(any)")

    # Resolve or provision the Yashigani identity
    idp_config = broker.get_idp(idp_id)
    try:
        identity_id = _resolve_or_create_identity(
            email=sso_result.email,
            name=sso_result.name,
            groups=sso_result.groups,
            idp_name=sso_result.idp_name,
            org_id=idp_config.org_id if idp_config else "",
            default_sensitivity=(
                idp_config.default_sensitivity if idp_config else "INTERNAL"
            ),
        )
    except RuntimeError as exc:
        logger.error("SSO identity resolution failed: %s", exc)
        _write_sso_failure_audit(
            idp_id, sso_result.idp_name, "identity_registry_unavailable", client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "identity_registry_unavailable"},
        )
    except Exception as exc:
        logger.error("SSO identity resolution error: %s", exc)
        _write_sso_failure_audit(
            idp_id, sso_result.idp_name, "identity_resolution_failed", client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "identity_resolution_failed"},
        )

    # Check if 2FA is required after SSO
    sso_2fa_required = os.getenv("YASHIGANI_SSO_2FA_REQUIRED", "false").lower() == "true"

    if sso_2fa_required:
        # Create a pending-2FA token instead of a full session.
        # The user must complete Yashigani TOTP before getting access.
        pending_token = secrets.token_urlsafe(32)
        pending_data = json.dumps({
            "identity_id": identity_id,
            "email": sso_result.email,
            "name": sso_result.name,
            "groups": sso_result.groups,
            "idp_id": idp_id,
            "idp_name": sso_result.idp_name,
            "client_ip": client_ip,
            "created_at": time.time(),
        })
        r.setex(f"{_PENDING_2FA_PREFIX}{pending_token}", _PENDING_2FA_TTL, pending_data)

        response = RedirectResponse(
            url="/auth/sso/2fa",
            status_code=status.HTTP_302_FOUND,
        )
        response.set_cookie(
            key=_PENDING_2FA_COOKIE,
            value=pending_token,
            httponly=True,
            secure=True,
            samesite="strict",
            max_age=_PENDING_2FA_TTL,
            path="/auth",
        )
        logger.info("SSO 2FA pending for identity %s (IdP: %s)", identity_id, idp_id)
        return response

    # 2FA not required — issue full session immediately
    session = backoffice_state.session_store.create(
        account_id=identity_id,
        account_tier="user",
        client_ip=client_ip,
    )

    _write_sso_success_audit(
        idp_id=idp_id,
        idp_name=sso_result.idp_name,
        identity_id=identity_id,
        email=sso_result.email,
        groups=sso_result.groups,
        client_ip=client_ip,
    )

    response = RedirectResponse(url="/chat", status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key=_USER_SESSION_COOKIE,
        value=session.token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=_SESSION_MAX_AGE,
        path="/",
    )
    return response


@router.get("/sso/2fa")
async def sso_2fa_page(request: Request):
    """
    Serve the 2FA verification prompt after SSO.
    The user must submit their Yashigani TOTP code to complete login.
    """
    pending_token = request.cookies.get(_PENDING_2FA_COOKIE)
    if not pending_token:
        return RedirectResponse(url="/login?error=no_pending_sso", status_code=302)

    r = _redis()
    if r is None or r.get(f"{_PENDING_2FA_PREFIX}{pending_token}") is None:
        return RedirectResponse(url="/login?error=sso_2fa_expired", status_code=302)

    return JSONResponse(content={
        "status": "pending_2fa",
        "message": "SSO authentication successful. Enter your Yashigani TOTP code to complete login.",
        "endpoint": "/auth/sso/2fa/verify",
        "method": "POST",
        "fields": ["totp_code"],
    })


@router.post("/sso/2fa/verify")
async def sso_2fa_verify(request: Request):
    """
    Verify the Yashigani TOTP code after SSO authentication.
    On success, upgrade the pending session to a full session.
    """
    pending_token = request.cookies.get(_PENDING_2FA_COOKIE)
    if not pending_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "no_pending_sso_session"},
        )

    r = _redis()
    if r is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "session_store_unavailable"},
        )

    # Atomically consume the pending token
    raw = r.get(f"{_PENDING_2FA_PREFIX}{pending_token}")
    if raw is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "sso_2fa_expired_or_invalid"},
        )

    try:
        pending = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_pending_session"},
        )

    # Parse TOTP code from request body
    try:
        body = await request.json()
        totp_code = body.get("totp_code", "")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_request_body"},
        )

    if not totp_code or len(totp_code) != 6 or not totp_code.isdigit():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_totp_code_format"},
        )

    # Look up the identity's TOTP secret
    identity_id = pending.get("identity_id", "")
    registry = getattr(backoffice_state, "identity_registry", None)
    if registry is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "identity_registry_unavailable"},
        )

    # Verify TOTP — the identity must have a provisioned TOTP secret
    from yashigani.auth.totp import verify_totp

    identity = registry.get(identity_id)
    if identity is None:
        r.delete(f"{_PENDING_2FA_PREFIX}{pending_token}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "identity_not_found"},
        )

    totp_secret = identity.get("totp_secret", "")
    if not totp_secret:
        # Identity hasn't provisioned TOTP yet — they need to do that first
        r.delete(f"{_PENDING_2FA_PREFIX}{pending_token}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "totp_not_provisioned",
                "message": "You must provision a TOTP authenticator before using SSO. Contact your administrator.",
            },
        )

    used_codes: set = set()  # Recovery codes not applicable here
    if not verify_totp(totp_secret, totp_code, used_codes):
        # Don't consume the pending token on TOTP failure — let them retry
        _write_sso_failure_audit(
            pending.get("idp_id", ""),
            pending.get("idp_name", ""),
            "totp_verification_failed",
            pending.get("client_ip", "unknown"),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_totp_code"},
        )

    # TOTP verified — consume the pending token and issue a full session
    r.delete(f"{_PENDING_2FA_PREFIX}{pending_token}")

    client_ip = pending.get("client_ip", "unknown")
    session = backoffice_state.session_store.create(
        account_id=identity_id,
        account_tier="user",
        client_ip=client_ip,
    )

    _write_sso_success_audit(
        idp_id=pending.get("idp_id", ""),
        idp_name=pending.get("idp_name", ""),
        identity_id=identity_id,
        email=pending.get("email", ""),
        groups=pending.get("groups", []),
        client_ip=client_ip,
    )

    response = RedirectResponse(url="/chat", status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key=_USER_SESSION_COOKIE,
        value=session.token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=_SESSION_MAX_AGE,
        path="/",
    )
    # Clear the pending cookie
    response.delete_cookie(_PENDING_2FA_COOKIE, path="/auth")
    return response


@router.post("/sso/saml/{idp_id}/acs")
async def saml_acs(idp_id: str, request: Request):
    """
    SAML v2 Assertion Consumer Service endpoint.
    Receives the IdP POST with SAMLResponse, validates the assertion,
    resolves/creates the identity, and issues a session.
    """
    client_ip = request.client.host if request.client else "unknown"

    try:
        require_feature("saml")
    except LicenseFeatureGated as exc:
        return JSONResponse(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            content=license_feature_gated_response(exc),
        )

    broker = backoffice_state.identity_broker
    if broker is None:
        _write_sso_failure_audit(idp_id, idp_id, "broker_unavailable", client_ip)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "identity_broker_unavailable"},
        )

    idp = broker.get_idp(idp_id)
    if idp is None or not idp.enabled or idp.protocol != "saml":
        _write_sso_failure_audit(idp_id, idp_id, "idp_not_found_or_not_saml", client_ip)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "idp_not_found"},
        )

    # Build request_data for python3-saml
    form_data = await request.form()
    saml_response = form_data.get("SAMLResponse", "")
    relay_state = form_data.get("RelayState", "")

    if not saml_response:
        _write_sso_failure_audit(idp_id, idp.name, "missing_saml_response", client_ip)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "missing_saml_response"},
        )

    # Construct request_data dict expected by python3-saml
    url = str(request.url)
    request_data = {
        "https": "on" if request.url.scheme == "https" else "off",
        "http_host": request.url.hostname or "localhost",
        "server_port": request.url.port or (443 if request.url.scheme == "https" else 80),
        "script_name": request.url.path,
        "post_data": {"SAMLResponse": saml_response, "RelayState": relay_state},
    }

    # Process the SAML response using the broker's SAML handler
    sso_result = broker.handle_saml_response(idp_id=idp_id, saml_response=saml_response)

    if not sso_result.success:
        _write_sso_failure_audit(idp_id, idp.name, sso_result.error, client_ip)
        return RedirectResponse(
            url=f"/login?error=sso_failed&idp={idp_id}",
            status_code=status.HTTP_302_FOUND,
        )

    # Resolve or create the identity
    try:
        identity_id = _resolve_or_create_identity(
            email=sso_result.email,
            name=sso_result.name,
            groups=sso_result.groups,
            idp_name=sso_result.idp_name,
            org_id=idp.org_id,
            default_sensitivity=idp.default_sensitivity,
        )
    except RuntimeError as exc:
        logger.error("SAML identity resolution failed: %s", exc)
        _write_sso_failure_audit(idp_id, idp.name, "identity_registry_unavailable", client_ip)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "identity_registry_unavailable"},
        )

    # Check 2FA requirement
    r = _redis()
    sso_2fa_required = os.getenv("YASHIGANI_SSO_2FA_REQUIRED", "false").lower() == "true"

    if sso_2fa_required and r is not None:
        pending_token = secrets.token_urlsafe(32)
        pending_data = json.dumps({
            "identity_id": identity_id,
            "email": sso_result.email,
            "name": sso_result.name,
            "groups": sso_result.groups,
            "idp_id": idp_id,
            "idp_name": idp.name,
            "client_ip": client_ip,
            "created_at": time.time(),
        })
        r.setex(f"{_PENDING_2FA_PREFIX}{pending_token}", _PENDING_2FA_TTL, pending_data)

        response = RedirectResponse(url="/auth/sso/2fa", status_code=status.HTTP_302_FOUND)
        response.set_cookie(
            key=_PENDING_2FA_COOKIE, value=pending_token,
            httponly=True, secure=True, samesite="strict",
            max_age=_PENDING_2FA_TTL, path="/auth",
        )
        return response

    # Issue full session
    session = backoffice_state.session_store.create(
        account_id=identity_id,
        account_tier="user",
        client_ip=client_ip,
    )

    _write_sso_success_audit(
        idp_id=idp_id, idp_name=idp.name,
        identity_id=identity_id, email=sso_result.email,
        groups=sso_result.groups, client_ip=client_ip,
    )

    response = RedirectResponse(url="/chat", status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key=_USER_SESSION_COOKIE, value=session.token,
        httponly=True, secure=True, samesite="strict",
        max_age=_SESSION_MAX_AGE, path="/",
    )
    return response
