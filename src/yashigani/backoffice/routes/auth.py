"""
Yashigani Backoffice — Authentication routes.
POST /auth/login       — username + password + TOTP
POST /auth/logout      — invalidate session
GET  /auth/status      — check session validity
POST /auth/password/change — forced change on first login
POST /auth/totp/provision  — TOTP + recovery codes provisioning
"""
from __future__ import annotations

import time
from typing import Annotated, Optional

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, get_session_store, _SESSION_COOKIE
from yashigani.backoffice.state import backoffice_state
from yashigani.auth.totp import verify_totp, generate_provisioning, generate_recovery_code_set

router = APIRouter()

_TOTP_FAILURE_LIMIT = 3
_totp_failures: dict[str, int] = {}    # session_prefix → count


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1)
    totp_code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=36)


class TotpConfirmRequest(BaseModel):
    totp_code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


@router.post("/login")
async def login(body: LoginRequest, request: Request, response: Response):
    """
    Authenticate with username + password + TOTP.
    Issues a session cookie on success.
    Returns 401 for any failure (no credential enumeration).
    """
    state = backoffice_state
    success, record, reason = state.auth_service.authenticate(
        body.username, body.password, body.totp_code
    )

    if not success:
        state.audit_writer.write(
            _make_login_event(body.username, "failure", reason)
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail={"error": "invalid_credentials"})

    client_ip = request.client.host if request.client else "unknown"
    session = state.session_store.create(
        account_id=record.account_id,
        account_tier="admin",
        client_ip=client_ip,
    )

    state.audit_writer.write(
        _make_login_event(body.username, "success", None)
    )

    _set_session_cookie(response, session.token)
    return {
        "status": "ok",
        "force_password_change": record.force_password_change,
        "force_totp_provision": record.force_totp_provision,
    }


@router.post("/logout")
async def logout(
    session: AdminSession,
    response: Response,
    store=Depends(get_session_store),
):
    store.invalidate(session.token)
    response.delete_cookie(_SESSION_COOKIE)
    return {"status": "ok"}


@router.get("/status")
async def session_status(session: AdminSession):
    return {
        "account_id": session.account_id,
        "account_tier": session.account_tier,
        "expires_at": session.expires_at,
    }


@router.post("/password/change")
async def change_password(
    body: PasswordChangeRequest,
    session: AdminSession,
    response: Response,
    store=Depends(get_session_store),
):
    """Force-change password. Invalidates ALL sessions (ASVS V2.1.4)."""
    state = backoffice_state
    # Find account by account_id
    record = _get_record_by_id(session.account_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail={"error": "account_not_found"})

    from yashigani.auth.password import verify_password, hash_password
    if not verify_password(body.current_password, record.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail={"error": "invalid_current_password"})

    record.password_hash = hash_password(body.new_password)
    record.force_password_change = False

    # Invalidate ALL sessions including current (ASVS V2.1.4)
    store.invalidate_all_for_account(session.account_id)
    response.delete_cookie(_SESSION_COOKIE)

    state.audit_writer.write(_make_config_event(
        record.username, "password_change", "", "changed"
    ))
    return {"status": "ok", "sessions_invalidated": True, "re_authentication_required": True}


@router.post("/totp/provision")
async def provision_totp(
    body: TotpConfirmRequest,
    session: AdminSession,
    response: Response,
):
    """
    Provision TOTP for the current admin account.
    Requires a valid TOTP code to confirm device pairing.
    Returns QR code (base64 PNG) and recovery codes — shown ONCE.
    """
    state = backoffice_state
    record = _get_record_by_id(session.account_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail={"error": "account_not_found"})

    prov, code_set = state.auth_service.provision_totp(record.username)

    # Verify the user scanned the QR correctly
    if not verify_totp(prov.secret_b32, body.totp_code, set()):
        # Rollback — remove the newly set seed
        record.totp_secret = ""
        record.recovery_codes = None
        record.force_totp_provision = True
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail={"error": "invalid_totp_code",
                                    "message": "TOTP code did not match. Re-scan the QR code."})

    state.audit_writer.write(_make_provision_event(record.username))

    return {
        "status": "ok",
        "qr_code_png_b64": prov.qr_code_png_b64,
        "provisioning_uri": prov.provisioning_uri,
        "recovery_codes": prov.recovery_codes,  # shown once — client must acknowledge
        "recovery_codes_count": len(prov.recovery_codes),
        "message": "Store these recovery codes securely. They will not be shown again.",
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=_SESSION_COOKIE,
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=14400,   # 4 hours absolute
        path="/",
    )


def _get_record_by_id(account_id: str):
    state = backoffice_state
    for record in state.auth_service._accounts.values():
        if record.account_id == account_id:
            return record
    return None


def _make_login_event(username: str, outcome: str, reason):
    from yashigani.audit.schema import AdminLoginEvent
    return AdminLoginEvent(
        account_tier="admin",
        admin_account=username,
        outcome=outcome,
        failure_reason=reason,
    )


def _make_config_event(username: str, setting: str, prev: str, new: str):
    from yashigani.audit.schema import ConfigChangedEvent
    return ConfigChangedEvent(
        account_tier="admin",
        admin_account=username,
        setting=setting,
        previous_value=prev,
        new_value=new,
    )


def _make_provision_event(username: str):
    from yashigani.audit.schema import TotpProvisionCompletedEvent
    return TotpProvisionCompletedEvent(
        account_tier="admin",
        user_handle=username,
    )
