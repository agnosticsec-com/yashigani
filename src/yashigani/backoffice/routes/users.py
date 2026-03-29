"""
Yashigani Backoffice — User/Operator account management routes.
Full reset requires admin TOTP re-verification (ASVS V2.8).
Delete blocked if last user (USER_MINIMUM_VIOLATION).
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.auth.totp import verify_totp

router = APIRouter()


class FullResetRequest(BaseModel):
    totp_code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=36)


@router.get("")
async def list_users(session: AdminSession):
    state = backoffice_state
    users = [
        {
            "username": r.username,
            "account_id": r.account_id,
            "disabled": r.disabled,
            "force_password_change": r.force_password_change,
            "created_at": r.created_at,
        }
        for r in state.auth_service._accounts.values()
        if r.account_tier == "user"
    ]
    return {
        "users": users,
        "total": state.auth_service.total_user_count(),
        "min_total": state.user_min_total,
    }


@router.post("")
async def create_user(body: CreateUserRequest, session: AdminSession):
    state = backoffice_state
    record = state.auth_service.create_user(body.username, body.password)
    state.audit_writer.write(_config_event(
        session.account_id, "user_account_created", "", body.username
    ))
    return {"status": "ok", "account_id": record.account_id}


@router.delete("/{username}")
async def delete_user(username: str, session: AdminSession):
    """Delete a user. Blocked if last user (USER_MINIMUM_VIOLATION)."""
    state = backoffice_state
    record = state.auth_service._accounts.get(username)
    if record is None or record.account_tier != "user":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail={"error": "account_not_found"})

    if state.auth_service.total_user_count() <= state.user_min_total:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "USER_MINIMUM_VIOLATION",
                "message": "Cannot delete the last user account",
            },
        )

    del state.auth_service._accounts[username]
    state.session_store.invalidate_all_for_account(record.account_id)
    state.audit_writer.write(_config_event(
        session.account_id, "user_account_deleted", username, ""
    ))
    return {"status": "ok"}


@router.post("/{username}/full-reset")
async def full_reset_user(
    username: str,
    body: FullResetRequest,
    session: AdminSession,
):
    """
    Full reset a user account. Requires admin TOTP re-verification.
    Strips all RBAC roles, sessions, API keys, TOTP, password.
    Retains: username, UUID, audit history.
    """
    state = backoffice_state

    # Resolve admin record for TOTP verification
    admin_record = None
    for r in state.auth_service._accounts.values():
        if r.account_id == session.account_id:
            admin_record = r
            break

    if admin_record is None or not admin_record.totp_secret:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail={"error": "admin_totp_not_configured"})

    # Verify admin TOTP — server-side enforced (not UI-only)
    used_codes: set = getattr(state, "_used_totp_codes", set())
    if not verify_totp(admin_record.totp_secret, body.totp_code, used_codes):
        state.audit_writer.write(_full_reset_totp_failure(
            admin_record.username, username
        ))
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "invalid_admin_totp"},
        )

    # Perform full reset
    success, reason = state.auth_service.full_reset_user(
        username,
        admin_totp_secret=admin_record.totp_secret,
        admin_totp_code=body.totp_code,
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": reason},
        )

    state.session_store.invalidate_all_for_account(
        state.auth_service._accounts[username].account_id
    )

    state.audit_writer.write(_full_reset_event(
        admin_record.username, username
    ))
    return {"status": "ok", "message": "User account fully reset"}


@router.post("/{username}/disable")
async def disable_user(username: str, session: AdminSession):
    state = backoffice_state
    if not state.auth_service.disable(username):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail={"error": "account_not_found"})
    state.audit_writer.write(_config_event(
        session.account_id, "user_account_disabled", username, "disabled"
    ))
    return {"status": "ok"}


@router.post("/{username}/enable")
async def enable_user(username: str, session: AdminSession):
    state = backoffice_state
    if not state.auth_service.enable(username):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail={"error": "account_not_found"})
    state.audit_writer.write(_config_event(
        session.account_id, "user_account_enabled", username, "enabled"
    ))
    return {"status": "ok"}


def _config_event(admin_id: str, setting: str, prev: str, new: str):
    from yashigani.audit.schema import ConfigChangedEvent
    return ConfigChangedEvent(
        account_tier="admin", admin_account=admin_id,
        setting=setting, previous_value=prev, new_value=new,
    )


def _full_reset_event(admin_username: str, target: str):
    from yashigani.audit.schema import UserFullResetEvent
    return UserFullResetEvent(
        account_tier="admin",
        admin_account=admin_username,
        admin_totp_verified=True,
        target_user_handle=target,
    )


def _full_reset_totp_failure(admin_username: str, target: str):
    from yashigani.audit.schema import FullResetTotpFailureEvent
    return FullResetTotpFailureEvent(
        account_tier="admin",
        admin_account=admin_username,
        target_user_handle=target,
        failure_reason="invalid",
    )
