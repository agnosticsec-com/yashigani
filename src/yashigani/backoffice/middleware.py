"""
Yashigani Backoffice — Auth middleware and dependencies.
All routes require a valid admin session. Session validated server-side.
"""
from __future__ import annotations

from typing import Annotated, Optional

from fastapi import Cookie, Depends, HTTPException, status, Request

from yashigani.auth.session import SessionStore, Session

_SESSION_COOKIE = "__Host-yashigani_admin_session"
_USER_SESSION_COOKIE = "__Host-yashigani_session"


def get_session_store() -> SessionStore:
    """FastAPI dependency — returns the singleton SessionStore."""
    from yashigani.backoffice.state import backoffice_state
    assert backoffice_state.session_store is not None  # set unconditionally at startup
    return backoffice_state.session_store


def _resolve_token(request: Request) -> Optional[str]:
    """Read session token from either admin or user cookie."""
    return request.cookies.get(_SESSION_COOKIE) or request.cookies.get(_USER_SESSION_COOKIE)


def require_admin_session(
    request: Request,
    store: SessionStore = Depends(get_session_store),
) -> Session:
    """
    FastAPI dependency that enforces a valid admin session.
    Returns the Session on success, raises HTTP 401 otherwise.
    Verifies account_tier == "admin" to prevent cross-tier access.
    """
    token = _resolve_token(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "authentication_required"},
        )

    session = store.get(token)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "session_expired_or_invalid"},
        )

    if session.account_tier != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "insufficient_tier"},
        )

    return session


def require_any_session(
    request: Request,
    store: SessionStore = Depends(get_session_store),
) -> Session:
    """
    FastAPI dependency that accepts any valid session (admin or user).
    Used for endpoints accessible to both tiers (password change, TOTP provision).
    """
    token = _resolve_token(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "authentication_required"},
        )

    session = store.get(token)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "session_expired_or_invalid"},
        )

    return session


AdminSession = Annotated[Session, Depends(require_admin_session)]
AnySession = Annotated[Session, Depends(require_any_session)]
