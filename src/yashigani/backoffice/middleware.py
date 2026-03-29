"""
Yashigani Backoffice — Auth middleware and dependencies.
All routes require a valid admin session. Session validated server-side.
"""
from __future__ import annotations

from typing import Annotated, Optional

from fastapi import Cookie, Depends, HTTPException, status, Request

from yashigani.auth.session import SessionStore, Session

_SESSION_COOKIE = "yashigani_admin_session"


def get_session_store() -> SessionStore:
    """FastAPI dependency — returns the singleton SessionStore."""
    from yashigani.backoffice.state import backoffice_state
    return backoffice_state.session_store


def require_admin_session(
    request: Request,
    yashigani_admin_session: Annotated[Optional[str], Cookie()] = None,
    store: SessionStore = Depends(get_session_store),
) -> Session:
    """
    FastAPI dependency that enforces a valid admin session.
    Returns the Session on success, raises HTTP 401 otherwise.
    Verifies account_tier == "admin" to prevent cross-tier access.
    """
    if not yashigani_admin_session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "authentication_required"},
        )

    session = store.get(yashigani_admin_session)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "session_expired_or_invalid"},
        )

    if session.account_tier != "admin":
        # Cross-tier attempt — return 403
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "insufficient_tier"},
        )

    return session


AdminSession = Annotated[Session, Depends(require_admin_session)]
