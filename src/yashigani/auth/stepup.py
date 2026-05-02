"""
Yashigani Auth — Step-up authentication (ASVS V6.8.4 / V2.4.x).

Per-route step-up logic: high-value admin endpoints require a fresh
TOTP code submitted within the last N minutes (default 5), independent
of session state and IdP/SSO claims.

Even a fully-authenticated admin must re-prove TOTP at the moment of a
dangerous action.  This is belt-and-braces: IdP compromise or session
hijack cannot bypass the per-action TOTP gate.

Last updated: 2026-04-27T00:00:00+01:00

ASVS references:
  V6.8.4 — Re-authentication before critical operations.
  V2.4.x — Verifier impersonation resistance (step-up is app-layer,
            not solely IdP-derived).
"""
from __future__ import annotations

import os
import time
from typing import TYPE_CHECKING

from fastapi import HTTPException, status

if TYPE_CHECKING:
    from yashigani.auth.session import Session


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

#: How long (seconds) a step-up TOTP verification remains valid.
#: Configurable via YASHIGANI_STEPUP_TTL_SECONDS. Default: 300 (5 minutes).
STEPUP_TTL_SECONDS: int = int(os.getenv("YASHIGANI_STEPUP_TTL_SECONDS", "300"))


# ---------------------------------------------------------------------------
# Core logic (pure — no FastAPI imports needed here)
# ---------------------------------------------------------------------------

def has_fresh_stepup(session: "Session") -> bool:
    """
    Return True if the session has a recent (<STEPUP_TTL_SECONDS) step-up
    TOTP event.

    Rules:
    - last_totp_verified_at is None (never performed) → False.
    - last_totp_verified_at > now (clock skew / tampered) → False (conservative).
    - Age >= TTL → False (expired).
    - Age < TTL → True.
    """
    if session.last_totp_verified_at is None:
        return False
    age_seconds = time.time() - session.last_totp_verified_at
    if age_seconds < 0:
        # Clock skew or tampered timestamp — reject conservatively.
        return False
    return age_seconds < STEPUP_TTL_SECONDS


class StepUpRequired(HTTPException):
    """
    Raised when a step-up TOTP verification is required before proceeding.
    HTTP 401 with detail.error = "step_up_required" — the JS interceptor
    catches this and shows the TOTP modal before retrying.
    """

    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "step_up_required",
                "message": (
                    "This action requires fresh TOTP verification. "
                    "POST a current TOTP code to /auth/stepup and retry."
                ),
                "stepup_endpoint": "/auth/stepup",
                "ttl_seconds": STEPUP_TTL_SECONDS,
            },
        )


def assert_fresh_stepup(session: "Session") -> None:
    """
    Raise StepUpRequired if the session does not have a fresh step-up.
    Call this at the top of any high-value route handler.
    """
    if not has_fresh_stepup(session):
        raise StepUpRequired()
