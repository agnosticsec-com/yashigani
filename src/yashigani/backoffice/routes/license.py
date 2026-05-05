"""
Yashigani Backoffice — License admin routes.

All routes require an active admin session.

Routes:
  GET    /admin/license          — current license status + usage across all dimensions
  POST   /admin/license/activate — activate a new license key
  DELETE /admin/license          — revert to community license
"""
# Last updated: 2026-04-27T21:53:12+01:00
from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel

from yashigani.backoffice.middleware import require_admin_session, require_stepup_admin_session

logger = logging.getLogger(__name__)
license_router = APIRouter(tags=["license"])

_LICENSE_SECRET_PATH = "/run/secrets/license_key"


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class ActivateRequest(BaseModel):
    license_content: Optional[str] = None


class RevertRequest(BaseModel):
    confirm: bool = False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _limit_block(current: int, maximum: int) -> dict:
    return {
        "current": current,
        "maximum": maximum if maximum != -1 else None,
        "unlimited": maximum == -1,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@license_router.get("")
async def get_license_status(session=Depends(require_admin_session)):
    from yashigani.licensing import get_license
    from yashigani.backoffice.state import backoffice_state

    lic = get_license()

    # Agent count
    current_agents = 0
    registry = backoffice_state.agent_registry
    if registry is not None:
        try:
            current_agents = registry.count("all")
        except Exception:
            current_agents = 0

    # End user count — non-admin accounts in auth_service.
    # NOTE: previously called `auth.count_users(admin=False)` which doesn't
    # exist on LocalAuthService — the AttributeError was swallowed by the
    # except clause and current_end_users silently reported 0, disagreeing
    # with the enforcer which uses total_user_count() correctly (internal QA Wave 2
    # Issue D).
    current_end_users = 0
    auth = backoffice_state.auth_service
    if auth is not None:
        try:
            current_end_users = await auth.total_user_count()
        except Exception:
            current_end_users = 0

    # Admin seat count — same bug, same fix.
    current_admin_seats = 0
    if auth is not None:
        try:
            current_admin_seats = await auth.total_admin_count()
        except Exception:
            current_admin_seats = 0

    # Org count (single-org in non-Enterprise deployments)
    current_orgs = 1

    expires_at = lic.expires_at.isoformat() if lic.expires_at is not None else None

    return {
        "tier": lic.tier.value,
        "org_domain": lic.org_domain,
        "valid": lic.valid,
        "expires_at": expires_at,
        "license_id": lic.license_id,
        "limits": {
            "agents":       _limit_block(current_agents,      lic.max_agents),
            "end_users":    _limit_block(current_end_users,   lic.max_end_users),
            "admin_seats":  _limit_block(current_admin_seats, lic.max_admin_seats),
            "orgs":         _limit_block(current_orgs,        lic.max_orgs),
        },
        "features": {
            "oidc": lic.has_feature("oidc"),
            "saml": lic.has_feature("saml"),
            "scim": lic.has_feature("scim"),
        },
        "upgrade_url": "https://yashigani.io/pricing",
    }


@license_router.post("/activate")
async def activate_license(
    license_content: Optional[str] = Form(default=None),
    license_file: Optional[UploadFile] = File(default=None),
    session=Depends(require_stepup_admin_session),
):
    from yashigani.licensing import set_license
    from yashigani.licensing.verifier import verify_license

    content: Optional[str] = None
    if license_file is not None:
        raw = await license_file.read()
        content = raw.decode("utf-8").strip()
    elif license_content is not None:
        content = license_content.strip()

    if not content:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "MISSING_LICENSE_CONTENT", "detail": "Provide license_content or license_file"},
        )

    # M-05 / LAURA-V231-002 follow-on: verify_license() is guarded here so that
    # a crafted malformed license file (null seat fields, garbage bytes, truncated
    # content, malformed JSON) cannot crash the backoffice worker with an
    # unhandled exception → 500 (DoS on admin plane, authenticated session required).
    # The route responds with a clean 4xx to the admin, logs the rejection, and
    # does NOT re-raise.
    try:
        new_lic = verify_license(content)
    except Exception as exc:
        logger.warning(
            "License activation rejected — verify_license raised unexpectedly "
            "(M-05 / LAURA-V231-002): %s",
            exc,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "INVALID_LICENSE", "detail": "malformed_license_content"},
        )

    if not new_lic.valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "INVALID_LICENSE", "detail": new_lic.error},
        )

    set_license(new_lic)

    try:
        with open(_LICENSE_SECRET_PATH, "w") as fh:
            fh.write(content)
    except OSError:
        logger.debug("License key secret path not writable (%s) — skipping persist", _LICENSE_SECRET_PATH)

    expires_at = new_lic.expires_at.isoformat() if new_lic.expires_at is not None else None

    logger.info(
        "License activated by %s: tier=%s org_domain=%s agents=%s end_users=%s admin_seats=%s",
        session.account_id,
        new_lic.tier.value,
        new_lic.org_domain,
        new_lic.max_agents,
        new_lic.max_end_users,
        new_lic.max_admin_seats,
    )

    return {
        "status": "activated",
        "tier": new_lic.tier.value,
        "org_domain": new_lic.org_domain,
        "expires_at": expires_at,
        "limits": {
            "agents":      new_lic.max_agents      if new_lic.max_agents      != -1 else "unlimited",
            "end_users":   new_lic.max_end_users   if new_lic.max_end_users   != -1 else "unlimited",
            "admin_seats": new_lic.max_admin_seats if new_lic.max_admin_seats != -1 else "unlimited",
            "orgs":        new_lic.max_orgs        if new_lic.max_orgs        != -1 else "unlimited",
        },
    }


@license_router.delete("")
async def revert_license(body: RevertRequest, session=Depends(require_stepup_admin_session)):
    from yashigani.licensing import COMMUNITY_LICENSE, set_license

    if not body.confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "CONFIRM_REQUIRED", "detail": "Set confirm=true to revert to community license"},
        )

    set_license(COMMUNITY_LICENSE)

    try:
        if os.path.exists(_LICENSE_SECRET_PATH):
            os.remove(_LICENSE_SECRET_PATH)
    except OSError as exc:
        logger.warning("Could not remove license key secret file: %s", exc)

    logger.info("License reverted to community by %s", session.account_id)

    return {"status": "reverted", "tier": "community"}
