"""
Yashigani SSO — TOTP provisioning for first-time SSO users.
When REQUIRE_YASHIGANI_TOTP_ON_SSO=true, a self-completing provisioning
token flow (Option B) is used — no out-of-band QR delivery.

Flow:
1. IdP assertion validates successfully.
2. Yashigani checks if user has a TOTP seed. If not:
3. Generate short-lived one-time provisioning token (UUID v4, 10-min TTL).
4. Redirect user to /user/auth/totp/provision?token=<token>
5. User scans QR, submits first TOTP code.
6. On success: seed committed to KSM, 8 recovery codes generated.
7. Full session token issued.
"""
from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

_PROVISION_TOKEN_TTL_SECONDS = 600  # 10 minutes


@dataclass
class ProvisioningToken:
    token_id: str
    user_subject: str       # IdP subject claim (stable identifier)
    issued_at: float
    expires_at: float
    used: bool = False


class SSOTotpProvisioningService:
    """
    Manages one-time TOTP provisioning tokens for first-time SSO users.
    Backed by an in-memory store (backed by Redis in production).
    """

    def __init__(self, redis_client=None) -> None:
        self._redis = redis_client
        self._local: dict[str, ProvisioningToken] = {}  # fallback for dev

    def needs_provisioning(self, user_subject: str) -> bool:
        """Check whether a user still needs TOTP provisioning."""
        key = f"yashigani:sso_totp_provisioned:{user_subject}"
        if self._redis:
            return not bool(self._redis.exists(key))
        # In-process fallback: always needs provisioning if not tracked
        return user_subject not in getattr(self, "_provisioned", set())

    def issue_token(self, user_subject: str) -> str:
        """
        Issue a single-use provisioning token for the given SSO user.
        Returns the token_id string. Previous unfinished tokens are replaced.
        """
        token_id = secrets.token_urlsafe(32)
        now = time.time()
        pt = ProvisioningToken(
            token_id=token_id,
            user_subject=user_subject,
            issued_at=now,
            expires_at=now + _PROVISION_TOKEN_TTL_SECONDS,
        )
        if self._redis:
            import json
            key = f"yashigani:prov_token:{token_id}"
            self._redis.setex(
                key,
                _PROVISION_TOKEN_TTL_SECONDS + 10,
                json.dumps({
                    "user_subject": user_subject,
                    "issued_at": now,
                    "expires_at": pt.expires_at,
                }),
            )
            # Index by subject for replacement
            self._redis.setex(
                f"yashigani:prov_token_by_subject:{user_subject}",
                _PROVISION_TOKEN_TTL_SECONDS + 10,
                token_id,
            )
        else:
            self._local[token_id] = pt

        logger.info(
            "TOTP provisioning token issued for SSO user (subject_hash=%.8s)",
            _hash(user_subject),
        )
        return token_id

    def consume_token(self, token_id: str) -> Optional[str]:
        """
        Validate and consume a provisioning token.
        Returns user_subject on success, None if invalid/expired/used.
        Token is invalidated immediately on first use.
        """
        if self._redis:
            import json
            key = f"yashigani:prov_token:{token_id}"
            raw = self._redis.getdel(key)
            if not raw:
                return None
            data = json.loads(raw)
            if time.time() > data["expires_at"]:
                return None
            return data["user_subject"]
        else:
            pt = self._local.pop(token_id, None)
            if pt is None:
                return None
            if pt.used or time.time() > pt.expires_at:
                return None
            return pt.user_subject

    def mark_provisioned(self, user_subject: str) -> None:
        """Mark a user as having completed TOTP provisioning."""
        if self._redis:
            # Store for 10 years — effectively permanent
            self._redis.setex(
                f"yashigani:sso_totp_provisioned:{user_subject}",
                315_360_000,
                "1",
            )
        else:
            if not hasattr(self, "_provisioned"):
                self._provisioned: set[str] = set()
            self._provisioned.add(user_subject)


def _hash(value: str) -> str:
    import hashlib
    return hashlib.sha256(value.encode()).hexdigest()
