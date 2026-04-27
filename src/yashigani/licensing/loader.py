"""
Load license from file or Docker secret.

Resolution order:
1. YASHIGANI_LICENSE_FILE env var (path)
2. /run/secrets/license_key
3. ./license.ysg in CWD
4. Not found → COMMUNITY_LICENSE (no error, no warning about absence)

Last updated: 2026-04-27T21:08:49+01:00
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

from yashigani.licensing.model import COMMUNITY_LICENSE, LicenseState
from yashigani.licensing.verifier import verify_license

logger = logging.getLogger(__name__)

_CANDIDATES = [
    lambda: os.environ.get("YASHIGANI_LICENSE_FILE"),
    lambda: "/run/secrets/license_key",
    lambda: str(Path.cwd() / "license.ysg"),
]


def load_license() -> LicenseState:
    """
    Attempt to load a license from the resolution order above.
    Falls back to COMMUNITY_LICENSE if no file is found or if the
    loaded license is invalid (logs a WARNING in that case).
    """
    for candidate_fn in _CANDIDATES:
        path = candidate_fn()
        if not path:
            continue
        p = Path(path)
        if not p.exists():
            continue

        # File found — attempt to read and verify
        try:
            content = p.read_text(encoding="utf-8")
        except Exception as exc:
            logger.warning("License loader: could not read %s: %s", path, exc)
            return COMMUNITY_LICENSE

        # LAURA-V231-002: wrap verify_license() so that any uncaught exception
        # (e.g. corrupt payload with unexpected field types slipping past
        # _safe_int, future field additions, or crypto library changes) causes a
        # fail-closed return to COMMUNITY rather than a gateway crash at boot.
        try:
            lic = verify_license(content)
        except Exception as exc:
            logger.critical(
                "License loader: unexpected exception during verification of %s "
                "(LAURA-V231-002) — falling back to COMMUNITY tier: %s",
                path,
                exc,
            )
            return COMMUNITY_LICENSE

        # #102 (LICENSE-2024-003 / CVSS 9.3) — org_domain enforcement.
        # A domain-bound license (org_domain != "*") is only valid when the
        # runtime's YASHIGANI_TLS_DOMAIN env matches.  If the env is unset or
        # mismatches, downgrade to COMMUNITY tier and log CRITICAL so that
        # stolen license files cannot be silently replayed across tenants.
        if lic.valid and lic.org_domain != "*":
            runtime_domain = os.environ.get("YASHIGANI_TLS_DOMAIN", "")
            if not runtime_domain or runtime_domain != lic.org_domain:
                logger.critical(
                    "License loader: domain mismatch — license binds to '%s' but "
                    "YASHIGANI_TLS_DOMAIN='%s'; falling back to COMMUNITY tier "
                    "(LICENSE-2024-003)",
                    lic.org_domain,
                    runtime_domain,
                )
                return COMMUNITY_LICENSE

        if not lic.valid:
            logger.warning(
                "License loader: license at %s is invalid (error=%s) — "
                "falling back to COMMUNITY tier",
                path,
                lic.error,
            )
            return COMMUNITY_LICENSE

        expires_str = lic.expires_at.isoformat() if lic.expires_at else "never"
        logger.info(
            "License loaded: tier=%s org=%s expires=%s",
            lic.tier.value,
            lic.org_domain,
            expires_str,
        )
        return lic

    # No license file found anywhere — silently use community
    return COMMUNITY_LICENSE
