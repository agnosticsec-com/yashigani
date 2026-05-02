"""
Load license from file or Docker secret.

Resolution order:
1. YASHIGANI_LICENSE_FILE env var (path)
2. /run/secrets/license_key
3. ./license.ysg in CWD
4. Not found → COMMUNITY_LICENSE (no error, no warning about absence)
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

        lic = verify_license(content)

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
