"""
Yashigani Backoffice -- CSP violation report endpoint.
OWASP ASVS 3.4.7: Content-Security-Policy report-uri handler.
Receives and logs CSP violation reports from browsers.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Request, Response, status

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/csp-report")
async def csp_report(request: Request):
    """
    Receive CSP violation reports (application/csp-report or application/json).
    Logs the report for security monitoring. No authentication required --
    browsers send these automatically and cannot attach cookies.
    """
    try:
        body = await request.json()
    except Exception:
        # Malformed report -- log and discard
        logger.warning("Received malformed CSP report (could not parse JSON)")
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    # Extract the nested csp-report object (standard format) or use body directly
    report = body.get("csp-report", body)

    logger.warning(
        "CSP violation: blocked-uri=%s violated-directive=%s document-uri=%s",
        report.get("blocked-uri", "unknown"),
        report.get("violated-directive", "unknown"),
        report.get("document-uri", "unknown"),
    )

    return Response(status_code=status.HTTP_204_NO_CONTENT)
