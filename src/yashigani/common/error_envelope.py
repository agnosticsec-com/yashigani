"""
Yashigani common — safe error envelope helper (V232-CSCAN-01e).

# Last updated: 2026-05-03T00:00:00+01:00

Standardises error responses so that:
  - Server: full traceback is logged via logger.exception().
  - Client: receives only {"error": <safe public message>, "request_id": <uuid>}.

This closes the py/stack-trace-exposure findings (#33–#39) and prevents future
regressions from traceback.format_exc() accidentally reaching HTTP responses.

Usage (FastAPI route):
    from yashigani.common.error_envelope import safe_error_envelope
    from fastapi.responses import JSONResponse

    except Exception as exc:
        payload, status_code = safe_error_envelope(exc, public_message="cache flush failed")
        return JSONResponse(status_code=status_code, content=payload)

Design notes:
- public_message must be a short, intentional string — never str(exc).
- request_id threads the log entry to the HTTP response for operator triage.
- status defaults to 500 but callers may pass 502, 503, etc.
"""
from __future__ import annotations

import logging
import uuid

logger = logging.getLogger(__name__)


def _new_request_id() -> str:
    return uuid.uuid4().hex


def safe_error_envelope(
    exc: BaseException,
    *,
    request_id: str | None = None,
    public_message: str | None = None,
    status: int = 500,
) -> tuple[dict, int]:
    """Log full traceback server-side; return safe client envelope.

    Parameters
    ----------
    exc:
        The exception that was caught.
    request_id:
        Optional opaque ID to thread log → response. A fresh UUID is
        generated if not supplied.
    public_message:
        Short human-readable message for the client. MUST NOT include
        exc class name or str(exc) — use a hard-coded string such as
        ``"kms backend unavailable"`` or ``"cache flush failed"``.
        Defaults to ``"internal error"`` if not supplied.
    status:
        HTTP status code to embed in the returned tuple. Defaults to 500.

    Returns
    -------
    tuple[dict, int]
        ``(payload_dict, http_status_code)`` — pass directly to
        ``JSONResponse(status_code=status_code, content=payload)``.
    """
    rid = request_id or _new_request_id()
    # Full traceback logged server-side only.
    logger.exception("request_failed", extra={"request_id": rid})
    payload = {
        "error": public_message or "internal error",
        "request_id": rid,
    }
    return payload, status
