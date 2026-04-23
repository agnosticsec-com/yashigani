"""
SPIFFE URI ACL gate — application-layer identity check for service-to-service
callers.

Last updated: 2026-04-23T23:32:19+01:00

Threat model and trust boundary
-------------------------------
Every request arriving at /internal/metrics (and future gated endpoints) passes
through Caddy, our internal TLS edge and CA. Caddy validates the peer's client
certificate against the internal CA and forwards the first URI SAN of the
verified peer cert as the ``X-SPIFFE-ID`` header. Caddy strips any inbound
occurrence of that header before setting its own — a co-tenant on the internal
bridge network cannot forge the value.

Python's trust in the header depends on the transport hop that delivered it:
the upstream connection from Caddy to gateway/backoffice is already on
core-plane mTLS (see internal-mtls Caddyfile snippet and Uvicorn's
``ssl_cert_reqs=CERT_REQUIRED``). Any request on that listener that claims a
SPIFFE ID therefore came via Caddy. We do NOT honour ``X-SPIFFE-ID`` on
public-facing paths — this module is only attached to internal endpoints.

Contract
--------
``require_spiffe_id(path)`` returns a FastAPI dependency that:

  * 401 if the header is missing (``no_spiffe_id``)
  * 403 if the ACL table has no entry for this path (``no_acl_for_path``)
  * 403 if the header value is not in the allowlist (``spiffe_id_not_allowed``)
  * 200-passthrough (returns the caller SPIFFE ID) on success

The ACL source is the same ``service_identities.yaml`` manifest used by the
PKI issuer. This keeps the allowlist in one place: the file that also mints
the cert that carries the URI SAN, reviewed under git.

Fail-closed semantics
---------------------
If the manifest is missing, malformed, or unreadable, the ACL cache is an
empty dict — every gated path returns 403. There is no silent open mode.

Cache
-----
The manifest is loaded lazily on first call and cached. Admin rotations that
edit service_identities.yaml must trigger a process restart for the new ACLs
to take effect — same invariant as the bootstrap_token_sha256 field.
"""
from __future__ import annotations

import logging
import os
from threading import Lock
from typing import Callable, Optional

from fastapi import HTTPException, Request, status

logger = logging.getLogger(__name__)

_ACL_CACHE: Optional[dict[str, frozenset[str]]] = None
_CACHE_LOCK = Lock()

_DEFAULT_MANIFEST_PATH = "/etc/yashigani/service_identities.yaml"
_HEADER_NAME = "x-spiffe-id"  # FastAPI lower-cases headers on lookup


def _load_acls() -> dict[str, frozenset[str]]:
    """Load endpoint_acls from the manifest. Returns {} on any failure.

    Fail-closed: a missing or malformed manifest means every gated endpoint
    returns 403, never 200.
    """
    global _ACL_CACHE
    if _ACL_CACHE is not None:
        return _ACL_CACHE
    with _CACHE_LOCK:
        if _ACL_CACHE is not None:
            return _ACL_CACHE
        manifest_path = os.getenv(
            "YASHIGANI_SERVICE_MANIFEST_PATH", _DEFAULT_MANIFEST_PATH
        )
        try:
            # Local import so tests can monkeypatch load_manifest on the
            # identity module without racing this module's import.
            from yashigani.pki.identity import load_manifest

            manifest = load_manifest(manifest_path)
            _ACL_CACHE = dict(manifest.endpoint_acls)
        except Exception as exc:  # pragma: no cover — defensive
            logger.error(
                "spiffe-gate: failed to load manifest from %s — "
                "every gated endpoint will 403: %s",
                manifest_path,
                exc,
            )
            _ACL_CACHE = {}
        return _ACL_CACHE


def _reset_cache_for_tests() -> None:
    """Test helper — clear the lazy ACL cache."""
    global _ACL_CACHE
    with _CACHE_LOCK:
        _ACL_CACHE = None


def require_spiffe_id(path: str) -> Callable[[Request], str]:
    """Return a FastAPI dependency that enforces the SPIFFE URI ACL for *path*.

    Usage::

        @app.get(
            "/internal/metrics",
            dependencies=[Depends(require_spiffe_id("/internal/metrics"))],
        )
        async def metrics():
            ...

    The ``path`` argument must match the key under ``endpoint_acls`` in
    ``service_identities.yaml``. It is passed explicitly (rather than read from
    ``request.url.path``) so the ACL wiring is visible in the route source and
    so that trailing-slash or rewrite quirks can't mis-select the rule.
    """

    async def _dep(request: Request) -> str:
        acls = _load_acls()
        allowed = acls.get(path)
        if not allowed:
            # Default-deny: no rule for this path.
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="no_acl_for_path",
            )

        caller = request.headers.get(_HEADER_NAME)
        if not caller:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="no_spiffe_id",
            )

        if caller not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="spiffe_id_not_allowed",
            )

        return caller

    return _dep


__all__ = ["require_spiffe_id"]
