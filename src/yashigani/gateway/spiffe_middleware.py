"""
Yashigani Gateway — SPIFFE peer-cert verification middleware.

# Last updated: 2026-04-27T00:00:00+01:00

LF-SPIFFE-FORGE fix (V10.3.5, 2026-04-27)
------------------------------------------
The original V10.3.5 fix in _resolve_identity() trusts the X-SPIFFE-ID header
that arrives with an HTTP request.  When the caller routes through Caddy, this
header is set by Caddy from the TLS peer cert URI SAN (strip-then-set pattern).
However, the gateway listener runs at 0.0.0.0:8080 with CERT_REQUIRED — any
service holding a valid internal-CA cert can connect DIRECTLY to gateway:8080
and forge X-SPIFFE-ID to match a stolen bearer token's bound_spiffe_uri.

Fix: this ASGI middleware extracts the SPIFFE URI SAN from the actual TLS peer
cert (via uvicorn's ASGI scope extensions) and writes it to a server-internal
header ``X-SPIFFE-ID-Peer-Cert`` that is NOT settable by clients (it is always
overwritten by this middleware before the request reaches a route handler).

_resolve_identity() is updated to use ``X-SPIFFE-ID-Peer-Cert`` for the
SPIFFE-URI binding check when present, falling back to ``X-SPIFFE-ID`` for the
Caddy-proxied code path (Caddy sets X-SPIFFE-ID from the peer cert; the
direct-to-gateway path sets X-SPIFFE-ID-Peer-Cert from the handshake).

Design
------
This middleware runs BEFORE any route handler.  It modifies the ASGI scope's
``headers`` list to inject ``X-SPIFFE-ID-Peer-Cert``.  Route handlers access
this via ``request.headers.get("x-spiffe-id-peer-cert")``.

Peer cert extraction (uvicorn 0.17+ / ASGI 3.0 extensions):
  scope["extensions"]["tls"]["peer_cert"]  → ssl.SSLSocket.getpeercert() dict

If the TLS scope extension is absent (non-TLS connection, older uvicorn,
test environment), the header is set to an empty string.

If the peer cert dict has a ``subjectAltName`` with URI type entries, the first
``spiffe://`` URI SAN is used.  Otherwise empty string (= no cert presented or
no SPIFFE URI in cert).

Threat model closure
--------------------
A compromised core-mesh peer connecting directly to gateway:8080 presents its
OWN cert.  The URI SAN on that cert is its own SPIFFE URI (e.g.
spiffe://yashigani.internal/wazuh-agent), NOT the bound_spiffe_uri of the
stolen API key (e.g. spiffe://yashigani.internal/my-agent).  The binding check
in _resolve_identity() rejects the mismatch.

An attacker who could forge the TLS handshake itself would need to break mTLS
— which is outside the threat model for v2.23.1.

References
----------
- Lu sanity-check: /Users/max/Documents/Claude/Internal/ACS/v3/asvs-sanity-check-post-fix-2026-04-29.md §LF-SPIFFE-FORGE
- ASVS v5 V10.3.5 (CWE-287)
"""
from __future__ import annotations

import logging
import ssl
from typing import Callable

logger = logging.getLogger(__name__)


def _extract_spiffe_uri_from_cert(peer_cert: dict | None) -> str:
    """Extract the first SPIFFE URI SAN from an ssl.getpeercert() dict.

    Returns empty string if not found or cert is None.
    """
    if not peer_cert:
        return ""
    for typ, value in peer_cert.get("subjectAltName", []):
        if typ == "URI" and value.startswith("spiffe://"):
            return value
    return ""


class SpiffePeerCertMiddleware:
    """ASGI middleware: inject X-SPIFFE-ID-Peer-Cert from the TLS handshake.

    Must be registered BEFORE any route handlers that need this header.
    """

    def __init__(self, app) -> None:
        self._app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http":
            peer_cert_uri = self._get_peer_cert_uri(scope)
            # Inject the server-controlled header.  Overwrite any existing value
            # (clients cannot set this header to a trusted value — it is always
            # replaced here from the TLS handshake or empty if no TLS).
            peer_cert_bytes = peer_cert_uri.encode("ascii", errors="replace")
            header_name = b"x-spiffe-id-peer-cert"

            # Remove any client-supplied x-spiffe-id-peer-cert (spoof-prevention).
            headers = [
                (k, v)
                for k, v in scope.get("headers", [])
                if k.lower() != header_name
            ]
            # Append the server-set value (may be empty string if no TLS/no cert).
            headers.append((header_name, peer_cert_bytes))
            scope = dict(scope)
            scope["headers"] = headers

        await self._app(scope, receive, send)

    @staticmethod
    def _get_peer_cert_uri(scope: dict) -> str:
        """Extract SPIFFE URI from the ASGI TLS extension (uvicorn 0.17+).

        Returns empty string on any error or if the extension is absent.
        """
        try:
            tls_ext = scope.get("extensions", {}).get("tls", {})
            # uvicorn exposes getpeercert() result under 'peer_cert'
            peer_cert = tls_ext.get("peer_cert")
            if peer_cert is None:
                # Uvicorn < 0.17 or non-TLS — no extension available.
                return ""
            return _extract_spiffe_uri_from_cert(peer_cert)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "spiffe-middleware: failed to extract peer cert URI: %s", exc
            )
            return ""


__all__ = ["SpiffePeerCertMiddleware", "_extract_spiffe_uri_from_cert"]
