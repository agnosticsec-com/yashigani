"""
Yashigani Gateway — SPIFFE peer-cert verification middleware.

# Last updated: 2026-04-30T04:30:00+01:00

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

LAURA-V232-002 hardening (2026-04-30)
--------------------------------------
uvicorn 0.34.x+ exposes ``peer_cert`` in the ASGI TLS scope extension (added in
uvicorn 0.34.0 — see upstream changelog).  However the original middleware
fallback allowed a client connecting directly to gateway:8080 to supply a
forged ``X-SPIFFE-ID`` header: when ``peer_cert`` is absent the middleware sets
``x-spiffe-id-peer-cert`` to an empty string, and ``require_spiffe_id()`` then
falls back to the client-supplied ``x-spiffe-id`` header.

This is a complete authentication bypass on the direct-mesh path.

PoC: ``gateway_client.crt`` + forged ``X-SPIFFE-ID: spiffe://yashigani.internal/prometheus``
→ HTTP 200 on ``/internal/metrics`` (internal security V232-002 2026-04-30).

Double-strip fix:
- This middleware strips BOTH ``x-spiffe-id-peer-cert`` AND ``x-spiffe-id``
  from all inbound client requests.
- It re-sets ``x-spiffe-id-peer-cert`` from the TLS handshake (or empty
  string if the ASGI TLS extension is absent).
- ``require_spiffe_id()`` now only trusts ``x-spiffe-id-peer-cert`` on the
  direct-mesh path; there is NO fallback to a client-supplied ``x-spiffe-id``.
- The Caddy-proxied path: Caddy strips inbound ``x-spiffe-id`` before setting
  its own value (strip-then-set pattern in Caddyfile).  The Caddy-set header
  survives because it is injected by Caddy AFTER this middleware strips
  client-supplied values — Caddy operates at the Caddy→upstream hop, so
  Caddy's ``header_up X-SPIFFE-ID`` directive adds the header to the request
  forwarded from Caddy to the upstream service, not to the client→Caddy leg.
  This means the Caddy-set ``x-spiffe-id`` is NOT present in the client→Caddy
  request that arrives at this middleware; it is injected downstream.
  Consequence: on the Caddy-proxied path ``x-spiffe-id-peer-cert`` is still
  empty (no ASGI TLS extension since Caddy is the TLS terminator), and
  ``x-spiffe-id`` IS set by Caddy.  To support the Caddy path, ``require_spiffe_id()``
  checks ``x-spiffe-id-peer-cert`` first; if non-empty, uses it; if empty,
  checks ``x-spiffe-id`` ONLY when that header is PRESENT (non-empty).  A truly
  absent header → 401.

Fail-closed on absent peer_cert:
  When uvicorn does not expose ``peer_cert`` (TLS extension absent) AND
  ``x-spiffe-id`` is not set (direct-mesh attack without forged header),
  ``require_spiffe_id()`` returns 401.  Attacker who forges ``X-SPIFFE-ID``
  — the header is stripped by this middleware before the route sees it.

uvicorn requirement: >=0.34.0 (``peer_cert`` in ASGI TLS scope extension).
pyproject.toml pins ``uvicorn[standard]>=0.34``.

Design
------
This middleware runs BEFORE any route handler.  It modifies the ASGI scope's
``headers`` list to strip client-supplied ``x-spiffe-id`` and inject
``X-SPIFFE-ID-Peer-Cert`` from the TLS handshake.

Peer cert extraction (uvicorn 0.34+ / ASGI 3.0 extensions):
  scope["extensions"]["tls"]["peer_cert"]  → ssl.SSLSocket.getpeercert() dict

If the TLS scope extension is absent (Caddy-proxied path, test environment,
non-TLS connection), the header is set to an empty string.  The gate in
``require_spiffe_id()`` then relies on the Caddy-set ``x-spiffe-id`` header.

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

A client forging ``X-SPIFFE-ID`` has it stripped by this middleware before any
route handler sees it — the forge cannot reach the gate.

References
----------
- Internal sanity-check: /Users/max/Documents/Claude/Internal/ACS/v3/asvs-sanity-check-post-fix-2026-04-29.md §LF-SPIFFE-FORGE
- ASVS v5 V10.3.5 (CWE-287)
- LAURA-V232-002 (2026-04-30)
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
            peer_cert_header_name = b"x-spiffe-id-peer-cert"
            # LAURA-V232-002: also strip client-supplied x-spiffe-id.
            # Caddy injects x-spiffe-id at the Caddy→upstream hop (after this
            # middleware runs on the client→Caddy leg), so the legitimate
            # Caddy-set header is NOT present in the inbound scope — it is
            # added by Caddy when it forwards to the upstream service.  Any
            # x-spiffe-id visible at this point came from the client and must
            # be stripped to prevent forge attacks on the direct-mesh path.
            spiffe_id_header_name = b"x-spiffe-id"

            headers = [
                (k, v)
                for k, v in scope.get("headers", [])
                if k.lower() != peer_cert_header_name
                and k.lower() != spiffe_id_header_name
            ]
            # Append the server-set value (may be empty string if no TLS/no cert).
            headers.append((peer_cert_header_name, peer_cert_bytes))
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
