"""
SSL context builders for the Yashigani internal mesh.

Every service that listens on the internal network should build a
:func:`server_ssl_context` via these helpers and pass the resulting
:class:`ssl.SSLContext` to uvicorn/asyncpg/redis-py.

Every outbound internal call should build a :func:`client_ssl_context`.

Both contexts enforce:
  * TLS 1.2 minimum (same floor as the edge TLS policy)
  * Internal intermediate CA is the ONLY trusted issuer (Pattern B — root never
    in workloads; no system roots fall back)
  * Server context requires client cert on every handshake
  * Hostname verification ON for clients (matches cert SANs)

Last updated: 2026-04-27T00:00:00+00:00
"""

from __future__ import annotations

import logging
import ssl
from pathlib import Path
from typing import Optional

from yashigani.pki.identity import ServiceIdentity, current_service

logger = logging.getLogger(__name__)


def server_ssl_context(identity: Optional[ServiceIdentity] = None) -> ssl.SSLContext:
    """Build an :class:`ssl.SSLContext` for inbound mTLS.

    * Loads this service's cert + private key.
    * Trusts only the internal intermediate CA (Pattern B — root never in workloads).
    * Requires every connecting client to present a cert signed by the
      same CA (mutual TLS).
    """
    ident = identity or current_service()
    cert_path, key_path, ca_intermediate = ident.expect_cert_files()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    ctx.load_verify_locations(cafile=str(ca_intermediate))
    ctx.verify_mode = ssl.CERT_REQUIRED
    # We explicitly DO NOT load_default_certs() — system trust roots must
    # not bridge into the internal mesh.
    logger.info(
        "internal-pki: server SSLContext built for %s (client auth REQUIRED, intermediate anchor)",
        ident.name,
    )
    return ctx


def client_ssl_context(identity: Optional[ServiceIdentity] = None) -> ssl.SSLContext:
    """Build an :class:`ssl.SSLContext` for outbound internal mTLS.

    Presents this service's client cert to peers and verifies the peer
    cert chains to the internal intermediate CA (Pattern B).
    """
    ident = identity or current_service()
    cert_path, key_path, ca_intermediate = ident.expect_cert_files()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    ctx.load_verify_locations(cafile=str(ca_intermediate))
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    logger.info(
        "internal-pki: client SSLContext built for %s (peer verify REQUIRED, intermediate anchor)",
        ident.name,
    )
    return ctx


def ca_trust_only_context(ca_intermediate_path: str | Path) -> ssl.SSLContext:
    """Client context that trusts ONLY the internal intermediate CA, no client cert.

    Pattern B: anchor is the intermediate CA, not the root.
    Used by components that can't present a client cert but still need to
    verify peers — e.g. the install.sh cert-extract step contacting Caddy
    admin before a client cert exists.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cafile=str(ca_intermediate_path))
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx
