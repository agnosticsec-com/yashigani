"""End-to-end test for Caddy-gated /internal/metrics (EX-231-08).

Last updated: 2026-04-23T23:32:19+01:00

Verifies that:
  * Prometheus's leaf cert (minted by install.sh bootstrap) carries the URI SAN
    ``spiffe://yashigani.internal/prometheus``.
  * A scrape against ``https://caddy:8444/internal/metrics`` with that cert
    returns 200.
  * A scrape against the same URL WITHOUT a client cert fails (TLS handshake).
  * A scrape with a non-prometheus identity (e.g. gateway's own cert) is
    accepted by Caddy's mTLS step but rejected 403 by the application ACL.

The test is marked skip unless a live Docker/Podman stack with internal PKI
exists at ``docker/secrets/``. On CI, run after ``install.sh`` has completed.
"""
from __future__ import annotations

import os
import pathlib
import ssl

import pytest

_SECRETS = pathlib.Path(__file__).resolve().parents[3] / "docker" / "secrets"


def _has_live_stack() -> bool:
    return (
        _SECRETS.exists()
        and (_SECRETS / "ca_root.crt").exists()
        and (_SECRETS / "prometheus_client.crt").exists()
        and (_SECRETS / "prometheus_client.key").exists()
        and os.environ.get("YASHIGANI_LIVE_STACK") == "1"
    )


pytestmark = pytest.mark.skipif(
    not _has_live_stack(),
    reason="Live stack not running — set YASHIGANI_LIVE_STACK=1 after install.sh",
)


def _ssl_context(cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=str(_SECRETS / "ca_root.crt"))
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    return ctx


def test_prometheus_leaf_has_spiffe_uri_san():
    """The leaf cert install.sh mints for prometheus must embed the URI SAN."""
    from cryptography import x509

    leaf_bundle = (_SECRETS / "prometheus_client.crt").read_bytes()
    leaf = x509.load_pem_x509_certificates(leaf_bundle)[0]
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
    assert "spiffe://yashigani.internal/prometheus" in uris


def test_scrape_via_caddy_with_prometheus_cert_returns_200():
    import http.client

    ctx = _ssl_context(
        cert=str(_SECRETS / "prometheus_client.crt"),
        key=str(_SECRETS / "prometheus_client.key"),
    )
    conn = http.client.HTTPSConnection("caddy", 8444, context=ctx)
    conn.request(
        "GET", "/internal/metrics", headers={"Host": "gateway"}
    )
    resp = conn.getresponse()
    assert resp.status == 200


def test_scrape_via_caddy_with_gateway_cert_returns_403():
    """Gateway's cert has a different URI SAN — Caddy accepts the TLS
    handshake (same trust root) but the app-layer ACL rejects."""
    import http.client

    ctx = _ssl_context(
        cert=str(_SECRETS / "gateway_client.crt"),
        key=str(_SECRETS / "gateway_client.key"),
    )
    conn = http.client.HTTPSConnection("caddy", 8444, context=ctx)
    conn.request(
        "GET", "/internal/metrics", headers={"Host": "gateway"}
    )
    resp = conn.getresponse()
    assert resp.status == 403


def test_scrape_via_caddy_without_cert_fails_handshake():
    """Caddy's :8444 listener is client_auth=require_and_verify — no cert,
    no handshake."""
    import http.client

    ctx = ssl.create_default_context(cafile=str(_SECRETS / "ca_root.crt"))
    conn = http.client.HTTPSConnection("caddy", 8444, context=ctx)
    with pytest.raises((ssl.SSLError, OSError)):
        conn.request(
            "GET", "/internal/metrics", headers={"Host": "gateway"}
        )
        conn.getresponse()
