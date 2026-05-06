"""Tests that issued leaf certs include localhost / 127.0.0.1 / ::1 SANs,
and that the cert verifies cleanly when presented over a TLS listener
to a client connecting via "localhost".

retro #49 — closes the gap where in-container healthchecks (`curl
https://localhost:...`) and self-connecting clients (`fasttext` / OPA
shim / Python `ssl` strict-mode peer) need the cert to verify against
the literal hostname `localhost` rather than the service DNS name.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import threading
from pathlib import Path
from typing import Optional

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from yashigani.pki.issuer import IssuerPaths, bootstrap


_MANIFEST = """\
schema_version: 1
services:
  - name: gateway
    dns_sans: [gateway, gateway.internal]
    purpose: "data plane"
    mtls_capable: true
    bootstrap_token_sha256: ""
    revoked: false
cert_policy:
  root_lifetime_years_min: 5
  root_lifetime_years_max: 20
  root_lifetime_years_default: 10
  root_rotation_requires_manual_confirmation: true
  intermediate_lifetime_days_min: 90
  intermediate_lifetime_days_max: 365
  intermediate_lifetime_days_default: 180
  leaf_lifetime_days_min: 30
  leaf_lifetime_days_max: 90
  leaf_lifetime_days_default: 90
  renewal_threshold: 0.33
ca_source:
  mode: yashigani_generated
  byo: {}
  remote_acme: {}
  min_license_tier:
    yashigani_generated: community
"""


@pytest.fixture
def paths(tmp_path: Path) -> IssuerPaths:
    manifest = tmp_path / "service_identities.yaml"
    manifest.write_text(_MANIFEST)
    return IssuerPaths(secrets_dir=tmp_path / "secrets", manifest_path=manifest)


# ─────────────────────────────────────────────────────────────────────────────
# Layer 1 — SAN content
# ─────────────────────────────────────────────────────────────────────────────


def test_leaf_san_includes_localhost_dnsname(paths: IssuerPaths):
    bootstrap(paths)
    leaf = x509.load_pem_x509_certificates(paths.leaf_cert("gateway").read_bytes())[0]
    san_ext = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_names = san_ext.value.get_values_for_type(x509.DNSName)
    assert "localhost" in dns_names, (
        f"leaf cert SAN missing literal 'localhost' DNSName — got {dns_names!r}. "
        "In-container healthchecks against `https://localhost:...` will fail "
        "peer-cert verification without this."
    )


def test_leaf_san_includes_loopback_ipv4(paths: IssuerPaths):
    bootstrap(paths)
    leaf = x509.load_pem_x509_certificates(paths.leaf_cert("gateway").read_bytes())[0]
    san_ext = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    ip_addrs = san_ext.value.get_values_for_type(x509.IPAddress)
    assert ipaddress.IPv4Address("127.0.0.1") in ip_addrs, (
        f"leaf cert SAN missing 127.0.0.1 IPAddress — got {ip_addrs!r}"
    )


def test_leaf_san_includes_loopback_ipv6(paths: IssuerPaths):
    bootstrap(paths)
    leaf = x509.load_pem_x509_certificates(paths.leaf_cert("gateway").read_bytes())[0]
    san_ext = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    ip_addrs = san_ext.value.get_values_for_type(x509.IPAddress)
    assert ipaddress.IPv6Address("::1") in ip_addrs, (
        f"leaf cert SAN missing ::1 IPAddress — got {ip_addrs!r}"
    )


def test_leaf_san_includes_service_dns(paths: IssuerPaths):
    """Sanity: localhost-injection didn't drop the service-name SANs."""
    bootstrap(paths)
    leaf = x509.load_pem_x509_certificates(paths.leaf_cert("gateway").read_bytes())[0]
    san_ext = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_names = san_ext.value.get_values_for_type(x509.DNSName)
    assert "gateway" in dns_names
    assert "gateway.internal" in dns_names


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2 — actual TLS handshake against a localhost listener
#
# The SAN test above is necessary but not sufficient — Python's ssl module
# can still reject the cert if the SAN is structured wrong (e.g. missing
# critical=False, wrong type, etc.). This test loads the leaf cert into a
# real SSLContext, opens a 127.0.0.1 listener, and connects via the literal
# string "localhost". The handshake must complete with no peer-name mismatch.
# ─────────────────────────────────────────────────────────────────────────────


def _split_leaf_and_intermediate(bundle_pem: bytes) -> tuple[bytes, bytes]:
    """The leaf-cert file is `leaf || intermediate`. Split for SSLContext."""
    certs = x509.load_pem_x509_certificates(bundle_pem)
    assert len(certs) >= 1
    leaf_pem = certs[0].public_bytes(serialization.Encoding.PEM)
    intermediate_pem = (
        certs[1].public_bytes(serialization.Encoding.PEM) if len(certs) > 1 else b""
    )
    return leaf_pem, intermediate_pem


def _serve_once(server_ctx: ssl.SSLContext, ready: threading.Event) -> Optional[int]:
    """Bind to 127.0.0.1:0, signal ready, accept one TLS handshake, exit."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    ready.port = port  # type: ignore[attr-defined]
    ready.set()
    sock.settimeout(5)
    try:
        client_sock, _ = sock.accept()
        with server_ctx.wrap_socket(client_sock, server_side=True) as tls:
            tls.recv(64)  # consume any handshake-only bytes
    finally:
        sock.close()
    return None


def test_leaf_cert_verifies_when_client_connects_via_localhost(paths: IssuerPaths, tmp_path: Path):
    """Open a TLS listener with the leaf, connect via 'localhost', no verify error."""
    bootstrap(paths)

    leaf_bundle = paths.leaf_cert("gateway").read_bytes()
    leaf_pem, _intermediate_pem = _split_leaf_and_intermediate(leaf_bundle)

    leaf_key_pem = paths.leaf_key("gateway").read_bytes()

    cert_file = tmp_path / "server-leaf.pem"
    cert_file.write_bytes(leaf_pem)
    key_file = tmp_path / "server-leaf.key"
    key_file.write_bytes(leaf_key_pem)

    # Server context — present the leaf cert.
    server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))

    # Client context — trust the issuing root + intermediate.
    client_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    client_ctx.load_verify_locations(cafile=str(paths.root_cert))
    # Intermediate too (Python ssl is libssl-direct; partial chain may not validate
    # without the intermediate present, depending on OpenSSL version).
    client_ctx.load_verify_locations(cafile=str(paths.intermediate_cert))

    ready = threading.Event()
    server_thread = threading.Thread(
        target=_serve_once, args=(server_ctx, ready), daemon=True
    )
    server_thread.start()
    assert ready.wait(timeout=2), "server thread failed to bind in time"

    port = ready.port  # type: ignore[attr-defined]

    # Connect via the literal string "localhost". The cert must verify against
    # this hostname — which only works because the SAN includes 'localhost'.
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with client_ctx.wrap_socket(raw, server_hostname="localhost") as tls:
            # Handshake completed if we got here without an SSLError.
            assert tls.version() is not None
            tls.send(b"ok\n")

    server_thread.join(timeout=2)
