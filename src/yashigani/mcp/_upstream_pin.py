"""
MCP Broker — upstream MCP-server cert/SPIFFE pinning (P8).

Phase-2 P8 finding:

  For each consumes.servers[] entry, the broker MUST verify the upstream
  MCP server's identity before forwarding calls:

  - ``pin_mode: cert_fingerprint`` (v1 default): the upstream server's TLS
    certificate SHA-256 fingerprint is pinned at onboard time.  The broker
    verifies the live cert fingerprint against the pinned value before
    forwarding.  On mismatch the connection is ABORTED and
    MCP_UPSTREAM_CERT_PIN_MISMATCH is logged / audited.

  - ``pin_mode: spiffe``: the upstream server presents a SPIFFE SVID (X.509)
    in the TLS handshake.  The broker verifies the SPIFFE ID matches the
    pinned value.

CRL/OCSP note: CRL/OCSP does not cover external upstreams (they are not
issued by our internal CA).  Manual pin-rotation is required when an upstream
server rotates its cert.  The operator updates the pinned fingerprint in the
consumes.servers[] config.  TODO [P8-v2]: automated pin-rotation alert via
PKI watch endpoint.

Validator:
  The ``require_pin_mode_for_servers()`` linter checks every server entry in
  a consumes manifest and returns errors for entries missing ``pin_mode``.

v2.25.0 / P1 Phase-2 / P8 / YSG-RISK-056 (upstream trust boundary) /
  Nico §8 upstream identity pinning.
"""
from __future__ import annotations

import hashlib
import logging
import ssl
import socket
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# Audit event label emitted when a pin mismatch is detected.
CERT_PIN_MISMATCH_LABEL = "MCP_UPSTREAM_CERT_PIN_MISMATCH"


class PinMode(str, Enum):
    """Supported upstream identity-pinning modes."""
    CERT_FINGERPRINT = "cert_fingerprint"
    SPIFFE = "spiffe"


@dataclass
class UpstreamPinConfig:
    """
    Pinning configuration for one upstream MCP server.

    Attributes
    ----------
    server_id:
        Logical identifier for the upstream server (e.g. "github-mcp").
    host:
        Upstream hostname (used for cert retrieval and SNI).
    port:
        Upstream TLS port (default 443).
    pin_mode:
        ``cert_fingerprint`` (default) or ``spiffe``.
    cert_fingerprint_sha256:
        Expected SHA-256 hex fingerprint of the upstream TLS leaf cert.
        Required when pin_mode=cert_fingerprint.  Case-insensitive; colons
        are stripped before comparison.
    spiffe_id:
        Expected SPIFFE ID (``spiffe://...``) from the upstream SVID.
        Required when pin_mode=spiffe.
    """
    server_id: str
    host: str
    port: int = 443
    pin_mode: PinMode = PinMode.CERT_FINGERPRINT
    cert_fingerprint_sha256: Optional[str] = None
    spiffe_id: Optional[str] = None


@dataclass
class PinVerificationResult:
    """Result of a cert/SPIFFE pin verification attempt."""
    server_id: str
    matched: bool
    reason: str                     # "ok" | specific mismatch / error label
    observed_fingerprint: Optional[str] = None   # for audit (never log to end-user)
    observed_spiffe_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _normalise_fingerprint(fp: str) -> str:
    """Normalise a SHA-256 fingerprint to lowercase hex without separators."""
    return fp.replace(":", "").replace(" ", "").lower()


def _get_cert_fingerprint_sha256(host: str, port: int, timeout: float = 5.0) -> str:
    """
    Retrieve the TLS leaf-cert SHA-256 fingerprint for the given host:port.

    Uses ssl.create_default_context() for the TLS handshake (validates the
    cert against system CA store during retrieval).  Returns hex fingerprint
    of the leaf cert DER bytes.

    Raises OSError / ssl.SSLError on failure.
    """
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            # get_peer_certificate(binary_form=True) returns the DER bytes of the
            # leaf certificate (first cert in the chain).
            der_cert = tls_sock.getpeercert(binary_form=True)
            if not der_cert:
                raise ssl.SSLError("No peer certificate returned")
            return hashlib.sha256(der_cert).hexdigest()


def _get_spiffe_id_from_san(host: str, port: int, timeout: float = 5.0) -> Optional[str]:
    """
    Extract the SPIFFE ID (URI SAN starting with ``spiffe://``) from the
    upstream server's TLS leaf certificate.

    Returns None if no SPIFFE URI SAN is present.
    """
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            cert: Any = tls_sock.getpeercert()
            if not cert:
                return None
            # getpeercert() returns a dict with 'subjectAltName' as a tuple of 2-tuples.
            for san_entry in cert.get("subjectAltName", []):
                san_type: str = san_entry[0]
                san_value: str = san_entry[1]
                if san_type == "URI" and san_value.startswith("spiffe://"):
                    return san_value
    return None


# ---------------------------------------------------------------------------
# Public verification interface
# ---------------------------------------------------------------------------


def verify_upstream_pin(
    config: UpstreamPinConfig,
    timeout: float = 5.0,
    # Allow injection of retrieval functions for testing
    _get_fp: Optional[Callable[..., str]] = None,
    _get_spiffe: Optional[Callable[..., Optional[str]]] = None,
) -> PinVerificationResult:
    """
    Verify the upstream MCP server's identity against the pinned value.

    On mismatch, returns PinVerificationResult(matched=False, reason=...).
    The caller MUST abort the connection and emit CERT_PIN_MISMATCH_LABEL.

    On network/TLS error, also returns matched=False (fail-closed).

    Parameters
    ----------
    config:
        Pinning configuration for the upstream server.
    timeout:
        TLS connection timeout in seconds.
    _get_fp / _get_spiffe:
        Injection hooks for unit testing (override live network calls).
    """
    get_fp = _get_fp if _get_fp is not None else _get_cert_fingerprint_sha256
    get_spiffe = _get_spiffe if _get_spiffe is not None else _get_spiffe_id_from_san

    try:
        if config.pin_mode == PinMode.CERT_FINGERPRINT:
            if not config.cert_fingerprint_sha256:
                return PinVerificationResult(
                    server_id=config.server_id,
                    matched=False,
                    reason="pin_config_error:cert_fingerprint_sha256_missing",
                )
            observed = get_fp(config.host, config.port, timeout)
            pinned = _normalise_fingerprint(config.cert_fingerprint_sha256)
            observed_norm = _normalise_fingerprint(observed)
            if observed_norm == pinned:
                return PinVerificationResult(
                    server_id=config.server_id,
                    matched=True,
                    reason="ok",
                    observed_fingerprint=observed_norm,
                )
            else:
                logger.warning(
                    "upstream-pin: %s CERT FINGERPRINT MISMATCH "
                    "host=%s:%d pinned=%s observed=%s",
                    CERT_PIN_MISMATCH_LABEL, config.host, config.port,
                    pinned[:16] + "...", observed_norm[:16] + "...",
                )
                return PinVerificationResult(
                    server_id=config.server_id,
                    matched=False,
                    reason=CERT_PIN_MISMATCH_LABEL,
                    observed_fingerprint=observed_norm,
                )

        elif config.pin_mode == PinMode.SPIFFE:
            if not config.spiffe_id:
                return PinVerificationResult(
                    server_id=config.server_id,
                    matched=False,
                    reason="pin_config_error:spiffe_id_missing",
                )
            observed_spiffe = get_spiffe(config.host, config.port, timeout)
            if observed_spiffe == config.spiffe_id:
                return PinVerificationResult(
                    server_id=config.server_id,
                    matched=True,
                    reason="ok",
                    observed_spiffe_id=observed_spiffe,
                )
            else:
                logger.warning(
                    "upstream-pin: %s SPIFFE ID MISMATCH "
                    "host=%s:%d pinned=%r observed=%r",
                    CERT_PIN_MISMATCH_LABEL, config.host, config.port,
                    config.spiffe_id, observed_spiffe,
                )
                return PinVerificationResult(
                    server_id=config.server_id,
                    matched=False,
                    reason=CERT_PIN_MISMATCH_LABEL,
                    observed_spiffe_id=observed_spiffe,
                )

        else:
            return PinVerificationResult(
                server_id=config.server_id,
                matched=False,
                reason=f"pin_config_error:unknown_pin_mode:{config.pin_mode}",
            )

    except (OSError, ssl.SSLError, ConnectionRefusedError, TimeoutError) as exc:
        logger.error(
            "upstream-pin: connection error verifying %s host=%s:%d: %s",
            config.server_id, config.host, config.port, exc,
        )
        return PinVerificationResult(
            server_id=config.server_id,
            matched=False,
            reason=f"connection_error:{type(exc).__name__}",
        )
    except Exception as exc:
        logger.error(
            "upstream-pin: unexpected error verifying %s: %s",
            config.server_id, exc,
        )
        return PinVerificationResult(
            server_id=config.server_id,
            matched=False,
            reason=f"unexpected_error:{type(exc).__name__}",
        )


# ---------------------------------------------------------------------------
# Manifest linter — require pin_mode per consumes.servers[]
# ---------------------------------------------------------------------------


class PinManifestValidationError(ValueError):
    """Raised when a consumes manifest fails pin-mode validation."""


def require_pin_mode_for_servers(
    servers: list[dict],
    allowed_modes: Optional[set[str]] = None,
) -> list[str]:
    """
    Validate that every entry in a consumes.servers[] list has a ``pin_mode``
    field set to an allowed value.

    Parameters
    ----------
    servers:
        List of server config dicts, each representing one upstream MCP server.
    allowed_modes:
        Set of allowed pin_mode strings.  Defaults to {"cert_fingerprint", "spiffe"}.

    Returns
    -------
    list[str]
        List of validation error strings (empty when all entries are valid).

    Callers should raise PinManifestValidationError (or log + fail-closed) when
    the returned list is non-empty.
    """
    if allowed_modes is None:
        allowed_modes = {pm.value for pm in PinMode}

    errors: list[str] = []
    for idx, server in enumerate(servers):
        server_id = server.get("id") or server.get("server_id") or f"[{idx}]"
        pin_mode = server.get("pin_mode")
        if pin_mode is None:
            errors.append(
                f"server {server_id!r}: missing required field 'pin_mode' "
                f"(allowed: {sorted(allowed_modes)})"
            )
        elif pin_mode not in allowed_modes:
            errors.append(
                f"server {server_id!r}: pin_mode={pin_mode!r} is not allowed "
                f"(allowed: {sorted(allowed_modes)})"
            )
        else:
            # Mode-specific required fields
            if pin_mode == PinMode.CERT_FINGERPRINT.value:
                if not server.get("cert_fingerprint_sha256"):
                    errors.append(
                        f"server {server_id!r}: pin_mode=cert_fingerprint requires "
                        f"'cert_fingerprint_sha256' to be set"
                    )
            elif pin_mode == PinMode.SPIFFE.value:
                if not server.get("spiffe_id"):
                    errors.append(
                        f"server {server_id!r}: pin_mode=spiffe requires "
                        f"'spiffe_id' to be set"
                    )
    return errors
