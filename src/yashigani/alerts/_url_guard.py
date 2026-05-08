"""
Yashigani Alerts — Webhook URL guard against SSRF (V232-CSCAN-01b).

# Last updated: 2026-05-03T00:00:00+01:00

Provides assert_webhook_url() which must be called:
  1. At admin PUT /admin/alerts/config — fail 400 before persisting the URL.
  2. At send-time in each sink's post_to_webhook() — last-line-of-defence even
     if the config-write path is somehow bypassed.

Threat model: malicious/compromised admin sets slack_webhook_url to an internal
endpoint (AWS IMDS 169.254.169.254, in-cluster Prometheus, RFC1918 host, loopback)
and triggers /admin/alerts/test/slack to exfiltrate IMDS credentials or probe
internal services.

Guards applied (in order):
  - Scheme must be https.
  - netloc must not contain userinfo (user:pass@ prefix).
  - Hostname must not parse as an IP literal (rejects 169.254.169.254, ::1, etc.).
  - All IPs that the hostname resolves to must be non-private, non-loopback,
    non-link-local, non-multicast, non-reserved (ALL resolved IPs checked — not
    just the first — to block DNS-rebinding round-1).
  - Hostname must match or be a subdomain of one of allowed_hosts.

Raises WebhookUrlForbidden (ValueError subclass) on any violation.
"""
from __future__ import annotations

import ipaddress
import socket
import logging
from collections.abc import Set as AbstractSet
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class WebhookUrlForbidden(ValueError):
    """Raised when a webhook URL fails the allowlist or IP-safety checks."""

    def __init__(self, reason: str, url: str) -> None:
        self.reason = reason
        self.url = url
        super().__init__(f"Webhook URL blocked [{reason}]: {url!r}")


def _is_unsafe_address(addr: str) -> bool:
    """Return True if the resolved address falls in a prohibited range."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        # Unparseable — treat as unsafe
        return True
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def assert_webhook_url(url: str, *, allowed_hosts: AbstractSet[str]) -> None:
    """Assert that *url* is safe to use as a webhook destination.

    Parameters
    ----------
    url:
        The full webhook URL to validate.
    allowed_hosts:
        Set of exact hostnames that are permitted (e.g. ``{"hooks.slack.com"}``).
        Subdomain matching is also applied: a host ``foo.hooks.slack.com``
        passes if ``"hooks.slack.com"`` is in *allowed_hosts*.

    Raises
    ------
    WebhookUrlForbidden
        On any violation.
    """
    if not url:
        raise WebhookUrlForbidden("empty_url", url)

    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise WebhookUrlForbidden("parse_error", url) from exc

    # 1. Scheme must be https only.
    scheme = (parsed.scheme or "").lower()
    if scheme != "https":
        raise WebhookUrlForbidden(f"scheme_not_https:{scheme!r}", url)

    # 2. Reject embedded userinfo (user:pass@host or user@host).
    netloc = parsed.netloc or ""
    if "@" in netloc:
        raise WebhookUrlForbidden("userinfo_in_netloc", url)

    # 3. Extract and normalise the hostname.
    hostname = (parsed.hostname or "").lower().strip(".")
    if not hostname:
        raise WebhookUrlForbidden("empty_hostname", url)

    # 4. Reject IP literals directly (covers IPv4, IPv6, and link-local).
    try:
        ipaddress.ip_address(hostname)
        raise WebhookUrlForbidden("ip_literal_hostname", url)
    except WebhookUrlForbidden:
        raise
    except ValueError:
        pass  # Not an IP literal — hostname continues checks below.

    # 5. Resolve DNS and reject if any resolved address is in a prohibited range.
    #    We check ALL returned addresses to block DNS-rebinding round-1 pivots.
    try:
        addrinfos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        # Resolution failure — reject rather than allow unresolvable hosts through.
        raise WebhookUrlForbidden(f"dns_resolution_failed:{exc}", url) from exc

    for _family, _type, _proto, _canonname, sockaddr in addrinfos:
        # sockaddr[0] is typed as `str | int` in typeshed (covers IPv4/IPv6 union);
        # in practice always a string IP literal — coerce explicitly for the type checker.
        addr = str(sockaddr[0])
        if _is_unsafe_address(addr):
            raise WebhookUrlForbidden(f"resolves_to_private_or_reserved:{addr}", url)

    # 6. Host must be in allowed_hosts (exact) or be a subdomain of an entry.
    def _host_allowed(h: str, allowed: AbstractSet[str]) -> bool:
        if h in allowed:
            return True
        for ah in allowed:
            if h.endswith("." + ah):
                return True
        return False

    if not _host_allowed(hostname, {ah.lower() for ah in allowed_hosts}):
        raise WebhookUrlForbidden(f"host_not_in_allowlist:{hostname!r}", url)

    logger.debug("assert_webhook_url: accepted %r (hostname=%r)", url, hostname)
