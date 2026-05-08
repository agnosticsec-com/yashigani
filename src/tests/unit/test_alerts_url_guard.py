"""
Unit tests for V232-CSCAN-01b — SSRF guard on alert webhook URLs.

Covers:
  - IMDS literal (169.254.169.254)
  - RFC1918 literals (10.x, 192.168.x, 172.16.x)
  - Loopback (127.0.0.1, ::1)
  - Link-local (169.254.x.x, fe80::)
  - DNS that resolves to private (mocked via patch)
  - http:// scheme (wrong scheme)
  - https://hooks.slack.com.evil.com/ (suffix-not-equal)
  - https://attacker.com/ (wrong host not in allowlist)
  - https://user:pass@hooks.slack.com/ (userinfo in netloc)
  - Empty URL
  - Positive: https://hooks.slack.com/services/T.../B.../...

Last updated: 2026-05-03T00:00:00+01:00
"""
from __future__ import annotations

import socket
from unittest.mock import patch, MagicMock

import pytest

from yashigani.alerts._url_guard import WebhookUrlForbidden, assert_webhook_url

_SLACK_HOSTS = {"hooks.slack.com"}
_TEAMS_HOSTS = {"webhook.office.com", "outlook.office.com", "outlook.office365.com", "logic.azure.com"}

# A fake valid Slack webhook URL we use for positive tests.
_VALID_SLACK = "https://hooks.slack.com/services/TXXXXXXX/BXXXXXXX/xxxxxxxxxxxxxxxxxxxxxxxx"


# ---------------------------------------------------------------------------
# Helper: mock DNS to return a specific address
# ---------------------------------------------------------------------------

def _mock_getaddrinfo(addr: str):
    """Return a getaddrinfo-shaped list resolving to the given IP address."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (addr, 0))]


# ---------------------------------------------------------------------------
# Scheme checks
# ---------------------------------------------------------------------------

class TestSchemeGuard:
    def test_rejects_http_scheme(self):
        url = "http://hooks.slack.com/services/T/B/x"
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)
        assert "scheme_not_https" in exc_info.value.reason

    def test_rejects_ftp_scheme(self):
        url = "ftp://hooks.slack.com/services/T/B/x"
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)
        assert "scheme_not_https" in exc_info.value.reason

    def test_rejects_empty_scheme(self):
        url = "//hooks.slack.com/services/T/B/x"
        with pytest.raises(WebhookUrlForbidden):
            assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)

    def test_rejects_empty_url(self):
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_webhook_url("", allowed_hosts=_SLACK_HOSTS)
        assert "empty_url" in exc_info.value.reason


# ---------------------------------------------------------------------------
# Userinfo in netloc
# ---------------------------------------------------------------------------

class TestUserinfoGuard:
    def test_rejects_user_pass_at_host(self):
        url = "https://user:pass@hooks.slack.com/services/T/B/x"
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("34.0.0.1")):
            with pytest.raises(WebhookUrlForbidden) as exc_info:
                assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)
        assert "userinfo_in_netloc" in exc_info.value.reason

    def test_rejects_user_only_at_host(self):
        url = "https://user@hooks.slack.com/services/T/B/x"
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("34.0.0.1")):
            with pytest.raises(WebhookUrlForbidden) as exc_info:
                assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)
        assert "userinfo_in_netloc" in exc_info.value.reason


# ---------------------------------------------------------------------------
# IP literal hostnames
# ---------------------------------------------------------------------------

class TestIpLiteralGuard:
    def test_rejects_imds_ipv4_literal(self):
        url = "https://169.254.169.254/latest/meta-data/iam/security-credentials/"
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)
        assert "ip_literal_hostname" in exc_info.value.reason

    def test_rejects_loopback_127_literal(self):
        url = "https://127.0.0.1/hook"
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)
        assert "ip_literal_hostname" in exc_info.value.reason

    def test_rejects_ipv6_loopback_literal(self):
        url = "https://[::1]/hook"
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)
        assert "ip_literal_hostname" in exc_info.value.reason

    def test_rejects_rfc1918_10_literal(self):
        url = "https://10.0.0.1/hook"
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)
        assert "ip_literal_hostname" in exc_info.value.reason

    def test_rejects_rfc1918_192_168_literal(self):
        url = "https://192.168.1.100/hook"
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)
        assert "ip_literal_hostname" in exc_info.value.reason

    def test_rejects_rfc1918_172_16_literal(self):
        url = "https://172.16.0.1/hook"
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)
        assert "ip_literal_hostname" in exc_info.value.reason

    def test_rejects_link_local_169_literal(self):
        url = "https://169.254.0.1/hook"
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)
        assert "ip_literal_hostname" in exc_info.value.reason


# ---------------------------------------------------------------------------
# DNS resolves to private/reserved (mocked)
# ---------------------------------------------------------------------------

class TestDnsResolveGuard:
    def test_rejects_hostname_resolving_to_loopback(self):
        """A hostname that resolves to 127.0.0.1 must be blocked."""
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("127.0.0.1")):
            with pytest.raises(WebhookUrlForbidden) as exc_info:
                assert_webhook_url(
                    "https://hooks.slack.com/services/T/B/x",
                    allowed_hosts=_SLACK_HOSTS,
                )
        assert "resolves_to_private_or_reserved" in exc_info.value.reason

    def test_rejects_hostname_resolving_to_imds_ip(self):
        """A hostname that resolves to 169.254.169.254 must be blocked (DNS rebind)."""
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("169.254.169.254")):
            with pytest.raises(WebhookUrlForbidden) as exc_info:
                assert_webhook_url(
                    "https://hooks.slack.com/services/T/B/x",
                    allowed_hosts=_SLACK_HOSTS,
                )
        assert "resolves_to_private_or_reserved" in exc_info.value.reason

    def test_rejects_hostname_resolving_to_rfc1918(self):
        """A hostname that resolves to 10.0.0.1 must be blocked."""
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("10.0.0.1")):
            with pytest.raises(WebhookUrlForbidden) as exc_info:
                assert_webhook_url(
                    "https://hooks.slack.com/services/T/B/x",
                    allowed_hosts=_SLACK_HOSTS,
                )
        assert "resolves_to_private_or_reserved" in exc_info.value.reason

    def test_rejects_if_any_resolved_ip_is_private(self):
        """If ANY resolved IP is private, the URL must be blocked (not just first)."""
        # One public IP + one private IP — must still block
        multi_addr = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("34.0.0.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0)),
        ]
        with patch("socket.getaddrinfo", return_value=multi_addr):
            with pytest.raises(WebhookUrlForbidden) as exc_info:
                assert_webhook_url(
                    "https://hooks.slack.com/services/T/B/x",
                    allowed_hosts=_SLACK_HOSTS,
                )
        assert "resolves_to_private_or_reserved" in exc_info.value.reason

    def test_rejects_on_dns_failure(self):
        """If DNS fails to resolve, the URL must be blocked (fail closed)."""
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("NXDOMAIN")):
            with pytest.raises(WebhookUrlForbidden) as exc_info:
                assert_webhook_url(
                    "https://hooks.slack.com/services/T/B/x",
                    allowed_hosts=_SLACK_HOSTS,
                )
        assert "dns_resolution_failed" in exc_info.value.reason


# ---------------------------------------------------------------------------
# Host allowlist checks
# ---------------------------------------------------------------------------

class TestHostAllowlistGuard:
    def test_rejects_wrong_host(self):
        """An out-of-allowlist hostname must be rejected."""
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("34.0.0.1")):
            with pytest.raises(WebhookUrlForbidden) as exc_info:
                assert_webhook_url(
                    "https://attacker.com/exfil",
                    allowed_hosts=_SLACK_HOSTS,
                )
        assert "host_not_in_allowlist" in exc_info.value.reason

    def test_rejects_suffix_trick_not_subdomain(self):
        """hooks.slack.com.evil.com is NOT a subdomain of hooks.slack.com."""
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("34.0.0.1")):
            with pytest.raises(WebhookUrlForbidden) as exc_info:
                assert_webhook_url(
                    "https://hooks.slack.com.evil.com/hook",
                    allowed_hosts=_SLACK_HOSTS,
                )
        assert "host_not_in_allowlist" in exc_info.value.reason

    def test_rejects_allowlist_as_substring(self):
        """xhooks.slack.com must not match hooks.slack.com."""
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("34.0.0.1")):
            with pytest.raises(WebhookUrlForbidden) as exc_info:
                assert_webhook_url(
                    "https://xhooks.slack.com/hook",
                    allowed_hosts=_SLACK_HOSTS,
                )
        assert "host_not_in_allowlist" in exc_info.value.reason

    def test_accepts_exact_allowlist_match(self):
        """hooks.slack.com exactly must be accepted (given safe resolution)."""
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("34.0.0.1")):
            # Must not raise
            assert_webhook_url(_VALID_SLACK, allowed_hosts=_SLACK_HOSTS)

    def test_accepts_subdomain_of_allowlist_entry(self):
        """foo.webhook.office.com is a valid subdomain of webhook.office.com."""
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("52.0.0.1")):
            assert_webhook_url(
                "https://foo.webhook.office.com/hook",
                allowed_hosts=_TEAMS_HOSTS,
            )


# ---------------------------------------------------------------------------
# Positive path
# ---------------------------------------------------------------------------

class TestPositivePath:
    def test_accepts_valid_slack_webhook(self):
        """A well-formed Slack webhook URL with a public IP must be accepted."""
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("34.0.0.1")):
            # Must not raise
            assert_webhook_url(_VALID_SLACK, allowed_hosts=_SLACK_HOSTS)

    def test_accepts_valid_teams_webhook(self):
        """A well-formed Teams webhook URL must be accepted."""
        url = "https://webhook.office.com/webhookb2/xxx@xxx/IncomingWebhook/xxx/xxx"
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("52.0.0.1")):
            assert_webhook_url(url, allowed_hosts=_TEAMS_HOSTS)

    def test_exception_carries_reason_and_url(self):
        """WebhookUrlForbidden.reason and .url are populated."""
        url = "http://hooks.slack.com/services/T/B/x"
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)
        exc = exc_info.value
        assert exc.url == url
        assert exc.reason  # non-empty reason


# ---------------------------------------------------------------------------
# SlackSink/TeamsSink constructor guard integration
# ---------------------------------------------------------------------------

class TestSinkConstructorGuard:
    """Confirm the sinks raise WebhookUrlForbidden if given a bad URL."""

    def test_slack_sink_rejects_http_url(self):
        from yashigani.alerts.slack_sink import SlackSink
        with pytest.raises(WebhookUrlForbidden):
            SlackSink("http://169.254.169.254/imds")

    def test_teams_sink_rejects_http_url(self):
        from yashigani.alerts.teams_sink import TeamsSink
        with pytest.raises(WebhookUrlForbidden):
            TeamsSink("http://169.254.169.254/imds")

    def test_slack_sink_rejects_wrong_host(self):
        from yashigani.alerts.slack_sink import SlackSink
        with pytest.raises(WebhookUrlForbidden):
            SlackSink("https://evil.com/hook")

    def test_teams_sink_rejects_wrong_host(self):
        from yashigani.alerts.teams_sink import TeamsSink
        with pytest.raises(WebhookUrlForbidden):
            TeamsSink("https://evil.com/hook")
