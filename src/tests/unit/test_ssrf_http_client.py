"""Tests for yashigani.net.HttpClient SSRF guardrails."""

import pytest

from yashigani.net import HttpClient, BlockedByPolicy


def test_blocks_plain_http_by_default():
    c = HttpClient(allow_http=False)
    with pytest.raises(BlockedByPolicy, match="Plain HTTP disallowed"):
        c._check_policy("http://example.com/")


def test_allows_plain_http_when_opted_in():
    c = HttpClient(allow_http=True)
    # Should not raise (host is public, no allowlist configured).
    c._check_policy("http://example.com/")


def test_blocks_cloud_metadata_endpoint():
    c = HttpClient(allow_http=True)
    with pytest.raises(BlockedByPolicy, match="private / loopback / metadata"):
        c._check_policy("http://169.254.169.254/latest/meta-data")


def test_blocks_google_metadata_hostname():
    c = HttpClient(allow_http=True)
    with pytest.raises(BlockedByPolicy):
        c._check_policy("http://metadata.google.internal/")


def test_blocks_loopback():
    c = HttpClient(allow_http=True)
    with pytest.raises(BlockedByPolicy):
        c._check_policy("http://127.0.0.1/")


def test_blocks_private_rfc1918():
    c = HttpClient(allow_http=True)
    with pytest.raises(BlockedByPolicy):
        c._check_policy("http://10.0.0.5/")
    with pytest.raises(BlockedByPolicy):
        c._check_policy("http://192.168.1.1/")


def test_allowlist_enforced():
    c = HttpClient(allowlist=["api.pwnedpasswords.com"])
    # Allowed host passes.
    c._check_policy("https://api.pwnedpasswords.com/range/ABCDE")
    # Non-allowlisted host fails.
    with pytest.raises(BlockedByPolicy, match="not in YASHIGANI_OUTBOUND_ALLOWLIST"):
        c._check_policy("https://evil.example.com/")


def test_suffix_allowlist_entry():
    c = HttpClient(allowlist=[".agnosticsec.com"])
    c._check_policy("https://api.agnosticsec.com/")
    c._check_policy("https://www.agnosticsec.com/")
    with pytest.raises(BlockedByPolicy):
        c._check_policy("https://agnosticsec.com.evil.com/")


def test_blocklist_overrides_allowlist():
    c = HttpClient(allowlist=[".example.com"], blocklist=["bad.example.com"])
    c._check_policy("https://good.example.com/")
    with pytest.raises(BlockedByPolicy, match="(?i)blocklist"):
        c._check_policy("https://bad.example.com/")


def test_blocks_non_http_scheme():
    c = HttpClient()
    with pytest.raises(BlockedByPolicy, match="Scheme"):
        c._check_policy("file:///etc/passwd")
    with pytest.raises(BlockedByPolicy, match="Scheme"):
        c._check_policy("gopher://example.com/")


def test_missing_hostname():
    c = HttpClient()
    with pytest.raises(BlockedByPolicy, match="lacks a hostname"):
        c._check_policy("https:///")
