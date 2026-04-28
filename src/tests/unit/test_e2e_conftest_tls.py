"""
Unit tests for e2e conftest TLS hardening (M-04).

Verifies that the health-check probe uses the real CA cert (not verify=False)
and that _resolve_ca_cert() resolution order is correct.

Last updated: 2026-04-27T21:53:12+01:00
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# _resolve_ca_cert() resolution tests
# ---------------------------------------------------------------------------

class TestResolveCaCert:
    """
    M-04: _resolve_ca_cert() must return a real CA path or None.
    It must never cause verify=False to be used on https:// probes.
    """

    def test_explicit_env_var_used_first(self, tmp_path, monkeypatch):
        """YASHIGANI_CA_CERT env var overrides auto-detection."""
        fake_ca = tmp_path / "my_ca.crt"
        fake_ca.write_text("cert data")
        monkeypatch.setenv("YASHIGANI_CA_CERT", str(fake_ca))

        # Re-import _resolve_ca_cert with the monkeypatched env
        from importlib import import_module
        import importlib
        # Import the function directly (it reads env at call time, not at import)
        from src.tests.e2e.conftest import _resolve_ca_cert  # type: ignore[import]
        result = _resolve_ca_cert()
        assert result == str(fake_ca)

    def test_returns_none_when_no_ca_found(self, tmp_path, monkeypatch):
        """When no CA file exists anywhere, returns None (probe will fail → skip)."""
        monkeypatch.delenv("YASHIGANI_CA_CERT", raising=False)
        # Patch Path.exists to return False for all candidates
        with patch("pathlib.Path.exists", return_value=False):
            from src.tests.e2e.conftest import _resolve_ca_cert  # type: ignore[import]
            result = _resolve_ca_cert()
        assert result is None

    def test_docker_secrets_path_used_when_exists(self, tmp_path, monkeypatch):
        """docker/secrets/ca_root.crt is used when it exists."""
        monkeypatch.delenv("YASHIGANI_CA_CERT", raising=False)
        # Create a fake ca_root.crt at the expected repo-relative location
        # We patch Path.exists to return True only for the docker/secrets path
        docker_secrets_path = Path(__file__).parents[4] / "docker" / "secrets" / "ca_root.crt"

        def _exists(self) -> bool:
            return str(self) == str(docker_secrets_path)

        with patch.object(Path, "exists", _exists):
            from src.tests.e2e.conftest import _resolve_ca_cert  # type: ignore[import]
            result = _resolve_ca_cert()
        assert result == str(docker_secrets_path)


# ---------------------------------------------------------------------------
# verify= usage in _stack_running()
# ---------------------------------------------------------------------------

class TestStackRunningVerify:
    """
    M-04: _stack_running() must pass the real CA cert to httpx.get() for
    https:// URLs.  verify=False must never be used for TLS health checks.
    """

    def test_https_probe_uses_ca_cert_not_false(self, monkeypatch):
        """httpx.get() for https:// URL receives verify=<path>, not verify=False."""
        # Patch _CA_CERT_PATH to a known value
        fake_ca = "/fake/ca_root.crt"
        import src.tests.e2e.conftest as conftest_mod
        monkeypatch.setattr(conftest_mod, "_CA_CERT_PATH", fake_ca)

        captured = {}

        def _mock_get(url, verify, timeout):
            captured["url"] = url
            captured["verify"] = verify
            # Simulate a 200 response so _stack_running returns True
            r = MagicMock()
            r.status_code = 200
            return r

        with patch("httpx.get", side_effect=_mock_get):
            # Override candidates to only hit https://
            override_url = "https://localhost/healthz"
            monkeypatch.setenv("YASHIGANI_HEALTH_URL", override_url)
            result = conftest_mod._stack_running()

        assert result is True
        assert captured.get("verify") == fake_ca, \
            f"Expected verify={fake_ca!r}, got verify={captured.get('verify')!r}. " \
            f"verify=False must not be used for https:// health probes (M-04)."

    def test_http_probe_does_not_use_ca_cert(self, monkeypatch):
        """httpx.get() for http:// URL uses verify=False (no TLS to verify)."""
        fake_ca = "/fake/ca_root.crt"
        import src.tests.e2e.conftest as conftest_mod
        monkeypatch.setattr(conftest_mod, "_CA_CERT_PATH", fake_ca)

        captured = {}

        def _mock_get(url, verify, timeout):
            captured["url"] = url
            captured["verify"] = verify
            r = MagicMock()
            r.status_code = 200
            return r

        with patch("httpx.get", side_effect=_mock_get):
            monkeypatch.setenv("YASHIGANI_HEALTH_URL", "http://localhost:8080/healthz")
            result = conftest_mod._stack_running()

        assert result is True
        # http:// uses verify=False (no TLS) — that is correct
        assert captured.get("verify") is False

    def test_no_ca_cert_https_probe_raises_and_continues(self, monkeypatch):
        """When _CA_CERT_PATH is None, https:// probe raises and falls through.

        The key invariant: verify is set to None (not False) for https:// URLs
        when no CA cert path is known.  httpx then raises on SSL verification
        failure, and _stack_running falls through to the container-exec fallback
        (which also fails in unit test context) → returns False.
        The point of this test is NOT that the final result is False, but that
        we never pass verify=False to an https:// probe.
        """
        import src.tests.e2e.conftest as conftest_mod
        monkeypatch.setattr(conftest_mod, "_CA_CERT_PATH", None)

        https_verify_values: list = []

        def _mock_get(url, verify, timeout):
            if url.startswith("https://"):
                https_verify_values.append(verify)
                raise Exception("SSL: CA file not found")
            # http:// also fails — simulating no stack
            raise Exception("Connection refused")

        with patch("httpx.get", side_effect=_mock_get):
            monkeypatch.delenv("YASHIGANI_HEALTH_URL", raising=False)
            result = conftest_mod._stack_running()

        # At least one https probe was attempted
        assert len(https_verify_values) >= 1, "Expected at least one https:// probe"
        # CRITICAL: none of the https probes used verify=False
        for v in https_verify_values:
            assert v is not False, \
                f"verify=False used on https:// probe — TLS bypass in health check (M-04). " \
                f"Got verify={v!r} for one of the https probes."
        # verify=None (no CA file found) is acceptable — it causes SSL failure → skip
        # That is better than silently swallowing a TLS misconfiguration.
