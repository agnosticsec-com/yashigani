"""
Unit tests for SiemTarget SSRF allowlist — YSG-RISK-007.C (CWE-918).

Verifies:
  - validate_siem_url() from yashigani.audit.writer enforces https-only
  - RFC 1918 / loopback / link-local / multicast hosts blocked
  - YASHIGANI_SIEM_HOSTNAMES allowlist bypasses DNS check
  - YASHIGANI_TEST_MODE=1 skips DNS check (https still required)
  - Pydantic SiemTargetRequest.url field_validator surfaces the error as 422
"""
from __future__ import annotations

import os
import pytest

# ---------------------------------------------------------------------------
# Load validate_siem_url directly from writer without the full stack
# ---------------------------------------------------------------------------

import importlib.util
from pathlib import Path

_WRITER_PATH = Path(__file__).parents[2] / "yashigani" / "audit" / "writer.py"


def _load_writer():
    """Load writer.py with stubs for unavailable deps (bcrypt/asyncpg/redis)."""
    import sys
    import types

    MOD_NAME = "yashigani.audit.writer"

    stubs = {
        "yashigani.audit.config": types.ModuleType("yashigani.audit.config"),
        "yashigani.audit.masking": types.ModuleType("yashigani.audit.masking"),
        "yashigani.audit.schema": types.ModuleType("yashigani.audit.schema"),
        "yashigani.audit.scope": types.ModuleType("yashigani.audit.scope"),
    }
    stubs["yashigani.audit.config"].AuditConfig = object
    stubs["yashigani.audit.masking"].CredentialMasker = object
    stubs["yashigani.audit.schema"].AuditEvent = object
    stubs["yashigani.audit.schema"].SiemDeliveryFailedEvent = object
    stubs["yashigani.audit.scope"].MaskingScopeConfig = object

    spec = importlib.util.spec_from_file_location(MOD_NAME, _WRITER_PATH)
    mod = importlib.util.module_from_spec(spec)

    old = {}
    for k, v in stubs.items():
        old[k] = sys.modules.get(k)
        sys.modules[k] = v
    # Register the module under its real name BEFORE exec so that dataclass
    # __module__ resolution works (Python 3.9 dataclasses need sys.modules[__name__])
    old[MOD_NAME] = sys.modules.get(MOD_NAME)
    sys.modules[MOD_NAME] = mod

    try:
        spec.loader.exec_module(mod)
    finally:
        for k, v in old.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v
    return mod


_writer = _load_writer()
_validate_siem_url = _writer.validate_siem_url


def _call(url: str, *, test_mode: bool = True, siem_hosts: str = ""):
    """Helper: call validate_siem_url with env isolation."""
    env_changes = {}
    if test_mode:
        env_changes["YASHIGANI_TEST_MODE"] = "1"
    else:
        env_changes["YASHIGANI_TEST_MODE"] = ""
    if siem_hosts is not None:
        env_changes["YASHIGANI_SIEM_HOSTNAMES"] = siem_hosts

    old = {}
    for k, v in env_changes.items():
        old[k] = os.environ.get(k)
        if v:
            os.environ[k] = v
        else:
            os.environ.pop(k, None)
    try:
        return _validate_siem_url(url)
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class TestValidateSiemUrlScheme:
    def test_https_passes_test_mode(self):
        """https:// passes (test mode, skips DNS)."""
        result = _call("https://siem.example.com/events", test_mode=True)
        assert result == "https://siem.example.com/events"

    def test_http_rejected(self):
        """http:// must always be rejected."""
        with pytest.raises(ValueError, match="must use https://"):
            _call("http://169.254.169.254/foo", test_mode=True)

    def test_http_even_on_safe_host_rejected(self):
        """http:// on an apparently safe host is still rejected."""
        with pytest.raises(ValueError, match="must use https://"):
            _call("http://siem.example.com/events", test_mode=True)

    def test_ftp_scheme_rejected(self):
        """ftp:// is rejected."""
        with pytest.raises(ValueError, match="must use https://"):
            _call("ftp://siem.example.com/events", test_mode=True)


class TestValidateSiemUrlLoopbackPrivate:
    def test_loopback_blocked_without_allowlist(self):
        """127.0.0.1 (loopback) must be blocked when DNS resolves (no test mode)."""
        with pytest.raises(ValueError):
            _call("https://127.0.0.1/events", test_mode=False)

    def test_localhost_blocked_when_dns_resolves(self):
        """localhost resolves to 127.0.0.1 — blocked without test mode."""
        with pytest.raises(ValueError):
            _call("https://localhost/events", test_mode=False)

    def test_link_local_blocked(self):
        """169.254.169.254 (link-local, IMDS) must be blocked."""
        with pytest.raises(ValueError):
            _call("https://169.254.169.254/foo", test_mode=False)


class TestValidateSiemUrlAllowlist:
    def test_allowlisted_host_bypasses_dns(self):
        """YASHIGANI_SIEM_HOSTNAMES allowlisted host passes without DNS check."""
        result = _call(
            "https://mysiem.internal/events",
            test_mode=False,
            siem_hosts="mysiem.internal",
        )
        assert result.startswith("https://")

    def test_non_allowlisted_host_still_checked(self):
        """A host not in the allowlist is still DNS-checked."""
        # 127.0.0.1 is not allowlisted here — should still be blocked.
        with pytest.raises(ValueError):
            _call(
                "https://127.0.0.1/events",
                test_mode=False,
                siem_hosts="other.example.com",
            )


class TestSiemTargetRequestPydanticValidation:
    """Verify that Pydantic SiemTargetRequest.url field_validator fires."""

    def _make_request_model(self):
        """Load SiemTargetRequest via isolated import to avoid circular deps."""
        import sys
        import types

        stubs = {
            "yashigani.audit.writer": _writer,
            "yashigani.backoffice.middleware": types.ModuleType("stub_mw"),
            "yashigani.backoffice.state": types.ModuleType("stub_state"),
        }
        stubs["yashigani.backoffice.middleware"].AdminSession = object
        stubs["yashigani.backoffice.state"].backoffice_state = None

        _AUDIT_ROUTES_PATH = (
            Path(__file__).parents[2] / "yashigani" / "backoffice" / "routes" / "audit.py"
        )

        old = {}
        for k, v in stubs.items():
            old[k] = sys.modules.get(k)
            sys.modules[k] = v

        spec = importlib.util.spec_from_file_location("audit_routes_isolated", _AUDIT_ROUTES_PATH)
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        finally:
            for k, v in old.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v
        return mod.SiemTargetRequest

    def test_http_metadata_url_raises_validation_error(self):
        """Pydantic validation rejects http://169.254.169.254/foo with YASHIGANI_TEST_MODE=1."""
        from pydantic import ValidationError
        SiemTargetRequest = self._make_request_model()

        # Even in test mode https is required
        old_tm = os.environ.get("YASHIGANI_TEST_MODE")
        os.environ["YASHIGANI_TEST_MODE"] = "1"
        try:
            with pytest.raises(ValidationError):
                SiemTargetRequest(
                    name="evil",
                    target_type="webhook",
                    url="http://169.254.169.254/foo",
                    auth_header="Authorization",
                    auth_value="Bearer token",
                )
        finally:
            if old_tm is None:
                os.environ.pop("YASHIGANI_TEST_MODE", None)
            else:
                os.environ["YASHIGANI_TEST_MODE"] = old_tm

    def test_valid_https_url_accepted_in_test_mode(self):
        """Valid https:// URL accepted by Pydantic in test mode (no DNS)."""
        SiemTargetRequest = self._make_request_model()

        old_tm = os.environ.get("YASHIGANI_TEST_MODE")
        os.environ["YASHIGANI_TEST_MODE"] = "1"
        try:
            obj = SiemTargetRequest(
                name="siem-test",
                target_type="webhook",
                url="https://siem.example.com/events",
                auth_header="Authorization",
                auth_value="Bearer token",
            )
            assert obj.url == "https://siem.example.com/events"
        finally:
            if old_tm is None:
                os.environ.pop("YASHIGANI_TEST_MODE", None)
            else:
                os.environ["YASHIGANI_TEST_MODE"] = old_tm
