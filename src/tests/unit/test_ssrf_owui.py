"""
Unit tests for _assert_safe_owui_url — YSG-RISK-007.A (CWE-918).

Verifies that the OWUI_API_URL allowlist helper blocks SSRF probes and
permits only explicitly allowlisted hostnames.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Load the agents module in isolation — the full import chain pulls in bcrypt/
# asyncpg which are not available in the macOS unit-test environment.
# ---------------------------------------------------------------------------
_AGENTS_PATH = Path(__file__).parents[2] / "yashigani" / "backoffice" / "routes" / "agents.py"


def _load_agents_module():
    """Load agents.py without triggering the full backoffice import chain."""
    # Stub the heavy transitive dependencies before importing
    _stubs = {
        "yashigani.backoffice.middleware": type(sys)("stub"),
        "yashigani.backoffice.state": type(sys)("stub"),
        "yashigani.licensing.enforcer": type(sys)("stub"),
        "pydantic": importlib.import_module("pydantic"),
        "fastapi": importlib.import_module("fastapi"),
    }
    # Add minimal attributes needed by the module-level imports
    _stubs["yashigani.backoffice.middleware"].require_admin_session = lambda *a, **kw: None
    _stubs["yashigani.backoffice.middleware"].AdminSession = object
    _stubs["yashigani.backoffice.middleware"].require_stepup_admin_session = lambda *a, **kw: None
    _stubs["yashigani.backoffice.middleware"].StepUpAdminSession = object
    _stubs["yashigani.backoffice.state"].backoffice_state = None
    _stubs["yashigani.licensing.enforcer"].require_feature = lambda *a, **kw: None

    old = {}
    for k, v in _stubs.items():
        old[k] = sys.modules.get(k)
        sys.modules[k] = v

    spec = importlib.util.spec_from_file_location("agents_isolated", _AGENTS_PATH)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    finally:
        for k, v in old.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v
    return mod


_agents = _load_agents_module()
_assert_safe_owui_url = _agents._assert_safe_owui_url


def _fn(url: str, hostnames_env: str = ""):
    """Call _assert_safe_owui_url with optional env override."""
    if hostnames_env:
        old = os.environ.get("YASHIGANI_OWUI_HOSTNAMES")
        os.environ["YASHIGANI_OWUI_HOSTNAMES"] = hostnames_env
        try:
            return _assert_safe_owui_url(url)
        finally:
            if old is None:
                os.environ.pop("YASHIGANI_OWUI_HOSTNAMES", None)
            else:
                os.environ["YASHIGANI_OWUI_HOSTNAMES"] = old
    else:
        # Remove any override so default list is used
        old = os.environ.pop("YASHIGANI_OWUI_HOSTNAMES", None)
        try:
            return _assert_safe_owui_url(url)
        finally:
            if old is not None:
                os.environ["YASHIGANI_OWUI_HOSTNAMES"] = old



class TestAssertSafeOwuiUrl:
    def test_default_allowlist_open_webui_http(self):
        """Default hostname open-webui with http:// must pass."""
        result = _fn("http://open-webui:8080")
        assert result == "http://open-webui:8080"

    def test_default_allowlist_localhost(self):
        """localhost is in the default allowlist."""
        result = _fn("http://localhost:8080")
        assert result == "http://localhost:8080"

    def test_default_allowlist_127(self):
        """127.0.0.1 is in the default allowlist."""
        result = _fn("http://127.0.0.1:8080")
        assert result == "http://127.0.0.1:8080"

    def test_https_allowed(self):
        """https:// scheme is allowed."""
        result = _fn("https://open-webui:8080/api")
        assert result.startswith("https://")

    def test_metadata_endpoint_blocked(self):
        """AWS IMDS metadata endpoint must be blocked."""
        with pytest.raises(RuntimeError, match="owui_url_blocked"):
            _fn("http://169.254.169.254/latest/meta-data/")

    def test_custom_allowlist_permits_custom_host(self):
        """A custom YASHIGANI_OWUI_HOSTNAMES env value allows the specified host."""
        result = _fn("http://my-owui.internal:8080", hostnames_env="my-owui.internal")
        assert result == "http://my-owui.internal:8080"

    def test_custom_allowlist_blocks_non_listed(self):
        """A host not in the custom allowlist must be blocked."""
        with pytest.raises(RuntimeError, match="owui_url_blocked"):
            _fn("http://evil.example.com:8080", hostnames_env="my-owui.internal")

    def test_file_scheme_blocked(self):
        """file:// scheme must be blocked."""
        with pytest.raises(RuntimeError, match="owui_url_blocked"):
            _fn("file:///etc/passwd")

    def test_ftp_scheme_blocked(self):
        """ftp:// scheme must be blocked."""
        with pytest.raises(RuntimeError, match="owui_url_blocked"):
            _fn("ftp://open-webui:21/")

    def test_metadata_via_custom_allowlist_still_scheme_checked(self):
        """Even if an allowlist explicitly lists the metadata IP, it passes scheme check
        but the IP itself would be blocked only by host-lookup (not the direct allowlist).
        Test that a valid-scheme, custom-listed host passes."""
        # 10.0.0.5 is RFC1918 but _assert_safe_owui_url uses hostname allowlist,
        # not IP range blocking — that's HttpClient's role. Test custom allowlist works.
        result = _fn("http://10.0.0.5:8080", hostnames_env="10.0.0.5")
        assert result == "http://10.0.0.5:8080"
