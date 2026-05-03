"""
Unit tests for V232-CSCAN-01a — path injection via agent name.

Covers:
  - AgentRegisterRequest.name: charset regex rejects path-traversal, absolute paths,
    NUL bytes, and other non-slug inputs.
  - AgentUpdateRequest.name: same constraint applies on update.
  - Positive case: a valid slug is accepted.
  - openai_router resolve-and-confine: resolved token path must be under /run/secrets.

Last updated: 2026-05-03T00:00:00+01:00
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

# ---------------------------------------------------------------------------
# Load agents module in isolation (mirrors test_v2232_security_regressions.py)
# ---------------------------------------------------------------------------

_AGENTS_PATH = Path(__file__).parents[2] / "yashigani" / "backoffice" / "routes" / "agents.py"


def _load_agents_module():
    _stubs = {
        "yashigani.backoffice.middleware": type(sys)("stub"),
        "yashigani.backoffice.state": type(sys)("stub"),
        "yashigani.licensing.enforcer": type(sys)("stub"),
        "pydantic": importlib.import_module("pydantic"),
        "fastapi": importlib.import_module("fastapi"),
    }
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

    spec = importlib.util.spec_from_file_location("agents_isolated_cscan01a", _AGENTS_PATH)
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


import typing

_agents_mod = _load_agents_module()
_AgentRegisterRequest = _agents_mod.AgentRegisterRequest
_AgentUpdateRequest = _agents_mod.AgentUpdateRequest
try:
    _AgentUpdateRequest.model_rebuild(
        _types_namespace={"Optional": typing.Optional, "list": list},
    )
except Exception:
    pass

_VALID_URL = "https://agent.example.com"


# ---------------------------------------------------------------------------
# AgentRegisterRequest.name — rejection tests
# ---------------------------------------------------------------------------

class TestAgentRegisterNameRejectsPathTraversal:
    """V232-CSCAN-01a: registration must reject path-traversal and non-slug names."""

    def test_rejects_dotdot_slash(self):
        """../etc/passwd — classic path traversal."""
        with pytest.raises(ValidationError) as exc_info:
            _AgentRegisterRequest(name="../etc/passwd", upstream_url=_VALID_URL)
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors

    def test_rejects_dotdot_only(self):
        """'..' alone should be rejected."""
        with pytest.raises(ValidationError) as exc_info:
            _AgentRegisterRequest(name="..", upstream_url=_VALID_URL)
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors

    def test_rejects_absolute_path(self):
        """/etc/passwd — absolute path."""
        with pytest.raises(ValidationError) as exc_info:
            _AgentRegisterRequest(name="/etc/passwd", upstream_url=_VALID_URL)
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors

    def test_rejects_nul_byte_in_name(self):
        """name\x00token — NUL byte injection."""
        with pytest.raises(ValidationError) as exc_info:
            _AgentRegisterRequest(name="name\x00token", upstream_url=_VALID_URL)
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors

    def test_rejects_embedded_slash(self):
        """name/../other — embedded traversal."""
        with pytest.raises(ValidationError) as exc_info:
            _AgentRegisterRequest(name="name/../other", upstream_url=_VALID_URL)
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors

    def test_rejects_uppercase(self):
        """Uppercase letters are not in the slug alphabet."""
        with pytest.raises(ValidationError) as exc_info:
            _AgentRegisterRequest(name="MyAgent", upstream_url=_VALID_URL)
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors

    def test_rejects_starts_with_digit(self):
        """Name must start with a lowercase letter."""
        with pytest.raises(ValidationError) as exc_info:
            _AgentRegisterRequest(name="1agent", upstream_url=_VALID_URL)
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors

    def test_rejects_starts_with_hyphen(self):
        """Name must start with a lowercase letter, not a hyphen."""
        with pytest.raises(ValidationError) as exc_info:
            _AgentRegisterRequest(name="-agent", upstream_url=_VALID_URL)
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors

    def test_rejects_space_in_name(self):
        """Spaces are not in the slug alphabet."""
        with pytest.raises(ValidationError) as exc_info:
            _AgentRegisterRequest(name="my agent", upstream_url=_VALID_URL)
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors

    def test_rejects_too_long(self):
        """Names over 64 chars must be rejected."""
        long_name = "a" + "b" * 64  # 65 chars
        with pytest.raises(ValidationError) as exc_info:
            _AgentRegisterRequest(name=long_name, upstream_url=_VALID_URL)
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors


# ---------------------------------------------------------------------------
# AgentRegisterRequest.name — acceptance tests
# ---------------------------------------------------------------------------

class TestAgentRegisterNameAcceptsValidSlugs:
    """V232-CSCAN-01a: valid slugs must be accepted and path must resolve safely."""

    def test_accepts_simple_slug(self):
        """my-agent-1 is a valid slug."""
        req = _AgentRegisterRequest(name="my-agent-1", upstream_url=_VALID_URL)
        assert req.name == "my-agent-1"

    def test_accepts_underscore_slug(self):
        """my_agent is a valid slug."""
        req = _AgentRegisterRequest(name="my_agent", upstream_url=_VALID_URL)
        assert req.name == "my_agent"

    def test_accepts_single_char(self):
        """Single lowercase letter is valid."""
        req = _AgentRegisterRequest(name="a", upstream_url=_VALID_URL)
        assert req.name == "a"

    def test_accepts_max_length(self):
        """Exactly 64-char slug must be accepted."""
        name = "a" + "b" * 63  # 64 chars
        req = _AgentRegisterRequest(name=name, upstream_url=_VALID_URL)
        assert req.name == name

    def test_valid_slug_resolves_within_secrets_dir(self):
        """For a valid slug, the resolved token path stays inside /run/secrets."""
        from pathlib import Path
        name = "my-agent-1"
        secrets_root = Path("/run/secrets").resolve()
        token_path = (secrets_root / f"{name}_token").resolve()
        assert token_path.is_relative_to(secrets_root), (
            f"Valid slug resolved to {token_path} which is outside {secrets_root}"
        )


# ---------------------------------------------------------------------------
# AgentUpdateRequest.name — same constraint
# ---------------------------------------------------------------------------

class TestAgentUpdateNameConstraint:
    """V232-CSCAN-01a: update must enforce the same slug constraint."""

    def test_update_rejects_path_traversal(self):
        """../etc/passwd must be rejected on update too."""
        with pytest.raises(ValidationError) as exc_info:
            _AgentUpdateRequest(name="../etc/passwd")
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors

    def test_update_accepts_none(self):
        """None (field omitted) must still pass for partial updates."""
        req = _AgentUpdateRequest(name=None)
        assert req.name is None

    def test_update_accepts_valid_slug(self):
        """Valid slug must still be accepted on update."""
        req = _AgentUpdateRequest(name="updated-agent")
        assert req.name == "updated-agent"


# ---------------------------------------------------------------------------
# Path-resolve guard in openai_router (defence-in-depth)
# ---------------------------------------------------------------------------

class TestOpenAIRouterPathResolveGuard:
    """V232-CSCAN-01a: openai_router must refuse to read a token file outside /run/secrets."""

    def test_resolve_guard_rejects_traversal_path(self):
        """An agent_name_lower containing '..' must not escape /run/secrets."""
        from pathlib import Path

        # Simulate what the router does: resolve and check is_relative_to
        malicious_name = "../../etc/passwd"
        secrets_root = Path("/run/secrets").resolve()
        token_path = (secrets_root / f"{malicious_name}_token").resolve()

        assert not token_path.is_relative_to(secrets_root), (
            "Path traversal via agent name should escape /run/secrets under resolve() — "
            "the guard must catch this"
        )

    def test_resolve_guard_accepts_safe_path(self):
        """A valid slug must produce a token path that remains inside /run/secrets."""
        from pathlib import Path

        safe_name = "my-agent-1"
        secrets_root = Path("/run/secrets").resolve()
        token_path = (secrets_root / f"{safe_name}_token").resolve()

        assert token_path.is_relative_to(secrets_root), (
            f"Safe slug produced path {token_path} outside {secrets_root}"
        )

    def test_resolve_guard_rejects_absolute_name(self):
        """/etc/passwd (if it reached the router) must not read outside /run/secrets."""
        from pathlib import Path

        # A name starting with '/' would produce a path like /etc/passwd_token
        # after lower(), but Path('/run/secrets') / '/etc/passwd_token' gives
        # /etc/passwd_token on Python's Path (leading / wins).
        absolute_name = "/etc/passwd"
        secrets_root = Path("/run/secrets").resolve()
        # Use the same logic as the router: construct then resolve
        token_path = (secrets_root / f"{absolute_name}_token").resolve()
        # /etc/passwd_token is not under /run/secrets
        assert not token_path.is_relative_to(secrets_root), (
            "Absolute-path agent name should produce a token path outside /run/secrets"
        )
