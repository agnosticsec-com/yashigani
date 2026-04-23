"""Unit tests for yashigani.auth.spiffe — SPIFFE URI ACL gate.

Last updated: 2026-04-23T23:32:19+01:00

Closes EX-231-08 per zero-trust directive. The gate protects
/internal/metrics and any other endpoint added to the endpoint_acls block
in service_identities.yaml. These tests do not spin up FastAPI — they call
the dependency directly with a fake Request to keep the fixture surface
minimal and avoid depending on httpx/TestClient for the gate semantics.
"""
from __future__ import annotations

import pytest

from fastapi import HTTPException

from yashigani.auth.spiffe import _reset_cache_for_tests, require_spiffe_id
from yashigani.auth import spiffe as _spiffe_mod


class _FakeHeaders:
    """Case-insensitive header mapping matching FastAPI's .headers interface."""

    def __init__(self, initial: dict[str, str] | None = None):
        self._h = {k.lower(): v for k, v in (initial or {}).items()}

    def get(self, key: str, default=None):
        return self._h.get(key.lower(), default)


class _FakeRequest:
    def __init__(self, headers: dict[str, str] | None = None):
        self.headers = _FakeHeaders(headers)


_PATH = "/internal/metrics"
_ALLOWED = "spiffe://yashigani.internal/prometheus"


@pytest.fixture(autouse=True)
def _reset_cache():
    _reset_cache_for_tests()
    yield
    _reset_cache_for_tests()


def _install_acl(monkeypatch, acls):
    monkeypatch.setattr(_spiffe_mod, "_load_acls", lambda: acls)


@pytest.mark.asyncio
async def test_missing_header_returns_401(monkeypatch):
    _install_acl(monkeypatch, {_PATH: frozenset({_ALLOWED})})
    dep = require_spiffe_id(_PATH)
    with pytest.raises(HTTPException) as exc:
        await dep(_FakeRequest())
    assert exc.value.status_code == 401
    assert exc.value.detail == "no_spiffe_id"


@pytest.mark.asyncio
async def test_disallowed_spiffe_returns_403(monkeypatch):
    _install_acl(monkeypatch, {_PATH: frozenset({_ALLOWED})})
    dep = require_spiffe_id(_PATH)
    with pytest.raises(HTTPException) as exc:
        await dep(
            _FakeRequest({"X-SPIFFE-ID": "spiffe://yashigani.internal/rogue"})
        )
    assert exc.value.status_code == 403
    assert exc.value.detail == "spiffe_id_not_allowed"


@pytest.mark.asyncio
async def test_allowed_spiffe_returns_id(monkeypatch):
    _install_acl(monkeypatch, {_PATH: frozenset({_ALLOWED})})
    dep = require_spiffe_id(_PATH)
    result = await dep(_FakeRequest({"X-SPIFFE-ID": _ALLOWED}))
    assert result == _ALLOWED


@pytest.mark.asyncio
async def test_no_acl_entry_for_path_returns_403(monkeypatch):
    # Empty ACL table — every gated path must 403 by default.
    _install_acl(monkeypatch, {})
    dep = require_spiffe_id(_PATH)
    with pytest.raises(HTTPException) as exc:
        await dep(_FakeRequest({"X-SPIFFE-ID": _ALLOWED}))
    assert exc.value.status_code == 403
    assert exc.value.detail == "no_acl_for_path"


@pytest.mark.asyncio
async def test_fail_closed_when_manifest_missing(monkeypatch, tmp_path):
    """If the manifest is missing or malformed, the cache becomes empty
    and every gated endpoint returns 403 (default-deny)."""
    monkeypatch.setenv(
        "YASHIGANI_SERVICE_MANIFEST_PATH", str(tmp_path / "does_not_exist.yaml")
    )
    _reset_cache_for_tests()
    dep = require_spiffe_id(_PATH)
    with pytest.raises(HTTPException) as exc:
        await dep(_FakeRequest({"X-SPIFFE-ID": _ALLOWED}))
    assert exc.value.status_code == 403
    assert exc.value.detail == "no_acl_for_path"


@pytest.mark.asyncio
async def test_fail_closed_on_malformed_yaml(monkeypatch, tmp_path):
    """Malformed YAML must also collapse to an empty ACL set, not raise."""
    bogus = tmp_path / "bogus.yaml"
    bogus.write_text(":::: not yaml ::::")
    monkeypatch.setenv("YASHIGANI_SERVICE_MANIFEST_PATH", str(bogus))
    _reset_cache_for_tests()
    dep = require_spiffe_id(_PATH)
    with pytest.raises(HTTPException) as exc:
        await dep(_FakeRequest({"X-SPIFFE-ID": _ALLOWED}))
    assert exc.value.status_code == 403
    assert exc.value.detail == "no_acl_for_path"


@pytest.mark.asyncio
async def test_header_lookup_is_case_insensitive(monkeypatch):
    """Starlette lower-cases incoming header names; the gate must not
    depend on the caller's casing."""
    _install_acl(monkeypatch, {_PATH: frozenset({_ALLOWED})})
    dep = require_spiffe_id(_PATH)
    # Uppercase — must still succeed.
    assert await dep(_FakeRequest({"X-SPIFFE-ID": _ALLOWED})) == _ALLOWED
    # Lowercase — must still succeed.
    assert await dep(_FakeRequest({"x-spiffe-id": _ALLOWED})) == _ALLOWED
