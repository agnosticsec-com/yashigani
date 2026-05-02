"""Unit tests for yashigani.auth.spiffe — SPIFFE URI ACL gate.

Last updated: 2026-04-27T00:00:00+01:00

Closes EX-231-08 per zero-trust directive. The gate protects
/internal/metrics and any other endpoint added to the endpoint_acls block
in service_identities.yaml. These tests do not spin up FastAPI — they call
the dependency directly with a fake Request to keep the fixture surface
minimal and avoid depending on httpx/TestClient for the gate semantics.

V8.3.3 TTL tests (tests 8–13) added 2026-04-27.
Closes: ASVS v5 V8.3.3 — SPIFFE ACL TTL refresh + retain-on-parse-failure.
Stage B report §8.1: /Users/max/Documents/Claude/Internal/ACS/v3/asvs-stage-b-class3-2026-04-28.md
"""
from __future__ import annotations

import logging

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
_ALLOWED_NEW = "spiffe://yashigani.internal/prometheus-v2"


@pytest.fixture(autouse=True)
def _reset_cache():
    _reset_cache_for_tests()
    yield
    _reset_cache_for_tests()


def _install_acl(monkeypatch, acls):
    monkeypatch.setattr(_spiffe_mod, "_load_acls", lambda: acls)


# ---------------------------------------------------------------------------
# Existing gate behaviour tests (tests 1–7)
# ---------------------------------------------------------------------------

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
    """Initial load from missing manifest → empty ACL → every gated path 403."""
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
    """Initial load from malformed YAML → empty ACL → every gated path 403."""
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


# ---------------------------------------------------------------------------
# V8.3.3 TTL / retain-on-parse-failure tests (tests 8–13)
# ---------------------------------------------------------------------------

def _make_good_manifest(path, spiffe_id=_ALLOWED):
    """Write a minimal valid service_identities.yaml to *path*.

    Includes the fields required by load_manifest: schema_version=1,
    at least one service entry, cert_policy, ca_source, and endpoint_acls.
    """
    path.write_text(
        "schema_version: 1\n"
        "services:\n"
        "  - name: prometheus\n"
        "    dns_sans: []\n"
        "    purpose: scrape\n"
        "    bootstrap_token_sha256: ''\n"
        f"    spiffe_id: '{spiffe_id}'\n"
        "cert_policy:\n"
        "  root_lifetime_years_min: 5\n"
        "  root_lifetime_years_max: 20\n"
        "  root_lifetime_years_default: 10\n"
        "  root_rotation_requires_manual_confirmation: true\n"
        "  intermediate_lifetime_days_min: 180\n"
        "  intermediate_lifetime_days_max: 730\n"
        "  intermediate_lifetime_days_default: 365\n"
        "  leaf_lifetime_days_min: 1\n"
        "  leaf_lifetime_days_max: 365\n"
        "  leaf_lifetime_days_default: 90\n"
        "  renewal_threshold: 0.2\n"
        "ca_source:\n"
        "  mode: yashigani_generated\n"
        "endpoint_acls:\n"
        f"  '{_PATH}':\n"
        f"    allowed_spiffe_ids:\n"
        f"      - '{spiffe_id}'\n"
    )


@pytest.mark.asyncio
async def test_ttl_cache_loads_on_first_call(monkeypatch, tmp_path):
    """Test 8 — ACL loads on first gate call and the allowed ID passes."""
    manifest = tmp_path / "identities.yaml"
    _make_good_manifest(manifest)
    monkeypatch.setenv("YASHIGANI_SERVICE_MANIFEST_PATH", str(manifest))
    monkeypatch.setenv("YASHIGANI_SPIFFE_ACL_TTL_SECONDS", "60")
    _reset_cache_for_tests()

    dep = require_spiffe_id(_PATH)
    result = await dep(_FakeRequest({"X-SPIFFE-ID": _ALLOWED}))
    assert result == _ALLOWED


@pytest.mark.asyncio
async def test_within_ttl_uses_old_acl(monkeypatch, tmp_path):
    """Test 9 — Manifest updated but gate called within TTL → OLD ACL still used."""
    manifest = tmp_path / "identities.yaml"
    _make_good_manifest(manifest)
    monkeypatch.setenv("YASHIGANI_SERVICE_MANIFEST_PATH", str(manifest))
    monkeypatch.setenv("YASHIGANI_SPIFFE_ACL_TTL_SECONDS", "60")
    _reset_cache_for_tests()

    dep = require_spiffe_id(_PATH)
    # Warm the cache.
    assert await dep(_FakeRequest({"X-SPIFFE-ID": _ALLOWED})) == _ALLOWED

    # Update manifest to only allow a NEW id.
    _make_good_manifest(manifest, spiffe_id=_ALLOWED_NEW)

    # Call within TTL — old ACL still applies; old ID still passes.
    assert await dep(_FakeRequest({"X-SPIFFE-ID": _ALLOWED})) == _ALLOWED

    # And the new id should be rejected (not yet loaded).
    with pytest.raises(HTTPException) as exc:
        await dep(_FakeRequest({"X-SPIFFE-ID": _ALLOWED_NEW}))
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_past_ttl_uses_new_acl(monkeypatch, tmp_path):
    """Test 10 — Manifest updated; time advances past TTL → next call reloads."""
    manifest = tmp_path / "identities.yaml"
    _make_good_manifest(manifest)
    monkeypatch.setenv("YASHIGANI_SERVICE_MANIFEST_PATH", str(manifest))
    monkeypatch.setenv("YASHIGANI_SPIFFE_ACL_TTL_SECONDS", "60")
    _reset_cache_for_tests()

    dep = require_spiffe_id(_PATH)
    # Warm cache with OLD id.
    assert await dep(_FakeRequest({"X-SPIFFE-ID": _ALLOWED})) == _ALLOWED

    # Update manifest to only allow NEW id.
    _make_good_manifest(manifest, spiffe_id=_ALLOWED_NEW)

    # Simulate clock advancing past TTL by back-dating the cached timestamp.
    with _spiffe_mod._CACHE_LOCK:
        loaded_at, acls = _spiffe_mod._CACHE
        _spiffe_mod._CACHE = (loaded_at - 120, acls)  # -120s → definitely expired

    # Next gate call should reload; old ID is now rejected.
    with pytest.raises(HTTPException) as exc:
        await dep(_FakeRequest({"X-SPIFFE-ID": _ALLOWED}))
    assert exc.value.status_code == 403
    assert exc.value.detail == "spiffe_id_not_allowed"

    # And new ID is now accepted.
    assert await dep(_FakeRequest({"X-SPIFFE-ID": _ALLOWED_NEW})) == _ALLOWED_NEW


@pytest.mark.asyncio
async def test_corrupt_manifest_retains_cache_and_logs_critical(
    monkeypatch, tmp_path, caplog
):
    """Test 11 — V8.3.3 retain-on-parse-failure.

    After a good load, a corrupt manifest on TTL refresh must:
    - NOT 403 requests (previous ACL retained).
    - Log at CRITICAL level.
    """
    manifest = tmp_path / "identities.yaml"
    _make_good_manifest(manifest)
    monkeypatch.setenv("YASHIGANI_SERVICE_MANIFEST_PATH", str(manifest))
    monkeypatch.setenv("YASHIGANI_SPIFFE_ACL_TTL_SECONDS", "60")
    _reset_cache_for_tests()

    dep = require_spiffe_id(_PATH)
    # Warm cache successfully.
    assert await dep(_FakeRequest({"X-SPIFFE-ID": _ALLOWED})) == _ALLOWED

    # Corrupt the manifest.
    manifest.write_text(":::: not valid yaml at all ::::")

    # Expire the cache.
    with _spiffe_mod._CACHE_LOCK:
        loaded_at, acls = _spiffe_mod._CACHE
        _spiffe_mod._CACHE = (loaded_at - 120, acls)

    # Gate call triggers reload attempt — must fail gracefully and retain old ACL.
    with caplog.at_level(logging.CRITICAL, logger="yashigani.auth.spiffe"):
        result = await dep(_FakeRequest({"X-SPIFFE-ID": _ALLOWED}))

    assert result == _ALLOWED, "retain-on-parse-failure: gate must stay open for known-good IDs"
    assert any("retain" in r.message.lower() for r in caplog.records if r.levelno >= logging.CRITICAL), (
        "CRITICAL log must mention retain-on-parse-failure"
    )


@pytest.mark.asyncio
async def test_corrupt_then_restore_reloads_fresh_acl(monkeypatch, tmp_path):
    """Test 12 — Restore valid manifest after a failed TTL refresh → next call reloads fresh ACL."""
    manifest = tmp_path / "identities.yaml"
    _make_good_manifest(manifest)
    monkeypatch.setenv("YASHIGANI_SERVICE_MANIFEST_PATH", str(manifest))
    monkeypatch.setenv("YASHIGANI_SPIFFE_ACL_TTL_SECONDS", "60")
    _reset_cache_for_tests()

    dep = require_spiffe_id(_PATH)
    # Warm cache.
    assert await dep(_FakeRequest({"X-SPIFFE-ID": _ALLOWED})) == _ALLOWED

    # Corrupt + expire.
    manifest.write_text(":::: bad ::::")
    with _spiffe_mod._CACHE_LOCK:
        loaded_at, acls = _spiffe_mod._CACHE
        _spiffe_mod._CACHE = (loaded_at - 120, acls)

    # Call — retain old cache (corrupt reload).
    result = await dep(_FakeRequest({"X-SPIFFE-ID": _ALLOWED}))
    assert result == _ALLOWED

    # Restore valid manifest with new SPIFFE ID only.
    _make_good_manifest(manifest, spiffe_id=_ALLOWED_NEW)

    # Expire again.
    with _spiffe_mod._CACHE_LOCK:
        loaded_at, acls = _spiffe_mod._CACHE
        _spiffe_mod._CACHE = (loaded_at - 120, acls)

    # Next call reloads fresh ACL — old ID rejected, new ID accepted.
    with pytest.raises(HTTPException) as exc:
        await dep(_FakeRequest({"X-SPIFFE-ID": _ALLOWED}))
    assert exc.value.status_code == 403

    assert await dep(_FakeRequest({"X-SPIFFE-ID": _ALLOWED_NEW})) == _ALLOWED_NEW


@pytest.mark.asyncio
async def test_ttl_env_var_override(monkeypatch, tmp_path):
    """Test 13 — YASHIGANI_SPIFFE_ACL_TTL_SECONDS=10 causes refresh after 10s."""
    manifest = tmp_path / "identities.yaml"
    _make_good_manifest(manifest)
    monkeypatch.setenv("YASHIGANI_SERVICE_MANIFEST_PATH", str(manifest))
    monkeypatch.setenv("YASHIGANI_SPIFFE_ACL_TTL_SECONDS", "10")
    _reset_cache_for_tests()

    dep = require_spiffe_id(_PATH)
    # Warm cache.
    assert await dep(_FakeRequest({"X-SPIFFE-ID": _ALLOWED})) == _ALLOWED

    # Update manifest with new ID.
    _make_good_manifest(manifest, spiffe_id=_ALLOWED_NEW)

    # Back-date by 11s — past the 10s TTL.
    with _spiffe_mod._CACHE_LOCK:
        loaded_at, acls = _spiffe_mod._CACHE
        _spiffe_mod._CACHE = (loaded_at - 11, acls)

    # Should reload — old ID rejected.
    with pytest.raises(HTTPException) as exc:
        await dep(_FakeRequest({"X-SPIFFE-ID": _ALLOWED}))
    assert exc.value.status_code == 403

    # New ID accepted.
    assert await dep(_FakeRequest({"X-SPIFFE-ID": _ALLOWED_NEW})) == _ALLOWED_NEW
