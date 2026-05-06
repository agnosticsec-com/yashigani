"""
Unit tests for /admin/backup/status and /admin/backup/verify endpoints.

Coverage:
- Empty / missing backup directory → empty state (not 500)
- Install vs update_preflight type classification
- All three MANIFEST states: signed, unsigned, corrupt
- Path traversal rejection (CWE-22)
- Backup not found → 404
- Verify unsigned → ok=True
- Verify signed → pass (checksums match)
- Verify signed → fail (checksum mismatch + mismatches list populated)
- CWE-200: backups_dir is always "backups" (relative), never absolute path

Last updated: 2026-05-06
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import yashigani.backoffice.routes.backup as backup_mod
from yashigani.backoffice.routes.backup import router


# ---------------------------------------------------------------------------
# App fixture — minimal FastAPI with auth bypass
# ---------------------------------------------------------------------------

def _make_app() -> FastAPI:
    """Minimal test app with auth bypassed via override."""
    from fastapi import Depends
    from yashigani.backoffice.middleware import require_admin_session

    app = FastAPI()

    class _FakeSession:
        account_id = "test-admin"
        account_tier = "admin"

    async def _fake_admin_session():
        return _FakeSession()

    app.dependency_overrides[require_admin_session] = _fake_admin_session
    app.include_router(router)
    return app


@pytest_asyncio.fixture
async def client(tmp_path: Path, monkeypatch) -> AsyncGenerator[AsyncClient, None]:
    """HTTP client with BACKUPS_DIR pointed at tmp_path."""
    monkeypatch.setattr(backup_mod, "_BACKUPS_DIR", tmp_path)
    app = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_manifest(backup_dir: Path, entries: dict[str, bytes]) -> None:
    """Write a valid MANIFEST.sha256 + MANIFEST.sha256.sig (stub sig) for given files."""
    lines = []
    for relpath, content in entries.items():
        lines.append(f"{_sha256_hex(content)}  {relpath}")
    (backup_dir / "MANIFEST.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
    # Stub sig — present but not cryptographically verified in Python-level unit tests
    (backup_dir / "MANIFEST.sha256.sig").write_bytes(b"stub-sig")


# ---------------------------------------------------------------------------
# Tests: /admin/backup/status
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_status_empty_dir(client: AsyncClient, tmp_path: Path):
    """Empty directory → backups=[], latest=null, no 500."""
    r = await client.get("/admin/backup/status")
    assert r.status_code == 200
    data = r.json()
    assert data["backups"] == []
    assert data["latest"] is None


@pytest.mark.asyncio
async def test_status_missing_dir(monkeypatch, tmp_path: Path):
    """Non-existent BACKUPS_DIR → empty state, not 500."""
    monkeypatch.setattr(backup_mod, "_BACKUPS_DIR", tmp_path / "does_not_exist")
    app = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/admin/backup/status")
    assert r.status_code == 200
    data = r.json()
    assert data["backups"] == []
    assert data["latest"] is None


@pytest.mark.asyncio
async def test_status_install_type(client: AsyncClient, tmp_path: Path):
    """Dir named 'YYYYMMDD_HHMMSS' → type='install'."""
    backup_dir = tmp_path / "20260502_230214"
    backup_dir.mkdir()
    (backup_dir / "postgres_dump.sql").write_bytes(b"-- dump")
    r = await client.get("/admin/backup/status")
    assert r.status_code == 200
    data = r.json()
    assert len(data["backups"]) == 1
    assert data["backups"][0]["type"] == "install"
    assert data["backups"][0]["name"] == "20260502_230214"


@pytest.mark.asyncio
async def test_status_update_preflight_type(client: AsyncClient, tmp_path: Path):
    """Dir named 'pre-update-...' → type='update_preflight'."""
    backup_dir = tmp_path / "pre-update-v2.23.1-20260501-120000"
    backup_dir.mkdir()
    (backup_dir / "config.yml").write_bytes(b"key: value")
    r = await client.get("/admin/backup/status")
    assert r.status_code == 200
    data = r.json()
    assert len(data["backups"]) == 1
    assert data["backups"][0]["type"] == "update_preflight"


@pytest.mark.asyncio
async def test_status_manifest_signed(client: AsyncClient, tmp_path: Path):
    """Both MANIFEST files present → manifest_state='signed'."""
    backup_dir = tmp_path / "20260502_000001"
    backup_dir.mkdir()
    content = b"data content"
    (backup_dir / "file.dat").write_bytes(content)
    _write_manifest(backup_dir, {"file.dat": content})
    r = await client.get("/admin/backup/status")
    assert r.status_code == 200
    assert r.json()["backups"][0]["manifest_state"] == "signed"


@pytest.mark.asyncio
async def test_status_manifest_unsigned(client: AsyncClient, tmp_path: Path):
    """Neither MANIFEST file present → manifest_state='unsigned'."""
    backup_dir = tmp_path / "20260501_000001"
    backup_dir.mkdir()
    (backup_dir / "secrets" ).mkdir()
    (backup_dir / "secrets" / "admin_password").write_bytes(b"secret")
    r = await client.get("/admin/backup/status")
    assert r.status_code == 200
    assert r.json()["backups"][0]["manifest_state"] == "unsigned"


@pytest.mark.asyncio
async def test_status_manifest_corrupt(client: AsyncClient, tmp_path: Path):
    """Only MANIFEST.sha256 present (no .sig) → manifest_state='corrupt'."""
    backup_dir = tmp_path / "20260503_000001"
    backup_dir.mkdir()
    (backup_dir / "file.dat").write_bytes(b"x")
    (backup_dir / "MANIFEST.sha256").write_text("abc123  file.dat\n")
    # Deliberately NO .sig file
    r = await client.get("/admin/backup/status")
    assert r.status_code == 200
    assert r.json()["backups"][0]["manifest_state"] == "corrupt"


# ---------------------------------------------------------------------------
# Tests: /admin/backup/verify
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_verify_path_traversal(client: AsyncClient):
    """backup_name containing '..' → 422."""
    r = await client.post("/admin/backup/verify", json={"backup_name": "../etc/passwd"})
    assert r.status_code == 422
    assert r.json()["detail"]["error"] in ("invalid_backup_name", "path_traversal_rejected")


@pytest.mark.asyncio
async def test_verify_not_found(client: AsyncClient):
    """Valid name but dir doesn't exist → 404."""
    r = await client.post("/admin/backup/verify", json={"backup_name": "nonexistent_backup"})
    assert r.status_code == 404
    assert r.json()["detail"]["error"] == "backup_not_found"


@pytest.mark.asyncio
async def test_verify_unsigned(client: AsyncClient, tmp_path: Path):
    """Backup with no MANIFEST → ok=True, manifest_state='unsigned'."""
    backup_dir = tmp_path / "20260502_unsigned"
    backup_dir.mkdir()
    (backup_dir / "postgres_dump.sql").write_bytes(b"-- dump data")
    r = await client.post("/admin/backup/verify", json={"backup_name": "20260502_unsigned"})
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert data["manifest_state"] == "unsigned"
    assert "postgres_dump.sql" in data["computed_checksums"]
    assert data["recorded_checksums"] is None
    assert data["mismatches"] == []


@pytest.mark.asyncio
async def test_verify_signed_pass(client: AsyncClient, tmp_path: Path):
    """Backup with valid MANIFEST → ok=True, manifest_state='signed', no mismatches."""
    backup_dir = tmp_path / "20260502_signed_pass"
    backup_dir.mkdir()
    content = b"important data"
    (backup_dir / "postgres_dump.sql").write_bytes(content)
    _write_manifest(backup_dir, {"postgres_dump.sql": content})
    r = await client.post("/admin/backup/verify", json={"backup_name": "20260502_signed_pass"})
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert data["manifest_state"] == "signed"
    assert data["mismatches"] == []
    assert "postgres_dump.sql" in data["computed_checksums"]
    assert "postgres_dump.sql" in data["recorded_checksums"]


@pytest.mark.asyncio
async def test_verify_signed_fail(client: AsyncClient, tmp_path: Path):
    """Backup with MANIFEST but tampered file → ok=False, mismatches populated."""
    backup_dir = tmp_path / "20260502_signed_fail"
    backup_dir.mkdir()
    original = b"original content"
    tampered = b"tampered content"
    (backup_dir / "postgres_dump.sql").write_bytes(tampered)  # write tampered content
    _write_manifest(backup_dir, {"postgres_dump.sql": original})  # manifest has original hash
    r = await client.post("/admin/backup/verify", json={"backup_name": "20260502_signed_fail"})
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert data["manifest_state"] == "signed"
    assert len(data["mismatches"]) >= 1
    mismatch = data["mismatches"][0]
    assert mismatch["file"] == "postgres_dump.sql"
    assert mismatch["recorded"] == _sha256_hex(original)
    assert mismatch["computed"] == _sha256_hex(tampered)


@pytest.mark.asyncio
async def test_status_no_absolute_path(client: AsyncClient, tmp_path: Path):
    """CWE-200: backups_dir in response is 'backups' (relative), never absolute."""
    # Create one backup dir so it's not degenerate
    backup_dir = tmp_path / "20260502_cwe200"
    backup_dir.mkdir()
    (backup_dir / "file.dat").write_bytes(b"data")
    r = await client.get("/admin/backup/status")
    assert r.status_code == 200
    data = r.json()
    # Must be relative sentinel, never the real tmp_path
    assert data["backups_dir"] == "backups"
    assert str(tmp_path) not in data["backups_dir"]
    # Also check no file entry leaks an absolute path
    for entry in data["backups"]:
        for f in entry.get("files", []):
            assert not f.startswith("/")
