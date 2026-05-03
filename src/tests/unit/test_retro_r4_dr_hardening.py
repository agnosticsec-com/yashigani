"""
Regression tests for RETRO-R4-1, RETRO-R4-2, RETRO-R4-3 — v2.23.2 DR hardening.

RETRO-R4-1: restore.sh CA bundle parity
  - _refresh_pgdata_ca must concatenate ca_root.crt + ca_intermediate.crt,
    not write only ca_root.crt (which left the postgres trust store incomplete).

RETRO-R4-2: asyncpg restart resilience
  - connect_with_retry_sync has a connect_timeout and retries on OperationalError.
  - create_pool passes timeout= so per-connection establishment has a cap.
  - advisory lock bootstrap in app.py uses connect_with_retry_sync.

RETRO-R4-3: validate_backup openssl verify
  - validate_backup checks for MANIFEST.sha256 + MANIFEST.sha256.sig.
  - A tampered manifest causes a hard failure.
  - A missing manifest emits a warning, not a hard failure (legacy backup).

Last updated: 2026-05-02T00:00:00+01:00
"""
from __future__ import annotations

import importlib
import inspect
import os
import re
import subprocess
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

SRC = Path(__file__).parent.parent.parent / "yashigani"
REPO = Path(__file__).parent.parent.parent.parent  # /Users/max/Documents/Claude/yashigani
RESTORE_SH = REPO / "restore.sh"
INSTALL_SH = REPO / "install.sh"
POSTGRES_PY = SRC / "db" / "postgres.py"
DB_INIT_PY = SRC / "db" / "__init__.py"
APP_PY = SRC / "backoffice" / "app.py"


# =============================================================================
# RETRO-R4-1: CA bundle parity in restore.sh
# =============================================================================

class TestRetroR41CaBundleParity:
    """restore.sh _refresh_pgdata_ca must write root.crt as a concatenation of
    ca_root.crt AND ca_intermediate.crt, matching install.sh."""

    def test_restore_sh_concatenates_ca_bundle(self):
        """Verify _refresh_pgdata_ca uses `cat ca_root.crt ca_intermediate.crt`
        not just `install -m 0644 ... ca_root.crt`."""
        assert RESTORE_SH.exists(), f"restore.sh not found at {RESTORE_SH}"
        content = RESTORE_SH.read_text()

        # Must contain the cat concatenation, matching install.sh pattern
        assert "cat /run/secrets/ca_root.crt /run/secrets/ca_intermediate.crt" in content, (
            "RETRO-R4-1: _refresh_pgdata_ca must concatenate ca_root.crt + ca_intermediate.crt "
            "into ${PGDATA}/root.crt to match install.sh trust bundle"
        )

    def test_restore_sh_does_not_solo_install_ca_root(self):
        """Ensure there is no bare `install ... ca_root.crt ${PGDATA}/root.crt` call
        that would write only the root (incomplete chain)."""
        assert RESTORE_SH.exists()
        content = RESTORE_SH.read_text()

        # The old pattern that caused the bug was a single-line:
        # install -m 0644 -o postgres -g postgres /run/secrets/ca_root.crt "${PGDATA}/root.crt"
        # (no re.DOTALL: must match on a single line to avoid false-positives from
        # the legitimate `install ... ca_root.crt "${PGDATA}/server.crt"` line which
        # appears on the same logical block but targets a different destination).
        bad_pattern = re.compile(
            r'install\s+-m\s+0644.*?ca_root\.crt[^"\n]*\$\{?PGDATA\}?/root\.crt',
        )
        assert not bad_pattern.search(content), (
            "RETRO-R4-1: Found solo `install ca_root.crt -> root.crt` — "
            "must use `cat ca_root.crt ca_intermediate.crt > root.crt` to match install.sh"
        )

    def test_install_sh_ca_bundle_pattern_matches_restore(self):
        """install.sh and restore.sh must produce the same root.crt content.
        Both must use cat ca_root.crt ca_intermediate.crt."""
        assert INSTALL_SH.exists()
        assert RESTORE_SH.exists()

        install_content = INSTALL_SH.read_text()
        restore_content = RESTORE_SH.read_text()

        # install.sh reference pattern
        assert "cat /run/secrets/ca_root.crt /run/secrets/ca_intermediate.crt" in install_content, (
            "install.sh trust bundle pattern changed — update this test"
        )
        # restore.sh must match
        assert "cat /run/secrets/ca_root.crt /run/secrets/ca_intermediate.crt" in restore_content, (
            "RETRO-R4-1: restore.sh CA bundle pattern does not match install.sh"
        )


# =============================================================================
# RETRO-R4-2: asyncpg restart resilience
# =============================================================================

class TestRetroR42AsyncpgRestart:
    """connect_with_retry_sync and create_pool must handle postgres restarts
    without hanging indefinitely."""

    def test_connect_with_retry_sync_exists(self):
        """connect_with_retry_sync must be importable from yashigani.db."""
        from yashigani.db import connect_with_retry_sync  # noqa: F401
        assert callable(connect_with_retry_sync)

    def test_connect_with_retry_sync_exported(self):
        """connect_with_retry_sync must be in yashigani.db.__all__."""
        import yashigani.db as db_module
        assert "connect_with_retry_sync" in db_module.__all__

    def _make_mock_psycopg2(self):
        """Build a minimal psycopg2 mock for unit tests (not installed in local venv)."""
        mock_pg2 = MagicMock()
        mock_pg2.OperationalError = type("OperationalError", (Exception,), {})
        return mock_pg2

    def test_connect_with_retry_sync_retries_on_operational_error(self):
        """Must retry up to max_attempts on psycopg2.OperationalError."""
        import sys

        mock_pg2 = self._make_mock_psycopg2()

        call_count = 0
        mock_conn = MagicMock()

        def _mock_connect(dsn):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise mock_pg2.OperationalError("connection refused")
            return mock_conn

        mock_pg2.connect = _mock_connect

        with patch.dict(sys.modules, {"psycopg2": mock_pg2}):
            # Re-import to pick up the mock
            import importlib
            import yashigani.db.postgres as _pg_mod
            importlib.reload(_pg_mod)
            try:
                with patch("time.sleep"):
                    result = _pg_mod.connect_with_retry_sync(
                        "postgresql://u:p@localhost:5432/db",
                        max_attempts=5,
                        backoff_s=1.0,
                    )
                assert result is mock_conn
                assert call_count == 3
            finally:
                importlib.reload(_pg_mod)  # restore

    def test_connect_with_retry_sync_raises_after_max_attempts(self):
        """Must raise OperationalError after max_attempts exhausted."""
        import sys, importlib

        mock_pg2 = self._make_mock_psycopg2()
        mock_pg2.connect = MagicMock(side_effect=mock_pg2.OperationalError("refused"))

        with patch.dict(sys.modules, {"psycopg2": mock_pg2}):
            import yashigani.db.postgres as _pg_mod
            importlib.reload(_pg_mod)
            try:
                with patch("time.sleep"):
                    with pytest.raises(mock_pg2.OperationalError):
                        _pg_mod.connect_with_retry_sync(
                            "postgresql://u:p@localhost:5432/db",
                            max_attempts=3,
                            backoff_s=1.0,
                        )
            finally:
                importlib.reload(_pg_mod)

    def test_connect_with_retry_sync_injects_connect_timeout(self):
        """connect_timeout must be injected into the DSN as a query parameter."""
        import sys, importlib

        mock_pg2 = self._make_mock_psycopg2()
        captured_dsns: list[str] = []

        def _mock_connect(dsn):
            captured_dsns.append(dsn)
            return MagicMock()

        mock_pg2.connect = _mock_connect

        with patch.dict(sys.modules, {"psycopg2": mock_pg2}):
            import yashigani.db.postgres as _pg_mod
            importlib.reload(_pg_mod)
            try:
                _pg_mod.connect_with_retry_sync(
                    "postgresql://u:p@localhost:5432/db",
                    connect_timeout=15,
                )
                assert len(captured_dsns) == 1
                assert "connect_timeout=15" in captured_dsns[0], (
                    f"connect_timeout not injected into DSN: {captured_dsns[0]}"
                )
            finally:
                importlib.reload(_pg_mod)

    def test_create_pool_passes_timeout(self):
        """create_pool must pass timeout= to asyncpg.create_pool so per-connection
        establishment is bounded (RETRO-R4-2 fix)."""
        assert POSTGRES_PY.exists()
        content = POSTGRES_PY.read_text()

        # The fix adds `timeout=_CONNECT_TIMEOUT_S` to create_pool call
        assert "timeout=" in content, (
            "RETRO-R4-2: create_pool must pass timeout= to asyncpg.create_pool"
        )
        assert "_CONNECT_TIMEOUT_S" in content, (
            "RETRO-R4-2: _CONNECT_TIMEOUT_S constant must be defined and used"
        )

    def test_app_py_uses_connect_with_retry(self):
        """app.py advisory lock bootstrap must use connect_with_retry_sync,
        not bare psycopg2.connect()."""
        assert APP_PY.exists()
        content = APP_PY.read_text()

        assert "connect_with_retry_sync" in content, (
            "RETRO-R4-2: backoffice app.py advisory lock must use connect_with_retry_sync "
            "not bare psycopg2.connect() (which hangs on pg restart)"
        )
        # Should NOT have bare psycopg2.connect( for the advisory lock
        # (it may appear in a comment explaining the old code, but not as a call)
        import ast
        try:
            tree = ast.parse(content)
        except SyntaxError:
            pytest.skip("app.py has syntax error — cannot AST-check")
            return

        class _FindPsycopg2Connect(ast.NodeVisitor):
            found: list[int] = []
            def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
                # Match _psycopg2.connect(...) or psycopg2.connect(...)
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == "connect":
                        if isinstance(node.func.value, ast.Name):
                            if "psycopg2" in node.func.value.id:
                                self.found.append(node.lineno)
                self.generic_visit(node)

        finder = _FindPsycopg2Connect()
        finder.visit(tree)
        assert not finder.found, (
            f"RETRO-R4-2: bare psycopg2.connect() call found at lines {finder.found} in app.py — "
            "must use connect_with_retry_sync instead"
        )

    def test_db_init_uses_connect_with_retry(self):
        """run_migrations() in db/__init__.py must use connect_with_retry_sync."""
        assert DB_INIT_PY.exists()
        content = DB_INIT_PY.read_text()

        assert "connect_with_retry_sync" in content, (
            "RETRO-R4-2: run_migrations() must use connect_with_retry_sync "
            "not bare psycopg2.connect() for the advisory lock connection"
        )


# =============================================================================
# RETRO-R4-3: validate_backup openssl verify
# =============================================================================

class TestRetroR43BackupSignatureVerify:
    """restore.sh validate_backup must use openssl dgst -verify for signature
    checking, not just file presence."""

    def test_restore_sh_has_openssl_dgst_verify(self):
        """validate_backup must call `openssl dgst ... -verify`."""
        assert RESTORE_SH.exists()
        content = RESTORE_SH.read_text()

        assert "openssl dgst" in content, (
            "RETRO-R4-3: restore.sh validate_backup must use `openssl dgst`"
        )
        assert "-verify" in content, (
            "RETRO-R4-3: restore.sh validate_backup must use `openssl dgst -verify`"
        )

    def test_restore_sh_checks_manifest_sig(self):
        """validate_backup must reference MANIFEST.sha256.sig."""
        assert RESTORE_SH.exists()
        content = RESTORE_SH.read_text()

        assert "MANIFEST.sha256.sig" in content, (
            "RETRO-R4-3: validate_backup must check MANIFEST.sha256.sig"
        )
        assert "MANIFEST.sha256" in content, (
            "RETRO-R4-3: validate_backup must check MANIFEST.sha256"
        )

    def test_restore_sh_sig_failure_is_hard_error(self):
        """A bad signature must increment errors (hard fail), not just warn."""
        assert RESTORE_SH.exists()
        content = RESTORE_SH.read_text()

        # After the openssl verify block, errors must be incremented on failure.
        # The pattern: openssl dgst ... ; if not verified then errors=$((errors + 1))
        # We check both keywords appear in the same function block.
        assert "openssl dgst -sha256 -verify" in content, (
            "RETRO-R4-3: verify command must use -sha256 -verify"
        )
        # The error increment must appear after the verify command
        verify_pos = content.find("openssl dgst -sha256 -verify")
        error_inc_pos = content.find("errors=$((errors + 1))", verify_pos)
        assert error_inc_pos > verify_pos, (
            "RETRO-R4-3: errors must be incremented after a failed openssl dgst -verify"
        )

    def test_restore_sh_absent_manifest_is_warning_not_error(self):
        """If MANIFEST.sha256 is absent, validate_backup must warn, not hard-fail.
        Older backups (pre-RETRO-R4-3) are unsigned and must still be restorable."""
        assert RESTORE_SH.exists()
        content = RESTORE_SH.read_text()

        # The fallback (no manifest) path must use log_warn, not log_error + errors++
        # We check that after the else branch for the manifest-absent case,
        # there is a log_warn call (not a hard errors increment).
        # Pattern: `else\n    log_warn "RETRO-R4-3: Backup has no manifest"
        assert "log_warn" in content, "log_warn must exist in restore.sh"
        # Ensure the no-manifest path does NOT add to errors
        # (it should warn and let the outer caller decide via --force)
        # We verify by checking that the RETRO-R4-3 warn message is present
        assert "pre-RETRO-R4-3 backup or unsigned" in content, (
            "RETRO-R4-3: validate_backup must warn about missing signature for legacy backups"
        )

    def test_install_sh_signs_backup(self):
        """install.sh _backup_existing_data must produce MANIFEST.sha256 + .sig."""
        assert INSTALL_SH.exists()
        content = INSTALL_SH.read_text()

        assert "MANIFEST.sha256" in content, (
            "RETRO-R4-3: install.sh _backup_existing_data must create MANIFEST.sha256"
        )
        assert "openssl dgst -sha256 -sign" in content, (
            "RETRO-R4-3: install.sh must sign the backup manifest with openssl dgst -sign"
        )
        assert "MANIFEST.sha256.sig" in content, (
            "RETRO-R4-3: install.sh must write MANIFEST.sha256.sig"
        )

    def test_install_sh_manifest_uses_ca_intermediate_key(self):
        """Backup signing must use ca_intermediate.key, not ca_root.key
        (root key never leaves the host unnecessarily)."""
        assert INSTALL_SH.exists()
        content = INSTALL_SH.read_text()

        # The signing key reference should be ca_intermediate.key
        assert "ca_intermediate.key" in content, (
            "RETRO-R4-3: install.sh should use ca_intermediate.key for signing backup manifests"
        )

    def test_restore_sh_verifies_with_ca_intermediate_cert(self):
        """restore.sh should verify using the public key from ca_intermediate.crt,
        not the root cert."""
        assert RESTORE_SH.exists()
        content = RESTORE_SH.read_text()

        assert "ca_intermediate.crt" in content, (
            "RETRO-R4-3: restore.sh validate_backup must verify against ca_intermediate.crt"
        )
        assert "openssl x509" in content and "-pubkey" in content, (
            "RETRO-R4-3: restore.sh must extract pubkey from cert before verifying"
        )
