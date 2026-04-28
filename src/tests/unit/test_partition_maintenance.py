"""
Unit tests for scripts/partition_maintenance.py — YSG-RISK-001 (CWE-89).

Verifies that:
  - _quote_ident rejects maliciously-crafted partition names before any SQL
    statement is composed.
  - Normal partition names (the only ones the script ever generates) pass.
  - The CREATE TABLE DDL no longer contains any f-string interpolation of
    user-derived values; instead $1/$2 bind parameters carry the date literals.

These tests do NOT require a live database connection.
"""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Import the script module without executing main()
# ---------------------------------------------------------------------------

# src/tests/unit/ -> src/ -> repo root is at parents[3]
_SCRIPT_PATH = Path(__file__).parents[3] / "scripts" / "partition_maintenance.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "partition_maintenance", _SCRIPT_PATH
    )
    mod = importlib.util.module_from_spec(spec)
    # Provide a stub asyncpg so the import doesn't fail at module level
    # (asyncpg is imported lazily inside ensure_partitions, not at module top).
    spec.loader.exec_module(mod)
    return mod


_pm = _load_module()


# ---------------------------------------------------------------------------
# _quote_ident tests
# ---------------------------------------------------------------------------

class TestQuoteIdent:
    def test_normal_table_name(self):
        """Standard audit_events name must pass."""
        assert _pm._quote_ident("audit_events") == '"audit_events"'

    def test_normal_partition_name(self):
        """A partition name like audit_events_2026_05 must pass."""
        result = _pm._quote_ident("audit_events_2026_05")
        assert result == '"audit_events_2026_05"'

    def test_all_partitioned_tables(self):
        """Every table in _PARTITIONED_TABLES must be quotable."""
        for table in _pm._PARTITIONED_TABLES:
            result = _pm._quote_ident(table)
            assert result.startswith('"') and result.endswith('"')

    def test_rejects_sql_injection_semicolon(self):
        """Semicolon in name must be rejected — classic injection."""
        with pytest.raises(ValueError, match="cannot be safely quoted"):
            _pm._quote_ident('audit_events"; DROP TABLE audit_events; --')

    def test_rejects_sql_injection_quote_close(self):
        """Double-quote in a crafted name must be rejected."""
        with pytest.raises(ValueError, match="cannot be safely quoted"):
            _pm._quote_ident('evil"--')

    def test_rejects_space(self):
        """Spaces are not valid in unquoted-style identifiers."""
        with pytest.raises(ValueError, match="cannot be safely quoted"):
            _pm._quote_ident("evil name")

    def test_rejects_hyphen(self):
        """Hyphens must be rejected (not in [a-zA-Z0-9_])."""
        with pytest.raises(ValueError, match="cannot be safely quoted"):
            _pm._quote_ident("bad-name")

    def test_rejects_null_byte(self):
        """Null bytes are an injection vector."""
        with pytest.raises(ValueError, match="cannot be safely quoted"):
            _pm._quote_ident("evil\x00name")

    def test_rejects_empty_string(self):
        """An empty identifier is not valid."""
        with pytest.raises(ValueError, match="cannot be safely quoted"):
            _pm._quote_ident("")


# ---------------------------------------------------------------------------
# DDL composition — no f-string SQL interpolation in source
# ---------------------------------------------------------------------------

class TestNoFstringInDDL:
    """Structural guard: the source file must not contain the original
    f-string DDL pattern (CREATE TABLE IF NOT EXISTS {name}) that was
    the root cause of YSG-RISK-001."""

    def test_fstring_dml_pattern_absent(self):
        source = _SCRIPT_PATH.read_text(encoding="utf-8")
        # The old pattern: f"""... {name} ... PARTITION OF {table} ...
        # We look for the specific dangerous interpolation inside a DDL.
        assert "PARTITION OF {table}" not in source, (
            "Unsafe f-string interpolation of 'table' identifier found in "
            "partition_maintenance.py — YSG-RISK-001 regression."
        )
        assert "NOT EXISTS {name}" not in source, (
            "Unsafe f-string interpolation of 'name' identifier found in "
            "partition_maintenance.py — YSG-RISK-001 regression."
        )

    def test_bind_params_present(self):
        """Ensure $1/$2 bind parameters are used for date literals."""
        source = _SCRIPT_PATH.read_text(encoding="utf-8")
        assert "$1" in source and "$2" in source, (
            "Expected asyncpg $1/$2 bind parameter markers in "
            "partition_maintenance.py — date literals must not be interpolated."
        )
