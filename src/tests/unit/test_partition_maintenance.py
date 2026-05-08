"""
Unit tests for scripts/partition_maintenance.py — YSG-RISK-001 (CWE-89).

Verifies that:
  - _quote_ident rejects maliciously-crafted partition names before any SQL
    statement is composed.
  - Normal partition names (the only ones the script ever generates) pass.
  - The CREATE TABLE DDL uses _quote_ident for identifier slots and
    date.isoformat() for date-range slots.
  - date.isoformat() output can never contain SQL-injectable characters
    (defence-in-depth regression guard per Internal follow-up #5,
     YCS-20260502-v2.23.1-CWE89-reaudit-001).

Background on DDL date-literal exception:
  PostgreSQL does not accept asyncpg $1/$2 bind parameters in DDL parser
  positions (PARTITION OF … FOR VALUES FROM … TO …). The server returns
  "expects 0 arguments". Therefore date literals are interpolated directly
  as strings. This is safe because date.isoformat() is locale-independent
  and always returns exactly 10 ASCII characters matching YYYY-MM-DD —
  no quote, no space, no escape character, no semicolon.

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

    def test_identifier_slots_use_quote_ident(self):
        """The DDL SQL string must use q_name and q_table (from _quote_ident),
        not bare 'name' or 'table' interpolation."""
        source = _SCRIPT_PATH.read_text(encoding="utf-8")
        # Positive assertion: quoted tokens appear in the DDL
        assert "{q_name}" in source, (
            "Expected {q_name} (from _quote_ident) in partition_maintenance.py "
            "DDL — identifier slot must use safe quoting."
        )
        assert "{q_table}" in source, (
            "Expected {q_table} (from _quote_ident) in partition_maintenance.py "
            "DDL — identifier slot must use safe quoting."
        )

    def test_date_slots_use_isoformat(self):
        """DDL date-range slots must use date.isoformat() (deterministic YYYY-MM-DD).
        asyncpg $1/$2 bind params are NOT accepted in DDL parser positions
        (PostgreSQL returns 'expects 0 arguments') — date.isoformat() is the
        correct approach for this DDL site."""
        source = _SCRIPT_PATH.read_text(encoding="utf-8")
        assert "start.isoformat()" in source, (
            "Expected start.isoformat() in DDL date-range slot — "
            "af114f7 DDL date-literal exception regression."
        )
        assert "end.isoformat()" in source, (
            "Expected end.isoformat() in DDL date-range slot — "
            "af114f7 DDL date-literal exception regression."
        )


class TestDateLiteralInjectionImpossible:
    """Defence-in-depth regression tests for the DDL date-literal slots.

    Internal follow-up #5 (YCS-20260502-v2.23.1-CWE89-reaudit-001):
    Even though start/end come from Python date arithmetic (not user input),
    we assert here that date.isoformat() CANNOT produce SQL-injectable output,
    so any future refactor that accidentally lets external data reach the date
    slots would still be safe.
    """

    INJECTION_CHARS = ["'", '"', ";", " ", "\n", "\r", "\\", "\x00", "--", "/*"]

    def test_isoformat_never_contains_single_quote(self):
        """date.isoformat() must never contain a single quote — the DDL wraps
        the date literal in single quotes, so a quote in the value would break
        out of the string literal."""
        from datetime import date
        # Spot-check a full year of date values (all months, start + end variants)
        for month in range(1, 13):
            d = date(2026, month, 1)
            assert "'" not in d.isoformat(), (
                f"date({2026}, {month}, 1).isoformat() returned a single quote"
            )

    def test_isoformat_output_matches_yyyy_mm_dd(self):
        """date.isoformat() must always return exactly YYYY-MM-DD (10 chars,
        only digits and hyphens). Validates locale-independence."""
        import re
        from datetime import date
        pattern = re.compile(r"^\d{4}-\d{2}-\d{2}$")
        for year in [2025, 2026, 2027]:
            for month in range(1, 13):
                d = date(year, month, 1)
                iso = d.isoformat()
                assert len(iso) == 10, f"Unexpected length {len(iso)} for {iso}"
                assert pattern.match(iso), (
                    f"date.isoformat() returned unexpected format: {iso!r}"
                )

    def test_isoformat_contains_no_injectable_characters(self):
        """date.isoformat() must not contain any character from the SQL injection
        character set, for the entire year of possible partition dates."""
        from datetime import date
        for month in range(1, 13):
            d = date(2026, month, 1)
            iso = d.isoformat()
            for ch in self.INJECTION_CHARS:
                assert ch not in iso, (
                    f"date.isoformat() returned {iso!r} which contains "
                    f"injection-class character {ch!r}"
                )
