"""
Unit tests for yashigani.db.health — partition health checks (v0.7.1 P1-C).

Tests cover:
- check_audit_partitions (async, asyncpg-style)
- check_audit_partitions_sync (sync, psycopg2-style)
- is_next_month_partition_missing
"""
from __future__ import annotations

import pytest
from datetime import date
from unittest.mock import AsyncMock, MagicMock, patch

from yashigani.db.health import (
    check_audit_partitions,
    check_audit_partitions_sync,
    is_next_month_partition_missing,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _expected_partition_names() -> list[str]:
    """Return the 3 partition names check_audit_partitions will query today."""
    today = date.today().replace(day=1)
    names = []
    for i in range(3):
        offset = today.month - 1 + i
        year = today.year + offset // 12
        month = offset % 12 + 1
        names.append(f"audit_events_{year}_{month:02d}")
    return names


# ---------------------------------------------------------------------------
# check_audit_partitions (async)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_check_audit_partitions_all_present():
    """All three partitions exist → all values True, gauge = 0."""
    conn = AsyncMock()
    conn.fetchval = AsyncMock(return_value=True)

    result = await check_audit_partitions(conn)

    assert all(result.values()), "All partitions present should return True for each"
    assert not is_next_month_partition_missing(result)


@pytest.mark.asyncio
async def test_check_audit_partitions_one_missing():
    """Next-month partition missing → its value is False."""
    names = _expected_partition_names()
    # First partition present, second (next month) absent, third present
    return_values = [True, False, True]

    conn = AsyncMock()
    conn.fetchval = AsyncMock(side_effect=return_values)

    result = await check_audit_partitions(conn)

    assert result[names[0]] is True
    assert result[names[1]] is False
    assert result[names[2]] is True
    assert is_next_month_partition_missing(result)


@pytest.mark.asyncio
async def test_check_audit_partitions_all_missing():
    conn = AsyncMock()
    conn.fetchval = AsyncMock(return_value=False)

    result = await check_audit_partitions(conn)

    assert all(v is False for v in result.values())
    assert is_next_month_partition_missing(result)


@pytest.mark.asyncio
async def test_check_audit_partitions_db_error_returns_false():
    """DB query failure → key set to False, no exception raised."""
    conn = AsyncMock()
    conn.fetchval = AsyncMock(side_effect=Exception("connection lost"))

    result = await check_audit_partitions(conn)

    # Must not raise; each entry should be False
    assert len(result) == 3
    assert all(v is False for v in result.values())
    assert is_next_month_partition_missing(result)


@pytest.mark.asyncio
async def test_check_audit_partitions_returns_correct_keys():
    """Keys must match the expected audit_events_YYYY_MM naming convention."""
    conn = AsyncMock()
    conn.fetchval = AsyncMock(return_value=True)

    result = await check_audit_partitions(conn)

    assert set(result.keys()) == set(_expected_partition_names())


# ---------------------------------------------------------------------------
# check_audit_partitions_sync
# ---------------------------------------------------------------------------

def _make_sync_conn(return_values: list[bool]) -> MagicMock:
    """Build a psycopg2-style mock connection."""
    cursor = MagicMock()
    cursor.__enter__ = MagicMock(return_value=cursor)
    cursor.__exit__ = MagicMock(return_value=False)
    cursor.fetchone = MagicMock(side_effect=[(v,) for v in return_values])

    conn = MagicMock()
    conn.cursor = MagicMock(return_value=cursor)
    return conn


def test_check_audit_partitions_sync_all_present():
    conn = _make_sync_conn([True, True, True])
    result = check_audit_partitions_sync(conn)

    assert all(result.values())
    assert not is_next_month_partition_missing(result)


def test_check_audit_partitions_sync_one_missing():
    names = _expected_partition_names()
    conn = _make_sync_conn([True, False, True])

    result = check_audit_partitions_sync(conn)

    assert result[names[0]] is True
    assert result[names[1]] is False
    assert is_next_month_partition_missing(result)


def test_check_audit_partitions_sync_db_error_returns_false():
    """DB error → key set to False, no exception raised."""
    cursor = MagicMock()
    cursor.__enter__ = MagicMock(return_value=cursor)
    cursor.__exit__ = MagicMock(return_value=False)
    cursor.execute = MagicMock(side_effect=Exception("timeout"))

    conn = MagicMock()
    conn.cursor = MagicMock(return_value=cursor)

    result = check_audit_partitions_sync(conn)

    assert len(result) == 3
    assert all(v is False for v in result.values())


# ---------------------------------------------------------------------------
# is_next_month_partition_missing
# ---------------------------------------------------------------------------

def test_is_next_month_partition_missing_empty_dict():
    """Empty status dict → no missing partitions."""
    assert is_next_month_partition_missing({}) is False


def test_is_next_month_partition_missing_all_true():
    status = {"audit_events_2026_04": True, "audit_events_2026_05": True}
    assert is_next_month_partition_missing(status) is False


def test_is_next_month_partition_missing_one_false():
    status = {"audit_events_2026_04": True, "audit_events_2026_05": False}
    assert is_next_month_partition_missing(status) is True


def test_is_next_month_partition_missing_all_false():
    status = {"audit_events_2026_04": False, "audit_events_2026_05": False}
    assert is_next_month_partition_missing(status) is True
