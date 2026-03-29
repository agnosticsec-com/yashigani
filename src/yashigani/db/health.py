"""
Yashigani DB — Health checks including audit log partition status.
Used by the metrics collector (Prometheus gauge) and the /health endpoint.
"""
from __future__ import annotations

import logging
from datetime import date
from typing import Optional

logger = logging.getLogger(__name__)

_PARTITIONED_TABLES = ["audit_events", "inference_events"]


def _upcoming_partition_names(months: int = 3) -> list[tuple[str, str]]:
    """
    Return list of (table, partition_name) for the current month + next `months` months.
    """
    today = date.today().replace(day=1)
    result = []
    for i in range(months + 1):
        month_offset = today.month - 1 + i
        year = today.year + month_offset // 12
        month = month_offset % 12 + 1
        for table in _PARTITIONED_TABLES:
            name = f"{table}_{year}_{month:02d}"
            result.append((table, name))
    return result


async def check_audit_partitions(conn) -> dict[str, bool]:
    """
    Async check (asyncpg connection): returns {partition_name: exists}
    for the current month and the next 2 months for audit_events only.

    Passes if the partition exists in pg_tables.
    """
    results: dict[str, bool] = {}
    today = date.today().replace(day=1)
    for i in range(3):
        month_offset = today.month - 1 + i
        year = today.year + month_offset // 12
        month = month_offset % 12 + 1
        name = f"audit_events_{year}_{month:02d}"
        try:
            exists = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM pg_tables WHERE tablename = $1)",
                name,
            )
            results[name] = bool(exists)
        except Exception as exc:
            logger.error("check_audit_partitions: query failed for %s: %s", name, exc)
            results[name] = False
    return results


def check_audit_partitions_sync(conn) -> dict[str, bool]:
    """
    Sync check (psycopg2-style connection): returns {partition_name: exists}
    for the current month and the next 2 months for audit_events only.
    """
    results: dict[str, bool] = {}
    today = date.today().replace(day=1)
    for i in range(3):
        month_offset = today.month - 1 + i
        year = today.year + month_offset // 12
        month = month_offset % 12 + 1
        name = f"audit_events_{year}_{month:02d}"
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT EXISTS(SELECT 1 FROM pg_tables WHERE tablename = %s)",
                    (name,),
                )
                exists = cur.fetchone()[0]
                results[name] = bool(exists)
        except Exception as exc:
            logger.error("check_audit_partitions_sync: query failed for %s: %s", name, exc)
            results[name] = False
    return results


def is_next_month_partition_missing(partition_status: dict[str, bool]) -> bool:
    """
    Returns True if the partition for next month (or any upcoming month) is missing.
    Used to set the Prometheus gauge.
    """
    return any(not exists for exists in partition_status.values())
