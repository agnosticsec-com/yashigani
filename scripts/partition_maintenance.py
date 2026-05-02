#!/usr/bin/env python3
"""
Yashigani DB Partition Maintenance
====================================
Ensures the current month + next `months_ahead` months of audit_events and
inference_events partitions exist.

Safe to run repeatedly — CREATE TABLE IF NOT EXISTS semantics.
Called from pg_cron or the Kubernetes CronJob on the 1st of each month at 00:05 UTC.

Usage:
    DATABASE_URL=postgresql://user:pass@host/db python scripts/partition_maintenance.py
    python scripts/partition_maintenance.py --months-ahead 6
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from datetime import date

logger = logging.getLogger(__name__)


_PARTITIONED_TABLES = ["audit_events", "inference_events"]


def _partition_range(year: int, month: int) -> tuple[date, date]:
    """Return (start_inclusive, end_exclusive) for a monthly partition."""
    start = date(year, month, 1)
    if month == 12:
        end = date(year + 1, 1, 1)
    else:
        end = date(year, month + 1, 1)
    return start, end


def _partition_name(table: str, year: int, month: int) -> str:
    return f"{table}_{year}_{month:02d}"


async def ensure_partitions(conn_dsn: str, months_ahead: int = 3) -> dict[str, list[str]]:
    """
    Ensure partitions exist for the current month through months_ahead months forward.

    Returns a dict mapping table name → list of partition names ensured.
    """
    try:
        import asyncpg
    except ImportError:
        logger.error("asyncpg is required. pip install asyncpg")
        sys.exit(1)

    conn = await asyncpg.connect(conn_dsn)
    created: dict[str, list[str]] = {t: [] for t in _PARTITIONED_TABLES}

    try:
        today = date.today().replace(day=1)
        for i in range(months_ahead + 1):
            month_offset = today.month - 1 + i
            year = today.year + month_offset // 12
            month = month_offset % 12 + 1
            start, end = _partition_range(year, month)

            for table in _PARTITIONED_TABLES:
                name = _partition_name(table, year, month)
                await conn.execute(f"""
                    CREATE TABLE IF NOT EXISTS {name}
                    PARTITION OF {table}
                    FOR VALUES FROM ('{start}') TO ('{end}')
                """)
                created[table].append(name)
                logger.info("Partition %s: OK", name)
    finally:
        await conn.close()

    return created


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="Create missing audit/inference log partitions"
    )
    parser.add_argument(
        "--months-ahead",
        type=int,
        default=3,
        help="Number of future months to pre-create (default: 3)",
    )
    args = parser.parse_args()

    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        logger.error("DATABASE_URL environment variable is required")
        sys.exit(1)

    created = asyncio.run(ensure_partitions(dsn, months_ahead=args.months_ahead))

    total = sum(len(v) for v in created.values())
    print(f"Partition maintenance complete: {total} partition(s) ensured.")
    for table, names in created.items():
        for name in names:
            print(f"  {name}: OK")


if __name__ == "__main__":
    main()
