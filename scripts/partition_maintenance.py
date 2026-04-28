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

Last updated: 2026-04-28T00:00:00+01:00
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import re
import sys
from datetime import date

logger = logging.getLogger(__name__)

# Identifier quoting: only allow identifiers that are safe ASCII alphanumeric +
# underscore, matching the naming convention enforced by _PARTITIONED_TABLES and
# _partition_name().  This is a defence-in-depth guard — asyncpg DDL params
# bind date literals; we use safe quoting for the identifier tokens.
_SAFE_IDENT_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def _quote_ident(name: str) -> str:
    """Quote a PostgreSQL identifier safely.

    Only ASCII alphanumeric + underscore identifiers are permitted; anything
    else raises ValueError so the caller (and the unit test) can catch a
    maliciously-crafted name before it ever reaches the database.

    This mirrors the behaviour of psycopg.sql.Identifier: wraps the name in
    double-quotes and rejects names that cannot be safely expressed that way
    without allowlisting.
    """
    if not _SAFE_IDENT_RE.match(name):
        raise ValueError(
            f"Identifier {name!r} contains characters outside [a-zA-Z0-9_] "
            "and cannot be safely quoted — possible injection attempt."
        )
    # Double any embedded double-quotes (none expected given the regex above,
    # but defensive completeness per SQL standard).
    escaped = name.replace('"', '""')
    return f'"{escaped}"'


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
                # Safe identifier quoting — _quote_ident rejects any name
                # that doesn't match [a-zA-Z_][a-zA-Z0-9_]* before the
                # statement is composed (CWE-89, YSG-RISK-001 #3ar).
                # Date literals are passed as $1/$2 bind parameters so the
                # database never interpolates them as SQL tokens.
                q_name = _quote_ident(name)
                q_table = _quote_ident(table)
                await conn.execute(
                    f"CREATE TABLE IF NOT EXISTS {q_name}"
                    f" PARTITION OF {q_table}"
                    " FOR VALUES FROM ($1) TO ($2)",
                    start,
                    end,
                )
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
