"""Bootstrap audit_events and inference_events partitions 2026-05 through 2027-06.

Revision ID: 0003
Revises: 0002
Create Date: 2026-03-28
Last updated: 2026-04-28T00:00:00+01:00

v0.7.1 (P1-B completion): The CronJob and maintenance script handle ongoing
partition creation, but a static bootstrap is needed so the first 14 months
(2026-05 → 2027-06) exist without requiring the CronJob to have run.

All CREATE TABLE statements use IF NOT EXISTS so the migration is safe to run
on instances where pg_partman has already pre-created some of these partitions.
"""
from __future__ import annotations

from alembic import op

# revision identifiers, used by Alembic.
revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

# Months to pre-create: (year, month) tuples for 2026-05 through 2027-06
_MONTHS = [
    (2026, 5), (2026, 6), (2026, 7), (2026, 8), (2026, 9), (2026, 10),
    (2026, 11), (2026, 12),
    (2027, 1), (2027, 2), (2027, 3), (2027, 4), (2027, 5), (2027, 6),
]

_TABLES = ["audit_events", "inference_events"]


def _partition_ddl(table: str, year: int, month: int) -> str:
    """Return CREATE TABLE IF NOT EXISTS DDL for one monthly partition."""
    name = f"{table}_{year}_{month:02d}"
    start = f"{year}-{month:02d}-01"
    # Calculate the first day of the following month
    if month == 12:
        end = f"{year + 1}-01-01"
    else:
        end = f"{year}-{month + 1:02d}-01"
    return (
        f"CREATE TABLE IF NOT EXISTS {name} "
        f"PARTITION OF {table} "
        f"FOR VALUES FROM ('{start}') TO ('{end}')"
    )


def upgrade() -> None:
    for year, month in _MONTHS:
        for table in _TABLES:
            op.execute(_partition_ddl(table, year, month))


def downgrade() -> None:
    # Drop in reverse order to avoid dependency issues.
    # op.drop_table() is used instead of a raw f-string DDL to ensure
    # Alembic handles identifier quoting correctly (CWE-89, YSG-RISK-002 #3as).
    # The loop already covers only the partitions created in upgrade(), so
    # IF NOT EXISTS semantics are not needed here — the tables exist.
    for year, month in reversed(_MONTHS):
        for table in _TABLES:
            name = f"{table}_{year}_{month:02d}"
            op.drop_table(name)
