"""Add allowed_cidrs column to agents table.

Revision ID: 0002
Revises: 0001
Create Date: 2026-03-28

v0.7.0 (P2-4): Stores the CIDR-based IP allowlist per agent.
An empty JSON array means "no restriction" (allow all IPs).
The enforcement is in AgentAuthMiddleware; this column persists the
configuration across restarts so it survives Redis eviction.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agent_registry",
        sa.Column(
            "allowed_cidrs",
            sa.JSON(),
            nullable=False,
            server_default="[]",
            comment="CIDR ranges allowed to call this agent. Empty = unrestricted.",
        ),
    )


def downgrade() -> None:
    op.drop_column("agent_registry", "allowed_cidrs")
