"""v2.23.1 — Persist admin_accounts + used_totp_codes in Postgres.

Revision ID: 0006
Revises: 0005
Create Date: 2026-04-23

Rationale:
    P0-2 (Internal YCS-20260423-v2.23.1-OWASP-3X): LocalAuthService persisted
    admin accounts in an in-memory dict, so password rotations and TOTP
    re-enrolments silently reverted on backoffice restart — a durability
    failure that violates ASVS V2.1 and V2.8. This migration creates the
    durable backing store that PostgresLocalAuthService uses.

Tables:
    admin_accounts      — every AccountRecord field, platform-scoped RLS
    used_totp_codes     — short-lived replay cache (≈60s TTL per row)

RLS: admin_accounts is platform-scoped via the sentinel tenant
    00000000-0000-0000-0000-000000000000 — usernames are global, not
    per-tenant, so the UNIQUE constraint on username deliberately lives
    outside the tenant partition.
"""
# Last updated: 2026-04-23T00:00:00+00:00
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_DDL_UP = """
-- ==========================================================================
-- ADMIN / USER ACCOUNT STORE (durable replacement for in-memory dict)
-- ==========================================================================

CREATE TABLE admin_accounts (
    account_id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id               UUID NOT NULL
                              DEFAULT '00000000-0000-0000-0000-000000000000'
                              REFERENCES tenants(id) ON DELETE CASCADE,
    username                TEXT NOT NULL UNIQUE,
    password_hash           TEXT NOT NULL,
    totp_secret             TEXT NOT NULL DEFAULT '',
    recovery_codes          JSONB,                                  -- {"hashes":[...],"used":[...]}
    account_tier            TEXT NOT NULL
                              CHECK (account_tier IN ('admin', 'user')),
    email                   TEXT,
    force_password_change   BOOLEAN NOT NULL DEFAULT true,
    force_totp_provision    BOOLEAN NOT NULL DEFAULT true,
    disabled                BOOLEAN NOT NULL DEFAULT false,
    failed_attempts         INTEGER NOT NULL DEFAULT 0,
    locked_until            DOUBLE PRECISION NOT NULL DEFAULT 0,    -- epoch seconds, matches dataclass
    totp_failed_attempts    INTEGER NOT NULL DEFAULT 0,
    totp_backoff_until      DOUBLE PRECISION NOT NULL DEFAULT 0,
    created_at              DOUBLE PRECISION NOT NULL DEFAULT EXTRACT(EPOCH FROM now()),
    password_changed_at     DOUBLE PRECISION NOT NULL DEFAULT EXTRACT(EPOCH FROM now())
);

CREATE INDEX idx_admin_accounts_tier ON admin_accounts (account_tier);
CREATE INDEX idx_admin_accounts_tenant ON admin_accounts (tenant_id);

ALTER TABLE admin_accounts ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON admin_accounts
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON admin_accounts TO yashigani_app;

-- ==========================================================================
-- USED TOTP REPLAY CACHE
-- Internal bookkeeping only — no RLS; rows auto-expire (<=60s).
-- ==========================================================================

CREATE TABLE used_totp_codes (
    code_hash   TEXT PRIMARY KEY,               -- sha256(secret_b32 + ":" + window_key)
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_used_totp_codes_expires ON used_totp_codes (expires_at);

GRANT SELECT, INSERT, DELETE ON used_totp_codes TO yashigani_app;
"""

_DDL_DOWN = """
DROP TABLE IF EXISTS used_totp_codes CASCADE;
DROP TABLE IF EXISTS admin_accounts CASCADE;
"""


def upgrade() -> None:
    op.execute(_DDL_UP)


def downgrade() -> None:
    op.execute(_DDL_DOWN)
