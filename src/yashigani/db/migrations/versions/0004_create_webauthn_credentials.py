"""Create webauthn_credentials table and user_id index.

Revision ID: 0004
Revises: 0003
Create Date: 2026-03-31

v0.9.0 (S-01): Persistent storage for WebAuthn/Passkey credentials.
public_key is stored as BYTEA encrypted at rest via pgp_sym_encrypt so the
app AES key (injected per transaction) is required to decrypt.
sign_count provides replay protection per the WebAuthn spec.
"""
from __future__ import annotations

from alembic import op

# revision identifiers, used by Alembic.
revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

_DDL_UP = """
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         TEXT         NOT NULL,
    credential_id   BYTEA        NOT NULL,
    public_key      BYTEA        NOT NULL,
    sign_count      INTEGER      NOT NULL DEFAULT 0,
    aaguid          TEXT         NOT NULL DEFAULT '',
    name            TEXT         NOT NULL DEFAULT 'Passkey',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ,
    CONSTRAINT uq_webauthn_credential_id UNIQUE (credential_id)
);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id
    ON webauthn_credentials (user_id);
"""

_DDL_DOWN = """
DROP INDEX IF EXISTS idx_webauthn_credentials_user_id;
DROP TABLE IF EXISTS webauthn_credentials;
"""


def upgrade() -> None:
    op.execute(_DDL_UP)


def downgrade() -> None:
    op.execute(_DDL_DOWN)
