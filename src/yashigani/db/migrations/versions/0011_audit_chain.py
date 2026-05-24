"""v2.24.1 — LU-AMEND-01: tamper-evident audit log (hash-chained audit_events).

Revision ID: 0011
Revises: 0010
Create Date: 2026-05-24

Rationale (LU-AMEND-01 specification):
    Lu GRC review (YCS-20260523-v2.24.1-COUNCIL-LU §3.LU-AMEND-01) requires a
    tamper-evident hash chain on the audit_events table so that auditors can
    independently verify the integrity of the audit trail.

    Compliance mapping:
      ASVS V7.3.3 — audit log integrity (tamper-evident)
      NIST 800-53 AU-9  — protection of audit information
      NIST 800-53 AU-10 — non-repudiation
      CMMC AU.L2-3.3.8  — protect audit information from unauthorized access/modification
      CMMC AU.L2-3.3.9  — limit audit management to subset of privileged users
      SOC 2 CC7.2 / CC7.3 — system monitoring + evaluation of security events
      ISO 27001 A.8.15 / A.5.28 — logging + evidence collection
      GDPR Art. 32(1)(b) — ongoing confidentiality/integrity/availability

Changes in this migration:

  1. ADD prev_hash TEXT and event_hash TEXT columns to audit_events.
     prev_hash  — SHA-384 hex of the preceding event's canonical JSON, or
                  SHA-384 of "YYYY-MM-DD" for the first event of each calendar
                  day (day-anchor, consistent with writer.py F-12 scheme).
     event_hash — SHA-384 hex of this event's canonical JSON (excluding
                  prev_event_hash; consistent with _canonical_json() in
                  writer.py). Allows individual event verification.

     Both columns are nullable — NOT NULL would block all existing events and
     partitioned inserts before the backfill job runs. The AuditChainService
     populates them on every new INSERT.

  2. REVOKE UPDATE, DELETE ON audit_events FROM yashigani_app.
     yashigani_app retains SELECT, INSERT (from migration 0001).
     This enforces append-only semantics at the DB privilege level.
     Superuser / postgres role can still UPDATE/DELETE for emergency fixes
     (requires explicit escalation — logged by the DBA).

  3. CREATE TABLE audit_chain_checkpoints — daily merkle-root record.
     The checkpoint job (AuditChainService.run_daily_checkpoint()) computes
     a SHA-384 merkle root over all event_hash values for the day and writes
     one row per tenant per day.
     The checkpoint itself is signed with the internal SPIFFE identity of the
     service that ran the job (stored as signing_spiffe_id).

     NOTE on Sigstore IdP choice (Lu open question §5):
       We use the Yashigani internal PKI SPIFFE identity rather than an
       external Sigstore / Fulcio endpoint. Rationale:
         - No external network dependency (works in airgapped enterprise).
         - Consistent with the existing yashigani.internal PKI investment.
         - Avoids key management complexity of an external CA cross-signature.
         - The signing_spiffe_id field provides the identity anchor; the
           signature is ECDSA-SHA384 over the merkle_root using the service's
           leaf private key from /run/secrets/<service>_client.key.
       This is recorded here as a deliberate architectural decision so Lu can
       evaluate it against the SOC 2 / ISO 27001 requirement.

     NOTE on hash-chain design decision (trigger-vs-app, Lu open question §5):
       App-side computation was chosen over PostgreSQL triggers because:
         - App-side is testable in unit tests without a live Postgres session.
         - No PL/pgSQL dependency (portable across Postgres versions).
         - Consistent with the existing writer.py in-memory chain (SHA-384).
         - Triggers run in the DB session and cannot access the in-memory
           chain state; they would need a separate chain-state table, adding
           complexity without benefit.
       Trade-off: a process crash between computing the hash and the INSERT
       could leave a gap. The AuditChainService detects gaps at checkpoint
       time and records them with a chain_break_count field.

Downgrade: removes the two columns and the checkpoint table.
           The REVOKE is reversed by RE-GRANTING UPDATE/DELETE on downgrade.

Evidence artefact: reference this migration SHA in the v2.24.1 compliance pack
for LU-AMEND-01 closure.
"""
# Last updated: 2026-05-24T00:00:00+00:00
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0011"
down_revision: Union[str, None] = "0010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_DDL_UP = """
-- ================================================================
-- LU-AMEND-01: Tamper-evident hash-chain columns on audit_events
-- ================================================================

-- Add hash-chain columns to the parent partitioned table.
-- Nullable to avoid blocking existing rows/partitions.
ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS prev_hash   TEXT,
    ADD COLUMN IF NOT EXISTS event_hash  TEXT;

-- Index for checkpoint job: scan event_hash values for a day quickly.
CREATE INDEX IF NOT EXISTS idx_audit_events_event_hash
    ON audit_events (tenant_id, created_at, event_hash)
    WHERE event_hash IS NOT NULL;

-- ================================================================
-- Append-only enforcement: REVOKE destructive privileges
-- ================================================================
-- yashigani_app retains SELECT + INSERT (granted in 0001).
-- UPDATE and DELETE are revoked at the DB level — no application
-- code path is authorised to modify or delete audit records.
-- Emergency fixes require a superuser session (which must be
-- separately authorised and logged by the DBA).

REVOKE UPDATE, DELETE ON audit_events FROM yashigani_app;

-- ================================================================
-- audit_chain_checkpoints — daily merkle-root records
-- ================================================================

CREATE TABLE audit_chain_checkpoints (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    checkpoint_date     DATE NOT NULL,
    event_count         BIGINT NOT NULL DEFAULT 0,
    merkle_root         TEXT NOT NULL,
    chain_break_count   INTEGER NOT NULL DEFAULT 0,
    signing_spiffe_id   TEXT NOT NULL DEFAULT '',
    signature_hex       TEXT NOT NULL DEFAULT '',
    computed_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, checkpoint_date)
);

-- RLS: tenants can only see their own checkpoint records.
ALTER TABLE audit_chain_checkpoints ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_chain_checkpoints
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- Index for the audit verification tool (scripts/audit_verify.py).
CREATE INDEX idx_audit_chain_checkpoints_date
    ON audit_chain_checkpoints (tenant_id, checkpoint_date DESC);

-- yashigani_app can SELECT (to read checkpoints for verification)
-- and INSERT (to write new daily checkpoints).
-- UPDATE and DELETE are intentionally NOT granted — checkpoints
-- are themselves immutable once written.
GRANT SELECT, INSERT ON audit_chain_checkpoints TO yashigani_app;
"""

_DDL_DOWN = """
-- Reverse: remove checkpoints table
DROP TABLE IF EXISTS audit_chain_checkpoints CASCADE;

-- Reverse: drop the index on event_hash
DROP INDEX IF EXISTS idx_audit_events_event_hash;

-- Reverse: remove the hash-chain columns from audit_events
-- (ADD COLUMN IF NOT EXISTS is safe; DROP COLUMN must be explicit)
ALTER TABLE audit_events
    DROP COLUMN IF EXISTS prev_hash,
    DROP COLUMN IF EXISTS event_hash;

-- Reverse: restore UPDATE/DELETE privileges (downgrade re-enables mutation)
GRANT UPDATE, DELETE ON audit_events TO yashigani_app;
"""


def upgrade() -> None:
    op.execute(_DDL_UP)


def downgrade() -> None:
    op.execute(_DDL_DOWN)
