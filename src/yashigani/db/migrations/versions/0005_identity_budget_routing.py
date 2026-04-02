"""v1.0 — Unified identity registry, three-tier budget system, model aliases, routing config.

Revision ID: 0005
Revises: 0004
Create Date: 2026-04-01
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_DDL_UP = """
-- ==========================================================================
-- UNIFIED IDENTITY REGISTRY
-- Replaces separate user/agent stores. Every entity is an identity.
-- ==========================================================================

CREATE TABLE identities (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_id         TEXT NOT NULL UNIQUE,          -- idnt_xxxxxxxxxxxx
    kind                TEXT NOT NULL CHECK (kind IN ('human', 'service')),
    name                TEXT NOT NULL,
    slug                TEXT NOT NULL,                  -- URL-safe, for @mentions
    description         TEXT NOT NULL DEFAULT '',
    expertise           TEXT[] DEFAULT '{}',            -- tags
    system_prompt       TEXT DEFAULT '',
    model_preference    TEXT DEFAULT '',
    sensitivity_ceiling TEXT DEFAULT 'PUBLIC'
        CHECK (sensitivity_ceiling IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')),
    upstream_url        TEXT DEFAULT '',                -- service identities only
    container_image     TEXT DEFAULT '',                -- Docker image for Pool Manager
    container_config    JSONB DEFAULT '{}',             -- resource limits, volumes, env
    capabilities        TEXT[] DEFAULT '{}',            -- code_execution, web_search, etc.
    allowed_tools       TEXT[] DEFAULT '{}',            -- MCP tool allowlist
    allowed_models      TEXT[] DEFAULT '{}',            -- which models this identity can use
    icon_url            TEXT DEFAULT '',
    idp_provider_id     UUID,                          -- FK to idp_providers (humans only)
    idp_subject         TEXT DEFAULT '',                -- external IdP subject identifier
    org_id              UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    api_key_hash        TEXT DEFAULT '',                -- bcrypt hash of API key
    api_key_created_at  TIMESTAMPTZ,
    api_key_expires_at  TIMESTAMPTZ,
    api_key_rotated_at  TIMESTAMPTZ,
    status              TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'deactivated')),
    groups              TEXT[] DEFAULT '{}',            -- RBAC group slugs
    allowed_callers     TEXT[] DEFAULT '{}',            -- which groups can invoke this identity
    allowed_paths       TEXT[] DEFAULT '{}',            -- API path allowlist
    allowed_cidrs       TEXT[] DEFAULT '{}',            -- network allowlist
    token_rotation_schedule TEXT DEFAULT '',            -- cron expression for auto-rotation
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at        TIMESTAMPTZ,
    UNIQUE (tenant_id, slug)
);

CREATE INDEX idx_identities_tenant_kind ON identities (tenant_id, kind);
CREATE INDEX idx_identities_slug ON identities (slug);
CREATE INDEX idx_identities_status ON identities (status);
CREATE INDEX idx_identities_org ON identities (org_id);
CREATE INDEX idx_identities_api_key_hash ON identities (api_key_hash) WHERE api_key_hash != '';

ALTER TABLE identities ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON identities
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- ==========================================================================
-- IDENTITY GROUP MEMBERSHIP (many-to-many with RBAC groups)
-- ==========================================================================

CREATE TABLE identity_group_membership (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_id     TEXT NOT NULL REFERENCES identities(identity_id) ON DELETE CASCADE,
    group_id        UUID NOT NULL REFERENCES rbac_groups(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, identity_id, group_id)
);

ALTER TABLE identity_group_membership ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON identity_group_membership
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- ==========================================================================
-- IDP PROVIDERS (for multi-IdP identity broker)
-- ==========================================================================

CREATE TABLE idp_providers (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,                      -- "Entra ID (US)"
    protocol        TEXT NOT NULL CHECK (protocol IN ('oidc', 'saml')),
    metadata_url    TEXT NOT NULL DEFAULT '',           -- discovery endpoint
    client_id       TEXT NOT NULL DEFAULT '',           -- RP client ID
    client_secret_encrypted BYTEA,                     -- stored in KMS
    entity_id       TEXT DEFAULT '',                    -- SAML entity ID
    group_mapping   JSONB DEFAULT '{}',                -- IdP group -> Yashigani group
    org_mapping     UUID REFERENCES tenants(id),       -- which org this IdP serves
    default_sensitivity TEXT DEFAULT 'INTERNAL'
        CHECK (default_sensitivity IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')),
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

ALTER TABLE idp_providers ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON idp_providers
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- Add FK from identities to idp_providers
ALTER TABLE identities
    ADD CONSTRAINT fk_identities_idp
    FOREIGN KEY (idp_provider_id) REFERENCES idp_providers(id) ON DELETE SET NULL;

-- ==========================================================================
-- THREE-TIER BUDGET SYSTEM
-- ==========================================================================

-- Organisation cloud caps (per cloud provider)
CREATE TABLE org_cloud_caps (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    org_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider        TEXT NOT NULL,                      -- 'anthropic', 'openai', 'azure', 'gemini'
    token_cap       BIGINT NOT NULL,                   -- monthly cap in tokens
    period          TEXT NOT NULL DEFAULT 'monthly'
        CHECK (period IN ('daily', 'weekly', 'monthly')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, org_id, provider)
);

ALTER TABLE org_cloud_caps ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON org_cloud_caps
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- Group budgets
CREATE TABLE group_budgets (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    group_id        UUID NOT NULL REFERENCES rbac_groups(id) ON DELETE CASCADE,
    provider        TEXT NOT NULL,                      -- 'anthropic', 'openai', etc. or '*' for all
    token_budget    BIGINT NOT NULL,                   -- tokens allocated to this group
    period          TEXT NOT NULL DEFAULT 'monthly'
        CHECK (period IN ('daily', 'weekly', 'monthly')),
    auto_calculated BOOLEAN NOT NULL DEFAULT false,    -- true if sum of individuals + 1
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, group_id, provider, period)
);

ALTER TABLE group_budgets ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON group_budgets
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- Individual budgets
CREATE TABLE individual_budgets (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_id     TEXT NOT NULL REFERENCES identities(identity_id) ON DELETE CASCADE,
    provider        TEXT NOT NULL,
    token_budget    BIGINT NOT NULL,
    period          TEXT NOT NULL DEFAULT 'monthly'
        CHECK (period IN ('daily', 'weekly', 'monthly')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, identity_id, provider, period)
);

ALTER TABLE individual_budgets ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON individual_budgets
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- Model pricing table (for cost signal in OE)
CREATE TABLE model_pricing (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    provider        TEXT NOT NULL,
    model_name      TEXT NOT NULL,
    input_cost_per_1k  NUMERIC(10, 6) NOT NULL DEFAULT 0,   -- USD per 1K input tokens
    output_cost_per_1k NUMERIC(10, 6) NOT NULL DEFAULT 0,   -- USD per 1K output tokens
    is_local        BOOLEAN NOT NULL DEFAULT false,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider, model_name)
);

-- Seed with common model pricing
INSERT INTO model_pricing (provider, model_name, input_cost_per_1k, output_cost_per_1k, is_local) VALUES
    ('ollama', 'qwen2.5:3b', 0, 0, true),
    ('ollama', 'llama3.1:8b', 0, 0, true),
    ('ollama', 'mistral:7b', 0, 0, true),
    ('anthropic', 'claude-opus-4-6', 0.015, 0.075, false),
    ('anthropic', 'claude-sonnet-4-6', 0.003, 0.015, false),
    ('anthropic', 'claude-haiku-4-5', 0.0008, 0.004, false),
    ('openai', 'gpt-4o', 0.005, 0.015, false),
    ('openai', 'gpt-4o-mini', 0.00015, 0.0006, false),
    ('google', 'gemini-2.0-flash', 0.0001, 0.0004, false);

-- ==========================================================================
-- MODEL ALIASES (DB-driven, Decision 8)
-- ==========================================================================

CREATE TABLE model_aliases (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    alias           TEXT NOT NULL,                      -- "fast", "smart", "secure"
    provider        TEXT NOT NULL,                      -- target provider
    model_name      TEXT NOT NULL,                      -- target model
    force_local     BOOLEAN NOT NULL DEFAULT false,     -- override: always route local
    description     TEXT DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, alias)
);

ALTER TABLE model_aliases ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON model_aliases
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- Seed default aliases
INSERT INTO model_aliases (tenant_id, alias, provider, model_name, force_local, description) VALUES
    ('00000000-0000-0000-0000-000000000000', 'fast', 'ollama', 'qwen2.5:3b', true, 'Fast local model for simple tasks'),
    ('00000000-0000-0000-0000-000000000000', 'smart', 'anthropic', 'claude-sonnet-4-6', false, 'High-capability cloud model'),
    ('00000000-0000-0000-0000-000000000000', 'secure', 'ollama', 'qwen2.5:3b', true, 'Local-only model for sensitive data');

-- ==========================================================================
-- ROUTING CONFIGURATION
-- ==========================================================================

-- Sensitivity patterns (admin-configurable regex patterns per classification)
CREATE TABLE sensitivity_patterns (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    classification  TEXT NOT NULL
        CHECK (classification IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')),
    pattern_type    TEXT NOT NULL CHECK (pattern_type IN ('regex', 'keyword', 'fasttext_label')),
    pattern         TEXT NOT NULL,
    description     TEXT DEFAULT '',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, classification, pattern_type, pattern)
);

ALTER TABLE sensitivity_patterns ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON sensitivity_patterns
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- Seed default PII/PCI regex patterns
INSERT INTO sensitivity_patterns (tenant_id, classification, pattern_type, pattern, description) VALUES
    ('00000000-0000-0000-0000-000000000000', 'CONFIDENTIAL', 'regex', '\b\d{3}-\d{2}-\d{4}\b', 'US Social Security Number'),
    ('00000000-0000-0000-0000-000000000000', 'RESTRICTED', 'regex', '\b(?:\d[ -]*?){13,19}\b', 'Credit/debit card number (PCI DSS)'),
    ('00000000-0000-0000-0000-000000000000', 'CONFIDENTIAL', 'regex', '\b[A-Z]{2}\d{2}[ ]?\d{4}[ ]?\d{4}[ ]?\d{4}[ ]?\d{4}[ ]?\d{0,2}\b', 'IBAN bank account number'),
    ('00000000-0000-0000-0000-000000000000', 'INTERNAL', 'regex', '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email address'),
    ('00000000-0000-0000-0000-000000000000', 'CONFIDENTIAL', 'regex', '\b[A-Z]{1,2}\d{1,2}[A-Z]?\s?\d[A-Z]{2}\b', 'UK National Insurance number'),
    ('00000000-0000-0000-0000-000000000000', 'CONFIDENTIAL', 'regex', '\b\d{3}[- ]?\d{3}[- ]?\d{4}\b', 'US/CA phone number'),
    ('00000000-0000-0000-0000-000000000000', 'RESTRICTED', 'regex', '\b(?:sk-|sk-ant-|sk-proj-)[A-Za-z0-9_-]{20,}\b', 'API key (OpenAI/Anthropic)'),
    ('00000000-0000-0000-0000-000000000000', 'RESTRICTED', 'keyword', 'CONFIDENTIAL', 'Document classification marker'),
    ('00000000-0000-0000-0000-000000000000', 'RESTRICTED', 'keyword', 'TOP SECRET', 'Government classification marker');

-- Trusted cloud providers (admin-configured for CONFIDENTIAL/RESTRICTED fallback)
CREATE TABLE trusted_cloud_providers (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider        TEXT NOT NULL,
    sensitivity_level TEXT NOT NULL
        CHECK (sensitivity_level IN ('CONFIDENTIAL', 'RESTRICTED')),
    dpa_reference   TEXT DEFAULT '',                    -- data processing agreement reference
    notes           TEXT DEFAULT '',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, provider, sensitivity_level)
);

ALTER TABLE trusted_cloud_providers ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON trusted_cloud_providers
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- Routing configuration (admin-configurable thresholds and defaults)
CREATE TABLE routing_config (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    complexity_token_threshold INTEGER NOT NULL DEFAULT 2000,
    budget_warn_pct INTEGER NOT NULL DEFAULT 80,
    default_route   TEXT NOT NULL DEFAULT 'local'
        CHECK (default_route IN ('local', 'cloud', 'tenant_default')),
    default_model   TEXT NOT NULL DEFAULT 'qwen2.5:3b',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id)
);

ALTER TABLE routing_config ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON routing_config
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- Seed default routing config for platform tenant
INSERT INTO routing_config (tenant_id, complexity_token_threshold, default_route, default_model) VALUES
    ('00000000-0000-0000-0000-000000000000', 2000, 'local', 'qwen2.5:3b');

-- ==========================================================================
-- ADDITIONAL PARTITIONS (2026-05 through 2026-12)
-- ==========================================================================

CREATE TABLE IF NOT EXISTS audit_events_2026_05
    PARTITION OF audit_events FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE IF NOT EXISTS audit_events_2026_06
    PARTITION OF audit_events FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

CREATE TABLE IF NOT EXISTS inference_events_2026_05
    PARTITION OF inference_events FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE IF NOT EXISTS inference_events_2026_06
    PARTITION OF inference_events FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

-- ==========================================================================
-- GRANTS
-- ==========================================================================

GRANT SELECT, INSERT, UPDATE ON identities TO yashigani_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON identity_group_membership TO yashigani_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON idp_providers TO yashigani_app;
GRANT SELECT, INSERT, UPDATE ON org_cloud_caps TO yashigani_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON group_budgets TO yashigani_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON individual_budgets TO yashigani_app;
GRANT SELECT, INSERT, UPDATE ON model_pricing TO yashigani_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON model_aliases TO yashigani_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON sensitivity_patterns TO yashigani_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON trusted_cloud_providers TO yashigani_app;
GRANT SELECT, INSERT, UPDATE ON routing_config TO yashigani_app;
"""

_DDL_DOWN = """
DROP TABLE IF EXISTS routing_config CASCADE;
DROP TABLE IF EXISTS trusted_cloud_providers CASCADE;
DROP TABLE IF EXISTS sensitivity_patterns CASCADE;
DROP TABLE IF EXISTS model_aliases CASCADE;
DROP TABLE IF EXISTS model_pricing CASCADE;
DROP TABLE IF EXISTS individual_budgets CASCADE;
DROP TABLE IF EXISTS group_budgets CASCADE;
DROP TABLE IF EXISTS org_cloud_caps CASCADE;
DROP TABLE IF EXISTS identity_group_membership CASCADE;
DROP TABLE IF EXISTS idp_providers CASCADE;
DROP TABLE IF EXISTS identities CASCADE;
"""


def upgrade() -> None:
    op.execute(_DDL_UP)


def downgrade() -> None:
    op.execute(_DDL_DOWN)
