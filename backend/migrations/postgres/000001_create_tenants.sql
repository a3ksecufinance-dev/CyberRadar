-- Migration: 000001_create_tenants
-- Foundation Platform — FND-01: Tenant Management

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─── Tenants ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tenants (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) NOT NULL,
    slug        VARCHAR(100) NOT NULL,
    parent_id   UUID REFERENCES tenants(id) ON DELETE SET NULL,
    plan        VARCHAR(50) NOT NULL DEFAULT 'standard',
    status      VARCHAR(20) NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'suspended', 'deleted')),
    config      JSONB NOT NULL DEFAULT '{}',
    features    JSONB NOT NULL DEFAULT '{}',
    limits      JSONB NOT NULL DEFAULT '{"max_users": 100, "max_assets": 10000, "max_eps": 1000}',
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMP WITH TIME ZONE
);

CREATE UNIQUE INDEX idx_tenants_slug ON tenants(slug) WHERE deleted_at IS NULL;
CREATE INDEX idx_tenants_parent ON tenants(parent_id) WHERE parent_id IS NOT NULL;
CREATE INDEX idx_tenants_status ON tenants(status);

-- ─── Tenant update trigger ─────────────────────────────────
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tenants_updated_at
    BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ─── Initial super-tenant (platform admin) ─────────────────
INSERT INTO tenants (id, name, slug, plan, status, features)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'CyberRadar Platform',
    'platform',
    'enterprise',
    'active',
    '{"all": true}'
)
ON CONFLICT DO NOTHING;
