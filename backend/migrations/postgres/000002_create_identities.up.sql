-- Migration: 000002_create_identities
-- Foundation Platform — FND-02/03/04: Identity, RBAC, Auth

-- ─── Roles ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        VARCHAR(100) NOT NULL,
    description TEXT,
    is_system   BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_roles_tenant_name ON roles(tenant_id, name);

CREATE TRIGGER roles_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ─── Permissions ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS permissions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource    VARCHAR(100) NOT NULL,   -- e.g. 'alerts', 'connectors'
    action      VARCHAR(50) NOT NULL,    -- e.g. 'read', 'write', 'delete'
    description TEXT
);

CREATE UNIQUE INDEX idx_permissions_resource_action ON permissions(resource, action);

-- ─── Role ↔ Permission mapping ─────────────────────────────
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id        UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id  UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- ─── Identities (Users) ───────────────────────────────────
CREATE TABLE IF NOT EXISTS identities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Core
    username        VARCHAR(255) NOT NULL,
    email           VARCHAR(255) NOT NULL,
    display_name    VARCHAR(255),
    password_hash   VARCHAR(255),
    identity_type   VARCHAR(50) NOT NULL DEFAULT 'user'
                        CHECK (identity_type IN ('user', 'admin', 'service_account', 'machine', 'bot')),

    -- Organization
    department      VARCHAR(100),
    business_unit   VARCHAR(100),
    manager_id      UUID REFERENCES identities(id) ON DELETE SET NULL,

    -- Security
    privilege_level VARCHAR(20) NOT NULL DEFAULT 'standard'
                        CHECK (privilege_level IN ('standard', 'elevated', 'admin', 'super_admin')),
    mfa_enabled     BOOLEAN NOT NULL DEFAULT false,
    mfa_secret      VARCHAR(255),             -- TOTP secret (encrypted)
    pam_managed     BOOLEAN NOT NULL DEFAULT false,
    risk_score      NUMERIC(5,2) NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    behavior_score  NUMERIC(5,2) NOT NULL DEFAULT 100 CHECK (behavior_score BETWEEN 0 AND 100),

    -- Status
    status          VARCHAR(20) NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'dormant', 'orphan', 'compromised', 'disabled')),
    last_activity   TIMESTAMP WITH TIME ZONE,
    password_last_set TIMESTAMP WITH TIME ZONE,
    failed_login_count INT NOT NULL DEFAULT 0,
    locked_until    TIMESTAMP WITH TIME ZONE,

    -- Source systems (federated identity metadata)
    source_systems  JSONB NOT NULL DEFAULT '[]',

    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMP WITH TIME ZONE
);

CREATE UNIQUE INDEX idx_identities_tenant_email
    ON identities(tenant_id, email) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX idx_identities_tenant_username
    ON identities(tenant_id, username) WHERE deleted_at IS NULL;
CREATE INDEX idx_identities_tenant ON identities(tenant_id);
CREATE INDEX idx_identities_risk ON identities(tenant_id, risk_score DESC);
CREATE INDEX idx_identities_status ON identities(tenant_id, status);

CREATE TRIGGER identities_updated_at
    BEFORE UPDATE ON identities
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ─── Identity ↔ Role mapping ───────────────────────────────
CREATE TABLE IF NOT EXISTS identity_roles (
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    role_id     UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    assigned_by UUID REFERENCES identities(id),
    PRIMARY KEY (identity_id, role_id)
);

-- ─── Privileges ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS identity_privileges (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_id    UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    privilege_name VARCHAR(255) NOT NULL,
    privilege_type VARCHAR(50) NOT NULL
                       CHECK (privilege_type IN ('group', 'role', 'permission', 'pam_role', 'local')),
    target_asset_id UUID,                  -- optional: asset-scoped privilege
    granted_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at     TIMESTAMP WITH TIME ZONE,
    source         VARCHAR(50),            -- 'AD', 'IAM', 'PAM', 'manual'
    is_active      BOOLEAN NOT NULL DEFAULT true
);

CREATE INDEX idx_privileges_identity ON identity_privileges(identity_id);
CREATE INDEX idx_privileges_tenant ON identity_privileges(tenant_id);

-- ─── Refresh Tokens ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash  VARCHAR(64) NOT NULL,   -- SHA-256 of the token
    user_agent  VARCHAR(512),
    ip_address  INET,
    expires_at  TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at  TIMESTAMP WITH TIME ZONE,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_identity ON refresh_tokens(identity_id);
CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash) WHERE revoked_at IS NULL;

-- ─── Seed standard permissions ─────────────────────────────
INSERT INTO permissions (resource, action, description) VALUES
    ('tenants',      'read',   'View tenants'),
    ('tenants',      'write',  'Create and update tenants'),
    ('tenants',      'delete', 'Delete tenants'),
    ('users',        'read',   'View users'),
    ('users',        'write',  'Create and update users'),
    ('users',        'delete', 'Delete users'),
    ('roles',        'read',   'View roles'),
    ('roles',        'write',  'Create and update roles'),
    ('alerts',       'read',   'View alerts'),
    ('alerts',       'write',  'Update alert status'),
    ('alerts',       'suppress','Suppress alerts'),
    ('incidents',    'read',   'View incidents'),
    ('incidents',    'write',  'Create and update incidents'),
    ('connectors',   'read',   'View connectors'),
    ('connectors',   'write',  'Create and update connectors'),
    ('connectors',   'delete', 'Delete connectors'),
    ('assets',       'read',   'View assets'),
    ('assets',       'write',  'Create and update assets'),
    ('rules',        'read',   'View detection rules'),
    ('rules',        'write',  'Create and update rules'),
    ('audit',        'read',   'View audit logs'),
    ('audit',        'export', 'Export audit logs'),
    ('config',       'read',   'View configuration'),
    ('config',       'write',  'Update configuration'),
    ('reports',      'read',   'View reports'),
    ('reports',      'generate','Generate reports')
ON CONFLICT DO NOTHING;

-- ─── Seed system roles ─────────────────────────────────────
-- Insert system roles into the platform tenant
INSERT INTO roles (id, tenant_id, name, description, is_system) VALUES
    ('10000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001', 'super_admin',       'Full platform access', true),
    ('10000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001', 'tenant_admin',      'Full tenant administration', true),
    ('10000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000001', 'soc_analyst_l1',    'SOC Analyst Level 1', true),
    ('10000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-000000000001', 'soc_analyst_l2',    'SOC Analyst Level 2', true),
    ('10000000-0000-0000-0000-000000000005', '00000000-0000-0000-0000-000000000001', 'threat_hunter',     'Threat Hunter', true),
    ('10000000-0000-0000-0000-000000000006', '00000000-0000-0000-0000-000000000001', 'incident_responder','Incident Responder', true),
    ('10000000-0000-0000-0000-000000000007', '00000000-0000-0000-0000-000000000001', 'fraud_analyst',     'Fraud Analyst', true),
    ('10000000-0000-0000-0000-000000000008', '00000000-0000-0000-0000-000000000001', 'compliance_officer','Compliance Officer', true),
    ('10000000-0000-0000-0000-000000000009', '00000000-0000-0000-0000-000000000001', 'auditor',           'Read-only auditor', true),
    ('10000000-0000-0000-0000-000000000010', '00000000-0000-0000-0000-000000000001', 'ciso',              'CISO dashboard access', true),
    ('10000000-0000-0000-0000-000000000011', '00000000-0000-0000-0000-000000000001', 'executive_viewer',  'Executive read-only', true)
ON CONFLICT DO NOTHING;
