-- ============================================================
-- Domain 20: Identity Governance & Administration (IGA)
-- ============================================================

-- Business roles (logical groupings of entitlements)
CREATE TABLE IF NOT EXISTS iga_roles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    role_type       TEXT NOT NULL DEFAULT 'business' CHECK (role_type IN (
                        'business','technical','privileged','application','emergency')),
    category        TEXT,                              -- e.g. "finance", "it_admin", "hr"
    owner           TEXT,                              -- role owner / approver
    risk_level      TEXT DEFAULT 'low' CHECK (risk_level IN ('critical','high','medium','low')),
    is_active       BOOL DEFAULT TRUE,
    requires_mfa    BOOL DEFAULT FALSE,
    max_duration_days INT,                             -- NULL = permanent
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_iga_roles_tenant ON iga_roles (tenant_id, role_type, is_active);

-- Role entitlements: what a role grants (system permissions, app rights, etc.)
CREATE TABLE IF NOT EXISTS iga_role_entitlements (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    role_id         UUID NOT NULL REFERENCES iga_roles(id) ON DELETE CASCADE,
    system_name     TEXT NOT NULL,                     -- target system (e.g. "SAP", "AD")
    entitlement     TEXT NOT NULL,                     -- permission/group/profile name
    entitlement_type TEXT DEFAULT 'permission' CHECK (entitlement_type IN (
                        'permission','group','profile','privilege','role')),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (role_id, system_name, entitlement)
);

CREATE INDEX IF NOT EXISTS idx_iga_entitlements_role ON iga_role_entitlements (role_id);

-- Identity role assignments (who has what role)
CREATE TABLE IF NOT EXISTS iga_role_assignments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    identity_id     UUID NOT NULL,                     -- references identity service
    identity_name   TEXT NOT NULL,
    identity_email  TEXT,
    role_id         UUID NOT NULL REFERENCES iga_roles(id) ON DELETE CASCADE,
    role_name       TEXT NOT NULL,
    assignment_type TEXT DEFAULT 'direct' CHECK (assignment_type IN (
                        'direct','delegated','emergency','inherited')),
    status          TEXT DEFAULT 'active' CHECK (status IN (
                        'active','pending_approval','suspended','expired','revoked')),
    justification   TEXT,
    requested_by    UUID,
    approved_by     UUID,
    approved_at     TIMESTAMPTZ,
    valid_from      TIMESTAMPTZ DEFAULT NOW(),
    valid_until     TIMESTAMPTZ,                       -- NULL = permanent
    last_reviewed_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (tenant_id, identity_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_iga_assignments_tenant   ON iga_role_assignments (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_iga_assignments_identity ON iga_role_assignments (tenant_id, identity_id);
CREATE INDEX IF NOT EXISTS idx_iga_assignments_role     ON iga_role_assignments (role_id, status);
CREATE INDEX IF NOT EXISTS idx_iga_assignments_expiry   ON iga_role_assignments (valid_until) WHERE valid_until IS NOT NULL;

-- Access review campaigns (certifications)
CREATE TABLE IF NOT EXISTS iga_campaigns (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    campaign_type   TEXT NOT NULL CHECK (campaign_type IN (
                        'periodic','triggered','privileged_access','role_cleanup',
                        'regulatory','separation_of_duties')),
    scope           TEXT DEFAULT 'all' CHECK (scope IN (
                        'all','role','department','application','privileged')),
    scope_filter    TEXT,                              -- dept/role/app name when scope != all
    status          TEXT DEFAULT 'draft' CHECK (status IN (
                        'draft','active','paused','completed','cancelled')),
    -- Reviewer configuration
    reviewer_type   TEXT DEFAULT 'manager' CHECK (reviewer_type IN (
                        'manager','role_owner','identity_owner','security_team','custom')),
    -- Progress
    total_items     INT DEFAULT 0,
    reviewed_items  INT DEFAULT 0,
    certified_items INT DEFAULT 0,
    revoked_items   INT DEFAULT 0,
    -- Dates
    start_date      DATE NOT NULL DEFAULT CURRENT_DATE,
    due_date        DATE NOT NULL,
    completed_at    TIMESTAMPTZ,
    created_by      UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_iga_campaigns_tenant ON iga_campaigns (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_iga_campaigns_due    ON iga_campaigns (due_date) WHERE status = 'active';

-- Individual review items within a campaign
CREATE TABLE IF NOT EXISTS iga_review_items (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    campaign_id     UUID NOT NULL REFERENCES iga_campaigns(id) ON DELETE CASCADE,
    identity_id     UUID NOT NULL,
    identity_name   TEXT NOT NULL,
    identity_email  TEXT,
    role_id         UUID REFERENCES iga_roles(id) ON DELETE SET NULL,
    role_name       TEXT NOT NULL,
    assignment_id   UUID REFERENCES iga_role_assignments(id) ON DELETE SET NULL,
    -- Review decision
    decision        TEXT CHECK (decision IN ('certified','revoked','delegated','abstained')),
    decision_reason TEXT,
    reviewer_id     UUID,
    reviewer_name   TEXT,
    reviewed_at     TIMESTAMPTZ,
    -- Risk signal
    risk_flags      TEXT[] DEFAULT '{}',  -- dormant_account/excessive_access/sod_conflict/etc.
    risk_score      INT DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_iga_review_items_campaign  ON iga_review_items (campaign_id);
CREATE INDEX IF NOT EXISTS idx_iga_review_items_identity  ON iga_review_items (tenant_id, identity_id);
CREATE INDEX IF NOT EXISTS idx_iga_review_items_pending   ON iga_review_items (campaign_id) WHERE decision IS NULL;

-- Separation of Duties policies (mutually exclusive role pairs)
CREATE TABLE IF NOT EXISTS iga_sod_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    role_a_id       UUID NOT NULL REFERENCES iga_roles(id) ON DELETE CASCADE,
    role_a_name     TEXT NOT NULL,
    role_b_id       UUID NOT NULL REFERENCES iga_roles(id) ON DELETE CASCADE,
    role_b_name     TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'high' CHECK (severity IN ('critical','high','medium','low')),
    action          TEXT DEFAULT 'block' CHECK (action IN ('block','flag','notify','log')),
    is_active       BOOL DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (tenant_id, role_a_id, role_b_id)
);

CREATE INDEX IF NOT EXISTS idx_iga_sod_policies_tenant ON iga_sod_policies (tenant_id, is_active);

-- SoD violations detected
CREATE TABLE IF NOT EXISTS iga_sod_violations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    policy_id       UUID NOT NULL REFERENCES iga_sod_policies(id) ON DELETE CASCADE,
    policy_name     TEXT NOT NULL,
    identity_id     UUID NOT NULL,
    identity_name   TEXT NOT NULL,
    identity_email  TEXT,
    role_a_id       UUID NOT NULL,
    role_a_name     TEXT NOT NULL,
    role_b_id       UUID NOT NULL,
    role_b_name     TEXT NOT NULL,
    severity        TEXT NOT NULL,
    status          TEXT DEFAULT 'open' CHECK (status IN (
                        'open','exception_granted','remediated','false_positive')),
    exception_reason TEXT,
    exception_by    UUID,
    exception_at    TIMESTAMPTZ,
    detected_at     TIMESTAMPTZ DEFAULT NOW(),
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_iga_sod_violations_tenant   ON iga_sod_violations (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_iga_sod_violations_identity ON iga_sod_violations (tenant_id, identity_id);
