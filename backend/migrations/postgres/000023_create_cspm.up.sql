-- ============================================================
-- Domain 21: Cloud Security Posture Management (CSPM)
-- ============================================================

-- Cloud accounts registered for scanning
CREATE TABLE IF NOT EXISTS cspm_accounts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    provider        TEXT NOT NULL CHECK (provider IN ('aws','azure','gcp','oci','alibaba')),
    account_id      TEXT NOT NULL,                 -- AWS account ID / Azure subscription ID / GCP project ID
    region          TEXT,                          -- primary region (NULL = all regions)
    environment     TEXT DEFAULT 'production' CHECK (environment IN (
                        'production','staging','development','sandbox')),
    status          TEXT DEFAULT 'active' CHECK (status IN ('active','inactive','error')),
    -- Posture scores (updated after each scan)
    posture_score   INT DEFAULT 0 CHECK (posture_score BETWEEN 0 AND 100),
    critical_count  INT DEFAULT 0,
    high_count      INT DEFAULT 0,
    medium_count    INT DEFAULT 0,
    low_count       INT DEFAULT 0,
    resource_count  INT DEFAULT 0,
    last_scanned_at TIMESTAMPTZ,
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (tenant_id, provider, account_id)
);

CREATE INDEX IF NOT EXISTS idx_cspm_accounts_tenant   ON cspm_accounts (tenant_id, provider);
CREATE INDEX IF NOT EXISTS idx_cspm_accounts_score    ON cspm_accounts (tenant_id, posture_score);

-- Security rules / checks (CIS, NIST, PCI-DSS, etc.)
CREATE TABLE IF NOT EXISTS cspm_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    rule_id         TEXT NOT NULL,                 -- e.g. "CIS-AWS-1.1", "NIST-AC-2"
    title           TEXT NOT NULL,
    description     TEXT,
    rationale       TEXT,
    remediation     TEXT,
    provider        TEXT NOT NULL CHECK (provider IN ('aws','azure','gcp','oci','alibaba','multi')),
    resource_type   TEXT NOT NULL,                 -- e.g. "s3_bucket", "security_group", "iam_user"
    framework       TEXT NOT NULL CHECK (framework IN (
                        'cis','nist','pci_dss','hipaa','sox','iso27001','gdpr','dora','custom')),
    framework_section TEXT,                        -- e.g. "1.1", "AC-2"
    severity        TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    is_active       BOOL DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (tenant_id, rule_id)
);

CREATE INDEX IF NOT EXISTS idx_cspm_rules_tenant    ON cspm_rules (tenant_id, provider, framework);
CREATE INDEX IF NOT EXISTS idx_cspm_rules_resource  ON cspm_rules (tenant_id, resource_type);

-- Discovered cloud resources
CREATE TABLE IF NOT EXISTS cspm_resources (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    account_id      UUID NOT NULL REFERENCES cspm_accounts(id) ON DELETE CASCADE,
    resource_uid    TEXT NOT NULL,                 -- provider-specific ARN / resource ID
    name            TEXT,
    resource_type   TEXT NOT NULL,                 -- e.g. "s3_bucket", "ec2_instance"
    service         TEXT NOT NULL,                 -- e.g. "S3", "EC2", "IAM"
    region          TEXT,
    tags            JSONB DEFAULT '{}',
    configuration   JSONB DEFAULT '{}',            -- resource config snapshot
    risk_score      INT DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    finding_count   INT DEFAULT 0,
    is_public       BOOL DEFAULT FALSE,
    last_seen_at    TIMESTAMPTZ DEFAULT NOW(),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (account_id, resource_uid)
);

CREATE INDEX IF NOT EXISTS idx_cspm_resources_account ON cspm_resources (account_id, resource_type);
CREATE INDEX IF NOT EXISTS idx_cspm_resources_tenant  ON cspm_resources (tenant_id, service);
CREATE INDEX IF NOT EXISTS idx_cspm_resources_public  ON cspm_resources (tenant_id, is_public) WHERE is_public = TRUE;
CREATE INDEX IF NOT EXISTS idx_cspm_resources_risk    ON cspm_resources (tenant_id, risk_score DESC);

-- Findings: rule violations on specific resources
CREATE TABLE IF NOT EXISTS cspm_findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    account_id      UUID NOT NULL REFERENCES cspm_accounts(id) ON DELETE CASCADE,
    resource_id     UUID REFERENCES cspm_resources(id) ON DELETE CASCADE,
    rule_id         UUID NOT NULL REFERENCES cspm_rules(id) ON DELETE CASCADE,
    rule_ref        TEXT NOT NULL,                 -- denormalized rule_id string
    title           TEXT NOT NULL,
    severity        TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    status          TEXT DEFAULT 'open' CHECK (status IN (
                        'open','suppressed','resolved','exception')),
    -- Finding details
    resource_uid    TEXT,
    resource_type   TEXT,
    region          TEXT,
    evidence        JSONB DEFAULT '{}',            -- what was found (config values, etc.)
    remediation     TEXT,
    -- Tracking
    first_seen_at   TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    suppressed_by   UUID,
    suppression_reason TEXT,
    scan_id         UUID,                          -- which scan found this
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cspm_findings_tenant   ON cspm_findings (tenant_id, severity, status);
CREATE INDEX IF NOT EXISTS idx_cspm_findings_account  ON cspm_findings (account_id, status);
CREATE INDEX IF NOT EXISTS idx_cspm_findings_resource ON cspm_findings (resource_id, status);
CREATE INDEX IF NOT EXISTS idx_cspm_findings_rule     ON cspm_findings (rule_id);
CREATE INDEX IF NOT EXISTS idx_cspm_findings_open     ON cspm_findings (tenant_id, first_seen_at DESC) WHERE status = 'open';

-- Scan jobs
CREATE TABLE IF NOT EXISTS cspm_scans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    account_id      UUID NOT NULL REFERENCES cspm_accounts(id) ON DELETE CASCADE,
    status          TEXT DEFAULT 'pending' CHECK (status IN (
                        'pending','running','completed','failed','cancelled')),
    scan_type       TEXT DEFAULT 'full' CHECK (scan_type IN ('full','incremental','targeted')),
    -- Results
    resources_scanned  INT DEFAULT 0,
    rules_evaluated    INT DEFAULT 0,
    findings_new       INT DEFAULT 0,
    findings_resolved  INT DEFAULT 0,
    posture_score      INT,
    error_message      TEXT,
    started_at         TIMESTAMPTZ,
    completed_at       TIMESTAMPTZ,
    triggered_by       UUID,
    created_at         TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cspm_scans_account ON cspm_scans (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cspm_scans_tenant  ON cspm_scans (tenant_id, status);
