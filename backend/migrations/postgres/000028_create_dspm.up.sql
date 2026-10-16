-- ─── Domain 26: DSPM (Data Security Posture Management) ─────────────────────

-- dspm_data_stores: catalogs of data repositories
CREATE TABLE IF NOT EXISTS dspm_data_stores (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    store_type      TEXT NOT NULL CHECK (store_type IN (
                        'database','object_storage','file_share','api',
                        'data_warehouse','message_queue','code_repository','other')),
    -- Location
    cloud_provider  TEXT,                       -- aws/azure/gcp/on_premise/other
    region          TEXT,
    endpoint        TEXT,
    -- Classification
    sensitivity_level TEXT DEFAULT 'internal' CHECK (sensitivity_level IN (
                        'public','internal','confidential','restricted','top_secret')),
    data_categories TEXT[] DEFAULT '{}',       -- pii/pci/phi/financial/credentials/intellectual_property/legal
    -- Security posture
    is_encrypted    BOOL DEFAULT FALSE,
    is_access_controlled BOOL DEFAULT FALSE,
    is_monitored    BOOL DEFAULT FALSE,
    is_backup_enabled BOOL DEFAULT FALSE,
    -- Ownership
    owner           TEXT,
    owner_id        UUID,
    department      TEXT,
    -- Risk
    risk_score      INT DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    risk_level      TEXT DEFAULT 'low' CHECK (risk_level IN ('critical','high','medium','low')),
    -- Scan
    last_scanned_at TIMESTAMPTZ,
    scan_status     TEXT DEFAULT 'never' CHECK (scan_status IN ('never','pending','running','completed','failed')),
    -- Metadata
    tags            TEXT[] DEFAULT '{}',
    notes           TEXT,
    created_by      UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dspm_stores_tenant    ON dspm_data_stores (tenant_id, store_type, risk_level);
CREATE INDEX IF NOT EXISTS idx_dspm_stores_sensitive ON dspm_data_stores (tenant_id, sensitivity_level);

-- dspm_scan_jobs: scan executions
CREATE TABLE IF NOT EXISTS dspm_scan_jobs (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL,
    data_store_id           UUID NOT NULL REFERENCES dspm_data_stores(id) ON DELETE CASCADE,
    scan_type               TEXT NOT NULL CHECK (scan_type IN ('discovery','classification','access_audit','vulnerability','full')),
    status                  TEXT DEFAULT 'pending' CHECK (status IN ('pending','running','completed','failed','cancelled')),
    findings_count          INT DEFAULT 0,
    sensitive_findings_count INT DEFAULT 0,
    scanned_objects         INT DEFAULT 0,
    error_message           TEXT,
    triggered_by            TEXT,                   -- manual/scheduled/api
    started_at              TIMESTAMPTZ,
    completed_at            TIMESTAMPTZ,
    duration_seconds        INT,
    created_at              TIMESTAMPTZ DEFAULT NOW(),
    updated_at              TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dspm_scans_store  ON dspm_scan_jobs (data_store_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_dspm_scans_tenant ON dspm_scan_jobs (tenant_id, status, created_at DESC);

-- dspm_findings: sensitive data found
CREATE TABLE IF NOT EXISTS dspm_findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    data_store_id   UUID NOT NULL REFERENCES dspm_data_stores(id) ON DELETE CASCADE,
    scan_job_id     UUID REFERENCES dspm_scan_jobs(id) ON DELETE SET NULL,
    -- Classification
    finding_type    TEXT NOT NULL CHECK (finding_type IN (
                        'pii','pci_data','phi','credentials','api_keys',
                        'financial_data','intellectual_property','encryption_key',
                        'personal_data','biometric_data','other')),
    severity        TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low')),
    status          TEXT DEFAULT 'open' CHECK (status IN (
                        'open','acknowledged','remediated','accepted_risk','false_positive')),
    -- Location within the store
    location_path   TEXT,                           -- table/bucket/path
    location_field  TEXT,                           -- column/field name
    -- Impact
    record_count    BIGINT DEFAULT 0,               -- estimated number of records
    is_public_accessible BOOL DEFAULT FALSE,
    is_encrypted    BOOL DEFAULT FALSE,
    -- Details
    title           TEXT NOT NULL,
    description     TEXT,
    evidence        TEXT,                           -- anonymized sample
    remediation     TEXT,
    -- Compliance
    compliance_violations TEXT[] DEFAULT '{}',     -- gdpr_art5/pci_req3/hipaa_164...
    -- Resolution
    resolved_by     TEXT,
    resolved_at     TIMESTAMPTZ,
    tags            TEXT[] DEFAULT '{}',
    detected_at     TIMESTAMPTZ DEFAULT NOW(),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dspm_findings_store  ON dspm_findings (data_store_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_dspm_findings_tenant ON dspm_findings (tenant_id, status, severity);
CREATE INDEX IF NOT EXISTS idx_dspm_findings_type   ON dspm_findings (tenant_id, finding_type, status);

-- dspm_policies: data governance policies
CREATE TABLE IF NOT EXISTS dspm_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    policy_type     TEXT NOT NULL CHECK (policy_type IN (
                        'retention','classification','access_control','encryption',
                        'masking','data_residency','sharing','other')),
    rules           JSONB NOT NULL DEFAULT '{}',
    action          TEXT DEFAULT 'alert' CHECK (action IN (
                        'alert','block','mask','encrypt','delete','notify','quarantine')),
    is_active       BOOL DEFAULT TRUE,
    applies_to_categories TEXT[] DEFAULT '{}',      -- which data categories this covers
    applies_to_types TEXT[] DEFAULT '{}',           -- which store_types
    compliance_frameworks TEXT[] DEFAULT '{}',      -- gdpr/pci_dss/sox/hipaa/...
    violation_count INT DEFAULT 0,
    created_by      UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dspm_policies_tenant ON dspm_policies (tenant_id, policy_type, is_active);

-- dspm_remediation_items: tracked remediation work
CREATE TABLE IF NOT EXISTS dspm_remediation_items (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    finding_id      UUID NOT NULL REFERENCES dspm_findings(id) ON DELETE CASCADE,
    status          TEXT DEFAULT 'open' CHECK (status IN (
                        'open','in_progress','resolved','accepted_risk','wont_fix')),
    priority        TEXT DEFAULT 'medium' CHECK (priority IN ('critical','high','medium','low')),
    assignee_id     UUID,
    assignee_name   TEXT,
    due_date        TIMESTAMPTZ,
    notes           TEXT,
    resolution      TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dspm_remediation_finding ON dspm_remediation_items (finding_id);
CREATE INDEX IF NOT EXISTS idx_dspm_remediation_tenant  ON dspm_remediation_items (tenant_id, status, priority);
