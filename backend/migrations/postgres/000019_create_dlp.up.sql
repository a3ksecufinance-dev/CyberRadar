-- ============================================================
-- Domain 17: Data Security & DLP (Data Loss Prevention)
-- ============================================================

-- Data classification labels
CREATE TABLE IF NOT EXISTS dlp_labels (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    sensitivity     TEXT NOT NULL CHECK (sensitivity IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED','TOP_SECRET')),
    color           TEXT DEFAULT '#6B7280',        -- hex color for UI
    regex_patterns  TEXT[] DEFAULT '{}',           -- patterns to auto-detect
    keywords        TEXT[] DEFAULT '{}',           -- keywords to auto-detect
    is_active       BOOL DEFAULT TRUE,
    created_by      UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_dlp_labels_tenant ON dlp_labels (tenant_id, is_active);

-- Data assets: databases, S3 buckets, file shares, APIs, etc.
CREATE TABLE IF NOT EXISTS dlp_data_assets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    asset_type      TEXT NOT NULL CHECK (asset_type IN (
                        'database','file_share','object_storage','api_endpoint',
                        'email','messaging','endpoint','cloud_storage')),
    location        TEXT NOT NULL,                 -- connection string / path / URL (masked)
    label_id        UUID REFERENCES dlp_labels(id) ON DELETE SET NULL,
    data_categories TEXT[] DEFAULT '{}',           -- pii/pci/phi/banking/swift/credentials/ip
    record_count    BIGINT DEFAULT 0,
    size_bytes      BIGINT DEFAULT 0,
    last_scanned_at TIMESTAMPTZ,
    scan_status     TEXT DEFAULT 'pending' CHECK (scan_status IN ('pending','scanning','clean','violations_found','error')),
    risk_score      INT DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    owner           TEXT,
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dlp_assets_tenant        ON dlp_data_assets (tenant_id, asset_type);
CREATE INDEX IF NOT EXISTS idx_dlp_assets_tenant_risk   ON dlp_data_assets (tenant_id, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_dlp_assets_tenant_scan   ON dlp_data_assets (tenant_id, scan_status);

-- DLP policies: rules governing data handling
CREATE TABLE IF NOT EXISTS dlp_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    policy_type     TEXT NOT NULL CHECK (policy_type IN (
                        'exfiltration','sharing','retention','access','encryption','classification')),
    sensitivity_levels TEXT[] DEFAULT '{}',        -- which labels this policy applies to
    data_categories TEXT[] DEFAULT '{}',           -- pii/pci/phi/banking
    action          TEXT NOT NULL CHECK (action IN ('block','alert','log','quarantine','encrypt','redact')),
    channels        TEXT[] DEFAULT '{}',           -- email/usb/cloud/print/api/clipboard
    conditions      JSONB DEFAULT '{}',            -- additional match conditions
    is_active       BOOL DEFAULT TRUE,
    violation_count BIGINT DEFAULT 0,
    created_by      UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dlp_policies_tenant ON dlp_policies (tenant_id, is_active);

-- DLP violations: detected policy breaches
CREATE TABLE IF NOT EXISTS dlp_violations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    policy_id       UUID REFERENCES dlp_policies(id) ON DELETE SET NULL,
    asset_id        UUID REFERENCES dlp_data_assets(id) ON DELETE SET NULL,
    label_id        UUID REFERENCES dlp_labels(id) ON DELETE SET NULL,
    violation_type  TEXT NOT NULL,                 -- maps to policy_type
    channel         TEXT,                          -- email/usb/cloud/print/api
    severity        TEXT NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    user_id_src     TEXT,                          -- source user (may be external)
    endpoint        TEXT,                          -- source device/IP
    destination     TEXT,                          -- where data was going
    data_snippet    TEXT,                          -- redacted evidence
    match_count     INT DEFAULT 1,                 -- how many matches found
    action_taken    TEXT NOT NULL,                 -- block/alert/log/quarantine
    status          TEXT DEFAULT 'open' CHECK (status IN ('open','investigating','false_positive','resolved')),
    investigated_by UUID,
    resolved_at     TIMESTAMPTZ,
    detected_at     TIMESTAMPTZ DEFAULT NOW(),
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dlp_violations_tenant        ON dlp_violations (tenant_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_dlp_violations_tenant_sev    ON dlp_violations (tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_dlp_violations_tenant_status ON dlp_violations (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_dlp_violations_policy        ON dlp_violations (policy_id);

-- Data scan jobs
CREATE TABLE IF NOT EXISTS dlp_scans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    asset_id        UUID REFERENCES dlp_data_assets(id) ON DELETE CASCADE,
    status          TEXT DEFAULT 'pending' CHECK (status IN ('pending','running','completed','failed')),
    items_scanned   BIGINT DEFAULT 0,
    violations_found INT DEFAULT 0,
    labels_detected TEXT[] DEFAULT '{}',
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    error_text      TEXT,
    created_by      UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dlp_scans_tenant     ON dlp_scans (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_dlp_scans_asset      ON dlp_scans (asset_id);
