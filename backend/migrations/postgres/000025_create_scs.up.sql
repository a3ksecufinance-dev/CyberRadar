-- ============================================================
-- Domain 23: Supply Chain Security (SCS)
-- ============================================================

-- Third-party vendors / suppliers
CREATE TABLE IF NOT EXISTS scs_vendors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    website         TEXT,
    vendor_type     TEXT NOT NULL CHECK (vendor_type IN (
                        'software','hardware','cloud','managed_service',
                        'contractor','open_source','data_provider','other')),
    -- Risk assessment
    risk_tier       INT DEFAULT 2 CHECK (risk_tier BETWEEN 1 AND 4),  -- 1=critical, 4=low
    risk_score      INT DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    risk_level      TEXT DEFAULT 'medium' CHECK (risk_level IN ('critical','high','medium','low')),
    -- Contacts
    contact_name    TEXT,
    contact_email   TEXT,
    contact_phone   TEXT,
    -- Compliance
    has_soc2        BOOL DEFAULT FALSE,
    has_iso27001    BOOL DEFAULT FALSE,
    has_pci_dss     BOOL DEFAULT FALSE,
    last_assessment_at TIMESTAMPTZ,
    next_assessment_at TIMESTAMPTZ,
    -- Status
    status          TEXT DEFAULT 'active' CHECK (status IN ('active','inactive','suspended','under_review')),
    tags            TEXT[] DEFAULT '{}',
    notes           TEXT,
    created_by      UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scs_vendors_tenant    ON scs_vendors (tenant_id, risk_tier, status);
CREATE INDEX IF NOT EXISTS idx_scs_vendors_riskLevel ON scs_vendors (tenant_id, risk_level);

-- Software / hardware components (SBOM entries)
CREATE TABLE IF NOT EXISTS scs_components (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    vendor_id       UUID REFERENCES scs_vendors(id) ON DELETE SET NULL,
    name            TEXT NOT NULL,
    version         TEXT NOT NULL,
    component_type  TEXT NOT NULL CHECK (component_type IN (
                        'library','framework','container','os','firmware',
                        'application','api','sdk','other')),
    ecosystem       TEXT,                          -- e.g. npm, maven, pypi, go, nuget, docker
    purl            TEXT,                          -- Package URL (purl spec)
    license         TEXT,                          -- SPDX license identifier
    -- Risk
    is_deprecated   BOOL DEFAULT FALSE,
    is_end_of_life  BOOL DEFAULT FALSE,
    has_known_vulns BOOL DEFAULT FALSE,
    vuln_count      INT DEFAULT 0,
    critical_vuln_count INT DEFAULT 0,
    risk_score      INT DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    -- Origin
    source_repo     TEXT,
    source_hash     TEXT,                          -- commit/tag hash
    -- Usage
    used_in         TEXT[] DEFAULT '{}',           -- application/service names
    is_direct       BOOL DEFAULT TRUE,             -- direct vs transitive dependency
    tags            TEXT[] DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scs_components_tenant  ON scs_components (tenant_id, ecosystem);
CREATE INDEX IF NOT EXISTS idx_scs_components_vendor  ON scs_components (vendor_id);
CREATE INDEX IF NOT EXISTS idx_scs_components_purl    ON scs_components (tenant_id, purl) WHERE purl IS NOT NULL;

-- SBOM (Software Bill of Materials) documents
CREATE TABLE IF NOT EXISTS scs_sboms (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,                 -- application/product name
    version         TEXT,
    sbom_format     TEXT DEFAULT 'cyclonedx' CHECK (sbom_format IN ('cyclonedx','spdx','syft','custom')),
    -- Component summary
    total_components INT DEFAULT 0,
    direct_components INT DEFAULT 0,
    transitive_components INT DEFAULT 0,
    -- Risk summary
    critical_vulns  INT DEFAULT 0,
    high_vulns      INT DEFAULT 0,
    medium_vulns    INT DEFAULT 0,
    low_vulns       INT DEFAULT 0,
    deprecated_count INT DEFAULT 0,
    eol_count       INT DEFAULT 0,
    risk_score      INT DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    -- Raw SBOM data
    raw_data        JSONB DEFAULT '{}',
    -- Source
    source          TEXT,                          -- e.g. "CI/CD pipeline", "manual upload"
    source_ref      TEXT,                          -- build ID, commit SHA
    generated_at    TIMESTAMPTZ DEFAULT NOW(),
    created_by      UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scs_sboms_tenant ON scs_sboms (tenant_id, generated_at DESC);

-- SBOM component membership
CREATE TABLE IF NOT EXISTS scs_sbom_components (
    sbom_id         UUID NOT NULL REFERENCES scs_sboms(id) ON DELETE CASCADE,
    component_id    UUID NOT NULL REFERENCES scs_components(id) ON DELETE CASCADE,
    PRIMARY KEY (sbom_id, component_id)
);

-- Vendor assessments / questionnaires
CREATE TABLE IF NOT EXISTS scs_assessments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    vendor_id       UUID NOT NULL REFERENCES scs_vendors(id) ON DELETE CASCADE,
    assessment_type TEXT DEFAULT 'security_questionnaire' CHECK (assessment_type IN (
                        'security_questionnaire','penetration_test','audit',
                        'document_review','on_site_visit','automated_scan')),
    status          TEXT DEFAULT 'planned' CHECK (status IN (
                        'planned','in_progress','completed','overdue','cancelled')),
    -- Scoring
    score           INT CHECK (score BETWEEN 0 AND 100),
    max_score       INT DEFAULT 100,
    risk_rating     TEXT CHECK (risk_rating IN ('critical','high','medium','low','not_rated')),
    -- Findings
    findings_count  INT DEFAULT 0,
    critical_findings INT DEFAULT 0,
    -- Dates
    planned_at      TIMESTAMPTZ,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    due_at          TIMESTAMPTZ,
    next_due_at     TIMESTAMPTZ,
    -- Details
    assessor        TEXT,
    assessor_id     UUID,
    questionnaire   JSONB DEFAULT '{}',            -- Q&A responses
    findings        JSONB DEFAULT '[]',            -- finding objects
    recommendations TEXT,
    notes           TEXT,
    created_by      UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scs_assessments_vendor ON scs_assessments (vendor_id, status);
CREATE INDEX IF NOT EXISTS idx_scs_assessments_tenant ON scs_assessments (tenant_id, status, due_at);

-- Supply chain incidents / alerts
CREATE TABLE IF NOT EXISTS scs_alerts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    vendor_id       UUID REFERENCES scs_vendors(id) ON DELETE SET NULL,
    component_id    UUID REFERENCES scs_components(id) ON DELETE SET NULL,
    alert_type      TEXT NOT NULL CHECK (alert_type IN (
                        'new_vulnerability','dependency_compromise','license_violation',
                        'eol_component','malicious_package','typosquatting',
                        'vendor_breach','data_leak','policy_violation','other')),
    severity        TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    status          TEXT DEFAULT 'open' CHECK (status IN (
                        'open','acknowledged','investigating','resolved','false_positive')),
    title           TEXT NOT NULL,
    description     TEXT,
    -- Affected
    affected_components TEXT[] DEFAULT '{}',
    affected_systems    TEXT[] DEFAULT '{}',
    -- CVE / advisory
    cve_ids         TEXT[] DEFAULT '{}',
    advisory_url    TEXT,
    -- Response
    remediation     TEXT,
    resolved_by     TEXT,
    resolved_at     TIMESTAMPTZ,
    -- Source
    source          TEXT,                          -- e.g. "OSV", "GitHub Advisory", "NVD"
    source_ref      TEXT,
    detected_at     TIMESTAMPTZ DEFAULT NOW(),
    tags            TEXT[] DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scs_alerts_tenant   ON scs_alerts (tenant_id, status, severity);
CREATE INDEX IF NOT EXISTS idx_scs_alerts_vendor   ON scs_alerts (vendor_id, status) WHERE vendor_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scs_alerts_detected ON scs_alerts (tenant_id, detected_at DESC);

-- Supply chain policies
CREATE TABLE IF NOT EXISTS scs_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    policy_type     TEXT NOT NULL CHECK (policy_type IN (
                        'license_allowlist','license_blocklist','vulnerability_threshold',
                        'vendor_tier','eol_prohibition','approved_registries','other')),
    -- Rule definition (flexible JSONB)
    rule            JSONB NOT NULL DEFAULT '{}',
    -- Enforcement
    action          TEXT DEFAULT 'alert' CHECK (action IN ('alert','block','notify','log')),
    is_active       BOOL DEFAULT TRUE,
    created_by      UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scs_policies_tenant ON scs_policies (tenant_id, policy_type, is_active);
