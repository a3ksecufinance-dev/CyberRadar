-- ============================================================
-- Domain 7 — Vulnerability & Exposure Management
-- ============================================================

-- Vulnerability / CVE library
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL,
    cve_id            VARCHAR(20),                           -- CVE-2024-XXXXX (NULL for non-CVE findings)
    title             TEXT        NOT NULL,
    description       TEXT,
    -- CVSS v3
    cvss_score        FLOAT       NOT NULL DEFAULT 0.0,     -- 0.0-10.0
    cvss_vector       TEXT,                                  -- CVSS:3.1/AV:N/AC:L/...
    cvss_severity     VARCHAR(20) NOT NULL DEFAULT 'MEDIUM', -- CRITICAL | HIGH | MEDIUM | LOW | INFO | NONE
    -- Exploitability
    is_exploited      BOOLEAN     NOT NULL DEFAULT false,    -- known exploited in the wild (KEV)
    exploit_available BOOLEAN     NOT NULL DEFAULT false,    -- PoC or public exploit exists
    epss_score        FLOAT       NOT NULL DEFAULT 0.0,      -- 0.0-1.0 EPSS probability
    -- CWE / categorization
    cwe_id            VARCHAR(20),
    cwe_name          TEXT,
    -- MITRE ATT&CK mapping
    mitre_technique   TEXT,
    -- Affected software/products (CPE-like)
    affected_products TEXT[]      NOT NULL DEFAULT '{}',
    -- Patch info
    patch_available   BOOLEAN     NOT NULL DEFAULT false,
    patch_url         TEXT,
    -- Publication dates
    published_at      TIMESTAMPTZ,
    modified_at       TIMESTAMPTZ,
    -- External references
    nvd_url           TEXT,
    references        TEXT[]      NOT NULL DEFAULT '{}',
    tags              TEXT[]      NOT NULL DEFAULT '{}',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, cve_id)
);

CREATE INDEX idx_vuln_tenant         ON vulnerabilities(tenant_id);
CREATE INDEX idx_vuln_cve            ON vulnerabilities(cve_id) WHERE cve_id IS NOT NULL;
CREATE INDEX idx_vuln_cvss_severity  ON vulnerabilities(tenant_id, cvss_severity);
CREATE INDEX idx_vuln_exploited      ON vulnerabilities(tenant_id) WHERE is_exploited = true;
CREATE INDEX idx_vuln_cvss_score     ON vulnerabilities(tenant_id, cvss_score DESC);

-- Asset ↔ Vulnerability linkage (one row per finding per asset)
CREATE TABLE IF NOT EXISTS asset_vulnerabilities (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    asset_id        UUID        NOT NULL,                    -- FK to assets.id
    vuln_id         UUID        NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    -- Finding metadata
    scan_job_id     UUID,                                    -- which scan detected this
    status          VARCHAR(30) NOT NULL DEFAULT 'open',
    -- open | in_remediation | resolved | accepted_risk | false_positive
    -- Risk context (computed)
    exposure_score  FLOAT       NOT NULL DEFAULT 0.0,        -- cvss × criticality multiplier, 0-10
    -- Port / service context
    port            INT,
    protocol        VARCHAR(10),
    service_name    TEXT,
    -- Dates
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    sla_due_at      TIMESTAMPTZ,                             -- computed from severity SLA policy
    -- Remediation tracking
    remediation_ticket_id UUID,
    assignee_id     UUID,
    notes           TEXT,
    -- Evidence
    evidence        JSONB       NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, asset_id, vuln_id)
);

CREATE INDEX idx_av_tenant       ON asset_vulnerabilities(tenant_id);
CREATE INDEX idx_av_asset        ON asset_vulnerabilities(tenant_id, asset_id);
CREATE INDEX idx_av_vuln         ON asset_vulnerabilities(vuln_id);
CREATE INDEX idx_av_status       ON asset_vulnerabilities(tenant_id, status);
CREATE INDEX idx_av_exposure     ON asset_vulnerabilities(tenant_id, exposure_score DESC);
CREATE INDEX idx_av_sla          ON asset_vulnerabilities(tenant_id, sla_due_at) WHERE status = 'open' OR status = 'in_remediation';
CREATE INDEX idx_av_scan         ON asset_vulnerabilities(scan_job_id) WHERE scan_job_id IS NOT NULL;

-- Scan jobs (manual or scheduled vulnerability scans)
CREATE TABLE IF NOT EXISTS vuln_scan_jobs (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    name            TEXT        NOT NULL,
    scan_type       VARCHAR(20) NOT NULL DEFAULT 'network',  -- network | web | container | config | cloud
    targets         JSONB       NOT NULL DEFAULT '{}',       -- {asset_ids:[], ip_ranges:[], tags:[]}
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',  -- pending | running | completed | failed | cancelled
    triggered_by    UUID,                                    -- user who started it
    scheduled_at    TIMESTAMPTZ,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    -- Results summary
    total_assets    INT         NOT NULL DEFAULT 0,
    scanned_assets  INT         NOT NULL DEFAULT 0,
    total_findings  INT         NOT NULL DEFAULT 0,
    new_findings    INT         NOT NULL DEFAULT 0,
    resolved_findings INT       NOT NULL DEFAULT 0,
    -- Severity breakdown
    critical_count  INT         NOT NULL DEFAULT 0,
    high_count      INT         NOT NULL DEFAULT 0,
    medium_count    INT         NOT NULL DEFAULT 0,
    low_count       INT         NOT NULL DEFAULT 0,
    error_message   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_tenant  ON vuln_scan_jobs(tenant_id);
CREATE INDEX idx_scan_status  ON vuln_scan_jobs(tenant_id, status);
CREATE INDEX idx_scan_created ON vuln_scan_jobs(tenant_id, created_at DESC);

-- Remediation tickets (bridge to ticketing / SOAR)
CREATE TABLE IF NOT EXISTS remediation_tickets (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    title           TEXT        NOT NULL,
    description     TEXT,
    status          VARCHAR(20) NOT NULL DEFAULT 'open',     -- open | in_progress | resolved | wont_fix | accepted_risk
    priority        SMALLINT    NOT NULL DEFAULT 2,          -- 1=low 2=medium 3=high 4=critical
    assignee_id     UUID,
    created_by      UUID,
    -- Linked findings
    finding_count   INT         NOT NULL DEFAULT 0,
    affected_asset_count INT    NOT NULL DEFAULT 0,
    -- SLA
    sla_due_at      TIMESTAMPTZ,
    resolved_at     TIMESTAMPTZ,
    -- External reference (JIRA, ServiceNow, etc.)
    external_id     TEXT,
    external_url    TEXT,
    tags            TEXT[]      NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rt_tenant    ON remediation_tickets(tenant_id);
CREATE INDEX idx_rt_status    ON remediation_tickets(tenant_id, status);
CREATE INDEX idx_rt_assignee  ON remediation_tickets(assignee_id) WHERE assignee_id IS NOT NULL;
CREATE INDEX idx_rt_priority  ON remediation_tickets(tenant_id, priority DESC);
CREATE INDEX idx_rt_sla       ON remediation_tickets(tenant_id, sla_due_at) WHERE status NOT IN ('resolved','wont_fix');
