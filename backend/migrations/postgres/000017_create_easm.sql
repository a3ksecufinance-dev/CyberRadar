-- ============================================================
-- Domain 15: External Attack Surface Management (EASM)
-- ============================================================

-- External assets discovered on the internet
CREATE TABLE IF NOT EXISTS easm_assets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    asset_type      TEXT NOT NULL CHECK (asset_type IN ('domain','subdomain','ip','cidr','asn','certificate','url')),
    value           TEXT NOT NULL,
    source          TEXT,                           -- dns_brute/cert_transparency/shodan_import/manual/mx_record
    status          TEXT DEFAULT 'active' CHECK (status IN ('active','inactive','unknown')),
    risk_score      INT DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    tags            TEXT[] DEFAULT '{}',
    first_seen_at   TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ DEFAULT NOW(),
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (tenant_id, asset_type, value)
);

CREATE INDEX IF NOT EXISTS idx_easm_assets_tenant_type  ON easm_assets (tenant_id, asset_type);
CREATE INDEX IF NOT EXISTS idx_easm_assets_tenant_risk  ON easm_assets (tenant_id, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_easm_assets_tenant_status ON easm_assets (tenant_id, status);

-- Exposure findings on discovered assets
CREATE TABLE IF NOT EXISTS easm_exposures (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID NOT NULL,
    asset_id         UUID NOT NULL REFERENCES easm_assets(id) ON DELETE CASCADE,
    exposure_type    TEXT NOT NULL CHECK (exposure_type IN (
                         'open_port','expired_tls','weak_cipher','http_redirect',
                         'dangling_dns','admin_interface','api_endpoint','sensitive_path')),
    port             INT,
    protocol         TEXT,
    title            TEXT NOT NULL,
    description      TEXT,
    severity         TEXT CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    is_remediated    BOOL DEFAULT FALSE,
    first_detected_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at     TIMESTAMPTZ DEFAULT NOW(),
    remediated_at    TIMESTAMPTZ,
    created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_easm_exposures_tenant_sev  ON easm_exposures (tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_easm_exposures_asset        ON easm_exposures (asset_id);
CREATE INDEX IF NOT EXISTS idx_easm_exposures_tenant_rem   ON easm_exposures (tenant_id, is_remediated);

-- Dark-web credential / data leaks
CREATE TABLE IF NOT EXISTS easm_leaks (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID NOT NULL,
    source           TEXT NOT NULL,                 -- forum name, breach DB, paste site, telegram
    breach_date      DATE,
    data_types       TEXT[] DEFAULT '{}',           -- email/password/hash/phone/card/ssn/internal_doc/api_key/source_code
    affected_count   INT,
    sample_data      TEXT,                          -- redacted
    severity         TEXT CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    is_acknowledged  BOOL DEFAULT FALSE,
    acknowledged_by  UUID,
    acknowledged_at  TIMESTAMPTZ,
    created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_easm_leaks_tenant           ON easm_leaks (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_easm_leaks_tenant_ack       ON easm_leaks (tenant_id, is_acknowledged);

-- Brand-abuse and phishing alerts
CREATE TABLE IF NOT EXISTS easm_brand_alerts (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID NOT NULL,
    alert_type       TEXT NOT NULL CHECK (alert_type IN (
                         'phishing_domain','typosquatting','impersonation',
                         'fake_app','social_media','dark_web_mention','paste_mention')),
    value            TEXT NOT NULL,                 -- detected domain / URL / mention
    similarity_score FLOAT,                         -- 0..1 for domain similarity
    status           TEXT DEFAULT 'new' CHECK (status IN (
                         'new','investigating','confirmed','false_positive',
                         'takedown_requested','resolved')),
    detected_at      TIMESTAMPTZ DEFAULT NOW(),
    resolved_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_easm_brand_tenant_type   ON easm_brand_alerts (tenant_id, alert_type);
CREATE INDEX IF NOT EXISTS idx_easm_brand_tenant_status ON easm_brand_alerts (tenant_id, status);

-- Discovery / audit scans
CREATE TABLE IF NOT EXISTS easm_scans (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID NOT NULL,
    scan_type        TEXT NOT NULL CHECK (scan_type IN (
                         'subdomain_enum','port_scan','tls_audit','leak_search','brand_monitor')),
    status           TEXT DEFAULT 'pending' CHECK (status IN ('pending','running','completed','failed')),
    targets          TEXT[] NOT NULL,
    assets_found     INT DEFAULT 0,
    exposures_found  INT DEFAULT 0,
    started_at       TIMESTAMPTZ,
    completed_at     TIMESTAMPTZ,
    error_text       TEXT,
    created_by       UUID,
    created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_easm_scans_tenant ON easm_scans (tenant_id, created_at DESC);
