-- ============================================================
-- Domain 24: OT/ICS Security
-- ============================================================

-- OT/ICS Assets (PLCs, HMIs, RTUs, sensors, historians, etc.)
CREATE TABLE IF NOT EXISTS ot_assets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    asset_type      TEXT NOT NULL CHECK (asset_type IN (
                        'plc','hmi','rtu','sensor','historian','scada','dcs',
                        'engineering_workstation','ied','firewall','switch',
                        'gateway','safety_system','other')),
    -- Identification
    vendor          TEXT,
    model           TEXT,
    firmware_version TEXT,
    serial_number   TEXT,
    -- Network
    ip_address      TEXT,
    mac_address     TEXT,
    protocol        TEXT[],                        -- e.g. Modbus, DNP3, IEC 61850, OPC-UA
    -- Location
    site            TEXT,                          -- plant / facility name
    zone            TEXT,                          -- Purdue level zone
    purdue_level    INT CHECK (purdue_level BETWEEN 0 AND 5),
                                                   -- 0=field, 1=control, 2=supervisory, 3=mfg, 4=business, 5=enterprise
    -- Security
    risk_score      INT DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    risk_level      TEXT DEFAULT 'medium' CHECK (risk_level IN ('critical','high','medium','low')),
    is_internet_facing BOOL DEFAULT FALSE,
    is_patched      BOOL DEFAULT FALSE,
    last_patched_at TIMESTAMPTZ,
    -- Operational
    is_active       BOOL DEFAULT TRUE,
    criticality     TEXT DEFAULT 'medium' CHECK (criticality IN ('critical','high','medium','low')),
    -- Lifecycle
    install_date    DATE,
    end_of_life_date DATE,
    -- Metadata
    tags            TEXT[] DEFAULT '{}',
    metadata        JSONB DEFAULT '{}',
    created_by      UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ot_assets_tenant   ON ot_assets (tenant_id, asset_type, risk_level);
CREATE INDEX IF NOT EXISTS idx_ot_assets_site     ON ot_assets (tenant_id, site, zone);
CREATE INDEX IF NOT EXISTS idx_ot_assets_purdue   ON ot_assets (tenant_id, purdue_level);

-- OT Network Zones (Purdue model segments)
CREATE TABLE IF NOT EXISTS ot_zones (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    zone_type       TEXT NOT NULL CHECK (zone_type IN (
                        'dmz','control','supervisory','enterprise','safety','external','cloud')),
    purdue_level    INT CHECK (purdue_level BETWEEN 0 AND 5),
    site            TEXT,
    -- Security posture
    is_air_gapped   BOOL DEFAULT FALSE,
    firewall_present BOOL DEFAULT FALSE,
    ids_present     BOOL DEFAULT FALSE,
    risk_score      INT DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    asset_count     INT DEFAULT 0,
    -- CIDR / network info
    network_ranges  TEXT[] DEFAULT '{}',
    created_by      UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (tenant_id, name, site)
);

CREATE INDEX IF NOT EXISTS idx_ot_zones_tenant ON ot_zones (tenant_id, site);

-- OT Network Communications (allowed / discovered flows between zones or assets)
CREATE TABLE IF NOT EXISTS ot_communications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    src_asset_id    UUID REFERENCES ot_assets(id) ON DELETE CASCADE,
    dst_asset_id    UUID REFERENCES ot_assets(id) ON DELETE CASCADE,
    src_zone_id     UUID REFERENCES ot_zones(id) ON DELETE SET NULL,
    dst_zone_id     UUID REFERENCES ot_zones(id) ON DELETE SET NULL,
    protocol        TEXT,
    port            INT,
    direction       TEXT DEFAULT 'bidirectional' CHECK (direction IN ('inbound','outbound','bidirectional')),
    -- Validation
    is_authorized   BOOL DEFAULT TRUE,
    is_anomalous    BOOL DEFAULT FALSE,
    first_seen_at   TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ DEFAULT NOW(),
    packet_count    BIGINT DEFAULT 0,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ot_comms_tenant ON ot_communications (tenant_id, is_anomalous);
CREATE INDEX IF NOT EXISTS idx_ot_comms_assets ON ot_communications (src_asset_id, dst_asset_id);

-- OT Vulnerabilities (CVEs specific to ICS/OT assets)
CREATE TABLE IF NOT EXISTS ot_vulnerabilities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    asset_id        UUID NOT NULL REFERENCES ot_assets(id) ON DELETE CASCADE,
    cve_id          TEXT,
    ics_cert_id     TEXT,                          -- ICS-CERT advisory ID
    title           TEXT NOT NULL,
    description     TEXT,
    severity        TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    cvss_score      NUMERIC(4,2),
    -- OT-specific impact
    affects_availability BOOL DEFAULT FALSE,
    affects_safety       BOOL DEFAULT FALSE,
    potential_impact TEXT,                         -- e.g. "process shutdown", "equipment damage"
    -- Status
    status          TEXT DEFAULT 'open' CHECK (status IN (
                        'open','acknowledged','mitigated','patched','accepted','false_positive')),
    -- Patch info
    patch_available BOOL DEFAULT FALSE,
    patch_notes     TEXT,
    workaround      TEXT,
    -- Dates
    discovered_at   TIMESTAMPTZ DEFAULT NOW(),
    remediated_at   TIMESTAMPTZ,
    tags            TEXT[] DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ot_vulns_asset  ON ot_vulnerabilities (asset_id, status);
CREATE INDEX IF NOT EXISTS idx_ot_vulns_tenant ON ot_vulnerabilities (tenant_id, severity, status);

-- OT Security Events / Alerts
CREATE TABLE IF NOT EXISTS ot_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    asset_id        UUID REFERENCES ot_assets(id) ON DELETE SET NULL,
    zone_id         UUID REFERENCES ot_zones(id) ON DELETE SET NULL,
    event_type      TEXT NOT NULL CHECK (event_type IN (
                        'unauthorized_access','anomalous_traffic','protocol_violation',
                        'firmware_change','config_change','scan_detected',
                        'malware_detected','dos_attempt','rogue_device',
                        'policy_violation','safety_alarm','process_anomaly','other')),
    severity        TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    status          TEXT DEFAULT 'open' CHECK (status IN (
                        'open','acknowledged','investigating','resolved','false_positive')),
    title           TEXT NOT NULL,
    description     TEXT,
    -- Source
    source_ip       TEXT,
    dest_ip         TEXT,
    protocol        TEXT,
    raw_payload     TEXT,
    -- Detection
    detected_by     TEXT,                          -- sensor / IDS / manual
    detection_rule  TEXT,
    -- Response
    acknowledged_by TEXT,
    acknowledged_at TIMESTAMPTZ,
    resolved_by     TEXT,
    resolved_at     TIMESTAMPTZ,
    -- Timestamps
    event_time      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tags            TEXT[] DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ot_events_tenant    ON ot_events (tenant_id, status, severity);
CREATE INDEX IF NOT EXISTS idx_ot_events_asset     ON ot_events (asset_id, event_time DESC) WHERE asset_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ot_events_time      ON ot_events (tenant_id, event_time DESC);

-- OT Security Policies (allowed protocols, zones, maintenance windows)
CREATE TABLE IF NOT EXISTS ot_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    policy_type     TEXT NOT NULL CHECK (policy_type IN (
                        'allowed_protocol','zone_isolation','change_control',
                        'patch_management','remote_access','backup','audit','other')),
    scope           TEXT DEFAULT 'global' CHECK (scope IN ('global','site','zone','asset')),
    scope_ref       UUID,                          -- site/zone/asset UUID
    -- Rule
    rule            JSONB NOT NULL DEFAULT '{}',
    action          TEXT DEFAULT 'alert' CHECK (action IN ('alert','block','notify','log','enforce')),
    is_active       BOOL DEFAULT TRUE,
    created_by      UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ot_policies_tenant ON ot_policies (tenant_id, policy_type, is_active);

-- OT Patch / Change Management
CREATE TABLE IF NOT EXISTS ot_patches (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    asset_id        UUID NOT NULL REFERENCES ot_assets(id) ON DELETE CASCADE,
    patch_type      TEXT DEFAULT 'firmware' CHECK (patch_type IN (
                        'firmware','software','configuration','hotfix','os')),
    title           TEXT NOT NULL,
    description     TEXT,
    version_before  TEXT,
    version_after   TEXT,
    cve_ids         TEXT[] DEFAULT '{}',
    -- Approval workflow
    status          TEXT DEFAULT 'pending' CHECK (status IN (
                        'pending','approved','scheduled','applied','failed','rolled_back')),
    risk_level      TEXT DEFAULT 'medium' CHECK (risk_level IN ('critical','high','medium','low')),
    requires_downtime BOOL DEFAULT TRUE,
    -- Scheduling
    scheduled_at    TIMESTAMPTZ,
    maintenance_window TEXT,                       -- e.g. "Saturday 02:00-06:00 UTC"
    -- Applied
    applied_at      TIMESTAMPTZ,
    applied_by      TEXT,
    rollback_plan   TEXT,
    notes           TEXT,
    created_by      UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ot_patches_asset  ON ot_patches (asset_id, status);
CREATE INDEX IF NOT EXISTS idx_ot_patches_tenant ON ot_patches (tenant_id, status, scheduled_at);
