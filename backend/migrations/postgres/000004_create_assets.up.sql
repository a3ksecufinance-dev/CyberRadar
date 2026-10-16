-- Migration: 000004_create_assets
-- Domain 2 — Asset Intelligence: inventory, relationships, scan history

-- ─── Asset types (enum-like) ──────────────────────────────────────────────────
-- Stored as VARCHAR to avoid migration churn when adding new types.
-- Valid values enforced at application layer.

-- ─── Assets ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS assets (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Identity
    name                VARCHAR(255) NOT NULL,
    hostname            VARCHAR(255),
    fqdn                VARCHAR(512),
    ip_addresses        TEXT[] NOT NULL DEFAULT '{}',
    mac_addresses       TEXT[] NOT NULL DEFAULT '{}',

    -- Classification
    asset_type          VARCHAR(50)  NOT NULL,   -- server, workstation, network, firewall,
                                                  -- cbs_server, atm, swift_gateway,
                                                  -- payment_terminal, database, cloud_instance
    os                  VARCHAR(100),
    os_version          VARCHAR(50),
    criticality         SMALLINT     NOT NULL DEFAULT 2  CHECK (criticality BETWEEN 1 AND 4),
                                                  -- 1=low 2=medium 3=high 4=critical
    status              VARCHAR(20)  NOT NULL DEFAULT 'active'
                                        CHECK (status IN ('active','inactive','decommissioned','unknown')),
    environment         VARCHAR(20)  NOT NULL DEFAULT 'production'
                                        CHECK (environment IN ('production','staging','development','dmz')),

    -- Ownership
    owner_id            UUID REFERENCES identities(id) ON DELETE SET NULL,
    department          VARCHAR(100),
    location            VARCHAR(255),
    business_service    VARCHAR(100),

    -- Banking-specific flags
    is_cbs_connected    BOOLEAN NOT NULL DEFAULT false,
    is_swift_connected  BOOLEAN NOT NULL DEFAULT false,
    is_pci_scope        BOOLEAN NOT NULL DEFAULT false,

    -- Flexible metadata
    tags                TEXT[]  NOT NULL DEFAULT '{}',
    metadata            JSONB   NOT NULL DEFAULT '{}',

    -- Risk
    risk_score          FLOAT   NOT NULL DEFAULT 0.0,
    vuln_critical       INT     NOT NULL DEFAULT 0,
    vuln_high           INT     NOT NULL DEFAULT 0,
    vuln_medium         INT     NOT NULL DEFAULT 0,
    vuln_low            INT     NOT NULL DEFAULT 0,

    -- Discovery
    discovered_by       VARCHAR(50) DEFAULT 'manual',  -- manual, auto, scan, agent
    last_seen_at        TIMESTAMP WITH TIME ZONE,
    first_seen_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Audit
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    deleted_at          TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_assets_tenant             ON assets(tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_assets_tenant_type        ON assets(tenant_id, asset_type) WHERE deleted_at IS NULL;
CREATE INDEX idx_assets_tenant_criticality ON assets(tenant_id, criticality DESC) WHERE deleted_at IS NULL;
CREATE INDEX idx_assets_tenant_risk        ON assets(tenant_id, risk_score DESC) WHERE deleted_at IS NULL;
CREATE INDEX idx_assets_ip                 ON assets USING GIN(ip_addresses) WHERE deleted_at IS NULL;
CREATE INDEX idx_assets_hostname           ON assets(tenant_id, hostname) WHERE deleted_at IS NULL AND hostname IS NOT NULL;
CREATE INDEX idx_assets_tags               ON assets USING GIN(tags) WHERE deleted_at IS NULL;
CREATE INDEX idx_assets_last_seen          ON assets(tenant_id, last_seen_at DESC) WHERE deleted_at IS NULL;

CREATE TRIGGER assets_updated_at
    BEFORE UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ─── Asset Relationships ──────────────────────────────────────────────────────
-- Directed graph edges — also mirrored in Neo4j (D9).
CREATE TABLE IF NOT EXISTS asset_relationships (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source_id           UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    target_id           UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    -- Relationship types (MITRE-aligned where applicable)
    relationship_type   VARCHAR(50) NOT NULL,    -- CONNECTS_TO, RUNS_ON, DEPENDS_ON,
                                                  -- HOSTS, MANAGED_BY, BACKS_UP, REPLICATES_TO
    bidirectional       BOOLEAN NOT NULL DEFAULT false,
    properties          JSONB NOT NULL DEFAULT '{}',
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_asset_rel UNIQUE (tenant_id, source_id, target_id, relationship_type)
);

CREATE INDEX idx_asset_rel_source ON asset_relationships(tenant_id, source_id);
CREATE INDEX idx_asset_rel_target ON asset_relationships(tenant_id, target_id);

-- ─── Asset Scan History ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS asset_scans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id        UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_type       VARCHAR(50) NOT NULL,   -- vuln_scan, compliance, config_audit, port_scan
    status          VARCHAR(20) NOT NULL DEFAULT 'running'
                        CHECK (status IN ('running','completed','failed','cancelled')),
    scanner         VARCHAR(100),            -- Nessus, OpenVAS, Qualys, CRP-native
    findings_count  INT NOT NULL DEFAULT 0,
    critical_count  INT NOT NULL DEFAULT 0,
    high_count      INT NOT NULL DEFAULT 0,
    medium_count    INT NOT NULL DEFAULT 0,
    low_count       INT NOT NULL DEFAULT 0,
    scan_data       JSONB NOT NULL DEFAULT '{}',
    started_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_asset_scans_asset     ON asset_scans(tenant_id, asset_id, started_at DESC);
CREATE INDEX idx_asset_scans_status    ON asset_scans(tenant_id, status) WHERE status = 'running';

-- ─── Asset Discovery Queue ────────────────────────────────────────────────────
-- Auto-discovery candidates seen in events but not yet in inventory.
CREATE TABLE IF NOT EXISTS asset_discovery_queue (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    hostname        VARCHAR(255),
    ip_address      VARCHAR(45),
    source_type     VARCHAR(50),        -- which connector saw it
    connector_id    VARCHAR(255),
    event_count     INT NOT NULL DEFAULT 1,
    first_seen_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    resolved        BOOLEAN NOT NULL DEFAULT false,
    resolved_asset_id UUID REFERENCES assets(id),
    resolved_at     TIMESTAMP WITH TIME ZONE,

    CONSTRAINT uq_discovery UNIQUE (tenant_id, ip_address)
);

CREATE INDEX idx_discovery_queue_tenant   ON asset_discovery_queue(tenant_id) WHERE resolved = false;
CREATE INDEX idx_discovery_queue_ip       ON asset_discovery_queue(tenant_id, ip_address);
