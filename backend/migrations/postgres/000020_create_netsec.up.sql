-- ============================================================
-- Domain 18: Network Security & Microsegmentation
-- ============================================================

-- Network zones (DMZ, PROD, MGMT, SWIFT, etc.)
CREATE TABLE IF NOT EXISTS netsec_zones (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    zone_type       TEXT NOT NULL CHECK (zone_type IN (
                        'dmz','production','management','swift','atm','internet',
                        'guest','iot','development','dr','restricted')),
    trust_level     INT NOT NULL DEFAULT 50 CHECK (trust_level BETWEEN 0 AND 100),
    cidr_blocks     TEXT[] DEFAULT '{}',          -- IP ranges belonging to this zone
    color           TEXT DEFAULT '#6B7280',
    is_active       BOOL DEFAULT TRUE,
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_netsec_zones_tenant ON netsec_zones (tenant_id, is_active);

-- Microsegmentation policies (zone-to-zone rules)
CREATE TABLE IF NOT EXISTS netsec_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    src_zone_id     UUID REFERENCES netsec_zones(id) ON DELETE CASCADE,
    dst_zone_id     UUID REFERENCES netsec_zones(id) ON DELETE CASCADE,
    src_cidr        TEXT,                         -- optional override
    dst_cidr        TEXT,
    protocol        TEXT DEFAULT 'any' CHECK (protocol IN ('tcp','udp','icmp','any')),
    ports           TEXT[] DEFAULT '{}',          -- e.g. ["80","443","8080-8090"]
    action          TEXT NOT NULL CHECK (action IN ('allow','deny','log','inspect')),
    priority        INT DEFAULT 100,              -- lower = higher priority
    is_active       BOOL DEFAULT TRUE,
    hit_count       BIGINT DEFAULT 0,
    last_hit_at     TIMESTAMPTZ,
    created_by      UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_netsec_policies_tenant      ON netsec_policies (tenant_id, is_active);
CREATE INDEX IF NOT EXISTS idx_netsec_policies_zones       ON netsec_policies (src_zone_id, dst_zone_id);

-- Network flows: observed traffic between endpoints
CREATE TABLE IF NOT EXISTS netsec_flows (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    src_ip          INET NOT NULL,
    dst_ip          INET NOT NULL,
    src_port        INT,
    dst_port        INT,
    protocol        TEXT,
    bytes_sent      BIGINT DEFAULT 0,
    bytes_recv      BIGINT DEFAULT 0,
    packets         BIGINT DEFAULT 0,
    duration_ms     INT DEFAULT 0,
    src_zone_id     UUID REFERENCES netsec_zones(id) ON DELETE SET NULL,
    dst_zone_id     UUID REFERENCES netsec_zones(id) ON DELETE SET NULL,
    action          TEXT DEFAULT 'allowed' CHECK (action IN ('allowed','blocked','inspected')),
    anomaly_score   INT DEFAULT 0 CHECK (anomaly_score BETWEEN 0 AND 100),
    flags           TEXT[] DEFAULT '{}',          -- anomaly tags: lateral_movement/data_exfil/port_scan/beacon
    flow_start      TIMESTAMPTZ NOT NULL,
    flow_end        TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_netsec_flows_tenant      ON netsec_flows (tenant_id, flow_start DESC);
CREATE INDEX IF NOT EXISTS idx_netsec_flows_src_ip      ON netsec_flows (tenant_id, src_ip);
CREATE INDEX IF NOT EXISTS idx_netsec_flows_dst_ip      ON netsec_flows (tenant_id, dst_ip);
CREATE INDEX IF NOT EXISTS idx_netsec_flows_anomaly     ON netsec_flows (tenant_id, anomaly_score DESC);

-- Network anomalies detected from flow analysis
CREATE TABLE IF NOT EXISTS netsec_anomalies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    anomaly_type    TEXT NOT NULL CHECK (anomaly_type IN (
                        'port_scan','lateral_movement','data_exfiltration',
                        'beaconing','dns_tunneling','policy_violation',
                        'unusual_volume','east_west_anomaly','c2_traffic')),
    severity        TEXT NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    src_ip          INET,
    dst_ip          INET,
    src_zone_id     UUID REFERENCES netsec_zones(id) ON DELETE SET NULL,
    dst_zone_id     UUID REFERENCES netsec_zones(id) ON DELETE SET NULL,
    flow_ids        UUID[] DEFAULT '{}',          -- contributing flows
    description     TEXT NOT NULL,
    evidence        JSONB DEFAULT '{}',
    status          TEXT DEFAULT 'open' CHECK (status IN ('open','investigating','false_positive','resolved')),
    resolved_at     TIMESTAMPTZ,
    detected_at     TIMESTAMPTZ DEFAULT NOW(),
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_netsec_anomalies_tenant      ON netsec_anomalies (tenant_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_netsec_anomalies_severity    ON netsec_anomalies (tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_netsec_anomalies_status      ON netsec_anomalies (tenant_id, status);

-- Network devices inventory (firewalls, switches, routers, load balancers)
CREATE TABLE IF NOT EXISTS netsec_devices (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    device_type     TEXT NOT NULL CHECK (device_type IN (
                        'firewall','switch','router','load_balancer',
                        'ids_ips','waf','vpn_gateway','proxy','dns')),
    ip_address      INET NOT NULL,
    zone_id         UUID REFERENCES netsec_zones(id) ON DELETE SET NULL,
    vendor          TEXT,
    model           TEXT,
    firmware        TEXT,
    is_managed      BOOL DEFAULT TRUE,
    last_seen_at    TIMESTAMPTZ DEFAULT NOW(),
    status          TEXT DEFAULT 'online' CHECK (status IN ('online','offline','degraded','unknown')),
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (tenant_id, ip_address)
);

CREATE INDEX IF NOT EXISTS idx_netsec_devices_tenant  ON netsec_devices (tenant_id, device_type);
CREATE INDEX IF NOT EXISTS idx_netsec_devices_zone    ON netsec_devices (zone_id);
