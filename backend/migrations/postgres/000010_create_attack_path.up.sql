-- ============================================================
-- Domain 8 — Attack Path Analysis
-- ============================================================

-- Attack graph nodes: assets, identities, services, cloud resources
CREATE TABLE IF NOT EXISTS attack_nodes (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    -- Reference to the originating domain
    ref_id          UUID        NOT NULL,        -- asset_id | identity_id | etc.
    node_type       VARCHAR(20) NOT NULL,        -- asset | identity | service | network | cloud
    label           TEXT        NOT NULL,        -- human-readable name
    -- Risk context
    risk_score      FLOAT       NOT NULL DEFAULT 0.0,
    criticality     SMALLINT    NOT NULL DEFAULT 1,    -- 1-4 matching asset criticality
    -- Flags for path traversal weighting
    is_internet_facing BOOLEAN  NOT NULL DEFAULT false,
    is_privileged      BOOLEAN  NOT NULL DEFAULT false, -- has admin/root privileges
    is_critical_system BOOLEAN  NOT NULL DEFAULT false, -- CBS, SWIFT, payment
    is_compromised     BOOLEAN  NOT NULL DEFAULT false, -- actively flagged by SIEM/UEBA
    -- Vulnerability context (denormalized for graph traversal speed)
    has_critical_vuln  BOOLEAN  NOT NULL DEFAULT false,
    has_known_exploit  BOOLEAN  NOT NULL DEFAULT false,
    open_vuln_count    INT      NOT NULL DEFAULT 0,
    -- Geographic / network position
    network_zone    VARCHAR(50),        -- dmz | internal | management | restricted
    ip_address      INET,
    hostname        TEXT,
    -- Metadata
    properties      JSONB       NOT NULL DEFAULT '{}',
    last_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, ref_id, node_type)
);

CREATE INDEX idx_an_tenant         ON attack_nodes(tenant_id);
CREATE INDEX idx_an_ref            ON attack_nodes(tenant_id, ref_id);
CREATE INDEX idx_an_type           ON attack_nodes(tenant_id, node_type);
CREATE INDEX idx_an_internet       ON attack_nodes(tenant_id) WHERE is_internet_facing = true;
CREATE INDEX idx_an_critical       ON attack_nodes(tenant_id) WHERE is_critical_system = true;
CREATE INDEX idx_an_compromised    ON attack_nodes(tenant_id) WHERE is_compromised = true;
CREATE INDEX idx_an_risk           ON attack_nodes(tenant_id, risk_score DESC);

-- Attack graph edges: possible lateral movement / privilege escalation vectors
CREATE TABLE IF NOT EXISTS attack_edges (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    source_id       UUID        NOT NULL REFERENCES attack_nodes(id) ON DELETE CASCADE,
    target_id       UUID        NOT NULL REFERENCES attack_nodes(id) ON DELETE CASCADE,
    -- Edge type categorizes the attack vector
    edge_type       VARCHAR(30) NOT NULL,
    -- network_access | credential_reuse | exploit | trust_relationship
    -- rdp | ssh | smb | api_call | supply_chain | physical
    -- Exploitability metrics (lower = easier for attacker)
    attack_complexity VARCHAR(10) NOT NULL DEFAULT 'LOW',   -- LOW | MEDIUM | HIGH
    privileges_required VARCHAR(10) NOT NULL DEFAULT 'NONE', -- NONE | LOW | HIGH
    -- CVE / vulnerability driving this edge (if any)
    vuln_id         UUID,
    cve_id          TEXT,
    -- MITRE ATT&CK technique
    mitre_technique TEXT,
    -- Computed edge weight for Dijkstra/BFS (lower = attacker prefers)
    weight          FLOAT       NOT NULL DEFAULT 1.0,
    -- Is this edge currently active (not blocked by firewall/policy)
    is_active       BOOLEAN     NOT NULL DEFAULT true,
    -- Evidence / source
    evidence_source VARCHAR(30) NOT NULL DEFAULT 'computed',
    -- computed | scan | alert | manual
    properties      JSONB       NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, source_id, target_id, edge_type)
);

CREATE INDEX idx_ae_tenant   ON attack_edges(tenant_id);
CREATE INDEX idx_ae_source   ON attack_edges(source_id);
CREATE INDEX idx_ae_target   ON attack_edges(target_id);
CREATE INDEX idx_ae_active   ON attack_edges(tenant_id, is_active);
CREATE INDEX idx_ae_weight   ON attack_edges(tenant_id, weight);

-- Attack scenarios: named simulation targets (e.g. "reach CBS core banking")
CREATE TABLE IF NOT EXISTS attack_scenarios (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    name            TEXT        NOT NULL,
    description     TEXT,
    -- Entry points and targets
    entry_node_ids  UUID[]      NOT NULL DEFAULT '{}',  -- starting nodes (internet-facing)
    target_node_ids UUID[]      NOT NULL DEFAULT '{}',  -- high-value targets
    -- Simulation parameters
    max_hops        INT         NOT NULL DEFAULT 10,
    include_types   TEXT[]      NOT NULL DEFAULT '{}',  -- filter node types to include
    -- Results summary (updated after each analysis run)
    status          VARCHAR(20) NOT NULL DEFAULT 'pending', -- pending | running | completed | failed
    path_count      INT         NOT NULL DEFAULT 0,
    shortest_path   INT,                               -- hops in shortest path found
    critical_path   INT,                               -- hops in most critical path
    last_run_at     TIMESTAMPTZ,
    last_run_ms     INT,                               -- analysis duration in ms
    risk_score      FLOAT       NOT NULL DEFAULT 0.0,  -- overall scenario risk 0-10
    created_by      UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);

CREATE INDEX idx_as_tenant  ON attack_scenarios(tenant_id);
CREATE INDEX idx_as_status  ON attack_scenarios(tenant_id, status);

-- Attack paths: discovered chains from entry to target
CREATE TABLE IF NOT EXISTS attack_paths (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    scenario_id     UUID        NOT NULL REFERENCES attack_scenarios(id) ON DELETE CASCADE,
    entry_node_id   UUID        NOT NULL REFERENCES attack_nodes(id),
    target_node_id  UUID        NOT NULL REFERENCES attack_nodes(id),
    -- Ordered list of node IDs forming the path
    node_sequence   UUID[]      NOT NULL,
    -- Ordered list of edge IDs
    edge_sequence   UUID[]      NOT NULL,
    hop_count       INT         NOT NULL,
    -- Path-level risk score (aggregate of node/edge weights)
    path_score      FLOAT       NOT NULL DEFAULT 0.0,   -- higher = more dangerous
    -- Attack likelihood and impact
    likelihood      FLOAT       NOT NULL DEFAULT 0.0,   -- 0.0-1.0
    impact          FLOAT       NOT NULL DEFAULT 0.0,   -- 0.0-10.0
    -- Classification
    path_type       VARCHAR(20) NOT NULL DEFAULT 'lateral_movement',
    -- lateral_movement | privilege_escalation | data_access | exfiltration
    has_internet_entry  BOOLEAN NOT NULL DEFAULT false,
    has_exploit_step    BOOLEAN NOT NULL DEFAULT false,  -- at least one CVE-exploitable edge
    has_priv_esc        BOOLEAN NOT NULL DEFAULT false,
    -- MITRE tactics observed along path
    mitre_tactics   TEXT[]      NOT NULL DEFAULT '{}',
    -- Remediation hint: which node/edge to block to break this path
    choke_point_node_id UUID,
    choke_point_edge_id UUID,
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ap_tenant    ON attack_paths(tenant_id);
CREATE INDEX idx_ap_scenario  ON attack_paths(scenario_id);
CREATE INDEX idx_ap_score     ON attack_paths(tenant_id, path_score DESC);
CREATE INDEX idx_ap_target    ON attack_paths(tenant_id, target_node_id);
CREATE INDEX idx_ap_entry     ON attack_paths(tenant_id, entry_node_id);
CREATE INDEX idx_ap_hops      ON attack_paths(tenant_id, hop_count);
