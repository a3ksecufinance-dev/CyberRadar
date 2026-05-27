-- ============================================================
-- Domain 5 — UEBA : PostgreSQL behavioral profile tables
-- ============================================================

-- Entity behavioral baseline and risk profile
CREATE TABLE IF NOT EXISTS ueba_profiles (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL,
    entity_id         UUID        NOT NULL,
    entity_type       VARCHAR(20) NOT NULL DEFAULT 'user',    -- user | asset
    -- Learned baselines (append-only sets)
    normal_hours      INT[]       NOT NULL DEFAULT '{}',      -- UTC hours 0-23
    normal_countries  TEXT[]      NOT NULL DEFAULT '{}',
    normal_ip_prefixes TEXT[]     NOT NULL DEFAULT '{}',      -- /24 CIDR blocks
    normal_event_types TEXT[]     NOT NULL DEFAULT '{}',
    -- Dimensional risk scores 0.0-10.0
    risk_score        FLOAT       NOT NULL DEFAULT 0.0,
    login_score       FLOAT       NOT NULL DEFAULT 0.0,       -- auth failures, new locations
    access_score      FLOAT       NOT NULL DEFAULT 0.0,       -- priv esc, lateral movement
    data_score        FLOAT       NOT NULL DEFAULT 0.0,       -- exfiltration, excess downloads
    peer_score        FLOAT       NOT NULL DEFAULT 0.0,       -- deviation from peer group
    temporal_score    FLOAT       NOT NULL DEFAULT 0.0,       -- off-hours, velocity spikes
    -- Counters
    event_count       INT         NOT NULL DEFAULT 0,
    anomaly_count     INT         NOT NULL DEFAULT 0,
    last_seen_at      TIMESTAMPTZ,
    baseline_ready    BOOLEAN     NOT NULL DEFAULT false,     -- true after enough observations
    peer_group_id     UUID,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, entity_id)
);

CREATE INDEX idx_ueba_profiles_tenant      ON ueba_profiles(tenant_id);
CREATE INDEX idx_ueba_profiles_risk        ON ueba_profiles(tenant_id, risk_score DESC);
CREATE INDEX idx_ueba_profiles_entity      ON ueba_profiles(entity_id);
CREATE INDEX idx_ueba_profiles_entity_type ON ueba_profiles(tenant_id, entity_type);

-- Peer groups for comparative behavioral analysis
CREATE TABLE IF NOT EXISTS ueba_peer_groups (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID        NOT NULL,
    name           VARCHAR(100) NOT NULL,
    description    TEXT,
    criteria       JSONB       NOT NULL DEFAULT '{}',        -- matching criteria (department, role...)
    avg_risk_score FLOAT       NOT NULL DEFAULT 0.0,
    member_count   INT         NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);

CREATE INDEX idx_ueba_peer_groups_tenant ON ueba_peer_groups(tenant_id);

-- Anomaly records (PostgreSQL for status tracking and assignment)
CREATE TABLE IF NOT EXISTS ueba_anomalies (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    entity_id       UUID        NOT NULL,
    entity_type     VARCHAR(20) NOT NULL DEFAULT 'user',
    anomaly_type    VARCHAR(50) NOT NULL,
    severity        VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    score           FLOAT       NOT NULL DEFAULT 0.0,
    baseline_val    TEXT,
    observed_val    TEXT,
    details         JSONB       NOT NULL DEFAULT '{}',
    source_event_id UUID,
    status          VARCHAR(20) NOT NULL DEFAULT 'open',     -- open | acknowledged | resolved | false_positive
    assignee_id     UUID,
    notes           TEXT,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ueba_anomalies_tenant   ON ueba_anomalies(tenant_id);
CREATE INDEX idx_ueba_anomalies_entity   ON ueba_anomalies(tenant_id, entity_id);
CREATE INDEX idx_ueba_anomalies_status   ON ueba_anomalies(tenant_id, status);
CREATE INDEX idx_ueba_anomalies_detected ON ueba_anomalies(tenant_id, detected_at DESC);
CREATE INDEX idx_ueba_anomalies_type     ON ueba_anomalies(tenant_id, anomaly_type);
CREATE INDEX idx_ueba_anomalies_severity ON ueba_anomalies(tenant_id, severity);
