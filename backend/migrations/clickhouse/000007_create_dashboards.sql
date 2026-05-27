-- Domain 11: Dashboards — ClickHouse platform-wide metric snapshots

CREATE DATABASE IF NOT EXISTS crp_dash;

-- ── Platform KPI snapshots ────────────────────────────────────────────────────
-- Each domain service publishes a snapshot every minute via Kafka.
-- ReplacingMergeTree deduplicates on (tenant_id, domain, metric_key, snapped_at).
CREATE TABLE IF NOT EXISTS crp_dash.kpi_snapshots
(
    tenant_id   UUID,
    domain      LowCardinality(String),   -- siem, ueba, ti, vuln, attackpath, soar, asset
    metric_key  LowCardinality(String),   -- open_alerts, risk_score, compromised_nodes …
    metric_value Float64,
    labels      Map(String, String),      -- e.g. {severity: CRITICAL}
    snapped_at  DateTime,
    updated_at  DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMM(snapped_at)
ORDER BY (tenant_id, domain, metric_key, snapped_at)
TTL snapped_at + INTERVAL 1 YEAR
SETTINGS index_granularity = 8192;

-- ── Hourly aggregates (materialized) ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS crp_dash.kpi_hourly
(
    tenant_id    UUID,
    domain       LowCardinality(String),
    metric_key   LowCardinality(String),
    hour         DateTime,
    avg_value    Float64,
    min_value    Float64,
    max_value    Float64,
    sample_count UInt32
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, domain, metric_key, hour)
TTL hour + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- ── Risk score timeline (one row per entity per hour) ─────────────────────────
CREATE TABLE IF NOT EXISTS crp_dash.risk_timeline
(
    tenant_id   UUID,
    entity_type LowCardinality(String),   -- asset, identity, node
    entity_id   UUID,
    hour        DateTime,
    risk_score  Float64,
    delta       Float64                   -- change from previous hour
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, entity_type, entity_id, hour)
TTL hour + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;
