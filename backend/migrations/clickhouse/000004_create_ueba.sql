-- ============================================================
-- Domain 5 — UEBA : ClickHouse behavioral time-series tables
-- ============================================================

CREATE DATABASE IF NOT EXISTS crp_ueba;

-- Behavioral event stream: one row per enriched event, per entity
CREATE TABLE IF NOT EXISTS crp_ueba.behavior_events
(
    event_id     UUID,
    tenant_id    String,
    entity_id    String,                        -- user_id or asset_id
    entity_type  LowCardinality(String),        -- user | asset
    event_type   LowCardinality(String),        -- IAM | NETWORK | ENDPOINT ...
    source_type  LowCardinality(String),
    action       String,
    outcome      LowCardinality(String),        -- success | failure | unknown
    ip_source    String,
    geo_country  LowCardinality(String),
    risk_score   Float32,
    hour_of_day  UInt8,                         -- 0-23 (UTC)
    day_of_week  UInt8,                         -- 0=Mon 6=Sun
    attributes   String,                        -- JSON extra fields
    event_time   DateTime64(3, 'UTC'),
    ingested_at  DateTime64(3, 'UTC') DEFAULT now64()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(event_time)
ORDER BY (tenant_id, entity_id, event_time)
TTL event_time + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- Detected anomalies (ClickHouse mirror — fast range queries)
CREATE TABLE IF NOT EXISTS crp_ueba.anomaly_events
(
    anomaly_id    UUID,
    tenant_id     String,
    entity_id     String,
    entity_type   LowCardinality(String),
    anomaly_type  LowCardinality(String),
    severity      LowCardinality(String),
    score         Float32,
    baseline_val  String,
    observed_val  String,
    details       String,                       -- JSON
    source_event_id UUID,
    detected_at   DateTime64(3, 'UTC') DEFAULT now64()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(detected_at)
ORDER BY (tenant_id, entity_id, detected_at)
TTL detected_at + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

-- Daily entity risk aggregations (SummingMergeTree for cheap dashboards)
CREATE TABLE IF NOT EXISTS crp_ueba.entity_risk_daily
(
    date           Date,
    tenant_id      String,
    entity_id      String,
    entity_type    LowCardinality(String),
    risk_score_sum Float64,
    anomaly_count  UInt32,
    event_count    UInt32
)
ENGINE = SummingMergeTree((risk_score_sum, anomaly_count, event_count))
PARTITION BY toYYYYMM(date)
ORDER BY (tenant_id, entity_id, date)
TTL date + INTERVAL 365 DAY;
