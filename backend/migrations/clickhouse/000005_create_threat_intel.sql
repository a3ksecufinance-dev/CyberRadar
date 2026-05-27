-- ============================================================
-- Domain 6 — Threat Intelligence : ClickHouse IOC hit time-series
-- ============================================================

CREATE DATABASE IF NOT EXISTS crp_ti;

-- High-throughput IOC match stream (written by matcher pipeline)
CREATE TABLE IF NOT EXISTS crp_ti.ioc_hits
(
    hit_id          UUID,
    tenant_id       String,
    ioc_id          UUID,
    ioc_type        LowCardinality(String),
    ioc_value       String,
    matched_field   LowCardinality(String),
    severity        LowCardinality(String),
    source_event_id UUID,
    alert_id        UUID,
    auto_blocked    UInt8,
    hit_at          DateTime64(3, 'UTC') DEFAULT now64()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(hit_at)
ORDER BY (tenant_id, hit_at, ioc_type)
TTL hit_at + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

-- Daily threat intel summary (for dashboard time-series charts)
CREATE TABLE IF NOT EXISTS crp_ti.ioc_stats_daily
(
    date            Date,
    tenant_id       String,
    ioc_type        LowCardinality(String),
    severity        LowCardinality(String),
    hit_count       UInt64,
    unique_iocs     UInt64,
    blocked_count   UInt64
)
ENGINE = SummingMergeTree((hit_count, unique_iocs, blocked_count))
PARTITION BY toYYYYMM(date)
ORDER BY (tenant_id, date, ioc_type, severity)
TTL date + INTERVAL 365 DAY;
