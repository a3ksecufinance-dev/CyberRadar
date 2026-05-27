-- ============================================================
-- Domain 7 — Vulnerability & Exposure : ClickHouse time-series
-- ============================================================

CREATE DATABASE IF NOT EXISTS crp_vuln;

-- Daily exposure snapshot per tenant (for trend charts)
CREATE TABLE IF NOT EXISTS crp_vuln.exposure_snapshots
(
    snapshot_date   Date,
    tenant_id       String,
    total_findings  UInt32,
    open_findings   UInt32,
    critical_count  UInt32,
    high_count      UInt32,
    medium_count    UInt32,
    low_count       UInt32,
    avg_cvss        Float32,
    avg_exposure    Float32,
    sla_breached    UInt32,         -- findings past their SLA due date
    assets_affected UInt32
)
ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMM(snapshot_date)
ORDER BY (tenant_id, snapshot_date)
TTL snapshot_date + INTERVAL 2 YEAR;

-- Scan job metrics (one row per completed scan)
CREATE TABLE IF NOT EXISTS crp_vuln.scan_metrics
(
    scan_id         UUID,
    tenant_id       String,
    scan_type       LowCardinality(String),
    status          LowCardinality(String),
    started_at      DateTime64(3, 'UTC'),
    completed_at    DateTime64(3, 'UTC'),
    duration_s      UInt32,
    total_assets    UInt32,
    total_findings  UInt32,
    new_findings    UInt32,
    critical_count  UInt32,
    high_count      UInt32
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(started_at)
ORDER BY (tenant_id, started_at)
TTL started_at + INTERVAL 1 YEAR;
