-- Migration: ClickHouse 000002_create_collector_tables
-- Domain 1 — Cyber Data Fabric: connector registry + raw event buffer

CREATE DATABASE IF NOT EXISTS crp_fabric;

-- ─── Connector Registry ───────────────────────────────────────────────────────
-- Tracks all registered data connectors and their ingestion statistics.
CREATE TABLE IF NOT EXISTS crp_fabric.connectors (
    id              UUID,
    tenant_id       String,
    name            String,
    source_type     String,     -- firewall, edr, iam, cbs, swift, atm, proxy, dns...
    format          String,     -- json, cef, syslog, leef, winevent, netflow
    status          Enum8('active' = 1, 'inactive' = 2, 'error' = 3),
    config          String,     -- JSON config blob
    last_seen_at    DateTime64(3, 'UTC'),
    events_total    UInt64 DEFAULT 0,
    events_failed   UInt64 DEFAULT 0,
    created_at      DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(last_seen_at)
PARTITION BY tenant_id
ORDER BY (tenant_id, id)
SETTINGS index_granularity = 8192;

-- ─── Raw Event Buffer ─────────────────────────────────────────────────────────
-- Short-lived buffer for raw events (TTL 7 days) to support replay and debugging.
-- NOT the long-term event store — that is crp_audit.cyber_events.
CREATE TABLE IF NOT EXISTS crp_fabric.raw_events (
    id              UUID,
    tenant_id       String,
    connector_id    String,
    source          String,
    source_type     String,
    format          String,
    received_at     DateTime64(3, 'UTC'),
    raw             String,
    normalized      UInt8 DEFAULT 0,   -- 0=pending, 1=done, 2=failed
    error           String DEFAULT ''
)
ENGINE = MergeTree()
PARTITION BY (tenant_id, toYYYYMM(received_at))
ORDER BY (tenant_id, received_at, id)
TTL received_at + INTERVAL 7 DAY
SETTINGS index_granularity = 8192;

-- ─── Pipeline Metrics ─────────────────────────────────────────────────────────
-- Per-minute aggregated ingestion stats per tenant + source_type.
CREATE TABLE IF NOT EXISTS crp_fabric.pipeline_metrics (
    tenant_id       String,
    source_type     String,
    minute          DateTime,
    events_received UInt64,
    events_failed   UInt64,
    events_written  UInt64,
    avg_lag_ms      Float32
)
ENGINE = SummingMergeTree((events_received, events_failed, events_written))
PARTITION BY toYYYYMM(minute)
ORDER BY (tenant_id, source_type, minute)
TTL minute + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;
