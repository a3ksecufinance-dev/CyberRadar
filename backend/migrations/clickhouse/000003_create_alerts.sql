-- Migration: ClickHouse 000003_create_alerts
-- Domain 4 — SIEM/XDR: alert storage + correlation metrics

CREATE DATABASE IF NOT EXISTS crp_siem;

-- ─── Alerts ───────────────────────────────────────────────────────────────────
-- High-volume alert store. Immutable after creation (status managed in PostgreSQL).
CREATE TABLE IF NOT EXISTS crp_siem.alerts (
    alert_id        UUID,
    tenant_id       String,
    rule_id         String,
    rule_name       String,

    -- Classification
    severity        Enum8('LOW'=1,'MEDIUM'=2,'HIGH'=3,'CRITICAL'=4),
    category        String,
    mitre_tactic    String DEFAULT '',
    mitre_technique String DEFAULT '',

    -- Entity context (what triggered the alert)
    entity_type     String,   -- user, asset, ip, domain
    entity_value    String,   -- the actual entity identifier

    -- Source event
    source_event_id String DEFAULT '',
    tenant_asset_id String DEFAULT '',
    user_id         String DEFAULT '',
    ip_source       String DEFAULT '',
    ip_destination  String DEFAULT '',

    -- Alert content
    title           String,
    description     String,
    raw_evidence    String,   -- JSON: matched event(s)

    -- Deduplication
    dedup_key       String,   -- hash(rule_id + entity_key) — prevents alert storms
    dedup_window_s  UInt32 DEFAULT 300,

    -- Timestamps
    event_time      DateTime64(3,'UTC'),
    detected_at     DateTime64(3,'UTC') DEFAULT now64(3),

    -- Counts (for threshold rules)
    event_count     UInt32 DEFAULT 1,
    risk_score      Float32 DEFAULT 0
)
ENGINE = MergeTree()
PARTITION BY (tenant_id, toYYYYMM(detected_at))
ORDER BY (tenant_id, severity DESC, detected_at, alert_id)
TTL detected_at + INTERVAL 365 DAY
SETTINGS
    index_granularity = 8192;

-- Deduplication guard: prevents inserting duplicate alerts within the window.
-- Application layer checks this before inserting a new alert.
CREATE TABLE IF NOT EXISTS crp_siem.alert_dedup (
    tenant_id       String,
    dedup_key       String,
    last_alert_id   UUID,
    first_seen_at   DateTime64(3,'UTC'),
    last_seen_at    DateTime64(3,'UTC') DEFAULT now64(3),
    hit_count       UInt32 DEFAULT 1
)
ENGINE = ReplacingMergeTree(last_seen_at)
ORDER BY (tenant_id, dedup_key)
TTL last_seen_at + INTERVAL 1 DAY
SETTINGS index_granularity = 8192;

-- ─── Correlation Metrics (per-minute aggregates) ───────────────────────────
CREATE TABLE IF NOT EXISTS crp_siem.correlation_metrics (
    tenant_id       String,
    rule_id         String,
    severity        String,
    minute          DateTime,
    alerts_fired    UInt64,
    alerts_deduped  UInt64,
    false_positives UInt64
)
ENGINE = SummingMergeTree((alerts_fired, alerts_deduped, false_positives))
PARTITION BY toYYYYMM(minute)
ORDER BY (tenant_id, rule_id, minute)
TTL minute + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;
