-- Migration: ClickHouse 000001_create_audit_logs
-- Foundation Platform — FND-07: Audit & Traceability (immutable)

CREATE DATABASE IF NOT EXISTS crp_audit;

-- ─── Audit Logs (Immutable) ─────────────────────────────────────────────────
-- CRITICAL: This table must remain write-only. No UPDATE or DELETE is permitted.
-- Immutability is enforced by:
--   1. MergeTree engine with non_replicated_deduplication_window = 0
--   2. checksum column (SHA-256 of row content)
--   3. Application layer write-only audit service
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS crp_audit.audit_logs (
    id              UUID,
    tenant_id       String,
    timestamp       DateTime64(3, 'UTC'),

    -- Actor
    actor_id        String,
    actor_type      Enum8('user' = 1, 'service' = 2, 'system' = 3, 'api' = 4),
    actor_email     String,

    -- Action
    action          String,
    resource_type   String,
    resource_id     String,

    -- Context
    ip_address      String,
    user_agent      String,
    session_id      String,
    request_id      String,

    -- Outcome
    result          Enum8('success' = 1, 'failure' = 2),
    details         String,     -- JSON payload

    -- Integrity
    checksum        String      -- SHA-256(tenant_id||timestamp||actor_id||action||resource_type||resource_id||result)
)
ENGINE = MergeTree()
PARTITION BY (tenant_id, toYYYYMM(timestamp))
ORDER BY (tenant_id, timestamp, id)
SETTINGS
    non_replicated_deduplication_window = 0,
    index_granularity = 8192;

-- ─── Cyber Events (long-term storage) ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS crp_audit.cyber_events (
    event_id            UUID,
    tenant_id           String,
    timestamp           DateTime64(3, 'UTC'),
    ingested_at         DateTime64(3, 'UTC') DEFAULT now64(3),

    -- Source
    source              String,
    source_type         String,
    connector_id        String,

    -- Identity
    user_id             Nullable(String),
    user_name           Nullable(String),
    user_email          Nullable(String),
    user_department     Nullable(String),
    user_risk_score     Nullable(Float32),

    -- Asset
    asset_id            Nullable(String),
    asset_hostname      Nullable(String),
    asset_type          Nullable(String),
    asset_criticality   Nullable(Float32),

    -- Network
    ip_source           Nullable(String),
    ip_destination      Nullable(String),
    port_source         Nullable(UInt16),
    port_dest           Nullable(UInt16),
    geo_country         Nullable(String),
    geo_asn             Nullable(String),

    -- Event
    action              String,
    category            Enum8('Security' = 1, 'Fraud' = 2, 'Network' = 3, 'IAM' = 4, 'Compliance' = 5, 'Transaction' = 6, 'Other' = 7),
    severity            Enum8('LOW' = 1, 'MEDIUM' = 2, 'HIGH' = 3, 'CRITICAL' = 4),
    outcome             Enum8('success' = 1, 'failure' = 2, 'unknown' = 3),

    -- Threat enrichment
    threat_score        Float32 DEFAULT 0,
    mitre_tactic        Nullable(String),
    mitre_technique     Nullable(String),
    ioc_matched         Array(String),

    -- Risk
    risk_score          Float32 DEFAULT 0,

    -- Business context
    business_service    Nullable(String),
    cbs_impact          UInt8 DEFAULT 0,
    swift_impact        UInt8 DEFAULT 0,

    -- Raw
    raw_event           String,
    schema_version      UInt8 DEFAULT 1
)
ENGINE = MergeTree()
PARTITION BY (tenant_id, toYYYYMM(timestamp))
ORDER BY (tenant_id, timestamp, event_id)
TTL
    timestamp + INTERVAL 30 DAY TO DISK 'warm',
    timestamp + INTERVAL 365 DAY TO DISK 'cold'
SETTINGS index_granularity = 8192;
