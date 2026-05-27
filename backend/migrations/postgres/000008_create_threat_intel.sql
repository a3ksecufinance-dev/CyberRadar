-- ============================================================
-- Domain 6 — Threat Intelligence : PostgreSQL tables
-- ============================================================

-- Feed source definitions (STIX/TAXII, MISP, CSV, internal)
CREATE TABLE IF NOT EXISTS ti_feeds (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    name            VARCHAR(100) NOT NULL,
    description     TEXT,
    feed_type       VARCHAR(20) NOT NULL DEFAULT 'stix',   -- stix | taxii | misp | csv | internal
    url             TEXT,
    api_key_ref     TEXT,        -- Vault path to credential, never stored plaintext
    collection_id   TEXT,        -- TAXII collection or MISP event filter
    poll_interval_s INT         NOT NULL DEFAULT 3600,     -- 1 hour default
    enabled         BOOLEAN     NOT NULL DEFAULT true,
    tlp             SMALLINT    NOT NULL DEFAULT 2,         -- 0=WHITE 1=GREEN 2=AMBER 3=RED 4=BLACK
    confidence      SMALLINT    NOT NULL DEFAULT 50,        -- 0-100
    last_polled_at  TIMESTAMPTZ,
    last_ioc_count  INT         NOT NULL DEFAULT 0,
    error_count     INT         NOT NULL DEFAULT 0,
    last_error      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);

CREATE INDEX idx_ti_feeds_tenant  ON ti_feeds(tenant_id);
CREATE INDEX idx_ti_feeds_enabled ON ti_feeds(tenant_id, enabled);

-- Indicators of Compromise (IOC) master table
CREATE TABLE IF NOT EXISTS ti_iocs (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    feed_id         UUID        REFERENCES ti_feeds(id) ON DELETE SET NULL,
    ioc_type        VARCHAR(20) NOT NULL,   -- ip | domain | url | hash_md5 | hash_sha256 | hash_sha1 | email | cve | asn
    value           TEXT        NOT NULL,
    normalized      TEXT        NOT NULL,   -- lowercase / canonicalized form for matching
    tlp             SMALLINT    NOT NULL DEFAULT 2,
    confidence      SMALLINT    NOT NULL DEFAULT 50,        -- 0-100
    severity        VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',  -- CRITICAL | HIGH | MEDIUM | LOW | INFO
    is_active       BOOLEAN     NOT NULL DEFAULT true,
    -- MITRE context
    mitre_tactic    TEXT,
    mitre_technique TEXT,
    -- Threat actor context
    threat_actor    TEXT,
    malware_family  TEXT,
    campaign        TEXT,
    -- Validity window
    valid_from      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    valid_until     TIMESTAMPTZ,                            -- NULL = no expiry
    -- Counters
    hit_count       INT         NOT NULL DEFAULT 0,
    last_hit_at     TIMESTAMPTZ,
    -- Source metadata
    external_id     TEXT,        -- original ID in source feed
    stix_id         TEXT,        -- STIX 2.1 indicator ID
    tags            TEXT[]       NOT NULL DEFAULT '{}',
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, ioc_type, normalized)
);

CREATE INDEX idx_ti_iocs_tenant       ON ti_iocs(tenant_id);
CREATE INDEX idx_ti_iocs_type_value   ON ti_iocs(tenant_id, ioc_type, normalized) WHERE is_active = true;
CREATE INDEX idx_ti_iocs_feed         ON ti_iocs(feed_id);
CREATE INDEX idx_ti_iocs_active       ON ti_iocs(tenant_id, is_active);
CREATE INDEX idx_ti_iocs_severity     ON ti_iocs(tenant_id, severity) WHERE is_active = true;
CREATE INDEX idx_ti_iocs_valid_until  ON ti_iocs(valid_until) WHERE valid_until IS NOT NULL AND is_active = true;
CREATE INDEX idx_ti_iocs_hit_count    ON ti_iocs(tenant_id, hit_count DESC);

-- Threat actor / group profiles
CREATE TABLE IF NOT EXISTS ti_threat_actors (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    name            VARCHAR(100) NOT NULL,
    aliases         TEXT[]      NOT NULL DEFAULT '{}',
    description     TEXT,
    motivation      VARCHAR(50),                            -- financial | espionage | hacktivism | disruption
    sophistication  VARCHAR(20) NOT NULL DEFAULT 'medium',  -- minimal | low | medium | high | advanced
    origin_country  TEXT,
    first_seen      DATE,
    last_seen       DATE,
    -- MITRE ATT&CK
    mitre_groups    TEXT[]      NOT NULL DEFAULT '{}',      -- e.g. G0001
    ttps            TEXT[]      NOT NULL DEFAULT '{}',      -- tactic/technique IDs
    -- Banking sector relevance flags
    targets_cbs     BOOLEAN     NOT NULL DEFAULT false,
    targets_swift   BOOLEAN     NOT NULL DEFAULT false,
    targets_atm     BOOLEAN     NOT NULL DEFAULT false,
    stix_id         TEXT,
    tags            TEXT[]      NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);

CREATE INDEX idx_ti_actors_tenant    ON ti_threat_actors(tenant_id);
CREATE INDEX idx_ti_actors_banking   ON ti_threat_actors(tenant_id) WHERE targets_cbs = true OR targets_swift = true OR targets_atm = true;

-- IOC match log (every time an IOC is matched against a live event)
CREATE TABLE IF NOT EXISTS ti_ioc_hits (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    ioc_id          UUID        NOT NULL REFERENCES ti_iocs(id) ON DELETE CASCADE,
    source_event_id UUID,
    alert_id        UUID,                                   -- linked SIEM alert if escalated
    matched_value   TEXT        NOT NULL,
    matched_field   VARCHAR(50) NOT NULL,                   -- ip_source | ip_destination | domain | hash | url
    severity        VARCHAR(20) NOT NULL,
    auto_blocked    BOOLEAN     NOT NULL DEFAULT false,
    hit_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ti_hits_tenant  ON ti_ioc_hits(tenant_id, hit_at DESC);
CREATE INDEX idx_ti_hits_ioc     ON ti_ioc_hits(ioc_id);
CREATE INDEX idx_ti_hits_event   ON ti_ioc_hits(source_event_id) WHERE source_event_id IS NOT NULL;
