-- Domain 9: Knowledge Graph
-- Semantic graph linking all platform entities across domains.

-- ── Entities ─────────────────────────────────────────────────────────────────
-- Polymorphic store for every observable: assets, identities, IPs, domains,
-- hashes, vulnerabilities, IOCs, alerts, incidents, threat actors, software.
CREATE TABLE IF NOT EXISTS kg_entities (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    entity_type     TEXT        NOT NULL
                    CHECK (entity_type IN (
                        'asset','identity','ip','domain','url',
                        'hash','vulnerability','ioc','alert',
                        'incident','threat_actor','software'
                    )),
    -- Canonical identifier within the originating service (cve_id, asset_id …)
    external_id     TEXT,
    name            TEXT        NOT NULL,
    description     TEXT,
    risk_score      FLOAT       NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 10),
    confidence      FLOAT       NOT NULL DEFAULT 1.0 CHECK (confidence BETWEEN 0 AND 1),
    tags            TEXT[]      NOT NULL DEFAULT '{}',
    properties      JSONB       NOT NULL DEFAULT '{}',
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Dedup: one canonical entity per (tenant, type, external_id)
CREATE UNIQUE INDEX IF NOT EXISTS uq_kg_entities_ext
    ON kg_entities (tenant_id, entity_type, external_id)
    WHERE external_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_kg_entities_tenant_type  ON kg_entities (tenant_id, entity_type);
CREATE INDEX IF NOT EXISTS idx_kg_entities_name         ON kg_entities (tenant_id, lower(name));
CREATE INDEX IF NOT EXISTS idx_kg_entities_risk         ON kg_entities (tenant_id, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_kg_entities_last_seen    ON kg_entities (tenant_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_kg_entities_props        ON kg_entities USING gin (properties);
CREATE INDEX IF NOT EXISTS idx_kg_entities_tags         ON kg_entities USING gin (tags);

-- ── Relationships ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS kg_relationships (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL,
    source_id         UUID        NOT NULL REFERENCES kg_entities(id) ON DELETE CASCADE,
    target_id         UUID        NOT NULL REFERENCES kg_entities(id) ON DELETE CASCADE,
    relationship_type TEXT        NOT NULL
                      CHECK (relationship_type IN (
                          'CONNECTS_TO','EXPLOITS','TARGETS',
                          'COMMUNICATES_WITH','BELONGS_TO','RESOLVES_TO',
                          'ASSOCIATED_WITH','ATTRIBUTED_TO','MITIGATES',
                          'HAS_VULNERABILITY','INDICATOR_OF','USES'
                      )),
    weight            FLOAT       NOT NULL DEFAULT 1.0,
    confidence        FLOAT       NOT NULL DEFAULT 1.0 CHECK (confidence BETWEEN 0 AND 1),
    evidence_source   TEXT        CHECK (evidence_source IN ('siem','ueba','ti','vuln','attackpath','manual','computed')),
    properties        JSONB       NOT NULL DEFAULT '{}',
    valid_from        TIMESTAMPTZ,
    valid_until       TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One directed edge per (source, target, type)
CREATE UNIQUE INDEX IF NOT EXISTS uq_kg_rel ON kg_relationships (tenant_id, source_id, target_id, relationship_type);

CREATE INDEX IF NOT EXISTS idx_kg_rel_source     ON kg_relationships (tenant_id, source_id);
CREATE INDEX IF NOT EXISTS idx_kg_rel_target     ON kg_relationships (tenant_id, target_id);
CREATE INDEX IF NOT EXISTS idx_kg_rel_type       ON kg_relationships (tenant_id, relationship_type);
CREATE INDEX IF NOT EXISTS idx_kg_rel_valid_until ON kg_relationships (valid_until) WHERE valid_until IS NOT NULL;

-- ── Observations (entity timeline) ────────────────────────────────────────────
-- Every time a domain service sees an entity (alert fires, scan detects vuln …)
-- it appends an observation. Drives the entity timeline and risk recalculation.
CREATE TABLE IF NOT EXISTS kg_observations (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID        NOT NULL,
    entity_id      UUID        NOT NULL REFERENCES kg_entities(id) ON DELETE CASCADE,
    observed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_service TEXT        NOT NULL
                   CHECK (source_service IN ('siem','ueba','ti','vuln','attackpath','collector','manual')),
    event_type     TEXT        NOT NULL,   -- e.g. ALERT_FIRED, VULN_DETECTED, IOC_MATCHED
    severity       TEXT        CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    description    TEXT,
    properties     JSONB       NOT NULL DEFAULT '{}',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_kg_obs_entity      ON kg_observations (tenant_id, entity_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_kg_obs_source      ON kg_observations (tenant_id, source_service, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_kg_obs_event_type  ON kg_observations (tenant_id, event_type);
CREATE INDEX IF NOT EXISTS idx_kg_obs_severity    ON kg_observations (tenant_id, severity) WHERE severity IS NOT NULL;
