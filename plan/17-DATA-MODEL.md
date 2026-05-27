# Modèles de données — Cyber Radar Platform

---

## 1. Universal Cyber Event (Event Store / ClickHouse)

```sql
CREATE TABLE cyber_events (
    event_id        UUID DEFAULT generateUUIDv4(),
    tenant_id       String,
    timestamp       DateTime64(3, 'UTC'),
    source          String,          -- connecteur source
    source_type     String,          -- 'windows', 'firewall', 'cbs', etc.

    -- Identity
    user_id         Nullable(String),
    user_name       Nullable(String),
    user_email      Nullable(String),
    user_department Nullable(String),
    user_risk_score Nullable(Float32),

    -- Asset
    asset_id        Nullable(String),
    asset_hostname  Nullable(String),
    asset_type      Nullable(String),
    asset_criticality Nullable(Float32),

    -- Network
    ip_source       Nullable(String),
    ip_destination  Nullable(String),
    port_source     Nullable(UInt16),
    port_dest       Nullable(UInt16),
    geo_country     Nullable(String),
    geo_asn         Nullable(String),

    -- Event
    action          String,
    category        String,          -- 'Security', 'Fraud', 'Network', 'IAM', etc.
    severity        Enum8('LOW'=1, 'MEDIUM'=2, 'HIGH'=3, 'CRITICAL'=4),
    outcome         Enum8('SUCCESS'=1, 'FAILURE'=2, 'UNKNOWN'=3),

    -- Threat
    threat_score    Float32 DEFAULT 0,
    mitre_tactic    Nullable(String),
    mitre_technique Nullable(String),
    ioc_matched     Array(String),

    -- Risk
    risk_score      Float32 DEFAULT 0,

    -- Business
    business_service Nullable(String),
    cbs_impact      Nullable(Bool),
    swift_impact    Nullable(Bool),

    -- Raw
    raw_event       String,
    schema_version  UInt8 DEFAULT 1
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, timestamp, event_id)
TTL timestamp + INTERVAL 30 DAY TO VOLUME 'warm';
```

---

## 2. Asset (PostgreSQL)

```sql
CREATE TABLE assets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,

    -- Identification
    hostname        VARCHAR(255),
    fqdn            VARCHAR(255),
    asset_type      VARCHAR(50),     -- 'server', 'workstation', 'firewall', 'cbs', 'atm'
    category        VARCHAR(50),     -- 'Infrastructure', 'Identity', 'Cloud', 'Banking'

    -- Ownership
    owner           VARCHAR(255),
    business_unit   VARCHAR(100),
    location        VARCHAR(100),
    environment     VARCHAR(20),     -- 'PROD', 'PREPROD', 'DEV'

    -- Technical
    os_name         VARCHAR(100),
    os_version      VARCHAR(50),
    ip_addresses    JSONB,           -- [{ip, type, interface}]
    mac_addresses   JSONB,
    installed_sw    JSONB,

    -- Security posture
    edr_installed   BOOLEAN DEFAULT false,
    av_installed    BOOLEAN DEFAULT false,
    patching_status VARCHAR(20),     -- 'UP_TO_DATE', 'OUTDATED', 'UNKNOWN'
    last_patch_date TIMESTAMP,

    -- Exposure
    internet_exposed BOOLEAN DEFAULT false,
    open_ports      JSONB,           -- [{port, protocol, service}]

    -- Business
    cbs_dependency  BOOLEAN DEFAULT false,
    swift_dependency BOOLEAN DEFAULT false,
    business_services JSONB,         -- [{service_id, name, criticality}]
    revenue_impact  DECIMAL(15,2),

    -- Scoring
    criticality_score DECIMAL(5,2) DEFAULT 0,  -- 0-100
    risk_score      DECIMAL(5,2) DEFAULT 0,    -- 0-100
    exposure_score  DECIMAL(5,2) DEFAULT 0,    -- 0-100

    -- Lifecycle
    status          VARCHAR(20) DEFAULT 'active', -- 'discovered', 'active', 'inactive', 'orphaned', 'retired', 'compromised'
    first_seen      TIMESTAMP DEFAULT NOW(),
    last_seen       TIMESTAMP DEFAULT NOW(),

    -- Fingerprint
    fingerprint_hash VARCHAR(64),
    confidence_score DECIMAL(5,2),

    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_assets_tenant ON assets(tenant_id);
CREATE INDEX idx_assets_type ON assets(asset_type);
CREATE INDEX idx_assets_risk ON assets(risk_score DESC);
CREATE INDEX idx_assets_cbs ON assets(tenant_id) WHERE cbs_dependency = true;
```

---

## 3. Identity (PostgreSQL)

```sql
CREATE TABLE identities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,

    -- Core
    username        VARCHAR(255) NOT NULL,
    email           VARCHAR(255),
    display_name    VARCHAR(255),
    identity_type   VARCHAR(50),     -- 'user', 'admin', 'service_account', 'machine', 'bot'

    -- Organization
    department      VARCHAR(100),
    business_unit   VARCHAR(100),
    manager_id      UUID REFERENCES identities(id),

    -- Security
    privilege_level VARCHAR(20),     -- 'standard', 'elevated', 'admin', 'super_admin'
    mfa_enabled     BOOLEAN DEFAULT false,
    pam_managed     BOOLEAN DEFAULT false,
    risk_score      DECIMAL(5,2) DEFAULT 0,    -- 0-100
    behavior_score  DECIMAL(5,2) DEFAULT 100,  -- 100 = normal

    -- Status
    status          VARCHAR(20) DEFAULT 'active', -- 'active', 'dormant', 'orphan', 'compromised', 'disabled'
    last_activity   TIMESTAMP,
    password_last_set TIMESTAMP,

    -- Sources
    source_systems  JSONB,           -- [{type: 'AD', dn: '...', id: '...'}]

    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);

CREATE TABLE identity_privileges (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id     UUID REFERENCES identities(id),
    privilege_name  VARCHAR(255),
    privilege_type  VARCHAR(50),     -- 'group', 'role', 'permission', 'pam_role'
    target_asset_id UUID REFERENCES assets(id),
    granted_at      TIMESTAMP,
    expires_at      TIMESTAMP,
    source          VARCHAR(50)
);
```

---

## 4. Alert (PostgreSQL)

```sql
CREATE TABLE alerts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,

    -- Detection
    rule_id         UUID,
    rule_name       VARCHAR(255),
    detection_source VARCHAR(50),    -- 'SIEM', 'UEBA', 'CTI', 'SOAR'

    -- Classification
    category        VARCHAR(50),
    severity        VARCHAR(20),     -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    mitre_tactic    VARCHAR(100),
    mitre_technique VARCHAR(100),

    -- Context
    user_id         UUID REFERENCES identities(id),
    asset_id        UUID REFERENCES assets(id),
    business_service VARCHAR(255),

    -- Scoring
    threat_score    DECIMAL(5,2),
    risk_score      DECIMAL(5,2),
    business_impact VARCHAR(20),     -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    confidence      DECIMAL(5,2),

    -- Status
    status          VARCHAR(20) DEFAULT 'new',  -- 'new', 'investigating', 'resolved', 'fp'
    qualification   VARCHAR(20),     -- 'true_positive', 'false_positive', 'accepted_risk'
    assigned_to     UUID,

    -- Correlation
    incident_id     UUID,
    related_events  JSONB,           -- [event_ids]
    related_iocs    JSONB,

    -- Timestamps
    detected_at     TIMESTAMP NOT NULL,
    first_event_at  TIMESTAMP,
    last_event_at   TIMESTAMP,
    resolved_at     TIMESTAMP,

    created_at      TIMESTAMP DEFAULT NOW()
);
```

---

## 5. Graph Model (Neo4j Cypher)

```cypher
// Nœuds
(:Identity {id, tenant_id, username, type, risk_score, mfa_enabled})
(:Asset    {id, tenant_id, hostname, type, criticality, risk_score})
(:Privilege {id, tenant_id, name, type, level})
(:Session  {id, tenant_id, start_time, end_time, ip, geo_country, risk_score})
(:BusinessService {id, tenant_id, name, revenue_impact, criticality})
(:Context  {id, tenant_id, timestamp, geo, device_posture, threat_active})

// Relations
(:Identity)-[:OWNS]->(:Asset)
(:Identity)-[:HAS_PRIVILEGE]->(:Privilege)
(:Identity)-[:AUTHENTICATED_TO]->(:Session)
(:Identity)-[:ACCESSES]->(:Asset)
(:Identity)-[:EXPOSED_TO]->(:Threat)
(:Privilege)-[:GRANTS_ACCESS_TO]->(:Asset)
(:Session)-[:INTERACTS_WITH]->(:Asset)
(:Asset)-[:CONNECTS_TO]->(:Asset)
(:Asset)-[:OWNED_BY]->(:BusinessService)
(:Asset)-[:PART_OF]->(:BusinessService)
(:BusinessService)-[:HAS_REVENUE_IMPACT {amount}]->(:BusinessService)

// Index
CREATE INDEX identity_tenant FOR (i:Identity) ON (i.tenant_id)
CREATE INDEX asset_criticality FOR (a:Asset) ON (a.criticality)
CREATE INDEX asset_type FOR (a:Asset) ON (a.type)
```

---

## 6. Tenant (PostgreSQL)

```sql
CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(100) UNIQUE NOT NULL,
    parent_id       UUID REFERENCES tenants(id),  -- MSSP model
    plan            VARCHAR(50),
    status          VARCHAR(20) DEFAULT 'active',
    config          JSONB,
    features        JSONB,           -- Feature flags
    limits          JSONB,           -- Quotas
    created_at      TIMESTAMP DEFAULT NOW()
);
```

---

## 7. Audit Log (ClickHouse — immutable)

```sql
CREATE TABLE audit_logs (
    id              UUID DEFAULT generateUUIDv4(),
    tenant_id       String,
    timestamp       DateTime64(3, 'UTC'),
    actor_id        String,
    actor_type      String,          -- 'user', 'system', 'api'
    action          String,          -- 'login', 'config_change', 'secret_access', etc.
    resource_type   String,
    resource_id     String,
    details         String,          -- JSON
    ip_address      String,
    result          Enum8('SUCCESS'=1, 'FAILURE'=2),
    checksum        String           -- SHA256 du log pour intégrité
)
ENGINE = MergeTree()
ORDER BY (tenant_id, timestamp)
SETTINGS non_replicated_deduplication_window = 0;  -- Immutable
```
