-- Migration: 000006_create_siem
-- Domain 4 — SIEM/XDR: detection rules, alert metadata, cases, incidents

-- ─── Detection Rules ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS detection_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    category        VARCHAR(50),
    severity        VARCHAR(20) NOT NULL DEFAULT 'MEDIUM'
                        CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),

    -- Rule logic (JSON — evaluated by the rule engine)
    conditions      JSONB NOT NULL DEFAULT '{}',
    -- e.g. {"field_matches":[{"field":"category","op":"eq","value":"IAM"}],
    --        "threshold":{"count":5,"window_seconds":300,"group_by":["user_name"]}}

    -- MITRE mapping
    mitre_tactic    VARCHAR(10),
    mitre_technique VARCHAR(10),

    -- Response actions (JSON)
    actions         JSONB NOT NULL DEFAULT '[]',
    -- e.g. [{"type":"notify","channel":"slack"},{"type":"create_case"}]

    -- Deduplication window in seconds
    dedup_window_s  INT NOT NULL DEFAULT 300,

    -- Lifecycle
    enabled         BOOLEAN NOT NULL DEFAULT true,
    is_system       BOOLEAN NOT NULL DEFAULT false,  -- built-in CRP rules
    false_positive_rate FLOAT DEFAULT 0.0,
    alerts_total    INT NOT NULL DEFAULT 0,
    last_fired_at   TIMESTAMP WITH TIME ZONE,

    created_by      UUID REFERENCES identities(id) ON DELETE SET NULL,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rules_tenant         ON detection_rules(tenant_id) WHERE enabled;
CREATE INDEX idx_rules_tenant_enabled ON detection_rules(tenant_id, severity) WHERE enabled;

CREATE TRIGGER detection_rules_updated_at
    BEFORE UPDATE ON detection_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ─── Alert Metadata (status/assignment — links to ClickHouse alert_id) ────────
-- ClickHouse stores the raw alert data; PostgreSQL tracks mutable status.
CREATE TABLE IF NOT EXISTS alert_metadata (
    alert_id        UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id         UUID REFERENCES detection_rules(id) ON DELETE SET NULL,

    status          VARCHAR(30) NOT NULL DEFAULT 'open'
                        CHECK (status IN ('open','acknowledged','in_progress','closed','false_positive','suppressed')),
    assignee_id     UUID REFERENCES identities(id) ON DELETE SET NULL,
    case_id         UUID,   -- FK to cases added below

    notes           TEXT,
    closed_reason   VARCHAR(100),

    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alert_meta_tenant    ON alert_metadata(tenant_id, status, created_at DESC);
CREATE INDEX idx_alert_meta_case      ON alert_metadata(tenant_id, case_id) WHERE case_id IS NOT NULL;
CREATE INDEX idx_alert_meta_assignee  ON alert_metadata(tenant_id, assignee_id) WHERE assignee_id IS NOT NULL;

CREATE TRIGGER alert_metadata_updated_at
    BEFORE UPDATE ON alert_metadata
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ─── Cases (Security Incidents) ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cases (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    title           VARCHAR(512) NOT NULL,
    description     TEXT,
    severity        VARCHAR(20) NOT NULL DEFAULT 'MEDIUM'
                        CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    status          VARCHAR(30) NOT NULL DEFAULT 'open'
                        CHECK (status IN ('open','in_progress','pending','resolved','closed','false_positive')),
    priority        SMALLINT NOT NULL DEFAULT 2 CHECK (priority BETWEEN 1 AND 4),

    -- Ownership
    assignee_id     UUID REFERENCES identities(id) ON DELETE SET NULL,
    created_by      UUID REFERENCES identities(id) ON DELETE SET NULL,

    -- MITRE context
    mitre_tactic    VARCHAR(10),
    mitre_technique VARCHAR(10),

    -- Timelines
    opened_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    due_at          TIMESTAMP WITH TIME ZONE,
    resolved_at     TIMESTAMP WITH TIME ZONE,
    closed_at       TIMESTAMP WITH TIME ZONE,

    -- Metrics
    alert_count     INT NOT NULL DEFAULT 0,
    mttr_seconds    INT,    -- filled on close

    tags            TEXT[] NOT NULL DEFAULT '{}',
    metadata        JSONB  NOT NULL DEFAULT '{}',

    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_cases_tenant         ON cases(tenant_id, status, severity, created_at DESC);
CREATE INDEX idx_cases_tenant_open    ON cases(tenant_id, priority DESC, opened_at) WHERE status IN ('open','in_progress');
CREATE INDEX idx_cases_assignee       ON cases(tenant_id, assignee_id) WHERE assignee_id IS NOT NULL;

CREATE TRIGGER cases_updated_at
    BEFORE UPDATE ON cases
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Add FK from alert_metadata to cases
ALTER TABLE alert_metadata ADD CONSTRAINT fk_alert_case
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE SET NULL;

-- ─── Case Comments / Timeline ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS case_comments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    case_id     UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    author_id   UUID REFERENCES identities(id) ON DELETE SET NULL,
    comment     TEXT NOT NULL,
    is_internal BOOLEAN NOT NULL DEFAULT false,  -- internal analyst note vs. public
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_case_comments_case ON case_comments(tenant_id, case_id, created_at);

-- ─── Case Observables (IOCs linked to a case) ─────────────────────────────────
CREATE TABLE IF NOT EXISTS case_observables (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    case_id     UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    obs_type    VARCHAR(50) NOT NULL,  -- ip, domain, hash_md5, hash_sha256, url, email, user
    value       VARCHAR(1024) NOT NULL,
    tlp         SMALLINT NOT NULL DEFAULT 2 CHECK (tlp BETWEEN 0 AND 4),  -- TLP: WHITE=0 GREEN=1 AMBER=2 RED=3
    is_ioc      BOOLEAN NOT NULL DEFAULT false,
    notes       TEXT,
    added_by    UUID REFERENCES identities(id) ON DELETE SET NULL,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_observables_case  ON case_observables(tenant_id, case_id);
CREATE INDEX idx_observables_value ON case_observables(tenant_id, obs_type, value);

-- ─── System detection rules (built-in) ───────────────────────────────────────
-- These are seeded for the platform super-tenant and cloned per tenant on onboarding.
DO $$
DECLARE platform_tenant UUID := '00000000-0000-0000-0000-000000000001';
BEGIN
  INSERT INTO detection_rules (tenant_id, name, description, category, severity, conditions, mitre_tactic, mitre_technique, dedup_window_s, is_system) VALUES
  (platform_tenant,
   'Multiple Failed Logins (Brute Force)',
   'Detects 5+ failed authentication attempts within 5 minutes from the same source.',
   'IAM', 'HIGH',
   '{"field_matches":[{"field":"category","op":"eq","value":"IAM"},{"field":"outcome","op":"eq","value":"failure"}],"threshold":{"count":5,"window_seconds":300,"group_by":["user_name","ip_source"]}}',
   'TA0006','T1110', 300, true),

  (platform_tenant,
   'Login from New Country',
   'User authenticated from a country not in their behavioral baseline.',
   'IAM', 'MEDIUM',
   '{"field_matches":[{"field":"category","op":"eq","value":"IAM"},{"field":"outcome","op":"eq","value":"success"},{"field":"geo_anomaly","op":"eq","value":"true"}],"threshold":{"count":1,"window_seconds":60,"group_by":["user_id"]}}',
   'TA0001','T1078', 3600, true),

  (platform_tenant,
   'Data Exfiltration (Large Transfer)',
   'Detects potential data exfiltration via large network transfers.',
   'Network', 'CRITICAL',
   '{"field_matches":[{"field":"mitre_tactic","op":"eq","value":"TA0010"}],"threshold":{"count":1,"window_seconds":60,"group_by":["user_id","ip_destination"]}}',
   'TA0010','T1041', 600, true),

  (platform_tenant,
   'Lateral Movement Detected',
   'Detects lateral movement techniques (RDP, PsExec, WMI).',
   'Network', 'HIGH',
   '{"field_matches":[{"field":"mitre_tactic","op":"eq","value":"TA0008"}],"threshold":{"count":2,"window_seconds":300,"group_by":["user_id"]}}',
   'TA0008','T1021', 300, true),

  (platform_tenant,
   'Privileged Account Activity After Hours',
   'Privileged account used outside normal business hours.',
   'IAM', 'HIGH',
   '{"field_matches":[{"field":"category","op":"eq","value":"IAM"},{"field":"outcome","op":"eq","value":"success"},{"field":"anomalous_hours","op":"eq","value":"true"}],"threshold":{"count":1,"window_seconds":60,"group_by":["user_id"]}}',
   'TA0001','T1078', 3600, true),

  (platform_tenant,
   'CBS / SWIFT Unusual Transaction Pattern',
   'Abnormal event pattern on core banking or SWIFT-connected assets.',
   'Transaction', 'CRITICAL',
   '{"field_matches":[{"field":"category","op":"eq","value":"Transaction"},{"field":"cbs_impact","op":"gt","value":"0"}],"threshold":{"count":3,"window_seconds":60,"group_by":["asset_id"]}}',
   'TA0011','T1657', 300, true)

  ON CONFLICT DO NOTHING;
END $$;
