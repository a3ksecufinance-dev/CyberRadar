-- ============================================================
-- Domain 22: Incident Response & Forensics (IR)
-- ============================================================

-- IR Playbooks: response templates by incident type
CREATE TABLE IF NOT EXISTS ir_playbooks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    incident_type   TEXT NOT NULL CHECK (incident_type IN (
                        'ransomware','data_breach','insider_threat','phishing',
                        'ddos','malware','apt','supply_chain','account_compromise',
                        'fraud','data_leak','vulnerability_exploit','generic')),
    severity        TEXT NOT NULL DEFAULT 'high' CHECK (severity IN ('critical','high','medium','low')),
    -- Ordered task templates (JSONB array)
    tasks           JSONB DEFAULT '[]',
    -- Estimated times
    estimated_hours INT DEFAULT 0,
    is_active       BOOL DEFAULT TRUE,
    version         INT DEFAULT 1,
    created_by      UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ir_playbooks_tenant ON ir_playbooks (tenant_id, incident_type);

-- Security incidents
CREATE TABLE IF NOT EXISTS ir_incidents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    -- Auto-generated incident number: INC-YYYY-NNNNN
    incident_number TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT,
    incident_type   TEXT NOT NULL CHECK (incident_type IN (
                        'ransomware','data_breach','insider_threat','phishing',
                        'ddos','malware','apt','supply_chain','account_compromise',
                        'fraud','data_leak','vulnerability_exploit','generic')),
    severity        TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low')),
    status          TEXT NOT NULL DEFAULT 'open' CHECK (status IN (
                        'open','investigating','contained','eradicated',
                        'recovered','closed','false_positive')),
    -- Priority (P1-P4)
    priority        INT DEFAULT 2 CHECK (priority BETWEEN 1 AND 4),
    -- Source / trigger
    source          TEXT,                          -- e.g. "SIEM alert", "user report", "threat intel"
    source_ref      TEXT,                          -- alert ID / ticket ID from source system
    -- Affected scope
    affected_systems TEXT[] DEFAULT '{}',
    affected_users   TEXT[] DEFAULT '{}',
    affected_data    TEXT[] DEFAULT '{}',          -- data types involved
    -- Containment & impact
    is_contained     BOOL DEFAULT FALSE,
    data_exfiltrated BOOL DEFAULT FALSE,
    estimated_impact TEXT,                         -- e.g. "500 accounts compromised"
    -- Attack details
    attack_vector    TEXT,                         -- e.g. "phishing email", "supply chain"
    iocs             JSONB DEFAULT '[]',           -- indicators of compromise
    -- MITRE ATT&CK mapping
    mitre_tactics    TEXT[] DEFAULT '{}',
    mitre_techniques TEXT[] DEFAULT '{}',
    -- Team
    lead_id          UUID,
    lead_name        TEXT,
    team_members     TEXT[] DEFAULT '{}',
    -- Playbook
    playbook_id      UUID REFERENCES ir_playbooks(id) ON DELETE SET NULL,
    -- Timeline
    detected_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reported_at      TIMESTAMPTZ DEFAULT NOW(),
    contained_at     TIMESTAMPTZ,
    eradicated_at    TIMESTAMPTZ,
    recovered_at     TIMESTAMPTZ,
    closed_at        TIMESTAMPTZ,
    -- MTTD / MTTR (in minutes)
    mttd_minutes     INT,                          -- time to detect
    mttr_minutes     INT,                          -- time to recover
    -- Regulatory
    requires_notification BOOL DEFAULT FALSE,
    notification_sent_at  TIMESTAMPTZ,
    -- Metadata
    tags            TEXT[] DEFAULT '{}',
    created_by      UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (tenant_id, incident_number)
);

CREATE INDEX IF NOT EXISTS idx_ir_incidents_tenant   ON ir_incidents (tenant_id, status, severity);
CREATE INDEX IF NOT EXISTS idx_ir_incidents_detected ON ir_incidents (tenant_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_ir_incidents_number   ON ir_incidents (tenant_id, incident_number);

-- Incident timeline: forensic events in chronological order
CREATE TABLE IF NOT EXISTS ir_timeline (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    incident_id     UUID NOT NULL REFERENCES ir_incidents(id) ON DELETE CASCADE,
    event_time      TIMESTAMPTZ NOT NULL,
    event_type      TEXT NOT NULL CHECK (event_type IN (
                        'detection','alert','action','communication','evidence',
                        'ioc','system_event','attacker_activity','recovery','note')),
    title           TEXT NOT NULL,
    description     TEXT,
    actor           TEXT,                          -- who performed this (attacker/analyst/system)
    actor_type      TEXT DEFAULT 'analyst' CHECK (actor_type IN ('attacker','analyst','system','automated')),
    source_system   TEXT,                          -- e.g. "EDR", "SIEM", "Firewall"
    iocs            TEXT[] DEFAULT '{}',
    evidence_refs   UUID[] DEFAULT '{}',           -- links to ir_evidence entries
    is_verified     BOOL DEFAULT FALSE,
    created_by      UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ir_timeline_incident ON ir_timeline (incident_id, event_time);
CREATE INDEX IF NOT EXISTS idx_ir_timeline_tenant   ON ir_timeline (tenant_id, event_time DESC);

-- Incident tasks (generated from playbook or manual)
CREATE TABLE IF NOT EXISTS ir_tasks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    incident_id     UUID NOT NULL REFERENCES ir_incidents(id) ON DELETE CASCADE,
    title           TEXT NOT NULL,
    description     TEXT,
    task_type       TEXT DEFAULT 'action' CHECK (task_type IN (
                        'investigation','containment','eradication','recovery',
                        'communication','documentation','action')),
    phase           TEXT DEFAULT 'investigation' CHECK (phase IN (
                        'preparation','detection','analysis','containment',
                        'eradication','recovery','lessons_learned')),
    status          TEXT DEFAULT 'pending' CHECK (status IN (
                        'pending','in_progress','completed','skipped','blocked')),
    priority        INT DEFAULT 2 CHECK (priority BETWEEN 1 AND 4),
    assigned_to     TEXT,
    assigned_id     UUID,
    due_at          TIMESTAMPTZ,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    completion_note TEXT,
    order_idx       INT DEFAULT 0,
    created_by      UUID,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ir_tasks_incident ON ir_tasks (incident_id, order_idx);
CREATE INDEX IF NOT EXISTS idx_ir_tasks_tenant   ON ir_tasks (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_ir_tasks_assigned ON ir_tasks (assigned_id, status) WHERE assigned_id IS NOT NULL;

-- Forensic evidence
CREATE TABLE IF NOT EXISTS ir_evidence (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    incident_id     UUID NOT NULL REFERENCES ir_incidents(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT,
    evidence_type   TEXT NOT NULL CHECK (evidence_type IN (
                        'log_file','memory_dump','disk_image','network_capture',
                        'malware_sample','screenshot','email','document',
                        'registry_export','artifact','ioc_list','other')),
    -- File info
    file_name       TEXT,
    file_size       BIGINT,
    file_hash_md5   TEXT,
    file_hash_sha256 TEXT,
    storage_path    TEXT,                          -- internal storage reference
    -- Chain of custody
    collected_by    TEXT,
    collected_at    TIMESTAMPTZ DEFAULT NOW(),
    collection_method TEXT,                        -- e.g. "Velociraptor", "manual", "EDR"
    -- Analysis
    status          TEXT DEFAULT 'collected' CHECK (status IN (
                        'collected','analyzing','analyzed','archived')),
    analysis_notes  TEXT,
    analyzed_by     TEXT,
    analyzed_at     TIMESTAMPTZ,
    is_sensitive    BOOL DEFAULT FALSE,
    tags            TEXT[] DEFAULT '{}',
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ir_evidence_incident ON ir_evidence (incident_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ir_evidence_tenant   ON ir_evidence (tenant_id, evidence_type);
