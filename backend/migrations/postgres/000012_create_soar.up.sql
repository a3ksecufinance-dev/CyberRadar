-- Domain 10: SOAR — Security Orchestration, Automation & Response

-- ── Incidents ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS soar_incidents (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL,
    title            TEXT        NOT NULL,
    description      TEXT,
    severity         TEXT        NOT NULL DEFAULT 'MEDIUM'
                     CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    status           TEXT        NOT NULL DEFAULT 'open'
                     CHECK (status IN ('open','in_progress','contained','resolved','closed')),
    -- Origin: which domain service raised this incident
    source_service   TEXT        CHECK (source_service IN ('siem','ueba','ti','vuln','attackpath','manual')),
    source_event_id  UUID,       -- FK into source domain (alert_id, anomaly_id, etc.)
    -- Assignment
    assignee_id      UUID,       -- user_id from identity service
    -- MITRE ATT&CK
    mitre_tactics    TEXT[]      NOT NULL DEFAULT '{}',
    mitre_techniques TEXT[]      NOT NULL DEFAULT '{}',
    -- Context
    affected_assets  UUID[]      NOT NULL DEFAULT '{}',
    ioc_ids          UUID[]      NOT NULL DEFAULT '{}',
    tags             TEXT[]      NOT NULL DEFAULT '{}',
    properties       JSONB       NOT NULL DEFAULT '{}',
    -- SLA tracking
    sla_due_at       TIMESTAMPTZ,
    contained_at     TIMESTAMPTZ,
    resolved_at      TIMESTAMPTZ,
    closed_at        TIMESTAMPTZ,
    created_by       UUID,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_soar_incidents_tenant_status   ON soar_incidents (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_soar_incidents_tenant_severity ON soar_incidents (tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_soar_incidents_assignee        ON soar_incidents (tenant_id, assignee_id) WHERE assignee_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_soar_incidents_source          ON soar_incidents (tenant_id, source_service, source_event_id) WHERE source_event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_soar_incidents_created         ON soar_incidents (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_soar_incidents_sla             ON soar_incidents (tenant_id, sla_due_at) WHERE sla_due_at IS NOT NULL;

-- ── Incident timeline (audit log for each incident) ──────────────────────────
CREATE TABLE IF NOT EXISTS soar_incident_events (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL,
    incident_id UUID        NOT NULL REFERENCES soar_incidents(id) ON DELETE CASCADE,
    event_type  TEXT        NOT NULL,  -- STATUS_CHANGED, ASSIGNED, NOTE_ADDED, PLAYBOOK_RUN, etc.
    actor_id    UUID,                  -- user or system
    actor_type  TEXT        NOT NULL DEFAULT 'system' CHECK (actor_type IN ('user','system')),
    details     JSONB       NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_soar_inc_events_incident ON soar_incident_events (incident_id, created_at DESC);

-- ── Playbooks ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS soar_playbooks (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID        NOT NULL,
    name               TEXT        NOT NULL,
    description        TEXT,
    trigger_type       TEXT        NOT NULL
                       CHECK (trigger_type IN ('manual','alert','ioc_match','anomaly','vuln','schedule')),
    -- JSON conditions that must match the triggering event to auto-fire:
    -- e.g. {"severity":["CRITICAL","HIGH"], "source_service":"siem"}
    trigger_conditions JSONB       NOT NULL DEFAULT '{}',
    is_active          BOOLEAN     NOT NULL DEFAULT TRUE,
    -- Stats
    run_count          INT         NOT NULL DEFAULT 0,
    success_count      INT         NOT NULL DEFAULT 0,
    failure_count      INT         NOT NULL DEFAULT 0,
    last_run_at        TIMESTAMPTZ,
    created_by         UUID,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_soar_playbooks_tenant        ON soar_playbooks (tenant_id);
CREATE INDEX IF NOT EXISTS idx_soar_playbooks_active_trigger ON soar_playbooks (tenant_id, trigger_type) WHERE is_active;

-- ── Playbook steps ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS soar_playbook_steps (
    id           UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    playbook_id  UUID    NOT NULL REFERENCES soar_playbooks(id) ON DELETE CASCADE,
    step_order   INT     NOT NULL,
    name         TEXT    NOT NULL,
    action_type  TEXT    NOT NULL
                 CHECK (action_type IN (
                     'block_ip','unblock_ip',
                     'disable_user','enable_user',
                     'isolate_host','unisolate_host',
                     'enrich_ioc','add_to_blocklist',
                     'create_ticket','close_ticket',
                     'send_notification',
                     'run_siem_query',
                     'tag_entity',
                     'mark_compromised',
                     'create_incident',
                     'wait'
                 )),
    -- Params: action-specific config, may reference event fields via {{field}} templates
    action_params JSONB  NOT NULL DEFAULT '{}',
    on_failure    TEXT   NOT NULL DEFAULT 'abort' CHECK (on_failure IN ('abort','continue','retry')),
    retry_count   INT    NOT NULL DEFAULT 0,
    timeout_sec   INT    NOT NULL DEFAULT 30,
    UNIQUE (playbook_id, step_order)
);

CREATE INDEX IF NOT EXISTS idx_soar_steps_playbook ON soar_playbook_steps (playbook_id, step_order);

-- ── Executions ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS soar_executions (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    playbook_id     UUID        NOT NULL REFERENCES soar_playbooks(id),
    incident_id     UUID        REFERENCES soar_incidents(id),
    -- The event that triggered this execution (full payload snapshot)
    trigger_event   JSONB       NOT NULL DEFAULT '{}',
    status          TEXT        NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','running','completed','failed','aborted')),
    steps_total     INT         NOT NULL DEFAULT 0,
    steps_completed INT         NOT NULL DEFAULT 0,
    steps_failed    INT         NOT NULL DEFAULT 0,
    result_summary  JSONB       NOT NULL DEFAULT '{}',
    error_message   TEXT,
    triggered_by    UUID,       -- user_id or NULL for auto-trigger
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_soar_exec_tenant    ON soar_executions (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_soar_exec_playbook  ON soar_executions (playbook_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_soar_exec_incident  ON soar_executions (incident_id) WHERE incident_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_soar_exec_status    ON soar_executions (tenant_id, status);

-- ── Execution step results ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS soar_execution_steps (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id  UUID        NOT NULL REFERENCES soar_executions(id) ON DELETE CASCADE,
    step_id       UUID        NOT NULL REFERENCES soar_playbook_steps(id),
    step_order    INT         NOT NULL,
    action_type   TEXT        NOT NULL,
    status        TEXT        NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','running','completed','failed','skipped')),
    output        JSONB       NOT NULL DEFAULT '{}',
    error_message TEXT,
    attempts      INT         NOT NULL DEFAULT 0,
    started_at    TIMESTAMPTZ,
    completed_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_soar_exec_steps_exec ON soar_execution_steps (execution_id, step_order);
