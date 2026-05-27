-- Domain 12: AI Copilot
-- Conversational security assistant powered by Claude.

-- ── Copilot sessions ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS copilot_sessions (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL,
    user_id     UUID        NOT NULL,
    title       TEXT,                   -- auto-generated from first message
    context     JSONB       NOT NULL DEFAULT '{}',  -- pinned entities, filters
    is_active   BOOLEAN     NOT NULL DEFAULT TRUE,
    message_count INT       NOT NULL DEFAULT 0,
    last_message_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_copilot_sessions_user    ON copilot_sessions (tenant_id, user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_copilot_sessions_active  ON copilot_sessions (tenant_id, is_active, updated_at DESC);

-- ── Messages ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS copilot_messages (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id  UUID        NOT NULL REFERENCES copilot_sessions(id) ON DELETE CASCADE,
    tenant_id   UUID        NOT NULL,
    role        TEXT        NOT NULL CHECK (role IN ('user','assistant','tool')),
    content     TEXT        NOT NULL,
    -- Tool use metadata (when role='tool' or assistant invoked a tool)
    tool_name   TEXT,
    tool_input  JSONB,
    tool_output JSONB,
    -- Token usage
    input_tokens  INT       NOT NULL DEFAULT 0,
    output_tokens INT       NOT NULL DEFAULT 0,
    -- Latency in milliseconds
    latency_ms  INT         NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_copilot_messages_session ON copilot_messages (session_id, created_at ASC);
CREATE INDEX IF NOT EXISTS idx_copilot_messages_tenant  ON copilot_messages (tenant_id, created_at DESC);

-- ── Async threat hunt jobs ────────────────────────────────────────────────────
-- Long-running AI analysis tasks that run in the background
CREATE TABLE IF NOT EXISTS copilot_hunt_jobs (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    user_id         UUID        NOT NULL,
    session_id      UUID        REFERENCES copilot_sessions(id),
    hunt_type       TEXT        NOT NULL
                    CHECK (hunt_type IN (
                        'threat_hunt',
                        'incident_triage',
                        'vuln_prioritization',
                        'attack_path_summary',
                        'ioc_correlation',
                        'entity_profiling'
                    )),
    query           TEXT        NOT NULL,   -- natural language query
    status          TEXT        NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','running','completed','failed')),
    result_summary  TEXT,
    result_payload  JSONB,
    error_message   TEXT,
    input_tokens    INT         NOT NULL DEFAULT 0,
    output_tokens   INT         NOT NULL DEFAULT 0,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_copilot_jobs_tenant  ON copilot_hunt_jobs (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_copilot_jobs_user    ON copilot_hunt_jobs (tenant_id, user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_copilot_jobs_status  ON copilot_hunt_jobs (tenant_id, status);
