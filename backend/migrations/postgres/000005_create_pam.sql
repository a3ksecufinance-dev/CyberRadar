-- Migration: 000005_create_pam
-- Domain 3 — Identity & PAM: privileged access management + identity risk

-- ─── Privileged Account Registry ─────────────────────────────────────────────
-- Catalogues all privileged accounts (root, admin, service accounts, shared).
CREATE TABLE IF NOT EXISTS privileged_accounts (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    account_name            VARCHAR(255) NOT NULL,   -- e.g. root, Administrator, sa, deploy
    account_type            VARCHAR(50)  NOT NULL
                                CHECK (account_type IN ('local_admin','domain_admin','service','shared','emergency','api_key')),
    target_asset_id         UUID REFERENCES assets(id) ON DELETE SET NULL,
    target_asset_hostname   VARCHAR(255),
    target_protocol         VARCHAR(20) DEFAULT 'ssh'
                                CHECK (target_protocol IN ('ssh','rdp','db','api','console','winrm')),

    -- Credential management
    credential_stored       BOOLEAN NOT NULL DEFAULT false,
    credential_ref          VARCHAR(512),   -- Vault path (never the actual secret)
    last_rotated_at         TIMESTAMP WITH TIME ZONE,
    rotation_policy_days    INT NOT NULL DEFAULT 30,
    auto_rotate             BOOLEAN NOT NULL DEFAULT true,

    -- Access policy
    requires_approval       BOOLEAN NOT NULL DEFAULT true,
    max_session_minutes     INT NOT NULL DEFAULT 60,
    allowed_roles           TEXT[] NOT NULL DEFAULT '{}',   -- roles that may request

    -- Status
    is_active               BOOLEAN NOT NULL DEFAULT true,
    last_used_at            TIMESTAMP WITH TIME ZONE,
    use_count               INT NOT NULL DEFAULT 0,

    created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_priv_accounts_tenant      ON privileged_accounts(tenant_id) WHERE is_active;
CREATE INDEX idx_priv_accounts_asset       ON privileged_accounts(tenant_id, target_asset_id) WHERE is_active;
CREATE INDEX idx_priv_accounts_rotation    ON privileged_accounts(tenant_id, last_rotated_at) WHERE auto_rotate AND is_active;

CREATE TRIGGER privileged_accounts_updated_at
    BEFORE UPDATE ON privileged_accounts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ─── JIT Access Requests ──────────────────────────────────────────────────────
-- Workflow: requester → pending → approved/rejected → session opened
CREATE TABLE IF NOT EXISTS pam_access_requests (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    requester_id            UUID NOT NULL REFERENCES identities(id),
    privileged_account_id   UUID REFERENCES privileged_accounts(id) ON DELETE SET NULL,
    target_asset_id         UUID REFERENCES assets(id) ON DELETE SET NULL,

    reason                  TEXT NOT NULL,
    ticket_ref              VARCHAR(255),   -- JIRA / ServiceNow ticket
    requested_duration_min  INT NOT NULL DEFAULT 60 CHECK (requested_duration_min BETWEEN 1 AND 480),

    status                  VARCHAR(20) NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending','approved','rejected','expired','cancelled','revoked')),
    approver_id             UUID REFERENCES identities(id) ON DELETE SET NULL,
    approval_note           TEXT,

    valid_from              TIMESTAMP WITH TIME ZONE,
    valid_until             TIMESTAMP WITH TIME ZONE,

    created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    resolved_at             TIMESTAMP WITH TIME ZONE,

    -- Auto-expire pending requests after 24h
    expires_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW() + INTERVAL '24 hours'
);

CREATE INDEX idx_pam_requests_tenant       ON pam_access_requests(tenant_id, status, created_at DESC);
CREATE INDEX idx_pam_requests_requester    ON pam_access_requests(tenant_id, requester_id, created_at DESC);
CREATE INDEX idx_pam_requests_pending      ON pam_access_requests(tenant_id) WHERE status = 'pending';

-- ─── Privileged Sessions ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pam_sessions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    request_id              UUID REFERENCES pam_access_requests(id) ON DELETE SET NULL,
    user_id                 UUID NOT NULL REFERENCES identities(id),
    privileged_account_id   UUID REFERENCES privileged_accounts(id) ON DELETE SET NULL,
    target_asset_id         UUID REFERENCES assets(id) ON DELETE SET NULL,

    protocol                VARCHAR(20),
    status                  VARCHAR(20) NOT NULL DEFAULT 'active'
                                CHECK (status IN ('active','terminated','expired','suspicious','locked')),

    -- Time bounds
    started_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at              TIMESTAMP WITH TIME ZONE NOT NULL,
    terminated_at           TIMESTAMP WITH TIME ZONE,

    -- Session context
    client_ip               VARCHAR(45),
    client_user_agent       VARCHAR(512),
    mfa_verified            BOOLEAN NOT NULL DEFAULT false,

    -- Activity metrics
    commands_count          INT NOT NULL DEFAULT 0,
    bytes_transferred       BIGINT NOT NULL DEFAULT 0,

    -- Risk
    risk_score              FLOAT NOT NULL DEFAULT 0.0,
    risk_flags              TEXT[] NOT NULL DEFAULT '{}',

    -- Recording (S3 path or vault ref)
    recording_ref           TEXT
);

CREATE INDEX idx_pam_sessions_tenant       ON pam_sessions(tenant_id, status, started_at DESC);
CREATE INDEX idx_pam_sessions_user         ON pam_sessions(tenant_id, user_id, started_at DESC);
CREATE INDEX idx_pam_sessions_active       ON pam_sessions(tenant_id, expires_at) WHERE status = 'active';
CREATE INDEX idx_pam_sessions_asset        ON pam_sessions(tenant_id, target_asset_id) WHERE status = 'active';

-- ─── Session Events (audit trail inside a session) ───────────────────────────
-- Written during an active session; immutable after session ends.
CREATE TABLE IF NOT EXISTS pam_session_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    session_id      UUID NOT NULL REFERENCES pam_sessions(id) ON DELETE CASCADE,
    timestamp       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    event_type      VARCHAR(50) NOT NULL
                        CHECK (event_type IN ('command','file_access','network','clipboard','screen','auth','transfer')),
    content         TEXT,       -- command text, file path, URL, etc.
    risk_flag       BOOLEAN NOT NULL DEFAULT false,
    risk_reason     TEXT
);

CREATE INDEX idx_pam_session_events_session  ON pam_session_events(tenant_id, session_id, timestamp);
CREATE INDEX idx_pam_session_events_risky    ON pam_session_events(tenant_id, session_id) WHERE risk_flag;

-- ─── Identity Risk Profiles ───────────────────────────────────────────────────
-- One row per identity — maintained by the risk engine from D1 events + behavior.
CREATE TABLE IF NOT EXISTS identity_risk_profiles (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_id             UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,

    -- Composite risk score (0–10)
    risk_score              FLOAT NOT NULL DEFAULT 0.0,

    -- Dimensional scores
    failed_login_score      FLOAT NOT NULL DEFAULT 0.0,
    anomalous_hours_score   FLOAT NOT NULL DEFAULT 0.0,
    geo_anomaly_score       FLOAT NOT NULL DEFAULT 0.0,
    privilege_abuse_score   FLOAT NOT NULL DEFAULT 0.0,
    data_exfil_score        FLOAT NOT NULL DEFAULT 0.0,
    lateral_movement_score  FLOAT NOT NULL DEFAULT 0.0,

    -- Behavioral baseline (learned over 30 days)
    normal_login_hours      INT[]   NOT NULL DEFAULT '{}',  -- hours 0–23
    normal_countries        TEXT[]  NOT NULL DEFAULT '{}',
    normal_ip_prefixes      TEXT[]  NOT NULL DEFAULT '{}',  -- /24 CIDR prefixes
    avg_daily_events        FLOAT   NOT NULL DEFAULT 0.0,
    baseline_ready          BOOLEAN NOT NULL DEFAULT false,  -- enough data collected

    -- Anomaly tracking
    last_anomaly_at         TIMESTAMP WITH TIME ZONE,
    anomaly_count_7d        INT NOT NULL DEFAULT 0,
    anomaly_count_30d       INT NOT NULL DEFAULT 0,

    -- Activity summary
    last_login_at           TIMESTAMP WITH TIME ZONE,
    last_login_ip           VARCHAR(45),
    last_login_country      VARCHAR(3),
    events_today            INT NOT NULL DEFAULT 0,
    events_7d               INT NOT NULL DEFAULT 0,
    priv_sessions_30d       INT NOT NULL DEFAULT 0,

    updated_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_identity_risk UNIQUE (tenant_id, identity_id)
);

CREATE INDEX idx_identity_risk_tenant      ON identity_risk_profiles(tenant_id, risk_score DESC);
CREATE INDEX idx_identity_risk_high        ON identity_risk_profiles(tenant_id) WHERE risk_score >= 7.0;
CREATE INDEX idx_identity_risk_anomaly     ON identity_risk_profiles(tenant_id, last_anomaly_at DESC)
    WHERE last_anomaly_at IS NOT NULL;
