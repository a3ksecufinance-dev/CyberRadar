-- Domain 13: API Framework — API Keys, Rate Limiting, Webhooks, Usage Tracking

-- ── API Keys ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS apifw_api_keys (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL,
    name             TEXT        NOT NULL,
    key_prefix       TEXT        NOT NULL,  -- first 8 chars + "..." shown in UI
    key_hash         TEXT        NOT NULL,  -- SHA-256 of the full raw key, never returned
    description      TEXT,
    scopes           TEXT[]      NOT NULL DEFAULT '{}',
                     -- read | write | admin | webhook
    rate_limit_rpm   INT         NOT NULL DEFAULT 60,   -- requests per minute
    rate_limit_rpd   INT         NOT NULL DEFAULT 10000, -- requests per day
    is_active        BOOLEAN     NOT NULL DEFAULT TRUE,
    last_used_at     TIMESTAMPTZ,
    expires_at       TIMESTAMPTZ,
    created_by       UUID,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_apifw_keys_tenant        ON apifw_api_keys (tenant_id);
CREATE INDEX IF NOT EXISTS idx_apifw_keys_tenant_active ON apifw_api_keys (tenant_id) WHERE is_active;
CREATE INDEX IF NOT EXISTS idx_apifw_keys_hash          ON apifw_api_keys (key_hash);

-- ── API Key Usage ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS apifw_key_usage (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID        NOT NULL,
    key_id       UUID        NOT NULL REFERENCES apifw_api_keys(id) ON DELETE CASCADE,
    endpoint     TEXT        NOT NULL,
    method       TEXT        NOT NULL,
    status_code  INT         NOT NULL,
    latency_ms   INT         NOT NULL DEFAULT 0,
    ip_address   TEXT,
    user_agent   TEXT,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_apifw_usage_key_time    ON apifw_key_usage (key_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_apifw_usage_tenant_time ON apifw_key_usage (tenant_id, requested_at DESC);

-- ── Webhooks ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS apifw_webhooks (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL,
    name              TEXT        NOT NULL,
    url               TEXT        NOT NULL,
    secret            TEXT,       -- HMAC-SHA256 signing secret
    events            TEXT[]      NOT NULL DEFAULT '{}',
                      -- alert.created | incident.created | ioc.matched | anomaly.detected | vuln.found
    is_active         BOOLEAN     NOT NULL DEFAULT TRUE,
    failure_count     INT         NOT NULL DEFAULT 0,
    last_triggered_at TIMESTAMPTZ,
    last_status_code  INT,
    created_by        UUID,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_apifw_webhooks_tenant        ON apifw_webhooks (tenant_id);
CREATE INDEX IF NOT EXISTS idx_apifw_webhooks_tenant_active ON apifw_webhooks (tenant_id) WHERE is_active;

-- ── Webhook Deliveries ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS apifw_webhook_deliveries (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    webhook_id      UUID        NOT NULL REFERENCES apifw_webhooks(id) ON DELETE CASCADE,
    event_type      TEXT        NOT NULL,
    payload         JSONB       NOT NULL DEFAULT '{}',
    response_status INT,
    response_body   TEXT,
    attempt         INT         NOT NULL DEFAULT 1,
    success         BOOLEAN     NOT NULL DEFAULT FALSE,
    delivered_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_apifw_deliveries_webhook ON apifw_webhook_deliveries (webhook_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_apifw_deliveries_tenant  ON apifw_webhook_deliveries (tenant_id, created_at DESC);
