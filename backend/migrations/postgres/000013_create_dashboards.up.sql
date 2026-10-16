-- Domain 11: Dashboards & Reporting

-- ── Dashboard definitions ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS dashboards (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL,
    name        TEXT        NOT NULL,
    description TEXT,
    layout      TEXT        NOT NULL DEFAULT 'grid'
                CHECK (layout IN ('grid','freeform')),
    -- Grid dimensions: columns (1-24), rows auto
    columns     INT         NOT NULL DEFAULT 12
                CHECK (columns BETWEEN 1 AND 24),
    is_default  BOOLEAN     NOT NULL DEFAULT FALSE,
    is_public   BOOLEAN     NOT NULL DEFAULT FALSE,   -- visible to all tenant users
    tags        TEXT[]      NOT NULL DEFAULT '{}',
    created_by  UUID,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Only one default dashboard per tenant
CREATE UNIQUE INDEX IF NOT EXISTS uq_dashboards_default
    ON dashboards (tenant_id) WHERE is_default;

CREATE INDEX IF NOT EXISTS idx_dashboards_tenant ON dashboards (tenant_id, updated_at DESC);

-- ── Widgets ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS dashboard_widgets (
    id            UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    dashboard_id  UUID    NOT NULL REFERENCES dashboards(id) ON DELETE CASCADE,
    tenant_id     UUID    NOT NULL,
    widget_type   TEXT    NOT NULL
                  CHECK (widget_type IN (
                      'metric_card',
                      'time_series',
                      'bar_chart',
                      'pie_chart',
                      'heatmap',
                      'table',
                      'alert_feed',
                      'risk_gauge',
                      'topology_map',
                      'text'
                  )),
    title         TEXT    NOT NULL,
    -- Grid position and size
    pos_x         INT     NOT NULL DEFAULT 0,
    pos_y         INT     NOT NULL DEFAULT 0,
    width         INT     NOT NULL DEFAULT 4 CHECK (width BETWEEN 1 AND 24),
    height        INT     NOT NULL DEFAULT 3 CHECK (height BETWEEN 1 AND 20),
    -- Data source: which domain service + metric key
    data_source   TEXT    NOT NULL
                  CHECK (data_source IN (
                      'siem','ueba','ti','vuln','attackpath',
                      'soar','asset','kg','platform'
                  )),
    metric_key    TEXT    NOT NULL,   -- e.g. "open_alerts", "risk_score_trend"
    -- Widget-specific config (filters, aggregation, thresholds, colors …)
    config        JSONB   NOT NULL DEFAULT '{}',
    -- Refresh interval in seconds (0 = manual only)
    refresh_sec   INT     NOT NULL DEFAULT 60,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_widgets_dashboard ON dashboard_widgets (dashboard_id);
CREATE INDEX IF NOT EXISTS idx_widgets_tenant    ON dashboard_widgets (tenant_id);

-- ── Reports ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS dashboard_reports (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    name            TEXT        NOT NULL,
    description     TEXT,
    report_type     TEXT        NOT NULL
                    CHECK (report_type IN (
                        'executive_summary',
                        'incident_summary',
                        'vulnerability_posture',
                        'threat_intelligence',
                        'compliance',
                        'custom'
                    )),
    -- Schedule: cron expression or NULL for on-demand
    schedule        TEXT,
    -- Last generated snapshot (JSON payload)
    last_payload    JSONB,
    last_run_at     TIMESTAMPTZ,
    next_run_at     TIMESTAMPTZ,
    status          TEXT        NOT NULL DEFAULT 'idle'
                    CHECK (status IN ('idle','running','completed','failed')),
    format          TEXT        NOT NULL DEFAULT 'json'
                    CHECK (format IN ('json','pdf')),
    recipients      TEXT[]      NOT NULL DEFAULT '{}',  -- email addresses
    created_by      UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reports_tenant        ON dashboard_reports (tenant_id);
CREATE INDEX IF NOT EXISTS idx_reports_next_run      ON dashboard_reports (next_run_at) WHERE next_run_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_reports_status        ON dashboard_reports (tenant_id, status);
