-- ─── The connector registry ───────────────────────────────────────────────────
--
-- What a connector *is*: declared by whoever set it up, mutable, low in volume
-- and read for its exact current state. That is relational configuration, and
-- it belongs beside the other per-tenant configuration this service owns.
--
-- What a connector *did* lives elsewhere, in ClickHouse, and is not duplicated
-- here: crp_audit.cyber_events holds every event with its connector, and the
-- collector answers "which source went quiet" from it. A counter kept in both
-- places would drift, and the one that disagreed with the events would be the
-- one people read.
--
-- There is a crp_fabric.connectors table in ClickHouse with a similar name. It
-- is a ReplacingMergeTree holding the last liveness report a connector sent
-- about itself — an observation, keyed the same way but neither unique nor
-- updatable. It is not this table and does not replace it.
CREATE TABLE IF NOT EXISTS connectors (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    name         TEXT NOT NULL,
    source_type  TEXT NOT NULL,              -- firewall, edr, iam, cbs, swift, proxy, dns…
    format       TEXT NOT NULL DEFAULT 'json', -- json, cef, syslog, leef, winevent…

    -- What the connector needs to do its job: endpoints, polling intervals,
    -- field mappings. Deliberately opaque to this service, which stores and
    -- returns it without interpreting it — a connector's own settings are its
    -- business, and parsing them here would make every new connector type a
    -- change to the tenant service.
    --
    -- No secrets: a credential belongs to the service account the connector
    -- authenticates with, not to its configuration row.
    config       JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- What the operator expects of it, not what it is doing. "enabled" means
    -- somebody wants this source collected; whether it is actually sending is
    -- the collector's answer, from the events.
    enabled      BOOLEAN NOT NULL DEFAULT true,

    -- How quiet this source may go before anyone should worry. A firewall and
    -- a quarterly compliance feed are silent on scales with nothing in common,
    -- so the threshold is a property of the connector and not a constant.
    silent_after_seconds INTEGER NOT NULL DEFAULT 3600
        CONSTRAINT connectors_silent_after_positive CHECK (silent_after_seconds > 0),

    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Two connectors of one tenant cannot share a name: the name is what an
    -- operator types when something is wrong, and an ambiguous one wastes the
    -- minutes that matter.
    CONSTRAINT connectors_name_unique_per_tenant UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_connectors_tenant ON connectors (tenant_id);
CREATE INDEX IF NOT EXISTS idx_connectors_enabled ON connectors (tenant_id, enabled) WHERE enabled;
