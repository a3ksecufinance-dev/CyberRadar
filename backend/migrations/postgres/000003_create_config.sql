-- Migration: 000003_create_config
-- Foundation Platform — FND-06: Configuration Management

CREATE TABLE IF NOT EXISTS config_entries (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key         VARCHAR(255) NOT NULL,
    value       JSONB NOT NULL,
    description TEXT,
    version     INT NOT NULL DEFAULT 1,
    created_by  UUID REFERENCES identities(id),
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_config_tenant_key ON config_entries(tenant_id, key);

CREATE TRIGGER config_updated_at
    BEFORE UPDATE ON config_entries
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ─── Config history (immutable versioning) ─────────────────
CREATE TABLE IF NOT EXISTS config_history (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    config_id   UUID NOT NULL REFERENCES config_entries(id),
    key         VARCHAR(255) NOT NULL,
    old_value   JSONB,
    new_value   JSONB NOT NULL,
    version     INT NOT NULL,
    changed_by  UUID REFERENCES identities(id),
    changed_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_config_history_config ON config_history(config_id);
CREATE INDEX idx_config_history_tenant ON config_history(tenant_id, changed_at DESC);

-- Auto-version trigger
CREATE OR REPLACE FUNCTION config_version_trigger()
RETURNS TRIGGER AS $$
BEGIN
    NEW.version = OLD.version + 1;
    INSERT INTO config_history (tenant_id, config_id, key, old_value, new_value, version)
    VALUES (OLD.tenant_id, OLD.id, OLD.key, OLD.value, NEW.value, NEW.version);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER config_versioning
    BEFORE UPDATE OF value ON config_entries
    FOR EACH ROW EXECUTE FUNCTION config_version_trigger();

-- ─── Notification rules ────────────────────────────────────
CREATE TABLE IF NOT EXISTS notification_rules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        VARCHAR(255) NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    conditions  JSONB NOT NULL DEFAULT '{}',  -- trigger conditions
    channels    JSONB NOT NULL DEFAULT '[]',  -- email, slack, webhook, etc.
    template_id VARCHAR(100),
    priority    INT NOT NULL DEFAULT 50,
    created_by  UUID REFERENCES identities(id),
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notif_rules_tenant ON notification_rules(tenant_id) WHERE enabled = true;

CREATE TRIGGER notif_rules_updated_at
    BEFORE UPDATE ON notification_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
