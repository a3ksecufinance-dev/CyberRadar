-- Migration: 000031_create_service_accounts
-- Foundation Platform — machine callers get an identity of their own.
--
-- Until now every caller was a person. Endpoints written for machines —
-- collector ingestion, the audit write API — could only be protected by
-- "some valid user token", so any analyst's token reached them and no
-- machine could be revoked without disabling a human.
--
-- A service account is an identity of type 'service_account', so roles,
-- role_permissions and the whole RBAC catalogue apply to it unchanged. This
-- table adds only what a machine needs and a person does not: a client
-- credential, a rotation deadline, and a scope.

CREATE TABLE IF NOT EXISTS service_accounts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- The principal. Roles come from identity_roles, exactly as for a user,
    -- which is why a service account needs no permission model of its own.
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    client_id   VARCHAR(128) NOT NULL,
    -- bcrypt, never the secret. It is shown once, at creation, and is
    -- unrecoverable afterwards.
    secret_hash VARCHAR(255) NOT NULL,

    -- 'tenant': tokens are always for tenant_id above — the normal case, and
    --   what an ingestion agent gets, so an agent at one bank cannot write
    --   events for another.
    -- 'platform': may request a token for any tenant, named explicitly. This
    --   is what lets one SOAR process act on an alert belonging to any
    --   customer. It is a broad grant, so it is opt-in per account and every
    --   token minted under it is logged with the tenant it was minted for.
    scope       VARCHAR(20) NOT NULL DEFAULT 'tenant'
                    CHECK (scope IN ('tenant', 'platform')),

    description TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT true,

    -- A credential with no end date is a credential nobody rotates.
    expires_at   TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    revoked_at   TIMESTAMP WITH TIME ZONE,

    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by  UUID REFERENCES identities(id),
    updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- client_id is what the credential presents, so it is unique platform-wide
-- rather than per tenant: the lookup happens before any tenant is known.
CREATE UNIQUE INDEX idx_service_accounts_client_id ON service_accounts(client_id);
CREATE INDEX idx_service_accounts_tenant ON service_accounts(tenant_id);
CREATE INDEX idx_service_accounts_identity ON service_accounts(identity_id);

CREATE TRIGGER service_accounts_updated_at
    BEFORE UPDATE ON service_accounts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ─── Permissions machines need and people did not ─────────────────────────
--
-- events:ingest is separate from any existing resource because writing raw
-- events into the pipeline is not something a role like soc_analyst should
-- inherit from a read right. audit:write likewise: reading the trail and
-- appending to it are different authorities, which is why audit:read and
-- audit:export already exist apart.
INSERT INTO permissions (resource, action, description) VALUES
    ('events', 'ingest', 'Submit raw events to the ingestion pipeline'),
    ('audit',  'write',  'Append entries to the audit trail')
ON CONFLICT (resource, action) DO NOTHING;

-- ─── Roles for machines ───────────────────────────────────────────────────
INSERT INTO roles (id, tenant_id, name, description, is_system) VALUES
    ('10000000-0000-0000-0000-000000000012', '00000000-0000-0000-0000-000000000001',
     'collector_agent',  'Ingestion agent or connector: submits events, nothing else', true),
    ('10000000-0000-0000-0000-000000000013', '00000000-0000-0000-0000-000000000001',
     'platform_service', 'A CRP service acting without a user behind it', true)
ON CONFLICT DO NOTHING;

-- collector_agent is deliberately minimal: an agent that is captured should
-- be able to submit events and read nothing at all.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON (p.resource, p.action) IN (('events', 'ingest'))
WHERE r.name = 'collector_agent'
  AND r.tenant_id = '00000000-0000-0000-0000-000000000001'
ON CONFLICT DO NOTHING;

-- platform_service records what a service does on its own behalf. It stays
-- narrow on purpose: a service acting for a user should forward that user's
-- token and stay inside their scope, as the copilot does, rather than reach
-- for this role.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON (p.resource, p.action) IN (('audit', 'write'))
WHERE r.name = 'platform_service'
  AND r.tenant_id = '00000000-0000-0000-0000-000000000001'
ON CONFLICT DO NOTHING;
