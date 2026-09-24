-- Migration: 000034_create_copilot_knowledge
-- A corpus the Copilot can retrieve from, rather than only query.
--
-- The Copilot's tools answer exact questions — "which alerts are critical",
-- "look up this IOC". They cannot answer the question an analyst actually asks
-- at 3am: "have we seen this before?". That is a similarity question, and it
-- needs a vector index over what the platform has already written down:
-- resolved incidents, playbook notes, detection-rule rationales, runbooks.

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS copilot_knowledge (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Where this chunk came from, so an answer can cite it and a re-index can
    -- replace it. source_ref is the id in that source system.
    source_type VARCHAR(50)  NOT NULL
                    CHECK (source_type IN ('incident', 'alert', 'playbook', 'rule', 'runbook', 'note')),
    source_ref  VARCHAR(255) NOT NULL,

    title       TEXT NOT NULL,
    content     TEXT NOT NULL,

    -- 1024 dimensions suits the open embedding models a sovereign deployment
    -- is most likely to self-host (bge-large, e5-large, multilingual-e5-large).
    -- The column's dimension is fixed, so changing model family is a migration,
    -- not a config change — the service checks its embedder against this at
    -- startup rather than letting a mismatch corrupt the index.
    embedding   vector(1024) NOT NULL,

    metadata    JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- One chunk per source document per tenant, so re-indexing a document replaces
-- it instead of accumulating near-duplicates that all match the same query.
CREATE UNIQUE INDEX idx_copilot_knowledge_source
    ON copilot_knowledge (tenant_id, source_type, source_ref);

-- HNSW with cosine distance: the embedding models above are trained for cosine
-- similarity, and HNSW keeps recall high without the IVFFlat requirement of
-- training on a populated table — which a new tenant does not have.
CREATE INDEX idx_copilot_knowledge_embedding
    ON copilot_knowledge USING hnsw (embedding vector_cosine_ops);

CREATE INDEX idx_copilot_knowledge_tenant ON copilot_knowledge (tenant_id);

CREATE TRIGGER copilot_knowledge_updated_at
    BEFORE UPDATE ON copilot_knowledge
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ─── Permission for the new DELETE route ──────────────────────────────────
--
-- 000030 declared :delete only for the domains that actually exposed a DELETE
-- route, so the right was never granted where nothing could be deleted. The
-- copilot now has one, so it earns the permission — without this the route
-- would answer 403 to everyone, for ever.
--
-- Removing a document changes what every later answer is grounded on, so it
-- goes to whoever may already add one rather than to a narrower set.
INSERT INTO permissions (resource, action, description) VALUES
    ('copilot', 'delete', 'Remove documents from the Copilot knowledge index')
ON CONFLICT (resource, action) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.resource = 'copilot' AND p.action = 'delete'
WHERE r.name IN ('tenant_admin', 'soc_analyst_l1', 'soc_analyst_l2', 'threat_hunter',
                 'incident_responder', 'fraud_analyst', 'ciso')
  AND r.tenant_id = '00000000-0000-0000-0000-000000000001'
ON CONFLICT DO NOTHING;
