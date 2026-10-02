// ═══════════════════════════════════════════════════════════════════════════
// 000002 — Knowledge graph: constraints and indexes
//
// The knowledge graph is mirrored from PostgreSQL, which stays the source of
// truth. The key is (tenant_id, id): PostgreSQL decides what an entity is, and
// its identifier is the one thing that is stable across a mirror rewrite.
//
// PostgreSQL's other uniqueness rule — (tenant_id, entity_type, external_id),
// and only where external_id is set — has no equivalent here, because Neo4j has
// no partial constraints. It does not need one: every write to this store comes
// from a row PostgreSQL has already accepted under that rule.
//
// Relationships carry their real Cypher type (USES, RESOLVES_TO, …) rather than
// one generic type with the real one as a property, so that filtering a
// traversal by type uses the type itself and the graph is readable in a
// browser. Cypher cannot parameterise a relationship type, so those statements
// are built from a fixed table keyed by the service's own constants — nothing
// from a request reaches the query text. There is no uniqueness constraint on
// them: relationship constraints are a Neo4j Enterprise feature and this
// deployment targets Community. MERGE on (tenant_id, source, target, type) —
// PostgreSQL's uq_kg_rel, restated — holds instead, because nothing creates a
// relationship any other way.
//
// Tenant isolation is a property here, not a column the schema enforces. Every
// read filters tenant_id on the relationship and on both endpoint entities, so
// a relationship written across tenants is unreachable from either side.
//
// The service applies these same statements at startup (EnsureSchema), so a
// deployment that never runs this file still gets them; the file is the record,
// and a test asserts the two agree.
// ═══════════════════════════════════════════════════════════════════════════

CREATE CONSTRAINT kg_entity_id IF NOT EXISTS
FOR (n:KGEntity) REQUIRE (n.tenant_id, n.id) IS UNIQUE;

CREATE INDEX kg_entity_tenant IF NOT EXISTS
FOR (n:KGEntity) ON (n.tenant_id);

CREATE INDEX kg_entity_type IF NOT EXISTS
FOR (n:KGEntity) ON (n.tenant_id, n.entity_type);
