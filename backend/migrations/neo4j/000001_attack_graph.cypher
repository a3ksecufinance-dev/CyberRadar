// ═══════════════════════════════════════════════════════════════════════════
// 000001 — Attack graph: constraints and indexes
//
// The attack graph is mirrored from PostgreSQL, which stays the source of
// truth. These constraints are the PostgreSQL keys restated in Cypher:
//
//   attack_node_id   ↔ attack_nodes' primary key, scoped by tenant
//   attack_node_ref  ↔ the ON CONFLICT target of UpsertNode
//
// Keeping them identical is what makes a difference between the two stores a
// bug rather than a difference between two schemas.
//
// There is deliberately no uniqueness constraint on the :ATTACKS relationship.
// Relationship constraints are a Neo4j Enterprise feature and this deployment
// targets Community; MergeEdge keys on (tenant_id, source, target, edge_type)
// through MERGE instead, which holds because nothing creates a relationship
// any other way.
//
// Tenant isolation is a property here, not a column the schema enforces. Every
// read in graph_neo4j.go filters tenant_id on the relationship and on both
// endpoint nodes, so a relationship written across tenants is unreachable from
// either side rather than leaking one bank's topology into the other's
// traversal.
//
// The service applies these same statements at startup (EnsureSchema), so a
// deployment that never runs this file still gets them; the file is the record,
// and a test asserts the two agree.
// ═══════════════════════════════════════════════════════════════════════════

CREATE CONSTRAINT attack_node_id IF NOT EXISTS
FOR (n:AttackNode) REQUIRE (n.tenant_id, n.id) IS UNIQUE;

CREATE CONSTRAINT attack_node_ref IF NOT EXISTS
FOR (n:AttackNode) REQUIRE (n.tenant_id, n.ref_id, n.node_type) IS UNIQUE;

CREATE INDEX attack_node_tenant IF NOT EXISTS
FOR (n:AttackNode) ON (n.tenant_id);

CREATE INDEX attack_edge_tenant IF NOT EXISTS
FOR ()-[e:ATTACKS]-() ON (e.tenant_id);
