package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/cyberradar/platform/internal/pkg/graphdb"
	"github.com/cyberradar/platform/services/knowledgegraph/internal/model"
	"github.com/google/uuid"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// Neo4jGraphStore reads the knowledge graph from Neo4j.
//
// It embeds *KGRepository and overrides only the two reads that are graph
// questions — Neighbors and Subgraph. Everything else stays relational:
// observations are an append-only log of sightings, not topology, and the
// statistics count them alongside entities. PostgreSQL remains the source of
// truth for all of it.
//
// # Tenant isolation
//
// In PostgreSQL isolation is a column the schema puts in every WHERE. In Cypher
// it is a property with no such net. Every read here filters tenant_id on the
// relationship and on both endpoint nodes, so a relationship written across
// tenants is unreachable from either side, and no Cypher in this file is built
// by concatenating anything that came from a request. A database per tenant
// would remove the question, but multi-database is a Neo4j Enterprise feature
// and this deployment targets Community.
type Neo4jGraphStore struct {
	*KGRepository
	driver   neo4j.DriverWithContext
	database string
}

// NewNeo4jGraphStore connects, verifies the connection and creates the schema.
func NewNeo4jGraphStore(ctx context.Context, cfg graphdb.Config, pg *KGRepository) (*Neo4jGraphStore, error) {
	driver, err := graphdb.Open(ctx, cfg)
	if err != nil {
		return nil, err
	}
	s := &Neo4jGraphStore{KGRepository: pg, driver: driver, database: cfg.DatabaseOrDefault()}
	if err := s.EnsureSchema(ctx); err != nil {
		_ = driver.Close(ctx)
		return nil, err
	}
	return s, nil
}

// Close releases the driver's connection pool.
func (s *Neo4jGraphStore) Close(ctx context.Context) error { return s.driver.Close(ctx) }

func (s *Neo4jGraphStore) query(ctx context.Context, cypher string, params map[string]any) (*neo4j.EagerResult, error) {
	return graphdb.Query(ctx, s.driver, s.database, cypher, params)
}

// ─── Schema ───────────────────────────────────────────────────────────────────

// schemaStatements are the constraints and indexes the graph needs.
//
// The key is (tenant_id, id): PostgreSQL decides what an entity is, and its
// identifier is the one thing that is stable. PostgreSQL's other uniqueness
// rule — (tenant_id, entity_type, external_id), and only where external_id is
// set — has no equivalent here, because Neo4j has no partial constraints. It
// does not need one: every write to this store comes from a row PostgreSQL has
// already accepted under that rule.
var schemaStatements = []string{
	`CREATE CONSTRAINT kg_entity_id IF NOT EXISTS
	 FOR (n:KGEntity) REQUIRE (n.tenant_id, n.id) IS UNIQUE`,
	`CREATE INDEX kg_entity_tenant IF NOT EXISTS
	 FOR (n:KGEntity) ON (n.tenant_id)`,
	`CREATE INDEX kg_entity_type IF NOT EXISTS
	 FOR (n:KGEntity) ON (n.tenant_id, n.entity_type)`,
}

// EnsureSchema creates the constraints and indexes if they are absent.
func (s *Neo4jGraphStore) EnsureSchema(ctx context.Context) error {
	for _, stmt := range schemaStatements {
		if _, err := s.query(ctx, stmt, nil); err != nil {
			return fmt.Errorf("neo4j schema: %w", err)
		}
	}
	return nil
}

// ─── Relationship types ───────────────────────────────────────────────────────

// relationshipTypes is every relationship type this graph has, as Cypher
// relationship types.
//
// Cypher cannot take a relationship type as a parameter. The choice is between
// one generic type carrying the real one as a property — which makes every
// query scan and the graph unreadable in a browser — and a fixed table like
// this one. The table wins, and it is keyed by the model's own constants so
// that no string from a request ever reaches the query text: an unknown type is
// refused before any Cypher is built.
var relationshipTypes = map[string]bool{
	model.RelConnectTo:        true,
	model.RelExploits:         true,
	model.RelTargets:          true,
	model.RelCommunicatesWith: true,
	model.RelBelongsTo:        true,
	model.RelResolvesTo:       true,
	model.RelAssociatedWith:   true,
	model.RelAttributedTo:     true,
	model.RelMitigates:        true,
	model.RelHasVulnerability: true,
	model.RelIndicatorOf:      true,
	model.RelUses:             true,
}

func checkRelationshipType(relType string) error {
	if !relationshipTypes[relType] {
		return fmt.Errorf("unknown relationship type %q", relType)
	}
	return nil
}

// ─── Reads ────────────────────────────────────────────────────────────────────

const relReturn = `
	RETURN r.id AS id, r.source_id AS source_id, r.target_id AS target_id,
	       type(r) AS relationship_type, r.weight AS weight, r.confidence AS confidence,
	       r.evidence_source AS evidence_source, r.properties_json AS properties_json,
	       r.valid_from AS valid_from, r.valid_until AS valid_until,
	       r.created_at AS created_at, r.updated_at AS updated_at`

const entityReturn = `
	RETURN n.id AS id, n.entity_type AS entity_type, n.external_id AS external_id,
	       n.name AS name, n.description AS description, n.risk_score AS risk_score,
	       n.confidence AS confidence, n.tags AS tags, n.properties_json AS properties_json,
	       n.first_seen_at AS first_seen_at, n.last_seen_at AS last_seen_at,
	       n.created_at AS created_at, n.updated_at AS updated_at`

// Neighbors walks outward from one entity, reading the graph from Neo4j. The
// walk itself is shared with the PostgreSQL store; only the adjacency query
// below differs.
func (s *Neo4jGraphStore) Neighbors(ctx context.Context, q model.NeighborQuery) ([]model.KGNeighbor, error) {
	return walk(ctx, q,
		func(ctx context.Context, frontier []uuid.UUID) ([]*model.KGRelationship, error) {
			return s.adjacentRelationships(ctx, q.TenantID, frontier, q.Direction, q.RelTypes)
		},
		func(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]*model.KGEntity, error) {
			return s.entitiesByIDs(ctx, q.TenantID, ids)
		})
}

func (s *Neo4jGraphStore) adjacentRelationships(ctx context.Context, tenantID uuid.UUID,
	frontier []uuid.UUID, direction string, relTypes []string) ([]*model.KGRelationship, error) {

	// The pattern is directed for outbound and inbound and undirected for
	// both. The tenant is asserted on the relationship and on both endpoints:
	// a relationship that somehow joined two tenants is then unreachable from
	// either, rather than leaking one bank's graph into the other's traversal.
	var pattern string
	switch direction {
	case "outbound":
		pattern = `(a:KGEntity {tenant_id: $tenant})-[r]->(b:KGEntity {tenant_id: $tenant})`
	case "inbound":
		pattern = `(a:KGEntity {tenant_id: $tenant})<-[r]-(b:KGEntity {tenant_id: $tenant})`
	default: // both
		pattern = `(a:KGEntity {tenant_id: $tenant})-[r]-(b:KGEntity {tenant_id: $tenant})`
	}

	res, err := s.query(ctx, `
		MATCH `+pattern+`
		WHERE a.id IN $frontier
		  AND r.tenant_id = $tenant
		  AND (r.valid_from IS NULL OR r.valid_from <= $now)
		  AND (r.valid_until IS NULL OR r.valid_until > $now)
		  AND (size($rel_types) = 0 OR type(r) IN $rel_types)`+relReturn+`
		ORDER BY r.id`,
		map[string]any{
			"tenant":    tenantID.String(),
			"frontier":  uuidStrings(frontier),
			"rel_types": relTypeFilter(relTypes),
			"now":       time.Now().UTC(),
		})
	if err != nil {
		return nil, err
	}

	// An undirected match returns a relationship once per endpoint in the
	// frontier, so the same one can arrive twice. The walk is idempotent on
	// entities already visited, but a duplicate would still be counted against
	// the traversal's cap, so drop it here.
	seen := make(map[uuid.UUID]bool, len(res.Records))
	out := make([]*model.KGRelationship, 0, len(res.Records))
	for _, rec := range res.Records {
		rel, err := relFromRecord(rec, tenantID)
		if err != nil {
			return nil, err
		}
		if seen[rel.ID] {
			continue
		}
		seen[rel.ID] = true
		out = append(out, rel)
	}
	return out, nil
}

func (s *Neo4jGraphStore) entitiesByIDs(ctx context.Context, tenantID uuid.UUID,
	ids []uuid.UUID) (map[uuid.UUID]*model.KGEntity, error) {

	out := make(map[uuid.UUID]*model.KGEntity, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	res, err := s.query(ctx,
		`MATCH (n:KGEntity {tenant_id: $tenant}) WHERE n.id IN $ids`+entityReturn,
		map[string]any{"tenant": tenantID.String(), "ids": uuidStrings(ids)})
	if err != nil {
		return nil, err
	}
	for _, rec := range res.Records {
		e, err := entityFromRecord(rec, tenantID)
		if err != nil {
			return nil, err
		}
		out[e.ID] = e
	}
	return out, nil
}

// Subgraph returns the named entities and the live relationships among them.
func (s *Neo4jGraphStore) Subgraph(ctx context.Context, tenantID uuid.UUID,
	entityIDs []uuid.UUID) (*model.KGSubgraph, error) {

	sg := &model.KGSubgraph{Entities: []model.KGEntity{}, Relationships: []model.KGRelationship{}}
	if len(entityIDs) == 0 {
		return sg, nil
	}

	entities, err := s.entitiesByIDs(ctx, tenantID, entityIDs)
	if err != nil {
		return nil, fmt.Errorf("subgraph entities: %w", err)
	}
	for _, e := range entities {
		sg.Entities = append(sg.Entities, *e)
	}
	sort.Slice(sg.Entities, func(i, j int) bool {
		return sg.Entities[i].ID.String() < sg.Entities[j].ID.String()
	})

	res, err := s.query(ctx, `
		MATCH (a:KGEntity {tenant_id: $tenant})-[r]->(b:KGEntity {tenant_id: $tenant})
		WHERE a.id IN $ids AND b.id IN $ids
		  AND r.tenant_id = $tenant
		  AND (r.valid_from IS NULL OR r.valid_from <= $now)
		  AND (r.valid_until IS NULL OR r.valid_until > $now)`+relReturn+`
		ORDER BY r.id`,
		map[string]any{
			"tenant": tenantID.String(),
			"ids":    uuidStrings(entityIDs),
			"now":    time.Now().UTC(),
		})
	if err != nil {
		return nil, fmt.Errorf("subgraph relationships: %w", err)
	}
	for _, rec := range res.Records {
		rel, err := relFromRecord(rec, tenantID)
		if err != nil {
			return nil, err
		}
		sg.Relationships = append(sg.Relationships, *rel)
	}
	return sg, nil
}

// ─── Mirror writes ────────────────────────────────────────────────────────────

// MirrorEntity copies an entity PostgreSQL has just accepted into Neo4j.
//
// Every field is written, identifier included: PostgreSQL decides what an
// entity is, and a repeated mirror must converge on that rather than preserve
// whatever Neo4j happened to hold.
func (s *Neo4jGraphStore) MirrorEntity(ctx context.Context, e *model.KGEntity) error {
	props, err := json.Marshal(e.Properties)
	if err != nil {
		return fmt.Errorf("mirror entity %s: encode properties: %w", e.ID, err)
	}
	tags := e.Tags
	if tags == nil {
		tags = []string{}
	}
	_, err = s.query(ctx, `
		MERGE (n:KGEntity {tenant_id: $tenant, id: $id})
		SET n.entity_type     = $entity_type,
		    n.external_id     = $external_id,
		    n.name            = $name,
		    n.description     = $description,
		    n.risk_score      = $risk_score,
		    n.confidence      = $confidence,
		    n.tags            = $tags,
		    n.properties_json = $properties_json,
		    n.first_seen_at   = $first_seen_at,
		    n.last_seen_at    = $last_seen_at,
		    n.created_at      = $created_at,
		    n.updated_at      = $updated_at`,
		map[string]any{
			"tenant":          e.TenantID.String(),
			"id":              e.ID.String(),
			"entity_type":     e.EntityType,
			"external_id":     e.ExternalID,
			"name":            e.Name,
			"description":     e.Description,
			"risk_score":      e.RiskScore,
			"confidence":      e.Confidence,
			"tags":            tags,
			"properties_json": string(props),
			"first_seen_at":   utc(e.FirstSeenAt),
			"last_seen_at":    utc(e.LastSeenAt),
			"created_at":      utc(e.CreatedAt),
			"updated_at":      utc(e.UpdatedAt),
		})
	if err != nil {
		return fmt.Errorf("mirror entity %s: %w", e.ID, err)
	}
	return nil
}

// MirrorRelationship copies a relationship PostgreSQL has just accepted.
//
// It reports an error when either endpoint is missing from Neo4j. Without that
// check the MERGE matches nothing and reports success, which is how a mirror
// quietly loses an edge: PostgreSQL has it, Neo4j does not, and a traversal on
// the Neo4j side never sees the connection it makes.
func (s *Neo4jGraphStore) MirrorRelationship(ctx context.Context, rel *model.KGRelationship) error {
	if err := checkRelationshipType(rel.RelationshipType); err != nil {
		return fmt.Errorf("mirror relationship %s: %w", rel.ID, err)
	}
	props, err := json.Marshal(rel.Properties)
	if err != nil {
		return fmt.Errorf("mirror relationship %s: encode properties: %w", rel.ID, err)
	}

	res, err := s.query(ctx, `
		MATCH (a:KGEntity {tenant_id: $tenant, id: $source_id})
		MATCH (b:KGEntity {tenant_id: $tenant, id: $target_id})
		MERGE (a)-[r:`+rel.RelationshipType+` {tenant_id: $tenant}]->(b)
		SET r.id              = $id,
		    r.source_id       = $source_id,
		    r.target_id       = $target_id,
		    r.weight          = $weight,
		    r.confidence      = $confidence,
		    r.evidence_source = $evidence_source,
		    r.properties_json = $properties_json,
		    r.valid_from      = $valid_from,
		    r.valid_until     = $valid_until,
		    r.created_at      = $created_at,
		    r.updated_at      = $updated_at
		RETURN r.id AS id`,
		map[string]any{
			"tenant":          rel.TenantID.String(),
			"id":              rel.ID.String(),
			"source_id":       rel.SourceID.String(),
			"target_id":       rel.TargetID.String(),
			"weight":          rel.Weight,
			"confidence":      rel.Confidence,
			"evidence_source": rel.EvidenceSource,
			"properties_json": string(props),
			"valid_from":      nullableTime(rel.ValidFrom),
			"valid_until":     nullableTime(rel.ValidUntil),
			"created_at":      utc(rel.CreatedAt),
			"updated_at":      utc(rel.UpdatedAt),
		})
	if err != nil {
		return fmt.Errorf("mirror relationship %s: %w", rel.ID, err)
	}
	if len(res.Records) == 0 {
		return fmt.Errorf("mirror relationship %s: entity %s or %s is not in neo4j",
			rel.ID, rel.SourceID, rel.TargetID)
	}
	return nil
}

// MirrorRelationshipDeleted removes a relationship PostgreSQL has deleted. A
// deletion that does not reach the mirror leaves a connection the traversal
// still walks — worse than a missing one, because it asserts something false.
func (s *Neo4jGraphStore) MirrorRelationshipDeleted(ctx context.Context, tenantID, relID uuid.UUID) error {
	if _, err := s.query(ctx, `
		MATCH (:KGEntity {tenant_id: $tenant})-[r {tenant_id: $tenant, id: $id}]-()
		DELETE r`,
		map[string]any{"tenant": tenantID.String(), "id": relID.String()}); err != nil {
		return fmt.Errorf("mirror relationship deletion %s: %w", relID, err)
	}
	return nil
}

// DeleteTenantGraph removes a tenant's whole graph from Neo4j.
//
// Offboarding a tenant has to reach the mirror too: a graph left behind in a
// second store is the tenant's topology still on disk after the relational
// record says it is gone.
func (s *Neo4jGraphStore) DeleteTenantGraph(ctx context.Context, tenantID uuid.UUID) error {
	if _, err := s.query(ctx,
		`MATCH (n:KGEntity {tenant_id: $tenant}) DETACH DELETE n`,
		map[string]any{"tenant": tenantID.String()}); err != nil {
		return fmt.Errorf("delete tenant graph %s: %w", tenantID, err)
	}
	return nil
}

// ─── Record decoding ──────────────────────────────────────────────────────────

func entityFromRecord(rec *neo4j.Record, tenantID uuid.UUID) (*model.KGEntity, error) {
	id, err := recUUID(rec, "id")
	if err != nil {
		return nil, err
	}
	return &model.KGEntity{
		ID: id, TenantID: tenantID,
		EntityType:  recString(rec, "entity_type"),
		ExternalID:  recString(rec, "external_id"),
		Name:        recString(rec, "name"),
		Description: recString(rec, "description"),
		RiskScore:   recFloat(rec, "risk_score"),
		Confidence:  recFloat(rec, "confidence"),
		Tags:        recStrings(rec, "tags"),
		Properties:  recProps(rec),
		FirstSeenAt: recTime(rec, "first_seen_at"),
		LastSeenAt:  recTime(rec, "last_seen_at"),
		CreatedAt:   recTime(rec, "created_at"),
		UpdatedAt:   recTime(rec, "updated_at"),
	}, nil
}

func relFromRecord(rec *neo4j.Record, tenantID uuid.UUID) (*model.KGRelationship, error) {
	id, err := recUUID(rec, "id")
	if err != nil {
		return nil, err
	}
	sourceID, err := recUUID(rec, "source_id")
	if err != nil {
		return nil, err
	}
	targetID, err := recUUID(rec, "target_id")
	if err != nil {
		return nil, err
	}
	return &model.KGRelationship{
		ID: id, TenantID: tenantID, SourceID: sourceID, TargetID: targetID,
		RelationshipType: recString(rec, "relationship_type"),
		Weight:           recFloat(rec, "weight"),
		Confidence:       recFloat(rec, "confidence"),
		EvidenceSource:   recString(rec, "evidence_source"),
		Properties:       recProps(rec),
		ValidFrom:        recTimePtr(rec, "valid_from"),
		ValidUntil:       recTimePtr(rec, "valid_until"),
		CreatedAt:        recTime(rec, "created_at"),
		UpdatedAt:        recTime(rec, "updated_at"),
	}, nil
}

func recValue(rec *neo4j.Record, key string) any {
	v, found := rec.Get(key)
	if !found {
		return nil
	}
	return v
}

func recString(rec *neo4j.Record, key string) string {
	s, _ := recValue(rec, key).(string)
	return s
}

func recStrings(rec *neo4j.Record, key string) []string {
	raw, _ := recValue(rec, key).([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// recFloat accepts an integer too: Neo4j stores 7.0 as a long, so a risk score
// written as a whole number comes back as int64 and would otherwise read zero.
func recFloat(rec *neo4j.Record, key string) float64 {
	switch v := recValue(rec, key).(type) {
	case float64:
		return v
	case int64:
		return float64(v)
	}
	return 0
}

func recTime(rec *neo4j.Record, key string) time.Time {
	t, _ := recValue(rec, key).(time.Time)
	return t.UTC()
}

func recTimePtr(rec *neo4j.Record, key string) *time.Time {
	t, ok := recValue(rec, key).(time.Time)
	if !ok {
		return nil
	}
	utc := t.UTC()
	return &utc
}

func recUUID(rec *neo4j.Record, key string) (uuid.UUID, error) {
	raw := recString(rec, key)
	if raw == "" {
		return uuid.Nil, fmt.Errorf("%s is missing", key)
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%s %q: %w", key, raw, err)
	}
	return id, nil
}

// recProps decodes the JSON that carries free-form properties. Neo4j cannot
// store a nested map in a property, so the map travels as text; malformed text
// reads as no properties rather than failing the load, because neither the
// traversal nor the graph view uses them.
func recProps(rec *neo4j.Record) map[string]any {
	raw := recString(rec, "properties_json")
	if raw == "" || raw == "null" {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil
	}
	return m
}

func utc(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC()
	}
	return t.UTC()
}

func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC()
}

func uuidStrings(ids []uuid.UUID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	return out
}
