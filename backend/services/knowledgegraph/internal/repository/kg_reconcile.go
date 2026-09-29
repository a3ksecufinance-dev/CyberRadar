package repository

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/cyberradar/platform/services/knowledgegraph/internal/model"
	"github.com/google/uuid"
)

// Reconciliation exists because a mirrored write is allowed to fail.
//
// PostgreSQL is the source of truth and must stay writable when Neo4j is not,
// so a failed mirror is logged and counted rather than failing the request.
// That makes drift possible by design — and a traversal reading a drifted graph
// asserts connections that do not exist, or misses the ones that do. This is
// what says whether the two agree, and it is the precondition for pointing
// reads at Neo4j.

// tenantGraph is everything a tenant has that lives in both stores: its
// entities and the relationships currently in force. Observations are not
// mirrored — they are an append-only log of sightings, not topology.
type tenantGraph struct {
	entities map[uuid.UUID]*model.KGEntity
	rels     map[uuid.UUID]*model.KGRelationship
}

// GraphDivergence is what the two stores disagree about for one tenant.
type GraphDivergence struct {
	TenantID                uuid.UUID   `json:"tenant_id"`
	EntitiesInPostgres      int         `json:"entities_in_postgres"`
	EntitiesInNeo4j         int         `json:"entities_in_neo4j"`
	RelationshipsInPostgres int         `json:"relationships_in_postgres"`
	RelationshipsInNeo4j    int         `json:"relationships_in_neo4j"`
	EntitiesOnlyInPostgres  []uuid.UUID `json:"entities_only_in_postgres,omitempty"`
	EntitiesOnlyInNeo4j     []uuid.UUID `json:"entities_only_in_neo4j,omitempty"`
	EntitiesDiffering       []uuid.UUID `json:"entities_differing,omitempty"`
	RelsOnlyInPostgres      []uuid.UUID `json:"relationships_only_in_postgres,omitempty"`
	RelsOnlyInNeo4j         []uuid.UUID `json:"relationships_only_in_neo4j,omitempty"`
	RelsDiffering           []uuid.UUID `json:"relationships_differing,omitempty"`
}

// Count is the number of disagreements. Zero is parity.
func (d GraphDivergence) Count() int {
	return len(d.EntitiesOnlyInPostgres) + len(d.EntitiesOnlyInNeo4j) + len(d.EntitiesDiffering) +
		len(d.RelsOnlyInPostgres) + len(d.RelsOnlyInNeo4j) + len(d.RelsDiffering)
}

// InParity reports whether a traversal would read the same graph from either store.
func (d GraphDivergence) InParity() bool { return d.Count() == 0 }

// Reconcile compares PostgreSQL and Neo4j for one tenant.
func (s *Neo4jGraphStore) Reconcile(ctx context.Context, tenantID uuid.UUID) (*GraphDivergence, error) {
	fromPG, err := s.KGRepository.tenantGraph(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("reconcile: postgres: %w", err)
	}
	fromNeo, err := s.tenantGraph(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("reconcile: neo4j: %w", err)
	}

	d := &GraphDivergence{
		TenantID:                tenantID,
		EntitiesInPostgres:      len(fromPG.entities),
		EntitiesInNeo4j:         len(fromNeo.entities),
		RelationshipsInPostgres: len(fromPG.rels),
		RelationshipsInNeo4j:    len(fromNeo.rels),
	}
	d.EntitiesOnlyInPostgres, d.EntitiesOnlyInNeo4j, d.EntitiesDiffering =
		diff(entityFingerprints(fromPG), entityFingerprints(fromNeo))
	d.RelsOnlyInPostgres, d.RelsOnlyInNeo4j, d.RelsDiffering =
		diff(relFingerprints(fromPG), relFingerprints(fromNeo))
	return d, nil
}

// MirrorTenant copies a tenant's whole graph from PostgreSQL into Neo4j and
// reports what it wrote. Entities go first, because a relationship whose
// endpoints are missing is refused rather than dropped.
func (s *Neo4jGraphStore) MirrorTenant(ctx context.Context, tenantID uuid.UUID) (entities, rels int, err error) {
	g, err := s.KGRepository.tenantGraph(ctx, tenantID)
	if err != nil {
		return 0, 0, fmt.Errorf("mirror tenant: postgres: %w", err)
	}
	for _, e := range g.entities {
		if err := s.MirrorEntity(ctx, e); err != nil {
			return entities, rels, err
		}
		entities++
	}
	for _, rel := range g.rels {
		if err := s.MirrorRelationship(ctx, rel); err != nil {
			return entities, rels, err
		}
		rels++
	}
	return entities, rels, nil
}

// ─── Loading a whole tenant, from each side ───────────────────────────────────

func (r *KGRepository) tenantGraph(ctx context.Context, tenantID uuid.UUID) (*tenantGraph, error) {
	g := &tenantGraph{
		entities: map[uuid.UUID]*model.KGEntity{},
		rels:     map[uuid.UUID]*model.KGRelationship{},
	}

	rows, err := r.db.Query(ctx, `SELECT `+entitySelect+` FROM kg_entities WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load entities: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		e, err := scanEntity(rows)
		if err != nil {
			return nil, fmt.Errorf("scan entity: %w", err)
		}
		g.entities[e.ID] = e
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load entities: %w", err)
	}

	relRows, err := r.db.Query(ctx, `
		SELECT `+relSelect+` FROM kg_relationships
		WHERE tenant_id = $1
		  AND (valid_from IS NULL OR valid_from <= NOW())
		  AND (valid_until IS NULL OR valid_until > NOW())`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load relationships: %w", err)
	}
	defer relRows.Close()
	for relRows.Next() {
		rel, err := scanRel(relRows)
		if err != nil {
			return nil, fmt.Errorf("scan relationship: %w", err)
		}
		g.rels[rel.ID] = rel
	}
	return g, relRows.Err()
}

func (s *Neo4jGraphStore) tenantGraph(ctx context.Context, tenantID uuid.UUID) (*tenantGraph, error) {
	g := &tenantGraph{
		entities: map[uuid.UUID]*model.KGEntity{},
		rels:     map[uuid.UUID]*model.KGRelationship{},
	}

	res, err := s.query(ctx, `MATCH (n:KGEntity {tenant_id: $tenant})`+entityReturn,
		map[string]any{"tenant": tenantID.String()})
	if err != nil {
		return nil, fmt.Errorf("load entities: %w", err)
	}
	for _, rec := range res.Records {
		e, err := entityFromRecord(rec, tenantID)
		if err != nil {
			return nil, fmt.Errorf("read entity: %w", err)
		}
		g.entities[e.ID] = e
	}

	relRes, err := s.query(ctx, `
		MATCH (a:KGEntity {tenant_id: $tenant})-[r]->(b:KGEntity {tenant_id: $tenant})
		WHERE r.tenant_id = $tenant
		  AND (r.valid_from IS NULL OR r.valid_from <= $now)
		  AND (r.valid_until IS NULL OR r.valid_until > $now)`+relReturn,
		map[string]any{"tenant": tenantID.String(), "now": time.Now().UTC()})
	if err != nil {
		return nil, fmt.Errorf("load relationships: %w", err)
	}
	for _, rec := range relRes.Records {
		rel, err := relFromRecord(rec, tenantID)
		if err != nil {
			return nil, fmt.Errorf("read relationship: %w", err)
		}
		g.rels[rel.ID] = rel
	}
	return g, nil
}

// ─── Fingerprints ─────────────────────────────────────────────────────────────

// entityFingerprints reduces each entity to the fields a reader acts on, so
// reconciliation reports a difference that changes an answer and ignores one
// that does not.
func entityFingerprints(g *tenantGraph) map[uuid.UUID]string {
	out := make(map[uuid.UUID]string, len(g.entities))
	for id, e := range g.entities {
		out[id] = fmt.Sprintf("%s|%s|%s|%s|%.4f|%.4f|%v",
			e.EntityType, e.ExternalID, e.Name, e.Description,
			e.RiskScore, e.Confidence, sortedCopy(e.Tags))
	}
	return out
}

func relFingerprints(g *tenantGraph) map[uuid.UUID]string {
	out := make(map[uuid.UUID]string, len(g.rels))
	for id, rel := range g.rels {
		out[id] = fmt.Sprintf("%s|%s|%s|%.4f|%.4f|%s|%s|%s",
			rel.SourceID, rel.TargetID, rel.RelationshipType,
			rel.Weight, rel.Confidence, rel.EvidenceSource,
			timeKey(rel.ValidFrom), timeKey(rel.ValidUntil))
	}
	return out
}

// timeKey renders a validity bound to the second. PostgreSQL keeps microseconds
// and Neo4j nanoseconds, so comparing the raw instants would report a
// divergence on every relationship that has one.
func timeKey(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.UTC().Truncate(time.Second).Format(time.RFC3339)
}

func sortedCopy(tags []string) []string {
	out := append([]string{}, tags...)
	sort.Strings(out)
	return out
}

func diff(left, right map[uuid.UUID]string) (onlyLeft, onlyRight, differing []uuid.UUID) {
	for id, lv := range left {
		rv, found := right[id]
		switch {
		case !found:
			onlyLeft = append(onlyLeft, id)
		case lv != rv:
			differing = append(differing, id)
		}
	}
	for id := range right {
		if _, found := left[id]; !found {
			onlyRight = append(onlyRight, id)
		}
	}
	sortIDs(onlyLeft)
	sortIDs(onlyRight)
	sortIDs(differing)
	return onlyLeft, onlyRight, differing
}

func sortIDs(ids []uuid.UUID) {
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
}
