package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cyberradar/platform/services/knowledgegraph/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// KGRepository handles all knowledge graph persistence.
type KGRepository struct {
	db *pgxpool.Pool
}

// NewKGRepository creates a KGRepository.
func NewKGRepository(db *pgxpool.Pool) *KGRepository {
	return &KGRepository{db: db}
}

// ─── Entities ─────────────────────────────────────────────────────────────────

// UpsertEntity inserts a new entity or updates it on (tenant, type, external_id) conflict.
// When external_id is empty the entity is always inserted as a new row.
func (r *KGRepository) UpsertEntity(ctx context.Context, tenantID uuid.UUID, req *model.UpsertEntityRequest) (*model.KGEntity, error) {
	props, _ := json.Marshal(req.Properties)
	tags := req.Tags
	if tags == nil {
		tags = []string{}
	}
	confidence := req.Confidence
	if confidence == 0 {
		confidence = 1.0
	}

	var row pgx.Row
	if req.ExternalID != "" {
		row = r.db.QueryRow(ctx, `
			INSERT INTO kg_entities
			    (tenant_id, entity_type, external_id, name, description, risk_score, confidence, tags, properties)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (tenant_id, entity_type, external_id)
			WHERE external_id IS NOT NULL
			DO UPDATE SET
			    name        = EXCLUDED.name,
			    description = COALESCE(NULLIF(EXCLUDED.description,''), kg_entities.description),
			    risk_score  = GREATEST(EXCLUDED.risk_score, kg_entities.risk_score),
			    confidence  = GREATEST(EXCLUDED.confidence, kg_entities.confidence),
			    tags        = (SELECT ARRAY(SELECT DISTINCT unnest(kg_entities.tags || EXCLUDED.tags))),
			    properties  = kg_entities.properties || EXCLUDED.properties,
			    last_seen_at = NOW(),
			    updated_at  = NOW()
			RETURNING `+entitySelect,
			tenantID, req.EntityType, req.ExternalID, req.Name, req.Description,
			req.RiskScore, confidence, tags, props)
	} else {
		row = r.db.QueryRow(ctx, `
			INSERT INTO kg_entities
			    (tenant_id, entity_type, name, description, risk_score, confidence, tags, properties)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			RETURNING `+entitySelect,
			tenantID, req.EntityType, req.Name, req.Description,
			req.RiskScore, confidence, tags, props)
	}
	return scanEntity(row)
}

// GetEntity returns an entity by ID with tenant guard.
func (r *KGRepository) GetEntity(ctx context.Context, tenantID, entityID uuid.UUID) (*model.KGEntity, error) {
	row := r.db.QueryRow(ctx,
		`SELECT `+entitySelect+` FROM kg_entities WHERE id=$1 AND tenant_id=$2`,
		entityID, tenantID)
	e, err := scanEntity(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return e, err
}

// UpdateEntity applies partial updates to an entity.
func (r *KGRepository) UpdateEntity(ctx context.Context, tenantID, entityID uuid.UUID, req *model.UpdateEntityRequest) (*model.KGEntity, error) {
	setClauses := []string{"updated_at = NOW()"}
	args := []any{entityID, tenantID}
	idx := 3

	if req.Name != nil {
		setClauses = append(setClauses, fmt.Sprintf("name = $%d", idx))
		args = append(args, *req.Name)
		idx++
	}
	if req.Description != nil {
		setClauses = append(setClauses, fmt.Sprintf("description = $%d", idx))
		args = append(args, *req.Description)
		idx++
	}
	if req.RiskScore != nil {
		setClauses = append(setClauses, fmt.Sprintf("risk_score = $%d", idx))
		args = append(args, *req.RiskScore)
		idx++
	}
	if req.Confidence != nil {
		setClauses = append(setClauses, fmt.Sprintf("confidence = $%d", idx))
		args = append(args, *req.Confidence)
		idx++
	}
	if req.Tags != nil {
		setClauses = append(setClauses, fmt.Sprintf("tags = $%d", idx))
		args = append(args, req.Tags)
		idx++
	}
	if req.Properties != nil {
		props, _ := json.Marshal(req.Properties)
		setClauses = append(setClauses, fmt.Sprintf("properties = properties || $%d", idx))
		args = append(args, props)
		idx++
	}

	q := fmt.Sprintf(
		`UPDATE kg_entities SET %s WHERE id=$1 AND tenant_id=$2 RETURNING %s`,
		strings.Join(setClauses, ", "), entitySelect)
	return scanEntity(r.db.QueryRow(ctx, q, args...))
}

// ListEntities returns entities with optional filters.
func (r *KGRepository) ListEntities(ctx context.Context, f model.EntityFilter) ([]*model.KGEntity, int, error) {
	where := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	idx := 2

	if f.EntityType != "" {
		where = append(where, fmt.Sprintf("entity_type = $%d", idx))
		args = append(args, f.EntityType)
		idx++
	}
	if f.Search != "" {
		where = append(where, fmt.Sprintf("lower(name) LIKE lower($%d)", idx))
		args = append(args, "%"+f.Search+"%")
		idx++
	}
	if f.MinRisk > 0 {
		where = append(where, fmt.Sprintf("risk_score >= $%d", idx))
		args = append(args, f.MinRisk)
		idx++
	}
	if len(f.Tags) > 0 {
		where = append(where, fmt.Sprintf("tags && $%d", idx))
		args = append(args, f.Tags)
		idx++
	}

	whereStr := strings.Join(where, " AND ")

	var total int
	if err := r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM kg_entities WHERE `+whereStr, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	args = append(args, limit, f.Offset)
	rows, err := r.db.Query(ctx,
		`SELECT `+entitySelect+` FROM kg_entities WHERE `+whereStr+
			` ORDER BY risk_score DESC, last_seen_at DESC LIMIT $`+fmt.Sprint(idx)+` OFFSET $`+fmt.Sprint(idx+1),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entities []*model.KGEntity
	for rows.Next() {
		e, err := scanEntity(rows)
		if err != nil {
			return nil, 0, err
		}
		entities = append(entities, e)
	}
	return entities, total, rows.Err()
}

// GetEntitiesByIDs batch-fetches entities by their IDs.
func (r *KGRepository) GetEntitiesByIDs(ctx context.Context, tenantID uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]*model.KGEntity, error) {
	if len(ids) == 0 {
		return map[uuid.UUID]*model.KGEntity{}, nil
	}
	rows, err := r.db.Query(ctx,
		`SELECT `+entitySelect+` FROM kg_entities WHERE tenant_id=$1 AND id=ANY($2)`,
		tenantID, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	m := make(map[uuid.UUID]*model.KGEntity, len(ids))
	for rows.Next() {
		e, err := scanEntity(rows)
		if err != nil {
			return nil, err
		}
		m[e.ID] = e
	}
	return m, rows.Err()
}

// ─── Relationships ────────────────────────────────────────────────────────────

// UpsertRelationship inserts or updates a directed typed edge.
func (r *KGRepository) UpsertRelationship(ctx context.Context, tenantID uuid.UUID, req *model.UpsertRelationshipRequest) (*model.KGRelationship, error) {
	props, _ := json.Marshal(req.Properties)
	weight := req.Weight
	if weight == 0 {
		weight = 1.0
	}
	confidence := req.Confidence
	if confidence == 0 {
		confidence = 1.0
	}

	row := r.db.QueryRow(ctx, `
		INSERT INTO kg_relationships
		    (tenant_id, source_id, target_id, relationship_type, weight, confidence,
		     evidence_source, properties, valid_from, valid_until)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (tenant_id, source_id, target_id, relationship_type) DO UPDATE SET
		    weight          = GREATEST(EXCLUDED.weight, kg_relationships.weight),
		    confidence      = GREATEST(EXCLUDED.confidence, kg_relationships.confidence),
		    evidence_source = COALESCE(EXCLUDED.evidence_source, kg_relationships.evidence_source),
		    properties      = kg_relationships.properties || EXCLUDED.properties,
		    valid_until     = EXCLUDED.valid_until,
		    updated_at      = NOW()
		RETURNING `+relSelect,
		tenantID, req.SourceID, req.TargetID, req.RelationshipType,
		weight, confidence, nvlS(req.EvidenceSource), props,
		req.ValidFrom, req.ValidUntil)
	return scanRel(row)
}

// GetRelationship returns a relationship by ID.
func (r *KGRepository) GetRelationship(ctx context.Context, tenantID, relID uuid.UUID) (*model.KGRelationship, error) {
	row := r.db.QueryRow(ctx,
		`SELECT `+relSelect+` FROM kg_relationships WHERE id=$1 AND tenant_id=$2`,
		relID, tenantID)
	rel, err := scanRel(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return rel, err
}

// DeleteRelationship removes a relationship.
func (r *KGRepository) DeleteRelationship(ctx context.Context, tenantID, relID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`DELETE FROM kg_relationships WHERE id=$1 AND tenant_id=$2`, relID, tenantID)
	return err
}

// ListRelationships returns edges for a given entity (source or target depending on direction).
func (r *KGRepository) ListRelationships(ctx context.Context, tenantID, entityID uuid.UUID, direction string) ([]*model.KGRelationship, error) {
	// live is the same window the traversal uses: a relationship counts when
	// now falls inside [valid_from, valid_until). Listing and traversing must
	// agree, or an analyst sees an edge here that the graph view does not draw.
	const live = ` AND (valid_from IS NULL OR valid_from <= NOW())
		 AND (valid_until IS NULL OR valid_until > NOW())`

	var q string
	switch direction {
	case "inbound":
		q = `SELECT ` + relSelect + ` FROM kg_relationships WHERE tenant_id=$1 AND target_id=$2` + live + ` ORDER BY updated_at DESC`
	case "outbound":
		q = `SELECT ` + relSelect + ` FROM kg_relationships WHERE tenant_id=$1 AND source_id=$2` + live + ` ORDER BY updated_at DESC`
	default: // both
		q = `SELECT ` + relSelect + ` FROM kg_relationships WHERE tenant_id=$1 AND (source_id=$2 OR target_id=$2)` + live + ` ORDER BY updated_at DESC`
	}
	rows, err := r.db.Query(ctx, q, tenantID, entityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rels []*model.KGRelationship
	for rows.Next() {
		rel, err := scanRel(rows)
		if err != nil {
			return nil, err
		}
		rels = append(rels, rel)
	}
	return rels, rows.Err()
}

// ─── Graph Traversal ──────────────────────────────────────────────────────────

// Neighbors walks outward from one entity. The walk itself is in traversal.go
// and shared with the Neo4j store; this supplies PostgreSQL's answer to "which
// live relationships touch these entities?".
func (r *KGRepository) Neighbors(ctx context.Context, q model.NeighborQuery) ([]model.KGNeighbor, error) {
	return walk(ctx, q,
		func(ctx context.Context, frontier []uuid.UUID) ([]*model.KGRelationship, error) {
			return r.adjacentRelationships(ctx, q.TenantID, frontier, q.Direction, q.RelTypes)
		},
		func(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]*model.KGEntity, error) {
			return r.GetEntitiesByIDs(ctx, q.TenantID, ids)
		})
}

// adjacentRelationships returns the live relationships touching any entity in
// the frontier, in the requested direction and of the requested types.
//
// A relationship is live when now falls inside [valid_from, valid_until).
// valid_from was recorded and never checked, so a relationship an analyst had
// declared effective from next month was already being traversed.
func (r *KGRepository) adjacentRelationships(ctx context.Context, tenantID uuid.UUID,
	frontier []uuid.UUID, direction string, relTypes []string) ([]*model.KGRelationship, error) {

	var touches string
	switch direction {
	case "outbound":
		touches = `source_id = ANY($2)`
	case "inbound":
		touches = `target_id = ANY($2)`
	default: // both
		touches = `(source_id = ANY($2) OR target_id = ANY($2))`
	}

	rows, err := r.db.Query(ctx, `
		SELECT `+relSelect+`
		FROM kg_relationships
		WHERE tenant_id = $1
		  AND `+touches+`
		  AND (valid_from IS NULL OR valid_from <= NOW())
		  AND (valid_until IS NULL OR valid_until > NOW())
		  AND (cardinality($3::text[]) = 0 OR relationship_type = ANY($3))
		ORDER BY id`,
		tenantID, frontier, relTypeFilter(relTypes))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*model.KGRelationship
	for rows.Next() {
		rel, err := scanRel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rel)
	}
	return out, rows.Err()
}

// Subgraph returns entities and relationships for a given set of entity IDs.
func (r *KGRepository) Subgraph(ctx context.Context, tenantID uuid.UUID, entityIDs []uuid.UUID) (*model.KGSubgraph, error) {
	entityMap, err := r.GetEntitiesByIDs(ctx, tenantID, entityIDs)
	if err != nil {
		return nil, err
	}

	// Fetch all edges where both endpoints are in the set
	rows, err := r.db.Query(ctx,
		`SELECT `+relSelect+` FROM kg_relationships
		 WHERE tenant_id=$1 AND source_id=ANY($2) AND target_id=ANY($2)
		   AND (valid_until IS NULL OR valid_until > NOW())`,
		tenantID, entityIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rels []model.KGRelationship
	for rows.Next() {
		rel, err := scanRel(rows)
		if err != nil {
			return nil, err
		}
		rels = append(rels, *rel)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	entities := make([]model.KGEntity, 0, len(entityMap))
	for _, e := range entityMap {
		entities = append(entities, *e)
	}
	return &model.KGSubgraph{Entities: entities, Relationships: rels}, nil
}

// ─── Observations ─────────────────────────────────────────────────────────────

// CreateObservation records a new entity observation and bumps last_seen_at.
func (r *KGRepository) CreateObservation(ctx context.Context, tenantID uuid.UUID, req *model.CreateObservationRequest) (*model.KGObservation, error) {
	props, _ := json.Marshal(req.Properties)
	observedAt := time.Now().UTC()
	if req.ObservedAt != nil {
		observedAt = *req.ObservedAt
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var obs model.KGObservation
	var propsRaw []byte
	err = tx.QueryRow(ctx, `
		INSERT INTO kg_observations
		    (tenant_id, entity_id, observed_at, source_service, event_type, severity, description, properties)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id, tenant_id, entity_id, observed_at, source_service, event_type,
		          COALESCE(severity,''), COALESCE(description,''), properties, created_at`,
		tenantID, req.EntityID, observedAt, req.SourceService, req.EventType,
		nvlS(req.Severity), nvlS(req.Description), props,
	).Scan(&obs.ID, &obs.TenantID, &obs.EntityID, &obs.ObservedAt,
		&obs.SourceService, &obs.EventType, &obs.Severity, &obs.Description,
		&propsRaw, &obs.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(propsRaw, &obs.Properties)

	// Bump last_seen_at on entity
	_, err = tx.Exec(ctx,
		`UPDATE kg_entities SET last_seen_at=GREATEST(last_seen_at,$1), updated_at=NOW() WHERE id=$2 AND tenant_id=$3`,
		observedAt, req.EntityID, tenantID)
	if err != nil {
		return nil, err
	}

	return &obs, tx.Commit(ctx)
}

// ListObservations returns observations with filters.
func (r *KGRepository) ListObservations(ctx context.Context, f model.ObservationFilter) ([]*model.KGObservation, int, error) {
	where := []string{"tenant_id = $1", "entity_id = $2"}
	args := []any{f.TenantID, f.EntityID}
	idx := 3

	if f.SourceService != "" {
		where = append(where, fmt.Sprintf("source_service = $%d", idx))
		args = append(args, f.SourceService)
		idx++
	}
	if f.Severity != "" {
		where = append(where, fmt.Sprintf("severity = $%d", idx))
		args = append(args, f.Severity)
		idx++
	}
	if f.Since != nil {
		where = append(where, fmt.Sprintf("observed_at >= $%d", idx))
		args = append(args, *f.Since)
		idx++
	}

	whereStr := strings.Join(where, " AND ")
	var total int
	if err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM kg_observations WHERE `+whereStr, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	args = append(args, limit, f.Offset)
	rows, err := r.db.Query(ctx,
		`SELECT id, tenant_id, entity_id, observed_at, source_service, event_type,
		        COALESCE(severity,''), COALESCE(description,''), properties, created_at
		 FROM kg_observations WHERE `+whereStr+
			` ORDER BY observed_at DESC LIMIT $`+fmt.Sprint(idx)+` OFFSET $`+fmt.Sprint(idx+1),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var obs []*model.KGObservation
	for rows.Next() {
		o, err := scanObs(rows)
		if err != nil {
			return nil, 0, err
		}
		obs = append(obs, o)
	}
	return obs, total, rows.Err()
}

// ─── Stats ────────────────────────────────────────────────────────────────────

// Stats returns the knowledge graph dashboard summary.
// Stats summarises a tenant's graph.
//
// Every query's error used to be discarded, so a failing count read as zero —
// and the dashboard's "total entities" card, which this feeds, showed an empty
// estate rather than saying it could not tell. A number nobody can distinguish
// from "none" is worse than an error.
func (r *KGRepository) Stats(ctx context.Context, tenantID uuid.UUID) (*model.KGStats, error) {
	stats := &model.KGStats{
		EntitiesByType: make(map[string]int),
		RelsByType:     make(map[string]int),
	}

	if err := r.db.QueryRow(ctx,
		`SELECT COUNT(*), COUNT(*) FILTER (WHERE risk_score >= 7) FROM kg_entities WHERE tenant_id=$1`,
		tenantID).Scan(&stats.TotalEntities, &stats.HighRiskEntities); err != nil {
		return nil, fmt.Errorf("count entities: %w", err)
	}

	if err := r.countByType(ctx, tenantID,
		`SELECT entity_type, COUNT(*) FROM kg_entities WHERE tenant_id=$1 GROUP BY entity_type`,
		stats.EntitiesByType); err != nil {
		return nil, fmt.Errorf("entities by type: %w", err)
	}

	if err := r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM kg_relationships
		 WHERE tenant_id=$1
		   AND (valid_from IS NULL OR valid_from <= NOW())
		   AND (valid_until IS NULL OR valid_until > NOW())`,
		tenantID).Scan(&stats.TotalRelationships); err != nil {
		return nil, fmt.Errorf("count relationships: %w", err)
	}

	if err := r.countByType(ctx, tenantID,
		`SELECT relationship_type, COUNT(*) FROM kg_relationships
		 WHERE tenant_id=$1
		   AND (valid_from IS NULL OR valid_from <= NOW())
		   AND (valid_until IS NULL OR valid_until > NOW())
		 GROUP BY relationship_type`,
		stats.RelsByType); err != nil {
		return nil, fmt.Errorf("relationships by type: %w", err)
	}

	since24h := time.Now().UTC().Add(-24 * time.Hour)
	if err := r.db.QueryRow(ctx,
		`SELECT COUNT(*), COUNT(*) FILTER (WHERE observed_at >= $2) FROM kg_observations WHERE tenant_id=$1`,
		tenantID, since24h).Scan(&stats.TotalObservations, &stats.RecentObservations); err != nil {
		return nil, fmt.Errorf("count observations: %w", err)
	}

	return stats, nil
}

func (r *KGRepository) countByType(ctx context.Context, tenantID uuid.UUID, query string, into map[string]int) error {
	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		var count int
		if err := rows.Scan(&kind, &count); err != nil {
			return err
		}
		into[kind] = count
	}
	return rows.Err()
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const entitySelect = `id, tenant_id, entity_type, COALESCE(external_id,''), name,
    COALESCE(description,''), risk_score, confidence, tags, properties,
    first_seen_at, last_seen_at, created_at, updated_at`

const relSelect = `id, tenant_id, source_id, target_id, relationship_type,
    weight, confidence, COALESCE(evidence_source,''), properties,
    valid_from, valid_until, created_at, updated_at`

type scannable interface {
	Scan(...any) error
}

func scanEntity(row scannable) (*model.KGEntity, error) {
	var e model.KGEntity
	var propsRaw []byte
	err := row.Scan(
		&e.ID, &e.TenantID, &e.EntityType, &e.ExternalID, &e.Name,
		&e.Description, &e.RiskScore, &e.Confidence, &e.Tags, &propsRaw,
		&e.FirstSeenAt, &e.LastSeenAt, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(propsRaw, &e.Properties)
	if e.Tags == nil {
		e.Tags = []string{}
	}
	return &e, nil
}

func scanRel(row scannable) (*model.KGRelationship, error) {
	var rel model.KGRelationship
	var propsRaw []byte
	err := row.Scan(
		&rel.ID, &rel.TenantID, &rel.SourceID, &rel.TargetID, &rel.RelationshipType,
		&rel.Weight, &rel.Confidence, &rel.EvidenceSource, &propsRaw,
		&rel.ValidFrom, &rel.ValidUntil, &rel.CreatedAt, &rel.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(propsRaw, &rel.Properties)
	return &rel, nil
}

func scanObs(row scannable) (*model.KGObservation, error) {
	var o model.KGObservation
	var propsRaw []byte
	err := row.Scan(
		&o.ID, &o.TenantID, &o.EntityID, &o.ObservedAt,
		&o.SourceService, &o.EventType, &o.Severity, &o.Description,
		&propsRaw, &o.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(propsRaw, &o.Properties)
	return &o, nil
}

func nvlS(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
