package service

import (
	"context"
	"time"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/knowledgegraph/internal/model"
	"github.com/cyberradar/platform/services/knowledgegraph/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// KGService orchestrates knowledge graph operations.
type KGService struct {
	repo   *repository.KGRepository
	logger zerolog.Logger
}

// NewKGService creates a KGService.
func NewKGService(repo *repository.KGRepository, logger zerolog.Logger) *KGService {
	return &KGService{repo: repo, logger: logger}
}

// ─── Entities ─────────────────────────────────────────────────────────────────

func (s *KGService) UpsertEntity(ctx context.Context, tenantID uuid.UUID, req *model.UpsertEntityRequest) (*model.KGEntity, error) {
	e, err := s.repo.UpsertEntity(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("upsert entity", err)
	}
	return e, nil
}

func (s *KGService) GetEntity(ctx context.Context, tenantID, entityID uuid.UUID) (*model.KGEntity, error) {
	e, err := s.repo.GetEntity(ctx, tenantID, entityID)
	if err != nil {
		return nil, apierrors.Internal("get entity", err)
	}
	if e == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "entity not found")
	}
	return e, nil
}

func (s *KGService) UpdateEntity(ctx context.Context, tenantID, entityID uuid.UUID, req *model.UpdateEntityRequest) (*model.KGEntity, error) {
	e, err := s.repo.UpdateEntity(ctx, tenantID, entityID, req)
	if err != nil {
		return nil, apierrors.Internal("update entity", err)
	}
	return e, nil
}

func (s *KGService) ListEntities(ctx context.Context, f model.EntityFilter) ([]*model.KGEntity, int, error) {
	entities, total, err := s.repo.ListEntities(ctx, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list entities", err)
	}
	return entities, total, nil
}

// ─── Relationships ────────────────────────────────────────────────────────────

func (s *KGService) UpsertRelationship(ctx context.Context, tenantID uuid.UUID, req *model.UpsertRelationshipRequest) (*model.KGRelationship, error) {
	// Validate endpoints belong to this tenant
	src, err := s.repo.GetEntity(ctx, tenantID, req.SourceID)
	if err != nil || src == nil {
		return nil, apierrors.New(apierrors.KindBadInput, "source entity not found")
	}
	tgt, err := s.repo.GetEntity(ctx, tenantID, req.TargetID)
	if err != nil || tgt == nil {
		return nil, apierrors.New(apierrors.KindBadInput, "target entity not found")
	}

	rel, err := s.repo.UpsertRelationship(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("upsert relationship", err)
	}
	return rel, nil
}

func (s *KGService) GetRelationship(ctx context.Context, tenantID, relID uuid.UUID) (*model.KGRelationship, error) {
	rel, err := s.repo.GetRelationship(ctx, tenantID, relID)
	if err != nil {
		return nil, apierrors.Internal("get relationship", err)
	}
	if rel == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "relationship not found")
	}
	return rel, nil
}

func (s *KGService) DeleteRelationship(ctx context.Context, tenantID, relID uuid.UUID) error {
	if err := s.repo.DeleteRelationship(ctx, tenantID, relID); err != nil {
		return apierrors.Internal("delete relationship", err)
	}
	return nil
}

func (s *KGService) ListRelationships(ctx context.Context, tenantID, entityID uuid.UUID, direction string) ([]*model.KGRelationship, error) {
	rels, err := s.repo.ListRelationships(ctx, tenantID, entityID, direction)
	if err != nil {
		return nil, apierrors.Internal("list relationships", err)
	}
	return rels, nil
}

// ─── Graph traversal ──────────────────────────────────────────────────────────

func (s *KGService) Neighbors(ctx context.Context, q model.NeighborQuery) ([]model.KGNeighbor, error) {
	// Confirm entity exists
	if _, err := s.GetEntity(ctx, q.TenantID, q.EntityID); err != nil {
		return nil, err
	}
	neighbors, err := s.repo.Neighbors(ctx, q)
	if err != nil {
		return nil, apierrors.Internal("neighbors traversal", err)
	}
	return neighbors, nil
}

func (s *KGService) Subgraph(ctx context.Context, tenantID uuid.UUID, entityIDs []uuid.UUID) (*model.KGSubgraph, error) {
	if len(entityIDs) == 0 {
		return &model.KGSubgraph{Entities: []model.KGEntity{}, Relationships: []model.KGRelationship{}}, nil
	}
	if len(entityIDs) > 100 {
		return nil, apierrors.New(apierrors.KindBadInput, "at most 100 entity IDs per subgraph request")
	}
	sg, err := s.repo.Subgraph(ctx, tenantID, entityIDs)
	if err != nil {
		return nil, apierrors.Internal("subgraph", err)
	}
	return sg, nil
}

// Enrich finds an entity by name+type and returns it enriched with 2-hop neighbors
// and the 20 most recent observations.
func (s *KGService) Enrich(ctx context.Context, tenantID uuid.UUID, entityType, name string) (*model.EnrichedEntity, error) {
	f := model.EntityFilter{
		TenantID:   tenantID,
		EntityType: entityType,
		Search:     name,
		Limit:      1,
	}
	entities, _, err := s.repo.ListEntities(ctx, f)
	if err != nil {
		return nil, apierrors.Internal("enrich lookup", err)
	}
	if len(entities) == 0 {
		return nil, apierrors.New(apierrors.KindNotFound, "entity not found")
	}
	entity := entities[0]

	neighbors, err := s.repo.Neighbors(ctx, model.NeighborQuery{
		TenantID:  tenantID,
		EntityID:  entity.ID,
		MaxHops:   2,
		Direction: "both",
	})
	if err != nil {
		s.logger.Warn().Err(err).Str("entity_id", entity.ID.String()).Msg("enrich_neighbor_error")
	}

	obsList, _, err := s.repo.ListObservations(ctx, model.ObservationFilter{
		TenantID: tenantID,
		EntityID: entity.ID,
		Limit:    20,
	})
	if err != nil {
		s.logger.Warn().Err(err).Str("entity_id", entity.ID.String()).Msg("enrich_obs_error")
	}

	observations := make([]model.KGObservation, 0, len(obsList))
	for _, o := range obsList {
		observations = append(observations, *o)
	}

	return &model.EnrichedEntity{
		Entity:       *entity,
		Neighbors:    neighbors,
		Observations: observations,
	}, nil
}

// ─── Observations ─────────────────────────────────────────────────────────────

func (s *KGService) CreateObservation(ctx context.Context, tenantID uuid.UUID, req *model.CreateObservationRequest) (*model.KGObservation, error) {
	// Confirm entity belongs to tenant
	e, err := s.repo.GetEntity(ctx, tenantID, req.EntityID)
	if err != nil || e == nil {
		return nil, apierrors.New(apierrors.KindBadInput, "entity not found")
	}
	obs, err := s.repo.CreateObservation(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("create observation", err)
	}
	return obs, nil
}

func (s *KGService) ListObservations(ctx context.Context, f model.ObservationFilter) ([]*model.KGObservation, int, error) {
	obs, total, err := s.repo.ListObservations(ctx, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list observations", err)
	}
	return obs, total, nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (s *KGService) GetStats(ctx context.Context, tenantID uuid.UUID) (*model.KGStats, error) {
	stats, err := s.repo.Stats(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("kg stats", err)
	}
	return stats, nil
}

// ─── Kafka ingestion ──────────────────────────────────────────────────────────

// IngestEvent is called by the Kafka consumer for each enriched event.
// It auto-creates/updates entity observations for IPs and alerts extracted from
// the event payload so the knowledge graph stays current with live traffic.
func (s *KGService) IngestEvent(ctx context.Context, tenantID uuid.UUID, sourceService, eventType, severity string, ipSource string) {
	if ipSource == "" {
		return
	}
	// Auto-upsert IP entity
	entity, err := s.repo.UpsertEntity(ctx, tenantID, &model.UpsertEntityRequest{
		EntityType: model.EntityTypeIP,
		ExternalID: ipSource,
		Name:       ipSource,
		Confidence: 0.9,
	})
	if err != nil {
		s.logger.Warn().Err(err).Str("ip", ipSource).Msg("kg_ingest_upsert_error")
		return
	}

	// Record observation
	ts := time.Now().UTC()
	_, err = s.repo.CreateObservation(ctx, tenantID, &model.CreateObservationRequest{
		EntityID:      entity.ID,
		ObservedAt:    &ts,
		SourceService: sourceService,
		EventType:     eventType,
		Severity:      severity,
	})
	if err != nil {
		s.logger.Warn().Err(err).Str("entity_id", entity.ID.String()).Msg("kg_ingest_obs_error")
	}
}
