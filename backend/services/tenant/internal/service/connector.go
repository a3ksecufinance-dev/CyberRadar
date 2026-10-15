package service

import (
	"context"

	"github.com/google/uuid"

	"github.com/cyberradar/platform/services/tenant/internal/model"
	"github.com/cyberradar/platform/services/tenant/internal/repository"
)

// ConnectorService owns the registry of declared telemetry sources.
//
// It is thin on purpose: registering a connector is storing what somebody
// declared, and there is no judgement to apply beyond refusing what cannot be
// acted on. The judgements worth making about a connector — is it sending, has
// it gone quiet — are made from the events, by the collector, and cannot be
// made here without copying facts that would then be able to disagree.
type ConnectorService struct {
	repo *repository.ConnectorRepository
}

func NewConnectorService(repo *repository.ConnectorRepository) *ConnectorService {
	return &ConnectorService{repo: repo}
}

func (s *ConnectorService) Register(ctx context.Context, tenantID uuid.UUID, req *model.CreateConnectorRequest) (*model.Connector, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	return s.repo.Create(ctx, tenantID, req)
}

func (s *ConnectorService) List(ctx context.Context, tenantID uuid.UUID) ([]*model.Connector, error) {
	return s.repo.List(ctx, tenantID)
}

func (s *ConnectorService) Get(ctx context.Context, tenantID, id uuid.UUID) (*model.Connector, error) {
	return s.repo.Get(ctx, tenantID, id)
}

func (s *ConnectorService) Update(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdateConnectorRequest) (*model.Connector, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	return s.repo.Update(ctx, tenantID, id, req)
}

func (s *ConnectorService) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	return s.repo.Delete(ctx, tenantID, id)
}
