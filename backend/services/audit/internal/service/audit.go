package service

import (
	"context"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/audit/internal/model"
	"github.com/cyberradar/platform/services/audit/internal/repository"
	"github.com/rs/zerolog"
)

// AuditService writes and reads immutable audit logs.
type AuditService struct {
	repo   *repository.AuditRepository
	logger zerolog.Logger
}

// NewAuditService creates an AuditService.
func NewAuditService(repo *repository.AuditRepository, logger zerolog.Logger) *AuditService {
	return &AuditService{repo: repo, logger: logger}
}

// Write persists a single audit event. Fails fast — callers should handle errors.
func (s *AuditService) Write(ctx context.Context, req *model.WriteAuditRequest) (*model.AuditEvent, error) {
	event := &model.AuditEvent{
		TenantID:     req.TenantID,
		ActorID:      req.ActorID,
		ActorType:    req.ActorType,
		ActorEmail:   req.ActorEmail,
		Action:       req.Action,
		ResourceType: req.ResourceType,
		ResourceID:   req.ResourceID,
		IPAddress:    req.IPAddress,
		UserAgent:    req.UserAgent,
		SessionID:    req.SessionID,
		RequestID:    req.RequestID,
		Result:       req.Result,
		Details:      req.Details,
	}

	if err := s.repo.Write(ctx, event); err != nil {
		s.logger.Error().Err(err).
			Str("tenant_id", req.TenantID).
			Str("action", req.Action).
			Msg("audit_write_failed")
		return nil, apierrors.Internal("write audit event", err)
	}

	return event, nil
}

// Search returns a paginated list of audit events matching the filter.
// tenant_id in the filter MUST come from the JWT — never from user input.
func (s *AuditService) Search(ctx context.Context, f *model.AuditEventFilter) (*model.AuditEventList, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	if f.Page <= 0 {
		f.Page = 1
	}

	events, total, err := s.repo.Search(ctx, f)
	if err != nil {
		return nil, apierrors.Internal("search audit events", err)
	}

	return &model.AuditEventList{
		Events: events,
		Total:  total,
		Page:   f.Page,
		Limit:  f.Limit,
	}, nil
}
