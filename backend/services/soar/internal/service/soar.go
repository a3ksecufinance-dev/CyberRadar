package service

import (
	"context"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/soar/internal/model"
	"github.com/cyberradar/platform/services/soar/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// SOARService orchestrates incident and playbook management.
type SOARService struct {
	repo     *repository.SOARRepository
	executor *Executor
	logger   zerolog.Logger
}

// NewSOARService creates a SOARService.
func NewSOARService(repo *repository.SOARRepository, logger zerolog.Logger) *SOARService {
	return &SOARService{
		repo:     repo,
		executor: NewExecutor(repo, logger),
		logger:   logger,
	}
}

// ─── Incidents ────────────────────────────────────────────────────────────────

func (s *SOARService) CreateIncident(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreateIncidentRequest) (*model.Incident, error) {
	inc, err := s.repo.CreateIncident(ctx, tenantID, callerID, req)
	if err != nil {
		return nil, apierrors.Internal("create incident", err)
	}
	s.logger.Info().
		Str("incident_id", inc.ID.String()).
		Str("severity", inc.Severity).
		Msg("incident_created")

	// Auto-trigger matching playbooks
	go s.autoTrigger(context.Background(), tenantID, model.TriggerAlert, inc.Severity, inc.SourceService, inc)
	return inc, nil
}

func (s *SOARService) GetIncident(ctx context.Context, tenantID, incidentID uuid.UUID) (*model.Incident, error) {
	inc, err := s.repo.GetIncident(ctx, tenantID, incidentID)
	if err != nil {
		return nil, apierrors.Internal("get incident", err)
	}
	if inc == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "incident not found")
	}
	return inc, nil
}

func (s *SOARService) UpdateIncident(ctx context.Context, tenantID, incidentID uuid.UUID, req *model.UpdateIncidentRequest, actorID *uuid.UUID) (*model.Incident, error) {
	inc, err := s.repo.UpdateIncident(ctx, tenantID, incidentID, req, actorID)
	if err != nil {
		return nil, apierrors.Internal("update incident", err)
	}
	return inc, nil
}

func (s *SOARService) ListIncidents(ctx context.Context, f model.IncidentFilter) ([]*model.Incident, int, error) {
	incidents, total, err := s.repo.ListIncidents(ctx, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list incidents", err)
	}
	return incidents, total, nil
}

func (s *SOARService) GetIncidentTimeline(ctx context.Context, tenantID, incidentID uuid.UUID) ([]*model.IncidentEvent, error) {
	events, err := s.repo.ListIncidentEvents(ctx, tenantID, incidentID)
	if err != nil {
		return nil, apierrors.Internal("incident timeline", err)
	}
	return events, nil
}

// ─── Playbooks ────────────────────────────────────────────────────────────────

func (s *SOARService) CreatePlaybook(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreatePlaybookRequest) (*model.Playbook, error) {
	pb, err := s.repo.CreatePlaybook(ctx, tenantID, callerID, req)
	if err != nil {
		return nil, apierrors.Internal("create playbook", err)
	}
	s.logger.Info().Str("playbook_id", pb.ID.String()).Str("name", pb.Name).Msg("playbook_created")
	return pb, nil
}

func (s *SOARService) GetPlaybook(ctx context.Context, tenantID, playbookID uuid.UUID) (*model.Playbook, error) {
	pb, err := s.repo.GetPlaybook(ctx, tenantID, playbookID)
	if err != nil {
		return nil, apierrors.Internal("get playbook", err)
	}
	if pb == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "playbook not found")
	}
	return pb, nil
}

func (s *SOARService) ListPlaybooks(ctx context.Context, tenantID uuid.UUID, activeOnly bool) ([]*model.Playbook, error) {
	playbooks, err := s.repo.ListPlaybooks(ctx, tenantID, activeOnly)
	if err != nil {
		return nil, apierrors.Internal("list playbooks", err)
	}
	return playbooks, nil
}

func (s *SOARService) SetPlaybookActive(ctx context.Context, tenantID, playbookID uuid.UUID, active bool) error {
	if err := s.repo.SetPlaybookActive(ctx, tenantID, playbookID, active); err != nil {
		return apierrors.Internal("set playbook active", err)
	}
	return nil
}

// RunPlaybook triggers a playbook manually.
func (s *SOARService) RunPlaybook(ctx context.Context, tenantID, playbookID uuid.UUID, callerID *uuid.UUID, req *model.RunPlaybookRequest) error {
	pb, err := s.GetPlaybook(ctx, tenantID, playbookID)
	if err != nil {
		return err
	}
	if !pb.IsActive {
		return apierrors.New(apierrors.KindBadInput, "playbook is not active")
	}
	if req.IncidentID != nil {
		if _, err := s.GetIncident(ctx, tenantID, *req.IncidentID); err != nil {
			return err
		}
	}
	s.executor.Run(ctx, tenantID, pb, req.IncidentID, req.TriggerEvent, callerID)
	return nil
}

// ─── Executions ───────────────────────────────────────────────────────────────

func (s *SOARService) GetExecution(ctx context.Context, tenantID, execID uuid.UUID) (*model.Execution, error) {
	exec, err := s.repo.GetExecution(ctx, tenantID, execID)
	if err != nil {
		return nil, apierrors.Internal("get execution", err)
	}
	if exec == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "execution not found")
	}
	return exec, nil
}

func (s *SOARService) ListExecutions(ctx context.Context, f model.ExecutionFilter) ([]*model.Execution, int, error) {
	execs, total, err := s.repo.ListExecutions(ctx, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list executions", err)
	}
	return execs, total, nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (s *SOARService) GetStats(ctx context.Context, tenantID uuid.UUID) (*model.SOARStats, error) {
	stats, err := s.repo.Stats(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("soar stats", err)
	}
	return stats, nil
}

// ─── Kafka auto-trigger ───────────────────────────────────────────────────────

// AutoTriggerFromEvent is called by the Kafka consumer to find and run matching playbooks.
func (s *SOARService) AutoTriggerFromEvent(ctx context.Context, tenantID uuid.UUID, triggerType, severity, sourceService string, event map[string]any) {
	s.autoTrigger(ctx, tenantID, triggerType, severity, sourceService, nil)
}

func (s *SOARService) autoTrigger(ctx context.Context, tenantID uuid.UUID, triggerType, severity, sourceService string, inc *model.Incident) {
	playbooks, err := s.repo.FindMatchingPlaybooks(ctx, tenantID, triggerType, severity, sourceService)
	if err != nil {
		s.logger.Warn().Err(err).Msg("auto_trigger_lookup_error")
		return
	}
	for _, pb := range playbooks {
		var incID *uuid.UUID
		triggerEvent := map[string]any{
			"trigger_type":   triggerType,
			"severity":       severity,
			"source_service": sourceService,
		}
		if inc != nil {
			incID = &inc.ID
			triggerEvent["incident_id"] = inc.ID.String()
			triggerEvent["title"] = inc.Title
		}
		s.executor.Run(ctx, tenantID, pb, incID, triggerEvent, nil)
		s.logger.Info().
			Str("playbook_id", pb.ID.String()).
			Str("trigger_type", triggerType).
			Str("severity", severity).
			Msg("auto_playbook_triggered")
	}
}
