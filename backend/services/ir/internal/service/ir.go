package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/cyberradar/platform/services/ir/internal/model"
	"github.com/cyberradar/platform/services/ir/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	kafka "github.com/segmentio/kafka-go"
)

type IRService struct {
	repo   *repository.IRRepository
	kafka  *kafka.Writer
	logger zerolog.Logger
}

func NewIRService(repo *repository.IRRepository, kw *kafka.Writer, logger zerolog.Logger) *IRService {
	return &IRService{repo: repo, kafka: kw, logger: logger}
}

// ─── Playbooks ────────────────────────────────────────────────────────────────

func (s *IRService) CreatePlaybook(ctx context.Context, tenantID uuid.UUID, req *model.CreatePlaybookRequest, createdBy *uuid.UUID) (*model.IRPlaybook, error) {
	return s.repo.CreatePlaybook(ctx, tenantID, req, createdBy)
}

func (s *IRService) GetPlaybook(ctx context.Context, tenantID, id uuid.UUID) (*model.IRPlaybook, error) {
	return s.repo.GetPlaybook(ctx, tenantID, id)
}

func (s *IRService) ListPlaybooks(ctx context.Context, tenantID uuid.UUID, incidentType string) ([]model.IRPlaybook, error) {
	return s.repo.ListPlaybooks(ctx, tenantID, incidentType)
}

func (s *IRService) UpdatePlaybook(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdatePlaybookRequest) (*model.IRPlaybook, error) {
	return s.repo.UpdatePlaybook(ctx, tenantID, id, req)
}

// ─── Incidents ────────────────────────────────────────────────────────────────

func (s *IRService) CreateIncident(ctx context.Context, tenantID uuid.UUID, req *model.CreateIncidentRequest, createdBy *uuid.UUID) (*model.IRIncident, error) {
	inc, err := s.repo.CreateIncident(ctx, tenantID, req, createdBy)
	if err != nil {
		return nil, err
	}

	// Auto-add detection timeline event
	go func() {
		bgCtx := context.Background()
		_, _ = s.repo.AddTimelineEvent(bgCtx, tenantID, inc.ID, &model.CreateTimelineEventRequest{
			EventTime:   inc.DetectedAt,
			EventType:   "detection",
			Title:       "Incident detected",
			Description: "Incident created: " + inc.Title,
			ActorType:   "system",
		}, createdBy)
	}()

	// Instantiate playbook tasks if playbook assigned
	if req.PlaybookID != nil {
		go func() {
			bgCtx := context.Background()
			if err := s.repo.InstantiatePlaybookTasks(bgCtx, tenantID, inc.ID, *req.PlaybookID, createdBy); err != nil {
				s.logger.Error().Err(err).Str("incident_id", inc.ID.String()).Msg("failed to instantiate playbook tasks")
			}
		}()
	}

	// Publish Kafka event for critical/high severity
	if inc.Severity == "critical" || inc.Severity == "high" {
		go s.publishIncidentEvent("ir.incident_created", inc)
	}

	return inc, nil
}

func (s *IRService) GetIncident(ctx context.Context, tenantID, id uuid.UUID) (*model.IRIncident, error) {
	return s.repo.GetIncident(ctx, tenantID, id)
}

func (s *IRService) ListIncidents(ctx context.Context, tenantID uuid.UUID, f model.ListIncidentsFilter) ([]model.IRIncident, int, error) {
	return s.repo.ListIncidents(ctx, tenantID, f)
}

func (s *IRService) UpdateIncident(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdateIncidentRequest, updatedBy *uuid.UUID) (*model.IRIncident, error) {
	inc, err := s.repo.UpdateIncident(ctx, tenantID, id, req)
	if err != nil {
		return nil, err
	}

	// Timeline entry for status changes
	if req.Status != nil {
		go func() {
			bgCtx := context.Background()
			_, _ = s.repo.AddTimelineEvent(bgCtx, tenantID, inc.ID, &model.CreateTimelineEventRequest{
				EventTime:  time.Now().UTC(),
				EventType:  "action",
				Title:      "Status changed to " + *req.Status,
				ActorType:  "analyst",
				IsVerified: true,
			}, updatedBy)
		}()

		// Publish closure/containment events
		switch *req.Status {
		case "contained", "recovered", "closed":
			go s.publishIncidentEvent("ir.incident_"+*req.Status, inc)
		}
	}

	return inc, nil
}

// ─── Timeline ─────────────────────────────────────────────────────────────────

func (s *IRService) AddTimelineEvent(ctx context.Context, tenantID, incidentID uuid.UUID, req *model.CreateTimelineEventRequest, createdBy *uuid.UUID) (*model.IRTimeline, error) {
	return s.repo.AddTimelineEvent(ctx, tenantID, incidentID, req, createdBy)
}

func (s *IRService) GetTimeline(ctx context.Context, tenantID, incidentID uuid.UUID) ([]model.IRTimeline, error) {
	return s.repo.GetTimeline(ctx, tenantID, incidentID)
}

// ─── Tasks ────────────────────────────────────────────────────────────────────

func (s *IRService) CreateTask(ctx context.Context, tenantID, incidentID uuid.UUID, req *model.CreateTaskRequest, createdBy *uuid.UUID) (*model.IRTask, error) {
	return s.repo.CreateTask(ctx, tenantID, incidentID, req, createdBy)
}

func (s *IRService) ListTasks(ctx context.Context, tenantID, incidentID uuid.UUID) ([]model.IRTask, error) {
	return s.repo.ListTasks(ctx, tenantID, incidentID)
}

func (s *IRService) UpdateTask(ctx context.Context, tenantID, incidentID, taskID uuid.UUID, req *model.UpdateTaskRequest) (*model.IRTask, error) {
	return s.repo.UpdateTask(ctx, tenantID, incidentID, taskID, req)
}

// ─── Evidence ─────────────────────────────────────────────────────────────────

func (s *IRService) CreateEvidence(ctx context.Context, tenantID, incidentID uuid.UUID, req *model.CreateEvidenceRequest, createdBy *uuid.UUID) (*model.IREvidence, error) {
	ev, err := s.repo.CreateEvidence(ctx, tenantID, incidentID, req, createdBy)
	if err != nil {
		return nil, err
	}
	// Timeline entry for evidence collection
	go func() {
		bgCtx := context.Background()
		_, _ = s.repo.AddTimelineEvent(bgCtx, tenantID, incidentID, &model.CreateTimelineEventRequest{
			EventTime:    time.Now().UTC(),
			EventType:    "evidence",
			Title:        "Evidence collected: " + ev.Name,
			Description:  ev.EvidenceType + " collected via " + ev.CollectionMethod,
			Actor:        ev.CollectedBy,
			ActorType:    "analyst",
			SourceSystem: ev.CollectionMethod,
		}, createdBy)
	}()
	return ev, nil
}

func (s *IRService) ListEvidence(ctx context.Context, tenantID, incidentID uuid.UUID) ([]model.IREvidence, error) {
	return s.repo.ListEvidence(ctx, tenantID, incidentID)
}

func (s *IRService) UpdateEvidence(ctx context.Context, tenantID, incidentID, evidenceID uuid.UUID, req *model.UpdateEvidenceRequest) (*model.IREvidence, error) {
	return s.repo.UpdateEvidence(ctx, tenantID, incidentID, evidenceID, req)
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (s *IRService) GetStats(ctx context.Context, tenantID uuid.UUID) (*model.IRStats, error) {
	return s.repo.GetStats(ctx, tenantID)
}

// ─── Kafka ────────────────────────────────────────────────────────────────────

func (s *IRService) publishIncidentEvent(eventType string, inc *model.IRIncident) {
	payload := map[string]any{
		"event_type":      eventType,
		"incident_id":     inc.ID,
		"incident_number": inc.IncidentNumber,
		"tenant_id":       inc.TenantID,
		"incident_type":   inc.IncidentType,
		"severity":        inc.Severity,
		"status":          inc.Status,
		"title":           inc.Title,
		"timestamp":       time.Now().UTC(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.kafka.WriteMessages(ctx, kafka.Message{
		Key:   []byte(inc.TenantID.String()),
		Value: data,
	})
}
