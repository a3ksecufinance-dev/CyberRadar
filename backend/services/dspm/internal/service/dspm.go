package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/cyberradar/platform/services/dspm/internal/model"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	kafka "github.com/segmentio/kafka-go"
)

type Repository interface {
	// Data Stores
	CreateDataStore(ctx context.Context, tenantID uuid.UUID, req model.CreateDataStoreRequest, createdBy *uuid.UUID) (*model.DSPMDataStore, error)
	GetDataStore(ctx context.Context, tenantID, storeID uuid.UUID) (*model.DSPMDataStore, error)
	ListDataStores(ctx context.Context, tenantID uuid.UUID, f model.ListDataStoresFilter) ([]model.DSPMDataStore, int, error)
	UpdateDataStore(ctx context.Context, tenantID, storeID uuid.UUID, req model.UpdateDataStoreRequest) (*model.DSPMDataStore, error)
	DeleteDataStore(ctx context.Context, tenantID, storeID uuid.UUID) error

	// Scan Jobs
	CreateScanJob(ctx context.Context, tenantID uuid.UUID, req model.CreateScanJobRequest) (*model.DSPMScanJob, error)
	GetScanJob(ctx context.Context, tenantID, jobID uuid.UUID) (*model.DSPMScanJob, error)
	ListScanJobs(ctx context.Context, tenantID, storeID uuid.UUID) ([]model.DSPMScanJob, error)
	UpdateScanJob(ctx context.Context, tenantID, jobID uuid.UUID, req model.UpdateScanJobRequest) (*model.DSPMScanJob, error)

	// Findings
	CreateFinding(ctx context.Context, tenantID uuid.UUID, req model.CreateFindingRequest) (*model.DSPMFinding, error)
	GetFinding(ctx context.Context, tenantID, findingID uuid.UUID) (*model.DSPMFinding, error)
	ListFindings(ctx context.Context, tenantID uuid.UUID, f model.ListFindingsFilter) ([]model.DSPMFinding, int, error)
	UpdateFinding(ctx context.Context, tenantID, findingID uuid.UUID, req model.UpdateFindingRequest) (*model.DSPMFinding, error)

	// Policies
	CreatePolicy(ctx context.Context, tenantID uuid.UUID, req model.CreatePolicyRequest, createdBy *uuid.UUID) (*model.DSPMPolicy, error)
	GetPolicy(ctx context.Context, tenantID, policyID uuid.UUID) (*model.DSPMPolicy, error)
	ListPolicies(ctx context.Context, tenantID uuid.UUID) ([]model.DSPMPolicy, error)
	UpdatePolicy(ctx context.Context, tenantID, policyID uuid.UUID, req model.UpdatePolicyRequest) (*model.DSPMPolicy, error)
	DeletePolicy(ctx context.Context, tenantID, policyID uuid.UUID) error

	// Remediation
	CreateRemediationItem(ctx context.Context, tenantID uuid.UUID, req model.CreateRemediationRequest) (*model.DSPMRemediationItem, error)
	GetRemediationItem(ctx context.Context, tenantID, itemID uuid.UUID) (*model.DSPMRemediationItem, error)
	ListRemediationItems(ctx context.Context, tenantID, findingID uuid.UUID) ([]model.DSPMRemediationItem, error)
	UpdateRemediationItem(ctx context.Context, tenantID, itemID uuid.UUID, req model.UpdateRemediationRequest) (*model.DSPMRemediationItem, error)

	// Stats
	GetStats(ctx context.Context, tenantID uuid.UUID) (*model.DSPMStats, error)
}

type DSPMService struct {
	repo   Repository
	kafka  *kafka.Writer
	topic  string
	logger zerolog.Logger
}

func NewDSPMService(repo Repository, kw *kafka.Writer, topic string, logger zerolog.Logger) *DSPMService {
	return &DSPMService{repo: repo, kafka: kw, topic: topic, logger: logger}
}

func (s *DSPMService) publish(event string, payload any) {
	go func() {
		data, err := json.Marshal(map[string]any{
			"event":     event,
			"payload":   payload,
			"timestamp": time.Now().UTC(),
		})
		if err != nil {
			s.logger.Error().Err(err).Str("event", event).Msg("marshal kafka event")
			return
		}
		msg := kafka.Message{Value: data}
		if err := s.kafka.WriteMessages(context.Background(), msg); err != nil {
			s.logger.Error().Err(err).Str("event", event).Msg("publish kafka event")
		}
	}()
}

// ─── Data Stores ──────────────────────────────────────────────────────────────

func (s *DSPMService) CreateDataStore(ctx context.Context, tenantID uuid.UUID, req model.CreateDataStoreRequest, createdBy *uuid.UUID) (*model.DSPMDataStore, error) {
	ds, err := s.repo.CreateDataStore(ctx, tenantID, req, createdBy)
	if err != nil {
		return nil, err
	}
	if ds.SensitivityLevel == "top_secret" || ds.SensitivityLevel == "restricted" {
		s.publish("dspm.store.sensitive_registered", map[string]any{
			"tenant_id":         tenantID,
			"store_id":          ds.ID,
			"name":              ds.Name,
			"store_type":        ds.StoreType,
			"sensitivity_level": ds.SensitivityLevel,
			"risk_score":        ds.RiskScore,
			"risk_level":        ds.RiskLevel,
		})
	}
	return ds, nil
}

func (s *DSPMService) GetDataStore(ctx context.Context, tenantID, storeID uuid.UUID) (*model.DSPMDataStore, error) {
	return s.repo.GetDataStore(ctx, tenantID, storeID)
}

func (s *DSPMService) ListDataStores(ctx context.Context, tenantID uuid.UUID, f model.ListDataStoresFilter) ([]model.DSPMDataStore, int, error) {
	return s.repo.ListDataStores(ctx, tenantID, f)
}

func (s *DSPMService) UpdateDataStore(ctx context.Context, tenantID, storeID uuid.UUID, req model.UpdateDataStoreRequest) (*model.DSPMDataStore, error) {
	return s.repo.UpdateDataStore(ctx, tenantID, storeID, req)
}

func (s *DSPMService) DeleteDataStore(ctx context.Context, tenantID, storeID uuid.UUID) error {
	return s.repo.DeleteDataStore(ctx, tenantID, storeID)
}

// ─── Scan Jobs ────────────────────────────────────────────────────────────────

func (s *DSPMService) CreateScanJob(ctx context.Context, tenantID uuid.UUID, req model.CreateScanJobRequest) (*model.DSPMScanJob, error) {
	return s.repo.CreateScanJob(ctx, tenantID, req)
}

func (s *DSPMService) GetScanJob(ctx context.Context, tenantID, jobID uuid.UUID) (*model.DSPMScanJob, error) {
	return s.repo.GetScanJob(ctx, tenantID, jobID)
}

func (s *DSPMService) ListScanJobs(ctx context.Context, tenantID, storeID uuid.UUID) ([]model.DSPMScanJob, error) {
	return s.repo.ListScanJobs(ctx, tenantID, storeID)
}

func (s *DSPMService) UpdateScanJob(ctx context.Context, tenantID, jobID uuid.UUID, req model.UpdateScanJobRequest) (*model.DSPMScanJob, error) {
	job, err := s.repo.UpdateScanJob(ctx, tenantID, jobID, req)
	if err != nil {
		return nil, err
	}
	if job != nil && req.Status != nil && *req.Status == "completed" && job.SensitiveFindingsCount > 0 {
		s.publish("dspm.scan.sensitive_data_found", map[string]any{
			"tenant_id":                tenantID,
			"job_id":                   job.ID,
			"data_store_id":            job.DataStoreID,
			"scan_type":                job.ScanType,
			"sensitive_findings_count": job.SensitiveFindingsCount,
			"findings_count":           job.FindingsCount,
			"duration_seconds":         job.DurationSeconds,
		})
	}
	return job, nil
}

// ─── Findings ─────────────────────────────────────────────────────────────────

func (s *DSPMService) CreateFinding(ctx context.Context, tenantID uuid.UUID, req model.CreateFindingRequest) (*model.DSPMFinding, error) {
	f, err := s.repo.CreateFinding(ctx, tenantID, req)
	if err != nil {
		return nil, err
	}
	if f.Severity == "critical" || f.FindingType == "pii" || f.FindingType == "pci_data" || f.FindingType == "credentials" {
		s.publish("dspm.finding.sensitive_data_exposed", map[string]any{
			"tenant_id":    tenantID,
			"finding_id":   f.ID,
			"store_id":     f.DataStoreID,
			"finding_type": f.FindingType,
			"severity":     f.Severity,
			"title":        f.Title,
			"record_count": f.RecordCount,
		})
	}
	if f.IsPublicAccessible {
		s.publish("dspm.finding.public_exposure", map[string]any{
			"tenant_id":    tenantID,
			"finding_id":   f.ID,
			"store_id":     f.DataStoreID,
			"finding_type": f.FindingType,
			"severity":     f.Severity,
			"title":        f.Title,
			"record_count": f.RecordCount,
		})
	}
	return f, nil
}

func (s *DSPMService) GetFinding(ctx context.Context, tenantID, findingID uuid.UUID) (*model.DSPMFinding, error) {
	return s.repo.GetFinding(ctx, tenantID, findingID)
}

func (s *DSPMService) ListFindings(ctx context.Context, tenantID uuid.UUID, f model.ListFindingsFilter) ([]model.DSPMFinding, int, error) {
	return s.repo.ListFindings(ctx, tenantID, f)
}

func (s *DSPMService) UpdateFinding(ctx context.Context, tenantID, findingID uuid.UUID, req model.UpdateFindingRequest) (*model.DSPMFinding, error) {
	f, err := s.repo.UpdateFinding(ctx, tenantID, findingID, req)
	if err != nil {
		return nil, err
	}
	if f != nil && req.Status != nil && *req.Status == "open" {
		if f.Severity == "critical" || f.Severity == "high" {
			if f.FindingType == "pii" || f.FindingType == "pci_data" {
				s.publish("dspm.finding.critical", map[string]any{
					"tenant_id":    tenantID,
					"finding_id":   f.ID,
					"store_id":     f.DataStoreID,
					"finding_type": f.FindingType,
					"severity":     f.Severity,
					"title":        f.Title,
				})
			}
		}
	}
	return f, nil
}

// ─── Policies ─────────────────────────────────────────────────────────────────

func (s *DSPMService) CreatePolicy(ctx context.Context, tenantID uuid.UUID, req model.CreatePolicyRequest, createdBy *uuid.UUID) (*model.DSPMPolicy, error) {
	return s.repo.CreatePolicy(ctx, tenantID, req, createdBy)
}

func (s *DSPMService) GetPolicy(ctx context.Context, tenantID, policyID uuid.UUID) (*model.DSPMPolicy, error) {
	return s.repo.GetPolicy(ctx, tenantID, policyID)
}

func (s *DSPMService) ListPolicies(ctx context.Context, tenantID uuid.UUID) ([]model.DSPMPolicy, error) {
	return s.repo.ListPolicies(ctx, tenantID)
}

func (s *DSPMService) UpdatePolicy(ctx context.Context, tenantID, policyID uuid.UUID, req model.UpdatePolicyRequest) (*model.DSPMPolicy, error) {
	return s.repo.UpdatePolicy(ctx, tenantID, policyID, req)
}

func (s *DSPMService) DeletePolicy(ctx context.Context, tenantID, policyID uuid.UUID) error {
	return s.repo.DeletePolicy(ctx, tenantID, policyID)
}

// ─── Remediation ──────────────────────────────────────────────────────────────

func (s *DSPMService) CreateRemediationItem(ctx context.Context, tenantID uuid.UUID, req model.CreateRemediationRequest) (*model.DSPMRemediationItem, error) {
	return s.repo.CreateRemediationItem(ctx, tenantID, req)
}

func (s *DSPMService) GetRemediationItem(ctx context.Context, tenantID, itemID uuid.UUID) (*model.DSPMRemediationItem, error) {
	return s.repo.GetRemediationItem(ctx, tenantID, itemID)
}

func (s *DSPMService) ListRemediationItems(ctx context.Context, tenantID, findingID uuid.UUID) ([]model.DSPMRemediationItem, error) {
	return s.repo.ListRemediationItems(ctx, tenantID, findingID)
}

func (s *DSPMService) UpdateRemediationItem(ctx context.Context, tenantID, itemID uuid.UUID, req model.UpdateRemediationRequest) (*model.DSPMRemediationItem, error) {
	return s.repo.UpdateRemediationItem(ctx, tenantID, itemID, req)
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (s *DSPMService) GetStats(ctx context.Context, tenantID uuid.UUID) (*model.DSPMStats, error) {
	return s.repo.GetStats(ctx, tenantID)
}
