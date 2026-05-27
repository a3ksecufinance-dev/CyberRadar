package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/cyberradar/platform/services/scs/internal/model"
	"github.com/cyberradar/platform/services/scs/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	kafka "github.com/segmentio/kafka-go"
)

type SCSService struct {
	repo   *repository.SCSRepository
	kafka  *kafka.Writer
	logger zerolog.Logger
}

func NewSCSService(repo *repository.SCSRepository, kw *kafka.Writer, logger zerolog.Logger) *SCSService {
	return &SCSService{repo: repo, kafka: kw, logger: logger}
}

// ─── Vendors ──────────────────────────────────────────────────────────────────

func (s *SCSService) CreateVendor(ctx context.Context, tenantID uuid.UUID, req *model.CreateVendorRequest, createdBy *uuid.UUID) (*model.SCSVendor, error) {
	return s.repo.CreateVendor(ctx, tenantID, req, createdBy)
}

func (s *SCSService) GetVendor(ctx context.Context, tenantID, id uuid.UUID) (*model.SCSVendor, error) {
	return s.repo.GetVendor(ctx, tenantID, id)
}

func (s *SCSService) ListVendors(ctx context.Context, tenantID uuid.UUID, f model.ListVendorsFilter) ([]model.SCSVendor, int, error) {
	return s.repo.ListVendors(ctx, tenantID, f)
}

func (s *SCSService) UpdateVendor(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdateVendorRequest) (*model.SCSVendor, error) {
	return s.repo.UpdateVendor(ctx, tenantID, id, req)
}

// ─── Components ───────────────────────────────────────────────────────────────

func (s *SCSService) CreateComponent(ctx context.Context, tenantID uuid.UUID, req *model.CreateComponentRequest) (*model.SCSComponent, error) {
	return s.repo.CreateComponent(ctx, tenantID, req)
}

func (s *SCSService) GetComponent(ctx context.Context, tenantID, id uuid.UUID) (*model.SCSComponent, error) {
	return s.repo.GetComponent(ctx, tenantID, id)
}

func (s *SCSService) ListComponents(ctx context.Context, tenantID uuid.UUID, f model.ListComponentsFilter) ([]model.SCSComponent, int, error) {
	return s.repo.ListComponents(ctx, tenantID, f)
}

func (s *SCSService) UpdateComponent(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdateComponentRequest) (*model.SCSComponent, error) {
	comp, err := s.repo.UpdateComponent(ctx, tenantID, id, req)
	if err != nil {
		return nil, err
	}
	// Alert on newly discovered critical vulns
	if req.CriticalVulnCount != nil && *req.CriticalVulnCount > 0 {
		go s.publishAlert("scs.critical_vuln_detected", map[string]any{
			"component_id":   comp.ID,
			"component_name": comp.Name,
			"version":        comp.Version,
			"tenant_id":      comp.TenantID,
			"critical_vulns": comp.CriticalVulnCount,
		})
	}
	return comp, nil
}

// ─── SBOMs ────────────────────────────────────────────────────────────────────

func (s *SCSService) CreateSBOM(ctx context.Context, tenantID uuid.UUID, req *model.CreateSBOMRequest, createdBy *uuid.UUID) (*model.SCSSBOM, error) {
	sbom, err := s.repo.CreateSBOM(ctx, tenantID, req, createdBy)
	if err != nil {
		return nil, err
	}
	// Publish event if risky SBOM
	if sbom.CriticalVulns > 0 || sbom.RiskScore >= 50 {
		go s.publishAlert("scs.sbom_risky", map[string]any{
			"sbom_id":       sbom.ID,
			"name":          sbom.Name,
			"tenant_id":     sbom.TenantID,
			"risk_score":    sbom.RiskScore,
			"critical_vulns": sbom.CriticalVulns,
		})
	}
	return sbom, nil
}

func (s *SCSService) GetSBOM(ctx context.Context, tenantID, id uuid.UUID) (*model.SCSSBOM, error) {
	return s.repo.GetSBOM(ctx, tenantID, id)
}

func (s *SCSService) ListSBOMs(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]model.SCSSBOM, int, error) {
	return s.repo.ListSBOMs(ctx, tenantID, limit, offset)
}

// ─── Assessments ──────────────────────────────────────────────────────────────

func (s *SCSService) CreateAssessment(ctx context.Context, tenantID uuid.UUID, req *model.CreateAssessmentRequest, createdBy *uuid.UUID) (*model.SCSAssessment, error) {
	return s.repo.CreateAssessment(ctx, tenantID, req, createdBy)
}

func (s *SCSService) ListAssessments(ctx context.Context, tenantID, vendorID uuid.UUID, status string) ([]model.SCSAssessment, error) {
	return s.repo.ListAssessments(ctx, tenantID, vendorID, status)
}

func (s *SCSService) UpdateAssessment(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdateAssessmentRequest) (*model.SCSAssessment, error) {
	a, err := s.repo.UpdateAssessment(ctx, tenantID, id, req)
	if err != nil {
		return nil, err
	}
	// Publish high-risk assessment completion
	if req.Status != nil && *req.Status == "completed" {
		if a.RiskRating == "critical" || a.RiskRating == "high" {
			go s.publishAlert("scs.assessment_high_risk", map[string]any{
				"assessment_id": a.ID,
				"vendor_id":     a.VendorID,
				"tenant_id":     a.TenantID,
				"risk_rating":   a.RiskRating,
				"score":         a.Score,
			})
		}
	}
	return a, nil
}

// ─── Alerts ───────────────────────────────────────────────────────────────────

func (s *SCSService) CreateAlert(ctx context.Context, tenantID uuid.UUID, req *model.CreateAlertRequest) (*model.SCSAlert, error) {
	alert, err := s.repo.CreateAlert(ctx, tenantID, req)
	if err != nil {
		return nil, err
	}
	if alert.Severity == "critical" || alert.Severity == "high" {
		go s.publishAlert("scs.alert_created", map[string]any{
			"alert_id":   alert.ID,
			"tenant_id":  alert.TenantID,
			"alert_type": alert.AlertType,
			"severity":   alert.Severity,
			"title":      alert.Title,
		})
	}
	return alert, nil
}

func (s *SCSService) ListAlerts(ctx context.Context, tenantID uuid.UUID, f model.ListAlertsFilter) ([]model.SCSAlert, int, error) {
	return s.repo.ListAlerts(ctx, tenantID, f)
}

func (s *SCSService) UpdateAlert(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdateAlertRequest) (*model.SCSAlert, error) {
	return s.repo.UpdateAlert(ctx, tenantID, id, req)
}

// ─── Policies ─────────────────────────────────────────────────────────────────

func (s *SCSService) CreatePolicy(ctx context.Context, tenantID uuid.UUID, req *model.CreatePolicyRequest, createdBy *uuid.UUID) (*model.SCSPolicy, error) {
	return s.repo.CreatePolicy(ctx, tenantID, req, createdBy)
}

func (s *SCSService) ListPolicies(ctx context.Context, tenantID uuid.UUID, policyType string) ([]model.SCSPolicy, error) {
	return s.repo.ListPolicies(ctx, tenantID, policyType)
}

func (s *SCSService) UpdatePolicy(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdatePolicyRequest) (*model.SCSPolicy, error) {
	return s.repo.UpdatePolicy(ctx, tenantID, id, req)
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (s *SCSService) GetStats(ctx context.Context, tenantID uuid.UUID) (*model.SCSStats, error) {
	return s.repo.GetStats(ctx, tenantID)
}

// ─── Kafka ────────────────────────────────────────────────────────────────────

func (s *SCSService) publishAlert(eventType string, payload map[string]any) {
	payload["event_type"] = eventType
	payload["timestamp"] = time.Now().UTC()
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	tenantID, _ := payload["tenant_id"].(uuid.UUID)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.kafka.WriteMessages(ctx, kafka.Message{
		Key:   []byte(tenantID.String()),
		Value: data,
	})
}
