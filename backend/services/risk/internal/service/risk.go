package service

import (
	"context"
	"encoding/json"
	"time"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/services/risk/internal/model"
	"github.com/cyberradar/platform/services/risk/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// RiskService orchestrates Cyber Risk Quantification.
type RiskService struct {
	repo     *repository.RiskRepository
	producer *pkgkafka.Producer
	logger   zerolog.Logger
}

// NewRiskService creates a RiskService.
func NewRiskService(repo *repository.RiskRepository, producer *pkgkafka.Producer, logger zerolog.Logger) *RiskService {
	return &RiskService{repo: repo, producer: producer, logger: logger}
}

// ─── Assets ───────────────────────────────────────────────────────────────────

func (s *RiskService) CreateAsset(ctx context.Context, tenantID uuid.UUID, req *model.CreateRiskAssetRequest) (*model.RiskAsset, error) {
	a, err := s.repo.CreateAsset(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("create risk asset", err)
	}
	s.logger.Info().Str("asset_id", a.ID.String()).Str("type", a.AssetType).Str("criticality", a.Criticality).Msg("risk_asset_created")
	return a, nil
}

func (s *RiskService) GetAsset(ctx context.Context, tenantID, assetID uuid.UUID) (*model.RiskAsset, error) {
	a, err := s.repo.GetAsset(ctx, tenantID, assetID)
	if err != nil {
		return nil, apierrors.Internal("get risk asset", err)
	}
	if a == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "risk asset not found")
	}
	return a, nil
}

func (s *RiskService) ListAssets(ctx context.Context, tenantID uuid.UUID, f model.ListAssetsFilter) ([]*model.RiskAsset, int, error) {
	assets, total, err := s.repo.ListAssets(ctx, tenantID, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list risk assets", err)
	}
	return assets, total, nil
}

func (s *RiskService) UpdateAsset(ctx context.Context, tenantID, assetID uuid.UUID, req *model.UpdateRiskAssetRequest) (*model.RiskAsset, error) {
	a, err := s.repo.UpdateAsset(ctx, tenantID, assetID, req)
	if err != nil {
		return nil, apierrors.Internal("update risk asset", err)
	}
	if a == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "risk asset not found")
	}
	return a, nil
}

// ─── Scenarios ────────────────────────────────────────────────────────────────

func (s *RiskService) CreateScenario(ctx context.Context, tenantID uuid.UUID, req *model.CreateScenarioRequest, createdBy uuid.UUID) (*model.RiskScenario, error) {
	sc, err := s.repo.CreateScenario(ctx, tenantID, req, createdBy)
	if err != nil {
		return nil, apierrors.Internal("create risk scenario", err)
	}
	s.logger.Info().Str("scenario_id", sc.ID.String()).Str("type", sc.ScenarioType).Str("level", sc.RiskLevel).Msg("risk_scenario_created")

	if sc.RiskLevel == model.CriticalityCritical || sc.RiskLevel == model.CriticalityHigh {
		go s.publishScenarioAlert(tenantID, sc)
	}
	return sc, nil
}

func (s *RiskService) GetScenario(ctx context.Context, tenantID, scenarioID uuid.UUID) (*model.RiskScenario, error) {
	sc, err := s.repo.GetScenario(ctx, tenantID, scenarioID)
	if err != nil {
		return nil, apierrors.Internal("get risk scenario", err)
	}
	if sc == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "risk scenario not found")
	}
	return sc, nil
}

func (s *RiskService) ListScenarios(ctx context.Context, tenantID uuid.UUID, f model.ListScenariosFilter) ([]*model.RiskScenario, int, error) {
	scenarios, total, err := s.repo.ListScenarios(ctx, tenantID, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list risk scenarios", err)
	}
	return scenarios, total, nil
}

func (s *RiskService) UpdateScenario(ctx context.Context, tenantID, scenarioID uuid.UUID, req *model.UpdateScenarioRequest) (*model.RiskScenario, error) {
	sc, err := s.repo.UpdateScenario(ctx, tenantID, scenarioID, req)
	if err != nil {
		return nil, apierrors.Internal("update risk scenario", err)
	}
	if sc == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "risk scenario not found")
	}
	return sc, nil
}

// ─── Treatments ───────────────────────────────────────────────────────────────

func (s *RiskService) CreateTreatment(ctx context.Context, tenantID uuid.UUID, req *model.CreateTreatmentRequest, createdBy uuid.UUID) (*model.RiskTreatment, error) {
	t, err := s.repo.CreateTreatment(ctx, tenantID, req, createdBy)
	if err != nil {
		return nil, apierrors.Internal("create risk treatment", err)
	}
	s.logger.Info().Str("treatment_id", t.ID.String()).Str("type", t.TreatmentType).Msg("risk_treatment_created")
	return t, nil
}

func (s *RiskService) GetTreatment(ctx context.Context, tenantID, treatmentID uuid.UUID) (*model.RiskTreatment, error) {
	t, err := s.repo.GetTreatment(ctx, tenantID, treatmentID)
	if err != nil {
		return nil, apierrors.Internal("get risk treatment", err)
	}
	if t == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "risk treatment not found")
	}
	return t, nil
}

func (s *RiskService) ListTreatments(ctx context.Context, tenantID uuid.UUID, scenarioID *uuid.UUID, status string, page, pageSize int) ([]*model.RiskTreatment, int, error) {
	treatments, total, err := s.repo.ListTreatments(ctx, tenantID, scenarioID, status, page, pageSize)
	if err != nil {
		return nil, 0, apierrors.Internal("list risk treatments", err)
	}
	return treatments, total, nil
}

func (s *RiskService) UpdateTreatment(ctx context.Context, tenantID, treatmentID uuid.UUID, req *model.UpdateTreatmentRequest) (*model.RiskTreatment, error) {
	t, err := s.repo.UpdateTreatment(ctx, tenantID, treatmentID, req)
	if err != nil {
		return nil, apierrors.Internal("update risk treatment", err)
	}
	if t == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "risk treatment not found")
	}
	return t, nil
}

// ─── Assessments ──────────────────────────────────────────────────────────────

func (s *RiskService) CreateAssessment(ctx context.Context, tenantID uuid.UUID, req *model.CreateAssessmentRequest, createdBy uuid.UUID) (*model.RiskAssessment, error) {
	a, err := s.repo.CreateAssessment(ctx, tenantID, req, createdBy)
	if err != nil {
		return nil, apierrors.Internal("create risk assessment", err)
	}
	// Immediately populate aggregates from existing scenarios
	go func() {
		ctx2 := context.Background()
		if err := s.repo.ComputeAssessment(ctx2, tenantID, a.ID); err != nil {
			s.logger.Error().Err(err).Str("assessment_id", a.ID.String()).Msg("risk_assessment_compute_failed")
		}
	}()
	s.logger.Info().Str("assessment_id", a.ID.String()).Str("type", a.AssessmentType).Msg("risk_assessment_created")
	return a, nil
}

func (s *RiskService) GetAssessment(ctx context.Context, tenantID, assessmentID uuid.UUID) (*model.RiskAssessment, error) {
	a, err := s.repo.GetAssessment(ctx, tenantID, assessmentID)
	if err != nil {
		return nil, apierrors.Internal("get risk assessment", err)
	}
	if a == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "risk assessment not found")
	}
	return a, nil
}

func (s *RiskService) ListAssessments(ctx context.Context, tenantID uuid.UUID, status string, page, pageSize int) ([]*model.RiskAssessment, int, error) {
	assessments, total, err := s.repo.ListAssessments(ctx, tenantID, status, page, pageSize)
	if err != nil {
		return nil, 0, apierrors.Internal("list risk assessments", err)
	}
	return assessments, total, nil
}

// ─── KRIs ─────────────────────────────────────────────────────────────────────

func (s *RiskService) CreateKRI(ctx context.Context, tenantID uuid.UUID, req *model.CreateKRIRequest) (*model.RiskKRI, error) {
	k, err := s.repo.CreateKRI(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("create KRI", err)
	}
	s.logger.Info().Str("kri_id", k.ID.String()).Str("metric", k.MetricName).Msg("risk_kri_created")
	return k, nil
}

func (s *RiskService) GetKRI(ctx context.Context, tenantID, kriID uuid.UUID) (*model.RiskKRI, error) {
	k, err := s.repo.GetKRI(ctx, tenantID, kriID)
	if err != nil {
		return nil, apierrors.Internal("get KRI", err)
	}
	if k == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "KRI not found")
	}
	return k, nil
}

func (s *RiskService) ListKRIs(ctx context.Context, tenantID uuid.UUID, category, status string) ([]*model.RiskKRI, error) {
	kris, err := s.repo.ListKRIs(ctx, tenantID, category, status)
	if err != nil {
		return nil, apierrors.Internal("list KRIs", err)
	}
	return kris, nil
}

func (s *RiskService) UpdateKRIValue(ctx context.Context, tenantID, kriID uuid.UUID, value float64) (*model.RiskKRI, error) {
	k, err := s.repo.UpdateKRIValue(ctx, tenantID, kriID, value)
	if err != nil {
		return nil, apierrors.Internal("update KRI value", err)
	}
	if k == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "KRI not found")
	}
	if k.Status == "red" {
		s.logger.Warn().Str("kri_id", k.ID.String()).Str("metric", k.MetricName).Float64("value", value).Msg("risk_kri_threshold_breached")
		go s.publishKRIAlert(tenantID, k)
	}
	return k, nil
}

func (s *RiskService) GetKRIHistory(ctx context.Context, tenantID, kriID uuid.UUID, limit int) ([]*model.RiskKRIHistory, error) {
	history, err := s.repo.GetKRIHistory(ctx, tenantID, kriID, limit)
	if err != nil {
		return nil, apierrors.Internal("get KRI history", err)
	}
	return history, nil
}

func (s *RiskService) Stats(ctx context.Context, tenantID uuid.UUID) (*model.RiskStats, error) {
	stats, err := s.repo.Stats(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("risk stats", err)
	}
	return stats, nil
}

// ─── Kafka publishing ─────────────────────────────────────────────────────────

func (s *RiskService) publishScenarioAlert(tenantID uuid.UUID, sc *model.RiskScenario) {
	ctx := context.Background()
	payload := map[string]any{
		"event_type":    "risk.scenario_high",
		"tenant_id":     tenantID.String(),
		"scenario_id":   sc.ID.String(),
		"scenario_type": sc.ScenarioType,
		"risk_level":    sc.RiskLevel,
		"risk_score":    sc.RiskScore,
		"total_loss":    sc.TotalLoss,
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(payload)
	if err := s.producer.Publish(ctx, sc.ID.String(), data); err != nil {
		s.logger.Error().Err(err).Msg("risk_scenario_publish_failed")
	}
}

func (s *RiskService) publishKRIAlert(tenantID uuid.UUID, k *model.RiskKRI) {
	ctx := context.Background()
	payload := map[string]any{
		"event_type":   "risk.kri_red",
		"tenant_id":    tenantID.String(),
		"kri_id":       k.ID.String(),
		"metric_name":  k.MetricName,
		"category":     k.Category,
		"value":        k.CurrentValue,
		"status":       k.Status,
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(payload)
	if err := s.producer.Publish(ctx, k.ID.String(), data); err != nil {
		s.logger.Error().Err(err).Msg("risk_kri_publish_failed")
	}
}
