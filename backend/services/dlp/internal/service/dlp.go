package service

import (
	"context"
	"encoding/json"
	"math/rand"
	"time"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/services/dlp/internal/model"
	"github.com/cyberradar/platform/services/dlp/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// DLPService orchestrates data security and loss prevention.
type DLPService struct {
	repo     *repository.DLPRepository
	producer *pkgkafka.Producer
	logger   zerolog.Logger
}

// NewDLPService creates a DLPService.
func NewDLPService(repo *repository.DLPRepository, producer *pkgkafka.Producer, logger zerolog.Logger) *DLPService {
	return &DLPService{repo: repo, producer: producer, logger: logger}
}

// ─── Labels ───────────────────────────────────────────────────────────────────

func (s *DLPService) CreateLabel(ctx context.Context, tenantID uuid.UUID, req *model.CreateLabelRequest, createdBy uuid.UUID) (*model.DLPLabel, error) {
	l, err := s.repo.CreateLabel(ctx, tenantID, req, createdBy)
	if err != nil {
		return nil, apierrors.Internal("create label", err)
	}
	s.logger.Info().Str("label_id", l.ID.String()).Str("sensitivity", l.Sensitivity).Msg("dlp_label_created")
	return l, nil
}

func (s *DLPService) GetLabel(ctx context.Context, tenantID, labelID uuid.UUID) (*model.DLPLabel, error) {
	l, err := s.repo.GetLabel(ctx, tenantID, labelID)
	if err != nil {
		return nil, apierrors.Internal("get label", err)
	}
	if l == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "label not found")
	}
	return l, nil
}

func (s *DLPService) ListLabels(ctx context.Context, tenantID uuid.UUID, activeOnly bool, page, pageSize int) ([]*model.DLPLabel, int, error) {
	labels, total, err := s.repo.ListLabels(ctx, tenantID, activeOnly, page, pageSize)
	if err != nil {
		return nil, 0, apierrors.Internal("list labels", err)
	}
	return labels, total, nil
}

func (s *DLPService) UpdateLabel(ctx context.Context, tenantID, labelID uuid.UUID, req *model.UpdateLabelRequest) (*model.DLPLabel, error) {
	l, err := s.repo.UpdateLabel(ctx, tenantID, labelID, req)
	if err != nil {
		return nil, apierrors.Internal("update label", err)
	}
	if l == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "label not found")
	}
	return l, nil
}

// ─── Data Assets ──────────────────────────────────────────────────────────────

func (s *DLPService) CreateAsset(ctx context.Context, tenantID uuid.UUID, req *model.CreateAssetRequest) (*model.DLPDataAsset, error) {
	a, err := s.repo.CreateAsset(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("create asset", err)
	}
	s.logger.Info().Str("asset_id", a.ID.String()).Str("type", a.AssetType).Msg("dlp_asset_registered")
	return a, nil
}

func (s *DLPService) GetAsset(ctx context.Context, tenantID, assetID uuid.UUID) (*model.DLPDataAsset, error) {
	a, err := s.repo.GetAsset(ctx, tenantID, assetID)
	if err != nil {
		return nil, apierrors.Internal("get asset", err)
	}
	if a == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "asset not found")
	}
	return a, nil
}

func (s *DLPService) ListAssets(ctx context.Context, tenantID uuid.UUID, f model.ListAssetsFilter) ([]*model.DLPDataAsset, int, error) {
	assets, total, err := s.repo.ListAssets(ctx, tenantID, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list assets", err)
	}
	return assets, total, nil
}

func (s *DLPService) UpdateAsset(ctx context.Context, tenantID, assetID uuid.UUID, req *model.UpdateAssetRequest) (*model.DLPDataAsset, error) {
	a, err := s.repo.UpdateAsset(ctx, tenantID, assetID, req)
	if err != nil {
		return nil, apierrors.Internal("update asset", err)
	}
	if a == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "asset not found")
	}
	return a, nil
}

// ─── Policies ─────────────────────────────────────────────────────────────────

func (s *DLPService) CreatePolicy(ctx context.Context, tenantID uuid.UUID, req *model.CreatePolicyRequest, createdBy uuid.UUID) (*model.DLPPolicy, error) {
	p, err := s.repo.CreatePolicy(ctx, tenantID, req, createdBy)
	if err != nil {
		return nil, apierrors.Internal("create policy", err)
	}
	s.logger.Info().Str("policy_id", p.ID.String()).Str("type", p.PolicyType).Str("action", p.Action).Msg("dlp_policy_created")
	return p, nil
}

func (s *DLPService) GetPolicy(ctx context.Context, tenantID, policyID uuid.UUID) (*model.DLPPolicy, error) {
	p, err := s.repo.GetPolicy(ctx, tenantID, policyID)
	if err != nil {
		return nil, apierrors.Internal("get policy", err)
	}
	if p == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "policy not found")
	}
	return p, nil
}

func (s *DLPService) ListPolicies(ctx context.Context, tenantID uuid.UUID, policyType string, activeOnly bool, page, pageSize int) ([]*model.DLPPolicy, int, error) {
	policies, total, err := s.repo.ListPolicies(ctx, tenantID, policyType, activeOnly, page, pageSize)
	if err != nil {
		return nil, 0, apierrors.Internal("list policies", err)
	}
	return policies, total, nil
}

func (s *DLPService) UpdatePolicy(ctx context.Context, tenantID, policyID uuid.UUID, req *model.UpdatePolicyRequest) (*model.DLPPolicy, error) {
	p, err := s.repo.UpdatePolicy(ctx, tenantID, policyID, req)
	if err != nil {
		return nil, apierrors.Internal("update policy", err)
	}
	if p == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "policy not found")
	}
	return p, nil
}

// ─── Violations ───────────────────────────────────────────────────────────────

func (s *DLPService) ReportViolation(ctx context.Context, tenantID uuid.UUID, req *model.ReportViolationRequest) (*model.DLPViolation, error) {
	v, err := s.repo.CreateViolation(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("report violation", err)
	}
	s.logger.Warn().
		Str("violation_id", v.ID.String()).
		Str("severity", v.Severity).
		Str("type", v.ViolationType).
		Str("action", v.ActionTaken).
		Msg("dlp_violation_detected")

	// Publish to Kafka for SOAR/SIEM integration
	if v.Severity == model.SeverityCritical || v.Severity == model.SeverityHigh {
		payload := map[string]any{
			"event_type":     "dlp.violation_detected",
			"tenant_id":      tenantID.String(),
			"violation_id":   v.ID.String(),
			"violation_type": v.ViolationType,
			"severity":       v.Severity,
			"action_taken":   v.ActionTaken,
			"channel":        v.Channel,
			"user_id_src":    v.UserIDSrc,
			"timestamp":      time.Now().UTC().Format(time.RFC3339),
		}
		data, _ := json.Marshal(payload)
		_ = s.producer.Publish(ctx, v.ID.String(), data)
	}
	return v, nil
}

func (s *DLPService) ListViolations(ctx context.Context, tenantID uuid.UUID, f model.ListViolationsFilter) ([]*model.DLPViolation, int, error) {
	viols, total, err := s.repo.ListViolations(ctx, tenantID, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list violations", err)
	}
	return viols, total, nil
}

func (s *DLPService) UpdateViolation(ctx context.Context, tenantID, violID uuid.UUID, req *model.UpdateViolationRequest) (*model.DLPViolation, error) {
	v, err := s.repo.UpdateViolation(ctx, tenantID, violID, req)
	if err != nil {
		return nil, apierrors.Internal("update violation", err)
	}
	if v == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "violation not found")
	}
	return v, nil
}

// ─── Scans ────────────────────────────────────────────────────────────────────

// TriggerScan creates a scan job and runs it asynchronously.
func (s *DLPService) TriggerScan(ctx context.Context, tenantID uuid.UUID, assetID *uuid.UUID, createdBy uuid.UUID) (*model.DLPScan, error) {
	scan, err := s.repo.CreateScan(ctx, tenantID, assetID, createdBy)
	if err != nil {
		return nil, apierrors.Internal("create scan", err)
	}
	s.logger.Info().Str("scan_id", scan.ID.String()).Msg("dlp_scan_queued")
	go s.runScan(tenantID, scan, assetID)
	return scan, nil
}

func (s *DLPService) runScan(tenantID uuid.UUID, scan *model.DLPScan, assetID *uuid.UUID) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error().Interface("panic", r).Str("scan_id", scan.ID.String()).Msg("dlp_scan_panic")
			_ = s.repo.UpdateScanStatus(context.Background(), scan.ID, "failed", 0, 0, []string{}, "internal panic")
		}
	}()

	_ = s.repo.UpdateScanStatus(context.Background(), scan.ID, "running", 0, 0, []string{}, "")

	// Simulate scan: 2-6s
	time.Sleep(time.Duration(2+rand.Intn(5)) * time.Second)

	itemsScanned := int64(1000 + rand.Intn(50000))
	violationsFound := rand.Intn(15)
	labelsDetected := pickLabels()

	// Update asset scan status if specific asset
	if assetID != nil {
		_ = s.repo.UpdateAssetScanStatus(context.Background(), *assetID,
			map[bool]string{true: "violations_found", false: "clean"}[violationsFound > 0],
			violationsFound, labelsDetected)
	}

	// Publish scan result
	payload := map[string]any{
		"event_type":       "dlp.scan_completed",
		"tenant_id":        tenantID.String(),
		"scan_id":          scan.ID.String(),
		"items_scanned":    itemsScanned,
		"violations_found": violationsFound,
		"labels_detected":  labelsDetected,
		"timestamp":        time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(payload)
	_ = s.producer.Publish(context.Background(), scan.ID.String(), data)

	status := "completed"
	_ = s.repo.UpdateScanStatus(context.Background(), scan.ID, status, itemsScanned, violationsFound, labelsDetected, "")
	s.logger.Info().Str("scan_id", scan.ID.String()).Int64("items", itemsScanned).Int("violations", violationsFound).Msg("dlp_scan_completed")
}

func pickLabels() []string {
	all := []string{"PII", "PCI", "CONFIDENTIAL", "BANKING", "SWIFT"}
	n := rand.Intn(3)
	if n == 0 {
		return []string{}
	}
	return all[:n]
}

func (s *DLPService) ListScans(ctx context.Context, tenantID uuid.UUID, assetID *uuid.UUID, page, pageSize int) ([]*model.DLPScan, int, error) {
	scans, total, err := s.repo.ListScans(ctx, tenantID, assetID, page, pageSize)
	if err != nil {
		return nil, 0, apierrors.Internal("list scans", err)
	}
	return scans, total, nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (s *DLPService) Stats(ctx context.Context, tenantID uuid.UUID) (*model.DLPStats, error) {
	stats, err := s.repo.Stats(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("stats", err)
	}
	return stats, nil
}
