package service

import (
	"context"
	"encoding/json"
	"math/rand"
	"time"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/services/easm/internal/model"
	"github.com/cyberradar/platform/services/easm/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// EASMService orchestrates external attack surface management.
type EASMService struct {
	repo     *repository.EASMRepository
	producer *pkgkafka.Producer
	logger   zerolog.Logger
}

// NewEASMService creates an EASMService.
func NewEASMService(repo *repository.EASMRepository, producer *pkgkafka.Producer, logger zerolog.Logger) *EASMService {
	return &EASMService{repo: repo, producer: producer, logger: logger}
}

// ─── Assets ───────────────────────────────────────────────────────────────────

func (s *EASMService) CreateAsset(ctx context.Context, tenantID uuid.UUID, req *model.CreateAssetRequest) (*model.EASMAsset, error) {
	a, err := s.repo.CreateAsset(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("create asset", err)
	}
	s.logger.Info().Str("asset_id", a.ID.String()).Str("type", a.AssetType).Str("value", a.Value).Msg("easm_asset_upserted")
	return a, nil
}

func (s *EASMService) GetAsset(ctx context.Context, tenantID, assetID uuid.UUID) (*model.EASMAsset, error) {
	a, err := s.repo.GetAsset(ctx, tenantID, assetID)
	if err != nil {
		return nil, apierrors.Internal("get asset", err)
	}
	if a == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "asset not found")
	}
	return a, nil
}

func (s *EASMService) ListAssets(ctx context.Context, tenantID uuid.UUID, f model.ListAssetsFilter) ([]*model.EASMAsset, int, error) {
	assets, total, err := s.repo.ListAssets(ctx, tenantID, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list assets", err)
	}
	return assets, total, nil
}

func (s *EASMService) UpdateAsset(ctx context.Context, tenantID, assetID uuid.UUID, req *model.UpdateAssetRequest) (*model.EASMAsset, error) {
	a, err := s.repo.UpdateAsset(ctx, tenantID, assetID, req)
	if err != nil {
		return nil, apierrors.Internal("update asset", err)
	}
	if a == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "asset not found")
	}
	return a, nil
}

func (s *EASMService) DeleteAsset(ctx context.Context, tenantID, assetID uuid.UUID) error {
	if err := s.repo.DeleteAsset(ctx, tenantID, assetID); err != nil {
		return apierrors.Internal("delete asset", err)
	}
	return nil
}

// ─── Exposures ────────────────────────────────────────────────────────────────

func (s *EASMService) CreateExposure(ctx context.Context, tenantID uuid.UUID, req *model.CreateExposureRequest) (*model.EASMExposure, error) {
	e, err := s.repo.CreateExposure(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("create exposure", err)
	}
	s.logger.Info().Str("exposure_id", e.ID.String()).Str("severity", e.Severity).Msg("easm_exposure_created")
	return e, nil
}

func (s *EASMService) ListExposures(ctx context.Context, tenantID uuid.UUID, assetID *uuid.UUID, severity string, remediated *bool, page, pageSize int) ([]*model.EASMExposure, int, error) {
	exposures, total, err := s.repo.ListExposures(ctx, tenantID, assetID, severity, remediated, page, pageSize)
	if err != nil {
		return nil, 0, apierrors.Internal("list exposures", err)
	}
	return exposures, total, nil
}

func (s *EASMService) RemediateExposure(ctx context.Context, tenantID, exposureID uuid.UUID) (*model.EASMExposure, error) {
	e, err := s.repo.RemediateExposure(ctx, tenantID, exposureID)
	if err != nil {
		return nil, apierrors.Internal("remediate exposure", err)
	}
	if e == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "exposure not found")
	}
	return e, nil
}

// ─── Leaks ────────────────────────────────────────────────────────────────────

func (s *EASMService) CreateLeak(ctx context.Context, tenantID uuid.UUID, req *model.CreateLeakRequest) (*model.EASMLeak, error) {
	l, err := s.repo.CreateLeak(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("create leak", err)
	}
	s.logger.Warn().Str("leak_id", l.ID.String()).Str("severity", l.Severity).Str("source", l.Source).Msg("easm_leak_created")
	return l, nil
}

func (s *EASMService) ListLeaks(ctx context.Context, tenantID uuid.UUID, acknowledged *bool, severity string, page, pageSize int) ([]*model.EASMLeak, int, error) {
	leaks, total, err := s.repo.ListLeaks(ctx, tenantID, acknowledged, severity, page, pageSize)
	if err != nil {
		return nil, 0, apierrors.Internal("list leaks", err)
	}
	return leaks, total, nil
}

func (s *EASMService) AcknowledgeLeak(ctx context.Context, tenantID, leakID, userID uuid.UUID) (*model.EASMLeak, error) {
	l, err := s.repo.AcknowledgeLeak(ctx, tenantID, leakID, userID)
	if err != nil {
		return nil, apierrors.Internal("acknowledge leak", err)
	}
	if l == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "leak not found")
	}
	return l, nil
}

// ─── Brand alerts ─────────────────────────────────────────────────────────────

func (s *EASMService) CreateBrandAlert(ctx context.Context, tenantID uuid.UUID, req *model.CreateBrandAlertRequest) (*model.EASMBrandAlert, error) {
	a, err := s.repo.CreateBrandAlert(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("create brand alert", err)
	}
	s.logger.Warn().Str("alert_id", a.ID.String()).Str("type", a.AlertType).Str("value", a.Value).Msg("easm_brand_alert_created")
	return a, nil
}

func (s *EASMService) ListBrandAlerts(ctx context.Context, tenantID uuid.UUID, alertType, status string, page, pageSize int) ([]*model.EASMBrandAlert, int, error) {
	alerts, total, err := s.repo.ListBrandAlerts(ctx, tenantID, alertType, status, page, pageSize)
	if err != nil {
		return nil, 0, apierrors.Internal("list brand alerts", err)
	}
	return alerts, total, nil
}

func (s *EASMService) UpdateBrandAlert(ctx context.Context, tenantID, alertID uuid.UUID, status string) (*model.EASMBrandAlert, error) {
	a, err := s.repo.UpdateBrandAlert(ctx, tenantID, alertID, status)
	if err != nil {
		return nil, apierrors.Internal("update brand alert", err)
	}
	if a == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "brand alert not found")
	}
	return a, nil
}

// ─── Scans ────────────────────────────────────────────────────────────────────

func (s *EASMService) CreateScan(ctx context.Context, tenantID uuid.UUID, req *model.CreateScanRequest, createdBy uuid.UUID) (*model.EASMScan, error) {
	scan, err := s.repo.CreateScan(ctx, tenantID, req, createdBy)
	if err != nil {
		return nil, apierrors.Internal("create scan", err)
	}
	s.logger.Info().Str("scan_id", scan.ID.String()).Str("type", scan.ScanType).Msg("easm_scan_queued")

	go s.simulateScan(tenantID, scan)
	return scan, nil
}

func (s *EASMService) simulateScan(tenantID uuid.UUID, scan *model.EASMScan) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error().Interface("panic", r).Str("scan_id", scan.ID.String()).Msg("easm_scan_panic")
			_ = s.repo.UpdateScanStatus(context.Background(), scan.ID, "failed", 0, 0, "internal panic")
		}
	}()

	// Mark as running
	_ = s.repo.UpdateScanStatus(context.Background(), scan.ID, "running", 0, 0, "")

	// Simulate scan duration (2–5s)
	delay := time.Duration(2+rand.Intn(4)) * time.Second
	time.Sleep(delay)

	assetsFound := 3 + rand.Intn(13)    // 3–15
	exposuresFound := 1 + rand.Intn(8)  // 1–8

	// Publish Kafka event
	payload := map[string]any{
		"event_type":      "easm.scan_completed",
		"tenant_id":       tenantID.String(),
		"scan_id":         scan.ID.String(),
		"scan_type":       scan.ScanType,
		"assets_found":    assetsFound,
		"exposures_found": exposuresFound,
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(payload)
	_ = s.producer.Publish(context.Background(), scan.ID.String(), data)

	_ = s.repo.UpdateScanStatus(context.Background(), scan.ID, "completed", assetsFound, exposuresFound, "")
	s.logger.Info().Str("scan_id", scan.ID.String()).Int("assets", assetsFound).Int("exposures", exposuresFound).Msg("easm_scan_completed")
}

func (s *EASMService) GetScan(ctx context.Context, tenantID, scanID uuid.UUID) (*model.EASMScan, error) {
	sc, err := s.repo.GetScan(ctx, tenantID, scanID)
	if err != nil {
		return nil, apierrors.Internal("get scan", err)
	}
	if sc == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "scan not found")
	}
	return sc, nil
}

func (s *EASMService) ListScans(ctx context.Context, tenantID string, page, pageSize int) ([]*model.EASMScan, int, error) {
	scans, total, err := s.repo.ListScans(ctx, tenantID, page, pageSize)
	if err != nil {
		return nil, 0, apierrors.Internal("list scans", err)
	}
	return scans, total, nil
}

// ─── Risk & stats ─────────────────────────────────────────────────────────────

func (s *EASMService) ExternalRiskScore(ctx context.Context, tenantID uuid.UUID) (*model.ExternalRiskScore, error) {
	score, err := s.repo.ComputeRiskScore(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("compute risk score", err)
	}
	return score, nil
}

func (s *EASMService) Stats(ctx context.Context, tenantID uuid.UUID) (*model.EASMStats, error) {
	stats, err := s.repo.Stats(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("stats", err)
	}
	return stats, nil
}
