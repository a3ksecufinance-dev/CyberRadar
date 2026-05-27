package service

import (
	"context"
	"fmt"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/asset/internal/model"
	"github.com/cyberradar/platform/services/asset/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// AssetService handles asset business logic.
type AssetService struct {
	repo   *repository.AssetRepository
	logger zerolog.Logger
}

// NewAssetService creates an AssetService.
func NewAssetService(repo *repository.AssetRepository, logger zerolog.Logger) *AssetService {
	return &AssetService{repo: repo, logger: logger}
}

// Create registers a new asset.
func (s *AssetService) Create(ctx context.Context, tenantID uuid.UUID, req *model.CreateAssetRequest) (*model.Asset, error) {
	a, err := s.repo.Create(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("create asset", err)
	}

	// Compute initial risk score
	score, _ := ScoreAsset(a)
	if updateErr := s.repo.UpdateRiskScore(ctx, tenantID, a.ID, score); updateErr != nil {
		s.logger.Warn().Err(updateErr).Str("asset_id", a.ID.String()).Msg("risk_score_update_failed")
	}
	a.RiskScore = score

	s.logger.Info().
		Str("asset_id", a.ID.String()).
		Str("tenant_id", tenantID.String()).
		Str("type", string(a.AssetType)).
		Msg("asset_created")

	return a, nil
}

// GetByID returns a single asset, enforcing tenant isolation.
func (s *AssetService) GetByID(ctx context.Context, tenantID, assetID uuid.UUID) (*model.Asset, error) {
	a, err := s.repo.GetByID(ctx, tenantID, assetID)
	if err != nil {
		return nil, apierrors.Internal("get asset", err)
	}
	if a == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "asset not found")
	}
	return a, nil
}

// List returns a paginated, filtered list of assets.
func (s *AssetService) List(ctx context.Context, f model.AssetFilter) (*model.AssetList, error) {
	result, err := s.repo.List(ctx, f)
	if err != nil {
		return nil, apierrors.Internal("list assets", err)
	}
	return result, nil
}

// Update applies a partial update to an asset and recomputes risk score.
func (s *AssetService) Update(ctx context.Context, tenantID, assetID uuid.UUID, req *model.UpdateAssetRequest) (*model.Asset, error) {
	existing, err := s.GetByID(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	_ = existing

	a, err := s.repo.Update(ctx, tenantID, assetID, req)
	if err != nil {
		return nil, apierrors.Internal("update asset", err)
	}
	if a == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "asset not found")
	}

	score, _ := ScoreAsset(a)
	_ = s.repo.UpdateRiskScore(ctx, tenantID, a.ID, score)
	a.RiskScore = score

	return a, nil
}

// Delete soft-deletes an asset.
func (s *AssetService) Delete(ctx context.Context, tenantID, assetID uuid.UUID) error {
	if err := s.repo.SoftDelete(ctx, tenantID, assetID); err != nil {
		return apierrors.Wrap(apierrors.KindNotFound, "asset not found", err)
	}
	s.logger.Info().
		Str("asset_id", assetID.String()).
		Str("tenant_id", tenantID.String()).
		Msg("asset_deleted")
	return nil
}

// RiskBreakdown returns a detailed risk explanation for an asset.
func (s *AssetService) RiskBreakdown(ctx context.Context, tenantID, assetID uuid.UUID) (*model.RiskBreakdown, error) {
	a, err := s.GetByID(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	_, rb := ScoreAsset(a)
	return rb, nil
}

// Stats returns aggregated statistics for the tenant.
func (s *AssetService) Stats(ctx context.Context, tenantID uuid.UUID) (*model.AssetStats, error) {
	stats, err := s.repo.Stats(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("asset stats", err)
	}
	return stats, nil
}

// AddRelationship links two assets.
func (s *AssetService) AddRelationship(ctx context.Context, tenantID, sourceID uuid.UUID, req *model.CreateRelationshipRequest) (*model.AssetRelationship, error) {
	// Ensure both assets belong to the tenant
	if _, err := s.GetByID(ctx, tenantID, sourceID); err != nil {
		return nil, err
	}
	if _, err := s.GetByID(ctx, tenantID, req.TargetID); err != nil {
		return nil, fmt.Errorf("target asset: %w", err)
	}

	rel, err := s.repo.CreateRelationship(ctx, tenantID, sourceID, req)
	if err != nil {
		return nil, apierrors.Internal("create relationship", err)
	}
	return rel, nil
}

// GetRelationships returns all edges for an asset.
func (s *AssetService) GetRelationships(ctx context.Context, tenantID, assetID uuid.UUID) ([]*model.AssetRelationship, error) {
	if _, err := s.GetByID(ctx, tenantID, assetID); err != nil {
		return nil, err
	}
	rels, err := s.repo.GetRelationships(ctx, tenantID, assetID)
	if err != nil {
		return nil, apierrors.Internal("get relationships", err)
	}
	return rels, nil
}

// ListDiscoveryCandidates returns unresolved auto-discovery candidates.
func (s *AssetService) ListDiscoveryCandidates(ctx context.Context, tenantID uuid.UUID) ([]*model.DiscoveryCandidate, error) {
	candidates, err := s.repo.ListDiscoveryCandidates(ctx, tenantID, 200)
	if err != nil {
		return nil, apierrors.Internal("list discovery candidates", err)
	}
	return candidates, nil
}

// TouchLastSeen updates the last_seen_at timestamp for assets matching an IP.
func (s *AssetService) TouchLastSeen(ctx context.Context, tenantID uuid.UUID, ip string) {
	if err := s.repo.UpdateLastSeen(ctx, tenantID, ip); err != nil {
		s.logger.Debug().Err(err).Str("ip", ip).Msg("last_seen_update_failed")
	}
}

// UpsertDiscoveryCandidate records a new auto-detected host.
func (s *AssetService) UpsertDiscoveryCandidate(ctx context.Context, tenantID uuid.UUID, ip, hostname, sourceType, connectorID string) {
	if err := s.repo.UpsertDiscoveryCandidate(ctx, tenantID, ip, hostname, sourceType, connectorID); err != nil {
		s.logger.Warn().Err(err).Str("ip", ip).Msg("discovery_upsert_failed")
	}
}
