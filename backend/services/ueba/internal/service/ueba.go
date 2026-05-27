package service

import (
	"context"
	"time"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/ueba/internal/model"
	"github.com/cyberradar/platform/services/ueba/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// UEBAService exposes behavioral analytics queries.
type UEBAService struct {
	profileRepo  *repository.ProfileRepository
	behaviorRepo *repository.BehaviorRepository
	logger       zerolog.Logger
}

// NewUEBAService creates a UEBAService.
func NewUEBAService(
	profileRepo *repository.ProfileRepository,
	behaviorRepo *repository.BehaviorRepository,
	logger zerolog.Logger,
) *UEBAService {
	return &UEBAService{profileRepo: profileRepo, behaviorRepo: behaviorRepo, logger: logger}
}

// ─── Profiles ─────────────────────────────────────────────────────────────────

func (s *UEBAService) ListProfiles(ctx context.Context, f model.ProfileFilter) ([]*model.EntityProfile, int, error) {
	profiles, total, err := s.profileRepo.ListProfiles(ctx, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list profiles", err)
	}
	return profiles, total, nil
}

func (s *UEBAService) GetProfile(ctx context.Context, tenantID, entityID uuid.UUID) (*model.EntityProfile, error) {
	p, err := s.profileRepo.GetByEntityID(ctx, tenantID, entityID)
	if err != nil {
		return nil, apierrors.Internal("get profile", err)
	}
	if p == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "profile not found")
	}
	return p, nil
}

// ─── Anomalies ────────────────────────────────────────────────────────────────

func (s *UEBAService) ListAnomalies(ctx context.Context, f model.AnomalyFilter) ([]*model.Anomaly, int, error) {
	anomalies, total, err := s.profileRepo.ListAnomalies(ctx, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list anomalies", err)
	}
	return anomalies, total, nil
}

func (s *UEBAService) UpdateAnomaly(ctx context.Context, tenantID, anomalyID uuid.UUID, req *model.UpdateAnomalyRequest) (*model.Anomaly, error) {
	a, err := s.profileRepo.UpdateAnomaly(ctx, tenantID, anomalyID, req)
	if err != nil {
		return nil, apierrors.Internal("update anomaly", err)
	}
	if a == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "anomaly not found")
	}
	return a, nil
}

func (s *UEBAService) GetStats(ctx context.Context, tenantID uuid.UUID) (*model.UEBAStats, error) {
	open, last24h, last7d, highRisk, bySeverity, err := s.profileRepo.AnomalyStats(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("ueba stats", err)
	}

	byType, err := s.behaviorRepo.AnomalyCountByType(ctx, tenantID.String(), 7)
	if err != nil {
		byType = map[string]int{} // non-fatal
	}

	f := model.ProfileFilter{TenantID: tenantID, MinRisk: 7.0, Limit: 10}
	top, _, _ := s.profileRepo.ListProfiles(ctx, f)

	var total int
	if profiles, t, e := s.profileRepo.ListProfiles(ctx, model.ProfileFilter{TenantID: tenantID, Limit: 1}); e == nil {
		_ = profiles
		total = t
	}

	return &model.UEBAStats{
		TotalProfiles:    total,
		HighRiskEntities: highRisk,
		OpenAnomalies:    open,
		AnomaliesLast24h: last24h,
		AnomaliesLast7d:  last7d,
		ByAnomalyType:    byType,
		BySeverity:       bySeverity,
		TopRiskyEntities: top,
	}, nil
}

// ─── Timeline ─────────────────────────────────────────────────────────────────

func (s *UEBAService) GetTimeline(ctx context.Context, tenantID, entityID uuid.UUID, days, limit int) ([]*model.BehaviorEvent, error) {
	from := timeMinusDays(days)
	events, err := s.behaviorRepo.Timeline(ctx, tenantID.String(), entityID.String(), from, limit)
	if err != nil {
		return nil, apierrors.Internal("get timeline", err)
	}
	return events, nil
}

// ─── Peer groups ──────────────────────────────────────────────────────────────

func (s *UEBAService) ListPeerGroups(ctx context.Context, tenantID uuid.UUID) ([]*model.PeerGroup, error) {
	groups, err := s.profileRepo.ListPeerGroups(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("list peer groups", err)
	}
	return groups, nil
}

func timeMinusDays(days int) time.Time {
	if days <= 0 {
		days = 7
	}
	return time.Now().UTC().AddDate(0, 0, -days)
}

func (s *UEBAService) CreatePeerGroup(ctx context.Context, tenantID uuid.UUID, req *model.CreatePeerGroupRequest) (*model.PeerGroup, error) {
	pg, err := s.profileRepo.CreatePeerGroup(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("create peer group", err)
	}
	s.logger.Info().Str("peer_group_id", pg.ID.String()).Str("name", pg.Name).Msg("peer_group_created")
	return pg, nil
}
