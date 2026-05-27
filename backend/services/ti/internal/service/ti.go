package service

import (
	"context"
	"time"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/ti/internal/model"
	"github.com/cyberradar/platform/services/ti/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// TIService orchestrates threat intelligence feeds, IOCs, and actors.
type TIService struct {
	iocRepo *repository.IOCRepository
	logger  zerolog.Logger
}

// NewTIService creates a TIService.
func NewTIService(iocRepo *repository.IOCRepository, logger zerolog.Logger) *TIService {
	return &TIService{iocRepo: iocRepo, logger: logger}
}

// ─── Feeds ────────────────────────────────────────────────────────────────────

func (s *TIService) CreateFeed(ctx context.Context, tenantID uuid.UUID, req *model.CreateFeedRequest) (*model.Feed, error) {
	f, err := s.iocRepo.CreateFeed(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("create feed", err)
	}
	s.logger.Info().Str("feed_id", f.ID.String()).Str("name", f.Name).Str("type", f.FeedType).Msg("ti_feed_created")
	return f, nil
}

func (s *TIService) GetFeed(ctx context.Context, tenantID, feedID uuid.UUID) (*model.Feed, error) {
	f, err := s.iocRepo.GetFeed(ctx, tenantID, feedID)
	if err != nil {
		return nil, apierrors.Internal("get feed", err)
	}
	if f == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "feed not found")
	}
	return f, nil
}

func (s *TIService) ListFeeds(ctx context.Context, tenantID uuid.UUID) ([]*model.Feed, error) {
	feeds, err := s.iocRepo.ListFeeds(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("list feeds", err)
	}
	return feeds, nil
}

func (s *TIService) UpdateFeed(ctx context.Context, tenantID, feedID uuid.UUID, req *model.UpdateFeedRequest) (*model.Feed, error) {
	f, err := s.iocRepo.UpdateFeed(ctx, tenantID, feedID, req)
	if err != nil {
		return nil, apierrors.Internal("update feed", err)
	}
	if f == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "feed not found")
	}
	return f, nil
}

func (s *TIService) DeleteFeed(ctx context.Context, tenantID, feedID uuid.UUID) error {
	if err := s.iocRepo.DeleteFeed(ctx, tenantID, feedID); err != nil {
		return apierrors.Wrap(apierrors.KindNotFound, "feed not found", err)
	}
	return nil
}

// ─── IOCs ─────────────────────────────────────────────────────────────────────

func (s *TIService) CreateIOC(ctx context.Context, tenantID uuid.UUID, req *model.CreateIOCRequest) (*model.IOC, error) {
	ioc, err := s.iocRepo.UpsertIOC(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("create ioc", err)
	}
	return ioc, nil
}

func (s *TIService) BulkCreateIOCs(ctx context.Context, tenantID uuid.UUID, req *model.BulkCreateIOCRequest) (int, error) {
	count := 0
	for i := range req.IOCs {
		item := &req.IOCs[i]
		if req.FeedID != nil && item.FeedID == nil {
			item.FeedID = req.FeedID
		}
		if _, err := s.iocRepo.UpsertIOC(ctx, tenantID, item); err != nil {
			s.logger.Error().Err(err).Str("value", item.Value).Msg("bulk_ioc_error")
			continue
		}
		count++
	}
	return count, nil
}

func (s *TIService) ListIOCs(ctx context.Context, f model.IOCFilter) ([]*model.IOC, int, error) {
	iocs, total, err := s.iocRepo.ListIOCs(ctx, f)
	if err != nil {
		return nil, 0, apierrors.Internal("list iocs", err)
	}
	return iocs, total, nil
}

// Lookup performs a single IOC type+value lookup and records the hit.
func (s *TIService) Lookup(ctx context.Context, tenantID uuid.UUID, req *model.LookupRequest) (*model.MatchResult, error) {
	ioc, err := s.iocRepo.Lookup(ctx, tenantID, req.Type, req.Value)
	if err != nil {
		return nil, apierrors.Internal("lookup ioc", err)
	}
	if ioc == nil {
		return &model.MatchResult{Matched: false}, nil
	}

	hit := &model.IOCHit{
		ID:           uuid.New(),
		TenantID:     tenantID,
		IOCID:        ioc.ID,
		MatchedValue: req.Value,
		MatchedField: req.Type,
		Severity:     ioc.Severity,
		AutoBlocked:  ioc.Severity == "CRITICAL",
		HitAt:        time.Now().UTC(),
	}
	_ = s.iocRepo.RecordHit(ctx, tenantID, ioc.ID, hit)

	return &model.MatchResult{
		Matched: true,
		IOC:     ioc,
		HitID:   hit.ID.String(),
	}, nil
}

// ListHits returns recent IOC hit records for a tenant.
func (s *TIService) ListHits(ctx context.Context, tenantID uuid.UUID, limit int) ([]*model.IOCHit, error) {
	hits, err := s.iocRepo.ListHits(ctx, tenantID, limit)
	if err != nil {
		return nil, apierrors.Internal("list hits", err)
	}
	return hits, nil
}

// ExpireIOCs deactivates IOCs past their valid_until date. Run via cron/ticker.
func (s *TIService) ExpireIOCs(ctx context.Context) error {
	n, err := s.iocRepo.DeactivateExpired(ctx)
	if err != nil {
		return apierrors.Internal("expire iocs", err)
	}
	if n > 0 {
		s.logger.Info().Int64("count", n).Msg("iocs_expired")
	}
	return nil
}

// ─── Threat Actors ────────────────────────────────────────────────────────────

func (s *TIService) CreateThreatActor(ctx context.Context, tenantID uuid.UUID, req *model.CreateThreatActorRequest) (*model.ThreatActor, error) {
	ta, err := s.iocRepo.CreateThreatActor(ctx, tenantID, req)
	if err != nil {
		return nil, apierrors.Internal("create threat actor", err)
	}
	s.logger.Info().Str("actor_id", ta.ID.String()).Str("name", ta.Name).Msg("threat_actor_created")
	return ta, nil
}

func (s *TIService) ListThreatActors(ctx context.Context, tenantID uuid.UUID, bankingOnly bool) ([]*model.ThreatActor, error) {
	actors, err := s.iocRepo.ListThreatActors(ctx, tenantID, bankingOnly)
	if err != nil {
		return nil, apierrors.Internal("list threat actors", err)
	}
	return actors, nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (s *TIService) GetStats(ctx context.Context, tenantID uuid.UUID) (*model.TIStats, error) {
	stats, err := s.iocRepo.Stats(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("ti stats", err)
	}
	return stats, nil
}
