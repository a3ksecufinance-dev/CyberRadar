package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/cyberradar/platform/internal/pkg/event"
	"github.com/cyberradar/platform/internal/pkg/iocindex"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/services/ti/internal/model"
	"github.com/cyberradar/platform/services/ti/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// IOCMatcher consumes crp.events.enriched and matches each event against active IOCs.
type IOCMatcher struct {
	iocRepo   *repository.IOCRepository
	consumer  *pkgkafka.Consumer
	publisher *pkgkafka.Producer // publishes IOC hits to crp.events.ti
	logger    zerolog.Logger
}

// NewIOCMatcher creates an IOCMatcher.
func NewIOCMatcher(
	iocRepo *repository.IOCRepository,
	consumer *pkgkafka.Consumer,
	publisher *pkgkafka.Producer,
	logger zerolog.Logger,
) *IOCMatcher {
	return &IOCMatcher{
		iocRepo:   iocRepo,
		consumer:  consumer,
		publisher: publisher,
		logger:    logger,
	}
}

// Run starts the Kafka consumer. Blocks until ctx is cancelled.
func (m *IOCMatcher) Run(ctx context.Context) error {
	m.logger.Info().Msg("ioc_matcher_started")
	return m.consumer.Run(ctx, m.handle)
}

// handle checks all extractable IOC fields of one enriched event.
func (m *IOCMatcher) handle(ctx context.Context, msg pkgkafka.Message) error {
	var ev event.NormalizedEvent
	if err := json.Unmarshal(msg.Value, &ev); err != nil {
		return nil
	}

	tid, err := uuid.Parse(ev.TenantID)
	if err != nil {
		return nil
	}

	// The candidate fields come from internal/pkg/iocindex, which the ingest
	// path also uses. There were two extractions and they disagreed — one read
	// user_name, the other would have read user_email — so which indicators
	// could ever match depended on which component was asked.
	candidates := iocindex.Candidates(&ev)

	for _, c := range candidates {
		// Looked up rather than trusted: this writes a record, and a recorded
		// hit must rest on the database's own answer, not on a field an
		// upstream component set.
		ioc, err := m.iocRepo.Lookup(ctx, tid, c.Type, c.Value)
		if err != nil || ioc == nil {
			continue
		}

		hit := &model.IOCHit{
			ID:           uuid.New(),
			TenantID:     tid,
			IOCID:        ioc.ID,
			MatchedValue: c.Value,
			MatchedField: c.Field,
			Severity:     ioc.Severity,
			AutoBlocked:  ioc.Severity == "CRITICAL",
			HitAt:        time.Now().UTC(),
		}
		srcID := ev.EventID
		hit.SourceEventID = &srcID

		if err := m.iocRepo.RecordHit(ctx, tid, ioc.ID, hit); err != nil {
			m.logger.Error().Err(err).Str("ioc_id", ioc.ID.String()).Msg("record_hit_error")
			continue
		}

		// Publish IOC hit for downstream SIEM/SOAR consumption
		_ = m.publisher.Publish(ctx, ev.TenantID, hit)

		m.logger.Warn().
			Str("ioc_id", ioc.ID.String()).
			Str("ioc_type", ioc.IOCType).
			Str("value", c.Value).
			Str("field", c.Field).
			Str("severity", ioc.Severity).
			Str("tenant_id", ev.TenantID).
			Bool("auto_blocked", hit.AutoBlocked).
			Msg("ioc_matched")
	}

	return nil
}
