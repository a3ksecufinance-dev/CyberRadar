package service

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/cyberradar/platform/internal/pkg/event"
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

	type candidate struct {
		iocType string
		value   string
		field   string
	}

	var candidates []candidate

	if ev.IPSource != nil && *ev.IPSource != "" {
		candidates = append(candidates, candidate{model.IOCTypeIP, *ev.IPSource, "ip_source"})
	}
	if ev.IPDestination != nil && *ev.IPDestination != "" {
		candidates = append(candidates, candidate{model.IOCTypeIP, *ev.IPDestination, "ip_destination"})
	}
	if ev.UserName != nil && strings.Contains(*ev.UserName, "@") {
		candidates = append(candidates, candidate{model.IOCTypeEmail, *ev.UserName, "user_name"})
	}
	// Hash fields from RawEvent metadata (best-effort extraction)
	if ev.RawEvent != "" {
		var rawMap map[string]any
		if json.Unmarshal([]byte(ev.RawEvent), &rawMap) == nil {
			if h, ok := rawMap["file_hash_sha256"].(string); ok && h != "" {
				candidates = append(candidates, candidate{model.IOCTypeHashSHA256, h, "file_hash_sha256"})
			}
			if h, ok := rawMap["file_hash_md5"].(string); ok && h != "" {
				candidates = append(candidates, candidate{model.IOCTypeHashMD5, h, "file_hash_md5"})
			}
			if d, ok := rawMap["domain"].(string); ok && d != "" {
				candidates = append(candidates, candidate{model.IOCTypeDomain, d, "domain"})
			}
			if u, ok := rawMap["url"].(string); ok && u != "" {
				candidates = append(candidates, candidate{model.IOCTypeURL, u, "url"})
			}
		}
	}

	for _, c := range candidates {
		ioc, err := m.iocRepo.Lookup(ctx, tid, c.iocType, c.value)
		if err != nil || ioc == nil {
			continue
		}

		hit := &model.IOCHit{
			ID:           uuid.New(),
			TenantID:     tid,
			IOCID:        ioc.ID,
			MatchedValue: c.value,
			MatchedField: c.field,
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
			Str("value", c.value).
			Str("field", c.field).
			Str("severity", ioc.Severity).
			Str("tenant_id", ev.TenantID).
			Bool("auto_blocked", hit.AutoBlocked).
			Msg("ioc_matched")
	}

	return nil
}
