package processor

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cyberradar/platform/internal/pkg/event"
	"github.com/cyberradar/platform/internal/pkg/iocindex"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/services/pipeline/internal/enricher"
	"github.com/cyberradar/platform/services/pipeline/internal/writer"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// IOCMatcher answers which known indicators an event touches.
//
// An interface so the processor can be tested without a database, and so a
// deployment that has not been given one is a deliberate, visible choice
// rather than a silent nil.
type IOCMatcher interface {
	Match(tenantID uuid.UUID, ev *event.NormalizedEvent) []iocindex.Hit
}

// Processor consumes normalized events, enriches them, and writes to ClickHouse.
type Processor struct {
	geo           *enricher.GeoEnricher
	threat        *enricher.ThreatEnricher
	iocs          IOCMatcher
	chWriter      *writer.ClickHouseWriter
	enrichedPub   *pkgkafka.Producer // publishes to crp.events.enriched
	alertPub      *pkgkafka.Producer // publishes to crp.events.alerts
	dlqPub        *pkgkafka.Producer // publishes to crp.events.dlq
	logger        zerolog.Logger
	flushInterval time.Duration
}

// Config holds Processor configuration.
type Config struct {
	FlushInterval time.Duration // how often to force-flush ClickHouse buffer
}

// NewProcessor creates a Processor.
func NewProcessor(
	geo *enricher.GeoEnricher,
	threat *enricher.ThreatEnricher,
	iocs IOCMatcher,
	chWriter *writer.ClickHouseWriter,
	enrichedPub *pkgkafka.Producer,
	alertPub *pkgkafka.Producer,
	dlqPub *pkgkafka.Producer,
	logger zerolog.Logger,
	cfg Config,
) *Processor {
	fi := cfg.FlushInterval
	if fi <= 0 {
		fi = 5 * time.Second
	}
	return &Processor{
		geo:           geo,
		threat:        threat,
		iocs:          iocs,
		chWriter:      chWriter,
		enrichedPub:   enrichedPub,
		alertPub:      alertPub,
		dlqPub:        dlqPub,
		logger:        logger,
		flushInterval: fi,
	}
}

// Handle processes a single Kafka message from crp.events.normalized.
func (p *Processor) Handle(ctx context.Context, msg pkgkafka.Message) error {
	var e event.NormalizedEvent
	if err := json.Unmarshal(msg.Value, &e); err != nil {
		p.sendDLQ(ctx, msg, fmt.Sprintf("unmarshal: %s", err.Error()))
		return nil // don't retry on bad payload
	}

	// ── Geo enrichment ───────────────────────────────────────────────────────
	if e.IPSource != nil {
		geo := p.geo.Lookup(*e.IPSource)
		if geo.Country != "" {
			e.GeoCountry = &geo.Country
		}
		if geo.ASN != "" {
			e.GeoASN = &geo.ASN
		}
	}

	// ── Indicator matching ───────────────────────────────────────────────────
	// Before the rule engine, not beside it. The threat intelligence service
	// also matches indicators, from its own consumer of the enriched topic —
	// but it runs alongside the rule engine, so a match it found could never
	// influence a detection. This is the same question asked early enough to
	// matter.
	var hits []iocindex.Hit
	if p.iocs != nil {
		if tenantID, err := uuid.Parse(e.TenantID); err == nil {
			hits = p.iocs.Match(tenantID, &e)
		}
	}

	// ── Threat enrichment ────────────────────────────────────────────────────
	threat := p.threat.Enrich(&e, hits)
	e.ThreatScore = threat.ThreatScore
	e.RiskScore = threat.RiskScore
	e.IOCMatched = threat.IOCMatched
	if threat.MitreTactic != "" {
		e.MitreTactic = &threat.MitreTactic
	}
	if threat.MitreTechnique != "" {
		e.MitreTechnique = &threat.MitreTechnique
	}

	// ── Write to ClickHouse ──────────────────────────────────────────────────
	if err := p.chWriter.Write(ctx, &e); err != nil {
		p.logger.Error().Err(err).
			Str("event_id", e.EventID.String()).
			Msg("clickhouse_write_error")
		// Don't DLQ on CH failure — will retry on next batch
		return err
	}

	// ── Publish enriched event ───────────────────────────────────────────────
	if err := p.enrichedPub.Publish(ctx, e.TenantID+"/"+e.EventID.String(), &e); err != nil {
		p.logger.Error().Err(err).Str("event_id", e.EventID.String()).Msg("enriched_pub_failed")
	}

	// ── Alert routing for high-risk events ──────────────────────────────────
	if e.IsHighRisk() {
		if err := p.alertPub.Publish(ctx, e.TenantID, &e); err != nil {
			p.logger.Error().Err(err).Str("event_id", e.EventID.String()).Msg("alert_pub_failed")
		}
		p.logger.Warn().
			Str("event_id", e.EventID.String()).
			Str("tenant_id", e.TenantID).
			Str("severity", string(e.Severity)).
			Float32("risk_score", e.RiskScore).
			Msg("high_risk_event_alerted")
	}

	return nil
}

// RunFlushLoop periodically flushes the ClickHouse buffer regardless of batch size.
// Run in a separate goroutine alongside the Kafka consumer.
func (p *Processor) RunFlushLoop(ctx context.Context) {
	ticker := time.NewTicker(p.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Final flush on shutdown
			flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = p.chWriter.Flush(flushCtx)
			cancel()
			return
		case <-ticker.C:
			if err := p.chWriter.Flush(ctx); err != nil {
				p.logger.Error().Err(err).Msg("periodic_flush_error")
			}
		}
	}
}

func (p *Processor) sendDLQ(ctx context.Context, msg pkgkafka.Message, reason string) {
	dlq := event.DLQMessage{
		OriginalTopic: event.TopicNormalized,
		Offset:        msg.Offset,
		Partition:     msg.Partition,
		Payload:       msg.Value,
		Error:         reason,
		FailedAt:      time.Now().UTC(),
	}
	if err := p.dlqPub.Publish(ctx, "", dlq); err != nil {
		p.logger.Error().Err(err).Msg("dlq_publish_failed")
	}
}
