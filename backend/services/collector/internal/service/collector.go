package service

import (
	"context"
	"fmt"
	"time"

	"github.com/cyberradar/platform/internal/pkg/event"
	"github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/services/collector/internal/model"
	"github.com/cyberradar/platform/services/collector/internal/normalizer"
	"github.com/cyberradar/platform/services/collector/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// CollectorService handles event ingestion and publishing.
type CollectorService struct {
	producer *kafka.Producer
	dlq      *kafka.Producer
	health   HealthStore
	logger   zerolog.Logger
}

// HealthStore keeps what the collector learns about its sources.
//
// An interface so a test can assert what was stored, and so a deployment
// without it is a visible refusal rather than a silent no-op — see Heartbeat.
type HealthStore interface {
	RecordHeartbeat(ctx context.Context, tenantID string, hb *model.ConnectorHeartbeat) error
	Sources(ctx context.Context, tenantID string, late, silent time.Duration) ([]repository.SourceHealth, error)
}

// NewCollectorService creates a CollectorService.
//
// The two producers write to different topics and must not be the same one. An
// event that failed to normalize goes to the dead-letter topic; publishing it
// to the normalized topic instead would hand the pipeline worker a DLQMessage
// where it expects a NormalizedEvent, and json.Unmarshal would accept it —
// silently injecting an event with no id, no tenant and no category for every
// malformed line a connector sends.
//
// dlq may be nil, in which case a failure to normalize is logged and dropped
// rather than published anywhere. That is a deliberate option for a deployment
// without a dead-letter topic, not a default: cmd/server passes one.
//
// health may be nil, and then Heartbeat fails loudly instead of accepting a
// liveness report it cannot keep. That is the one behaviour this service must
// not have: it had it, and an agent reporting itself alive was answered
// {"status":"ok"} while nothing anywhere recorded the beat.
func NewCollectorService(producer, dlq *kafka.Producer, health HealthStore, logger zerolog.Logger) *CollectorService {
	return &CollectorService{producer: producer, dlq: dlq, health: health, logger: logger}
}

// Ingest normalizes raw events and publishes them to Kafka.
func (s *CollectorService) Ingest(ctx context.Context, tenantID string, req *model.IngestRequest) (*model.IngestResponse, error) {
	resp := &model.IngestResponse{
		Received: len(req.Events),
	}

	for i, rawStr := range req.Events {
		raw := event.RawEvent{
			ID:          uuid.New(),
			TenantID:    tenantID,
			ConnectorID: req.ConnectorID,
			Source:      req.Source,
			SourceType:  req.SourceType,
			Format:      req.Format,
			ReceivedAt:  time.Now().UTC(),
			Raw:         rawStr,
		}

		norm, err := normalizer.Normalize(raw)
		if err != nil {
			s.logger.Warn().Err(err).
				Int("index", i).
				Str("format", string(req.Format)).
				Str("tenant_id", tenantID).
				Msg("normalization_failed")
			resp.Failed++
			resp.Errors = append(resp.Errors, fmt.Sprintf("event[%d]: %s", i, err.Error()))
			s.publishDLQ(ctx, rawStr, tenantID, err)
			continue
		}

		if err := s.producer.Publish(ctx, tenantID+"/"+norm.EventID.String(), norm); err != nil {
			s.logger.Error().Err(err).
				Str("event_id", norm.EventID.String()).
				Str("tenant_id", tenantID).
				Msg("kafka_publish_failed")
			resp.Failed++
			resp.Errors = append(resp.Errors, fmt.Sprintf("event[%d]: publish error", i))
			continue
		}

		resp.Published++
		s.logger.Debug().
			Str("event_id", norm.EventID.String()).
			Str("tenant_id", tenantID).
			Str("action", norm.Action).
			Str("severity", string(norm.Severity)).
			Msg("event_published")
	}

	return resp, nil
}

// Heartbeat records a connector's liveness report.
//
// It used to write a log line, return nil, and let the handler answer
// {"status":"ok"}. An agent was therefore told its beat had been received
// when nothing had kept it, and the platform could not say which of its
// sources had gone quiet — the question a SOC asks first. Storing the beat is
// the point of the endpoint; without a store there is nothing to report, and
// saying so beats pretending.
func (s *CollectorService) Heartbeat(ctx context.Context, tenantID string, hb *model.ConnectorHeartbeat) error {
	s.logger.Info().
		Str("tenant_id", tenantID).
		Str("connector_id", hb.ConnectorID).
		Str("source", hb.Source).
		Str("source_type", hb.SourceType).
		Int64("events_queued", hb.EventsQueued).
		Str("version", hb.Version).
		Msg("connector_heartbeat")

	if s.health == nil {
		return fmt.Errorf("collector has no health store: the heartbeat cannot be kept")
	}
	return s.health.RecordHeartbeat(ctx, tenantID, hb)
}

func (s *CollectorService) publishDLQ(ctx context.Context, raw string, tenantID string, cause error) {
	if s.dlq == nil {
		s.logger.Warn().
			Str("tenant_id", tenantID).
			Msg("dlq_not_configured_event_dropped")
		return
	}
	dlq := event.DLQMessage{
		OriginalTopic: event.TopicNormalized,
		Payload:       []byte(raw),
		Error:         cause.Error(),
		FailedAt:      time.Now().UTC(),
		TenantID:      tenantID,
	}
	if err := s.dlq.Publish(ctx, tenantID, dlq); err != nil {
		s.logger.Error().Err(err).Msg("dlq_publish_failed")
	}
}

// SourceHealth reports which sources are still talking.
func (s *CollectorService) SourceHealth(ctx context.Context, tenantID string, late, silent time.Duration) ([]repository.SourceHealth, error) {
	if s.health == nil {
		return nil, fmt.Errorf("collector has no health store: source health cannot be read")
	}
	return s.health.Sources(ctx, tenantID, late, silent)
}
