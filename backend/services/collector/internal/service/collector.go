package service

import (
	"context"
	"fmt"
	"time"

	"github.com/cyberradar/platform/internal/pkg/event"
	"github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/services/collector/internal/model"
	"github.com/cyberradar/platform/services/collector/internal/normalizer"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// CollectorService handles event ingestion and publishing.
type CollectorService struct {
	producer *kafka.Producer
	logger   zerolog.Logger
}

// NewCollectorService creates a CollectorService.
func NewCollectorService(producer *kafka.Producer, logger zerolog.Logger) *CollectorService {
	return &CollectorService{producer: producer, logger: logger}
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

// Heartbeat logs a connector heartbeat.
func (s *CollectorService) Heartbeat(ctx context.Context, tenantID string, hb *model.ConnectorHeartbeat) error {
	s.logger.Info().
		Str("tenant_id", tenantID).
		Str("connector_id", hb.ConnectorID).
		Str("source", hb.Source).
		Str("source_type", hb.SourceType).
		Int64("events_queued", hb.EventsQueued).
		Str("version", hb.Version).
		Msg("connector_heartbeat")
	return nil
}

func (s *CollectorService) publishDLQ(ctx context.Context, raw string, tenantID string, cause error) {
	dlq := event.DLQMessage{
		OriginalTopic: event.TopicNormalized,
		Payload:       []byte(raw),
		Error:         cause.Error(),
		FailedAt:      time.Now().UTC(),
		TenantID:      tenantID,
	}
	if err := s.producer.Publish(ctx, tenantID, dlq); err != nil {
		s.logger.Error().Err(err).Msg("dlq_publish_failed")
	}
}
