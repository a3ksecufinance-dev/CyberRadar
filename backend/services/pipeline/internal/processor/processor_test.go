package processor

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cyberradar/platform/internal/pkg/event"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/services/pipeline/internal/enricher"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// recordingPublisher keeps what it was given, and fails if told to.
type recordingPublisher struct {
	err  error
	keys []string
	vals []any
}

func (p *recordingPublisher) Publish(_ context.Context, key string, value any) error {
	if p.err != nil {
		return p.err
	}
	p.keys = append(p.keys, key)
	p.vals = append(p.vals, value)
	return nil
}

func normalizedMessage(t *testing.T) pkgkafka.Message {
	t.Helper()
	e := event.NormalizedEvent{
		EventID:       uuid.New(),
		TenantID:      uuid.New().String(),
		Timestamp:     time.Now().UTC(),
		IngestedAt:    time.Now().UTC(),
		Source:        "test",
		SourceType:    "test",
		ConnectorID:   uuid.New().String(),
		Action:        "login",
		Category:      event.CategoryIAM,
		Severity:      event.SeverityLow,
		Outcome:       event.OutcomeSuccess,
		SchemaVersion: 1,
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return pkgkafka.Message{Value: b, Topic: event.TopicNormalized, Partition: 3, Offset: 41}
}

// processorWithoutClickHouse builds a processor whose ClickHouse writer is nil.
// Handle must therefore be called on a path that does not write — which is why
// each test here passes a nil writer only where it does not reach it.
func processorWithoutClickHouse(enriched, alert, dlq Publisher) *Processor {
	return NewProcessor(
		enricher.NewGeoEnricher(),
		enricher.NewThreatEnricher(),
		nil,
		nil,
		enriched, alert, dlq,
		zerolog.Nop(),
		Config{},
	)
}

// A payload that is not an event is not retried — it would fail identically
// forever — so it must be recorded somewhere, with enough of the original to
// be replayed once whatever produced it is fixed.
func TestAnUnreadablePayloadIsDeadLetteredAndNotRetried(t *testing.T) {
	dlq := &recordingPublisher{}
	p := processorWithoutClickHouse(&recordingPublisher{}, &recordingPublisher{}, dlq)

	msg := pkgkafka.Message{Value: []byte("{not json"), Topic: event.TopicNormalized, Partition: 2, Offset: 7}
	if err := p.Handle(context.Background(), msg); err != nil {
		t.Fatalf("a bad payload must not be retried, got error: %v", err)
	}

	if len(dlq.vals) != 1 {
		t.Fatalf("dead-letter queue received %d messages, want 1", len(dlq.vals))
	}
	sent, ok := dlq.vals[0].(event.DLQMessage)
	if !ok {
		t.Fatalf("dead-letter payload is %T, want event.DLQMessage", dlq.vals[0])
	}
	if sent.Partition != 2 || sent.Offset != 7 {
		t.Errorf("dead-letter message points at partition %d offset %d, want 2/7", sent.Partition, sent.Offset)
	}
	if string(sent.Payload) != "{not json" {
		t.Errorf("dead-letter message lost the original payload: %q", sent.Payload)
	}
}

// The enriched topic is what the rule engine reads. An event that fails to
// publish there is an event nothing will ever detect on, so it must not be
// committed in silence.
func TestAFailedEnrichedPublishIsDeadLettered(t *testing.T) {
	dlq := &recordingPublisher{}
	enriched := &recordingPublisher{err: errors.New("broker unreachable")}
	p := processorWithoutClickHouse(enriched, &recordingPublisher{}, dlq)
	p.chWriter = nil

	msg := normalizedMessage(t)
	// With no ClickHouse writer the write step would panic, so the test drives
	// the publish step directly: it is that step's failure handling under test.
	var e event.NormalizedEvent
	if err := json.Unmarshal(msg.Value, &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := p.publishEnriched(context.Background(), msg, &e); err != nil {
		t.Fatalf("publishEnriched returned %v, want nil — the event is already in ClickHouse, retrying would duplicate it", err)
	}

	if len(dlq.vals) != 1 {
		t.Fatalf("dead-letter queue received %d messages, want 1", len(dlq.vals))
	}
	sent := dlq.vals[0].(event.DLQMessage)
	if sent.Offset != 41 || sent.Partition != 3 {
		t.Errorf("dead-letter message points at partition %d offset %d, want 3/41", sent.Partition, sent.Offset)
	}
	if sent.Error == "" {
		t.Error("dead-letter message does not say why the event is there")
	}
}

// The dead-letter queue is the last thing holding the event. When it refuses
// too, the offset must not be committed — a duplicate row on retry is a
// smaller loss than an event nothing anywhere records.
func TestWhenTheDeadLetterQueueAlsoFailsTheOffsetIsNotCommitted(t *testing.T) {
	enriched := &recordingPublisher{err: errors.New("broker unreachable")}
	dlq := &recordingPublisher{err: errors.New("broker unreachable")}
	p := processorWithoutClickHouse(enriched, &recordingPublisher{}, dlq)

	msg := normalizedMessage(t)
	var e event.NormalizedEvent
	if err := json.Unmarshal(msg.Value, &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := p.publishEnriched(context.Background(), msg, &e); err == nil {
		t.Fatal("publishEnriched returned nil although nothing holds the event — the offset would be committed and the event lost")
	}
}

// Same for a payload that cannot be parsed: unreadable is a reason to
// dead-letter it, not a reason to drop it when the dead-letter queue is down.
func TestAnUnreadablePayloadIsNotDroppedWhenTheDeadLetterQueueIsDown(t *testing.T) {
	dlq := &recordingPublisher{err: errors.New("broker unreachable")}
	p := processorWithoutClickHouse(&recordingPublisher{}, &recordingPublisher{}, dlq)

	msg := pkgkafka.Message{Value: []byte("{not json"), Topic: event.TopicNormalized}
	if err := p.Handle(context.Background(), msg); err == nil {
		t.Fatal("Handle returned nil although the payload reached nothing — the offset would be committed and the payload lost")
	}
}

// The ordinary path: the event reaches the enriched topic keyed so that the
// collector's and the pipeline's views of it agree.
func TestASuccessfulEnrichedPublishIsNotDeadLettered(t *testing.T) {
	dlq := &recordingPublisher{}
	enriched := &recordingPublisher{}
	p := processorWithoutClickHouse(enriched, &recordingPublisher{}, dlq)

	msg := normalizedMessage(t)
	var e event.NormalizedEvent
	if err := json.Unmarshal(msg.Value, &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := p.publishEnriched(context.Background(), msg, &e); err != nil {
		t.Fatalf("publishEnriched: %v", err)
	}

	if len(dlq.vals) != 0 {
		t.Fatalf("a successful publish produced %d dead-letter messages", len(dlq.vals))
	}
	if len(enriched.keys) != 1 {
		t.Fatalf("enriched topic received %d messages, want 1", len(enriched.keys))
	}
	if want := e.TenantID + "/" + e.EventID.String(); enriched.keys[0] != want {
		t.Errorf("published under key %q, want %q", enriched.keys[0], want)
	}
}
