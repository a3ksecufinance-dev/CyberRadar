package service

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	segkafka "github.com/segmentio/kafka-go"

	"github.com/cyberradar/platform/internal/pkg/event"
	"github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/internal/pkg/testinfra"
	"github.com/cyberradar/platform/services/collector/internal/model"
)

// The ingestion path, end to end: a batch of raw lines in, normalized events on
// one topic and dead letters on another.
//
// This runs against a real broker because the property worth proving is where
// the messages land. A test with a fake producer would have passed while the
// service published its dead letters onto the normalized topic — which is what
// it did until this suite was written: cmd/server built a DLQ producer and the
// service never received it, so every malformed line was published as a
// DLQMessage into crp.events.normalized, where the pipeline worker reads
// NormalizedEvents. json.Unmarshal accepts it, so each malformed line became an
// event with no id, no tenant and no category.

const tenant = "33333333-3333-3333-3333-333333333333"

func quiet() zerolog.Logger { return zerolog.New(io.Discard) }

// ingestion is a service wired to two topics of its own, plus readers for each.
type ingestion struct {
	svc      *CollectorService
	events   *segkafka.Reader
	dead     *segkafka.Reader
	topic    string
	dlqTopic string
}

func newIngestion(t *testing.T) *ingestion {
	t.Helper()
	f := testinfra.Kafka(t)
	dlqTopic := f.NewTopic("dlq")

	producer := kafka.NewProducer(kafka.ProducerConfig{
		Brokers: f.Brokers, Topic: f.Topic,
	}, quiet())
	t.Cleanup(func() { _ = producer.Close() })

	dlqProducer := kafka.NewProducer(kafka.ProducerConfig{
		Brokers: f.Brokers, Topic: dlqTopic,
	}, quiet())
	t.Cleanup(func() { _ = dlqProducer.Close() })

	reader := func(topic string) *segkafka.Reader {
		r := segkafka.NewReader(segkafka.ReaderConfig{
			Brokers:     f.Brokers,
			Topic:       topic,
			MinBytes:    1,
			MaxBytes:    10 << 20,
			MaxWait:     100 * time.Millisecond,
			StartOffset: segkafka.FirstOffset,
		})
		t.Cleanup(func() { _ = r.Close() })
		return r
	}

	return &ingestion{
		svc:      NewCollectorService(producer, dlqProducer, quiet()),
		events:   reader(f.Topic),
		dead:     reader(dlqTopic),
		topic:    f.Topic,
		dlqTopic: dlqTopic,
	}
}

// read takes n messages off a topic, or fails saying how many arrived. A test
// that waited forever on a message that was published elsewhere would hang the
// suite rather than name the defect.
func (i *ingestion) read(t *testing.T, r *segkafka.Reader, n int, what string) []segkafka.Message {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var got []segkafka.Message
	for len(got) < n {
		m, err := r.ReadMessage(ctx)
		if err != nil {
			t.Fatalf("%s: %d of %d messages arrived: %v", what, len(got), n, err)
		}
		got = append(got, m)
	}
	return got
}

// empty asserts nothing is waiting on a topic, which is how "the dead letter
// did not go to the normalized topic" is stated.
func (i *ingestion) empty(t *testing.T, r *segkafka.Reader, what string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	m, err := r.ReadMessage(ctx)
	if err == nil {
		t.Fatalf("%s: a message was waiting: %s", what, truncate(string(m.Value)))
	}
}

func truncate(s string) string {
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}

// A batch of good events is published, counted, and arrives whole.
func TestIngestPublishesWhatItNormalized(t *testing.T) {
	i := newIngestion(t)

	resp, err := i.svc.Ingest(context.Background(), tenant, &model.IngestRequest{
		ConnectorID: uuid.NewString(),
		Source:      "pare-feu01",
		SourceType:  "firewall",
		Format:      event.FormatJSON,
		Events: []string{
			`{"action":"login","severity":"HIGH","user_name":"alice"}`,
			`{"action":"logout","severity":"LOW","user_name":"alice"}`,
		},
	})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if resp.Received != 2 || resp.Published != 2 || resp.Failed != 0 {
		t.Fatalf("received %d, published %d, failed %d", resp.Received, resp.Published, resp.Failed)
	}
	if len(resp.Errors) != 0 {
		t.Errorf("errors were reported for a clean batch: %v", resp.Errors)
	}

	msgs := i.read(t, i.events, 2, "the normalized topic")
	actions := map[string]bool{}
	for _, m := range msgs {
		var norm event.NormalizedEvent
		if err := json.Unmarshal(m.Value, &norm); err != nil {
			t.Fatalf("the published message is not a NormalizedEvent: %v\n%s", err, m.Value)
		}
		if norm.TenantID != tenant {
			t.Errorf("the published event belongs to %q, want %q", norm.TenantID, tenant)
		}
		if norm.EventID == uuid.Nil {
			t.Error("the published event has no id")
		}
		// The key is tenant/event-id, so a partition holds one tenant's events
		// in order rather than interleaving customers.
		if !strings.HasPrefix(string(m.Key), tenant+"/") {
			t.Errorf("the message key is %q, want a %s/ prefix", m.Key, tenant)
		}
		actions[norm.Action] = true
	}
	if !actions["login"] || !actions["logout"] {
		t.Errorf("the actions that arrived are %v", actions)
	}

	i.empty(t, i.dead, "the dead-letter topic after a clean batch")
}

// A malformed line goes to the dead-letter topic and nowhere else. The second
// half of that sentence is the part that was broken.
func TestAMalformedEventGoesToTheDeadLetterTopicOnly(t *testing.T) {
	i := newIngestion(t)

	resp, err := i.svc.Ingest(context.Background(), tenant, &model.IngestRequest{
		ConnectorID: uuid.NewString(),
		Source:      "pare-feu01",
		SourceType:  "firewall",
		Format:      event.FormatJSON,
		Events:      []string{"ceci n'est pas du JSON"},
	})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if resp.Received != 1 || resp.Published != 0 || resp.Failed != 1 {
		t.Fatalf("received %d, published %d, failed %d", resp.Received, resp.Published, resp.Failed)
	}
	if len(resp.Errors) != 1 || !strings.Contains(resp.Errors[0], "event[0]") {
		t.Errorf("the errors are %v, want one naming the index", resp.Errors)
	}

	msgs := i.read(t, i.dead, 1, "the dead-letter topic")
	var dlq event.DLQMessage
	if err := json.Unmarshal(msgs[0].Value, &dlq); err != nil {
		t.Fatalf("the dead letter is not a DLQMessage: %v\n%s", err, msgs[0].Value)
	}
	if dlq.TenantID != tenant {
		t.Errorf("the dead letter belongs to %q, want %q", dlq.TenantID, tenant)
	}
	if string(dlq.Payload) != "ceci n'est pas du JSON" {
		t.Errorf("the payload is %q, want the line that failed", dlq.Payload)
	}
	if dlq.Error == "" {
		t.Error("the dead letter does not say why it failed")
	}
	if dlq.FailedAt.IsZero() {
		t.Error("the dead letter has no time")
	}

	// And the normalized topic is untouched: a DLQMessage published there is
	// read by the pipeline worker as a NormalizedEvent, because json.Unmarshal
	// accepts the unknown fields and zeroes the rest.
	i.empty(t, i.events, "the normalized topic after a malformed event")
}

// A batch with both kinds is split: the good events are published, the bad one
// is dead-lettered, and the counts add up. A connector sending a thousand lines
// must not lose the 999 good ones to the one that was truncated.
func TestAMixedBatchIsSplitRatherThanRejected(t *testing.T) {
	i := newIngestion(t)

	resp, err := i.svc.Ingest(context.Background(), tenant, &model.IngestRequest{
		ConnectorID: uuid.NewString(),
		Source:      "pare-feu01",
		SourceType:  "firewall",
		Format:      event.FormatCEF,
		Events: []string{
			`CEF:0|V|P|1|100|Accepté|3|src=10.0.0.1`,
			`pas du CEF du tout`,
			`CEF:0|V|P|1|101|Refusé|8|src=10.0.0.2`,
		},
	})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if resp.Received != 3 || resp.Published != 2 || resp.Failed != 1 {
		t.Fatalf("received %d, published %d, failed %d", resp.Received, resp.Published, resp.Failed)
	}
	if resp.Published+resp.Failed != resp.Received {
		t.Errorf("the counts do not add up: %d + %d != %d", resp.Published, resp.Failed, resp.Received)
	}
	if len(resp.Errors) != 1 || !strings.Contains(resp.Errors[0], "event[1]") {
		t.Errorf("the errors are %v, want one naming index 1", resp.Errors)
	}

	i.read(t, i.events, 2, "the normalized topic")
	i.read(t, i.dead, 1, "the dead-letter topic")
}

// An empty batch is accepted and publishes nothing: the handler's validator
// refuses it upstream, and the service must not divide by zero or publish a
// placeholder if it is ever called directly.
func TestAnEmptyBatchPublishesNothing(t *testing.T) {
	i := newIngestion(t)

	resp, err := i.svc.Ingest(context.Background(), tenant, &model.IngestRequest{
		ConnectorID: uuid.NewString(),
		Source:      "x", SourceType: "firewall",
		Format: event.FormatJSON,
		Events: nil,
	})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if resp.Received != 0 || resp.Published != 0 || resp.Failed != 0 {
		t.Errorf("an empty batch reported %+v", resp)
	}
}

// A deployment without a dead-letter topic logs and drops rather than failing
// the whole batch or publishing the dead letter onto the event topic.
func TestWithoutADeadLetterTopicTheEventIsDroppedNotMisrouted(t *testing.T) {
	f := testinfra.Kafka(t)
	producer := kafka.NewProducer(kafka.ProducerConfig{
		Brokers: f.Brokers, Topic: f.Topic,
	}, quiet())
	t.Cleanup(func() { _ = producer.Close() })

	svc := NewCollectorService(producer, nil, quiet())
	resp, err := svc.Ingest(context.Background(), tenant, &model.IngestRequest{
		ConnectorID: uuid.NewString(),
		Source:      "x", SourceType: "firewall",
		Format: event.FormatJSON,
		Events: []string{"pas du JSON", `{"action":"ok"}`},
	})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if resp.Failed != 1 || resp.Published != 1 {
		t.Fatalf("published %d, failed %d", resp.Published, resp.Failed)
	}

	// Exactly one message on the topic: the good event, not the dead letter.
	r := segkafka.NewReader(segkafka.ReaderConfig{
		Brokers: f.Brokers, Topic: f.Topic,
		MinBytes: 1, MaxBytes: 10 << 20, MaxWait: 100 * time.Millisecond,
		StartOffset: segkafka.FirstOffset,
	})
	defer r.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	m, err := r.ReadMessage(ctx)
	if err != nil {
		t.Fatalf("read the published event: %v", err)
	}
	var norm event.NormalizedEvent
	if err := json.Unmarshal(m.Value, &norm); err != nil {
		t.Fatalf("not a NormalizedEvent: %v", err)
	}
	if norm.Action != "ok" {
		t.Errorf("the published event is %+v, want the one that parsed", norm.Action)
	}

	short, cancelShort := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelShort()
	if extra, err := r.ReadMessage(short); err == nil {
		t.Errorf("a second message is on the event topic: %s", truncate(string(extra.Value)))
	}
}

// Each of the six formats survives the whole path, so a connector configured
// for any of them gets events in ClickHouse rather than a dead-letter queue.
func TestEveryFormatSurvivesTheWholePath(t *testing.T) {
	i := newIngestion(t)
	ctx := context.Background()

	for _, c := range []struct {
		format event.Format
		body   string
	}{
		{event.FormatJSON, `{"action":"login"}`},
		{event.FormatCEF, `CEF:0|V|P|1|100|Login|5|src=10.0.0.1`},
		{event.FormatSyslog, `<34>Mar 14 08:00:00 host sshd: échec`},
		{event.FormatLEEF, "LEEF:1.0|V|P|1|Login|src=10.0.0.1"},
		{event.FormatWinEvent, `{"EventId":4625,"Computer":"PC01"}`},
		{event.FormatCLF, `10.0.0.1 - - [14/Mar/2026:08:00:00 +0000] "GET / HTTP/1.1" 200 1`},
	} {
		resp, err := i.svc.Ingest(ctx, tenant, &model.IngestRequest{
			ConnectorID: uuid.NewString(),
			Source:      "test", SourceType: "firewall",
			Format: c.format,
			Events: []string{c.body},
		})
		if err != nil {
			t.Fatalf("%s: Ingest: %v", c.format, err)
		}
		if resp.Published != 1 {
			t.Errorf("%s: published %d, failed %d (%v)",
				c.format, resp.Published, resp.Failed, resp.Errors)
		}
	}

	msgs := i.read(t, i.events, 6, "the normalized topic")
	for _, m := range msgs {
		var norm event.NormalizedEvent
		if err := json.Unmarshal(m.Value, &norm); err != nil {
			t.Fatalf("a published message is not a NormalizedEvent: %v", err)
		}
		if norm.Timestamp.Year() < 2000 {
			t.Errorf("an event was published with its timestamp in year %d: %s",
				norm.Timestamp.Year(), norm.RawEvent)
		}
	}
	i.empty(t, i.dead, "the dead-letter topic")
}

// A heartbeat is accepted and reported as handled. It writes nothing yet, which
// is worth pinning: a connector's liveness is currently a log line and not a
// row, so no dashboard can say a connector has gone quiet.
func TestHeartbeatIsAcceptedAndRecordsNothingYet(t *testing.T) {
	i := newIngestion(t)

	err := i.svc.Heartbeat(context.Background(), tenant, &model.ConnectorHeartbeat{
		ConnectorID:  uuid.NewString(),
		Source:       "agent-01",
		SourceType:   "firewall",
		EventsQueued: 12,
		Version:      "1.2.3",
	})
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	i.empty(t, i.events, "the event topic after a heartbeat")
	i.empty(t, i.dead, "the dead-letter topic after a heartbeat")
}
