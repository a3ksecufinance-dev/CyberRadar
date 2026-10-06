package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cyberradar/platform/internal/pkg/event"
	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
)

const (
	defaultMaxAttempts  = 3
	defaultRetryBackoff = 250 * time.Millisecond
)

// Where a consumer with no committed offset begins.
//
// The choice is not a tuning knob, it is what happens to the events that
// arrived while the consumer was down. For anything that decides whether an
// attack is happening, that has one answer: read them. A detection engine
// that skips to the end discards the window in which it was restarted and
// says nothing about it — the attack simply did not happen, as far as the
// product is concerned.
//
// It is the opposite for a consumer that *acts*. Replaying an alert means
// running its playbook again, so the SOAR would re-block addresses and
// re-isolate hosts on the strength of history. That one skips to the end on
// purpose.
//
// Written as named constants because -1 and -2 at a call site say nothing,
// and the rule engine carried -1 — skip the restart window — where the
// pipeline worker beside it carried -2.
const (
	// FromTheBeginning reads everything the topic still retains. For
	// detection, and for anything whose job is not to lose an event.
	FromTheBeginning = kafka.FirstOffset

	// OnlyNewEvents skips whatever arrived while the consumer was away. For
	// consumers of current state, and for anything that acts on what it reads.
	OnlyNewEvents = kafka.LastOffset
)

// ConsumerConfig holds Kafka consumer configuration.
type ConsumerConfig struct {
	Brokers  []string
	Topic    string
	GroupID  string
	MinBytes int           // default 1B
	MaxBytes int           // default 10MB
	MaxWait  time.Duration // default 500ms

	// StartOffset is FromTheBeginning or OnlyNewEvents, and it decides what
	// happens to the events that arrived while this consumer was not there.
	// It applies only when the group has no committed offset — so on a fresh
	// installation, and after that never again.
	StartOffset int64

	// MaxAttempts is how many times a message is handed to the handler before
	// it is routed to the dead letter queue. Default 3.
	MaxAttempts int

	// RetryBackoff is the pause before the second attempt; it doubles on each
	// further attempt. Default 250ms.
	RetryBackoff time.Duration

	// DLQTopic receives messages whose attempts are exhausted. It is required:
	// a SIEM holds evidence, so there is no acceptable configuration in which a
	// failed event is silently discarded.
	DLQTopic string
}

// Message wraps a kafka.Message for handler consumption.
type Message struct {
	Topic     string
	Partition int
	Offset    int64
	Key       []byte
	Value     []byte
	Time      time.Time
}

// HandlerFunc processes a single Kafka message. Returning an error causes the
// message to be retried, then routed to the dead letter queue.
type HandlerFunc func(ctx context.Context, msg Message) error

// Consumer reads from a Kafka topic and dispatches to a handler.
type Consumer struct {
	reader *kafka.Reader
	dlq    *Producer
	cfg    ConsumerConfig
	logger zerolog.Logger
}

// NewConsumer creates a new Kafka consumer.
//
// It fails when no DLQ topic is set. Previously a handler error either retried
// forever or dropped the message, both silently, and the offset of a later
// message then committed past the failure — so a failed event was lost with no
// trace. Requiring the DLQ up front makes that unrepresentable.
func NewConsumer(cfg ConsumerConfig, logger zerolog.Logger) (*Consumer, error) {
	if cfg.DLQTopic == "" {
		return nil, fmt.Errorf("kafka consumer for %q: DLQTopic is required", cfg.Topic)
	}
	if cfg.DLQTopic == cfg.Topic {
		return nil, fmt.Errorf("kafka consumer for %q: DLQTopic must differ from the source topic", cfg.Topic)
	}

	minBytes := cfg.MinBytes
	if minBytes <= 0 {
		minBytes = 1
	}
	maxBytes := cfg.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 10 << 20 // 10MB
	}
	maxWait := cfg.MaxWait
	if maxWait <= 0 {
		maxWait = 500 * time.Millisecond
	}
	// Zero is "not set", and the safe default for an unset one is to skip:
	// a consumer whose author did not think about it is more likely to be one
	// of current state than one that must not lose an event. The ones that
	// must not say so explicitly.
	startOffset := cfg.StartOffset
	if startOffset == 0 {
		startOffset = OnlyNewEvents
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = defaultMaxAttempts
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = defaultRetryBackoff
	}

	// The topic has to exist, with a leader, before the reader joins its group.
	//
	// Relying on auto-creation loses events, silently. A consumer that joins at
	// the instant its topic is created can end up in a generation holding no
	// partition, and then it blocks on ReadMessage with nothing to show for it:
	// no error, no log line, no lag — it simply never reads. On a cold
	// installation that is every consumer, because nothing has produced yet.
	//
	// It cost this platform its detection chain. The collector published 48
	// events, the pipeline worker committed none of them, `crp.events.enriched`
	// stayed at zero, and the rule engine waited correctly on an empty topic.
	// Both journals looked healthy: neither logs a line per event, so a
	// handover that worked and one that never happened read the same. Only the
	// broker's offsets said otherwise.
	//
	// A production cluster usually has auto-creation disabled anyway, which
	// turns the same race into a permanent failure rather than a start-up one.
	if err := EnsureTopic(cfg.Brokers, cfg.Topic, topicReadyWait, logger); err != nil {
		return nil, fmt.Errorf("prepare topic %s: %w", cfg.Topic, err)
	}

	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:     cfg.Brokers,
		Topic:       cfg.Topic,
		GroupID:     cfg.GroupID,
		MinBytes:    minBytes,
		MaxBytes:    maxBytes,
		MaxWait:     maxWait,
		StartOffset: startOffset,
		// A consumer that starts before its topic exists is assigned no
		// partitions, and without this it never notices when the topic
		// appears — it blocks on ReadMessage forever, with no error to show
		// for it. Seen for real: the dashboard's KPI ingestor started ahead of
		// the first producer and consumed nothing until it was restarted.
		WatchPartitionChanges: true,
	})

	dlq := NewProducer(ProducerConfig{Brokers: cfg.Brokers, Topic: cfg.DLQTopic}, logger)

	return &Consumer{reader: r, dlq: dlq, cfg: cfg, logger: logger}, nil
}

// How long to wait before trying the broker again, and the ceiling on that
// wait. Thirty seconds is short enough that a recovered broker is noticed
// promptly and long enough that an outage does not fill the log.
const (
	fetchRetryMin = time.Second
	fetchRetryMax = 30 * time.Second
)

// Run starts the consume loop. It blocks until ctx is cancelled, or until a
// message can be neither handled nor parked in the DLQ.
//
// A broker that goes away does not end the loop.
//
// It used to: any fetch error returned, the caller logged it, and nothing
// started the consumer again. So a broker restart — an upgrade, a rolling
// deployment, a network blip — stopped detection permanently, with one line in
// a log and no alert anywhere, until somebody restarted the service. The
// end-to-end chain found it by accident: Kafka was bounced under a running
// SIEM, the rule engine logged "rule_engine_error" once, and every event after
// that was ingested, enriched, stored — and evaluated against nothing.
//
// Retrying forever is deliberate. A detection engine that gives up is worse
// than one that keeps trying and says so, and the alternative — exiting so a
// supervisor restarts the process — is not available to a consumer that runs
// beside an HTTP server in the same binary. The backoff is capped so a long
// outage does not turn into a long silence, and every attempt past the first
// is logged at error level: an operator reading the log sees the platform is
// not detecting.
func (c *Consumer) Run(ctx context.Context, handler HandlerFunc) error {
	c.logger.Info().
		Str("topic", c.cfg.Topic).
		Str("group", c.cfg.GroupID).
		Str("dlq", c.cfg.DLQTopic).
		Int("max_attempts", c.cfg.MaxAttempts).
		Msg("kafka_consumer_started")

	backoff := fetchRetryMin
	for {
		km, err := c.reader.FetchMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown
			}
			c.logger.Error().Err(err).
				Str("topic", c.cfg.Topic).
				Dur("retry_in", backoff).
				Msg("kafka_fetch_failed_not_consuming")
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			if backoff < fetchRetryMax {
				backoff *= 2
				if backoff > fetchRetryMax {
					backoff = fetchRetryMax
				}
			}
			continue
		}
		backoff = fetchRetryMin

		msg := Message{
			Topic:     km.Topic,
			Partition: km.Partition,
			Offset:    km.Offset,
			Key:       km.Key,
			Value:     km.Value,
			Time:      km.Time,
		}

		if handlerErr := c.handle(ctx, handler, msg); handlerErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			if err := c.park(ctx, msg, handlerErr); err != nil {
				// The message could not be handled and could not be parked.
				// Stopping without committing keeps it replayable from the last
				// committed offset; committing here would bury it for good.
				return fmt.Errorf("dead letter %s@%d: %w", msg.Topic, msg.Offset, err)
			}
		}

		if err := c.reader.CommitMessages(ctx, km); err != nil {
			c.logger.Error().Err(err).Msg("kafka_commit_error")
		}
	}
}

// handle runs the handler, retrying with an exponential backoff.
func (c *Consumer) handle(ctx context.Context, handler HandlerFunc, msg Message) error {
	backoff := c.cfg.RetryBackoff
	var err error

	for attempt := 1; attempt <= c.cfg.MaxAttempts; attempt++ {
		if err = handler(ctx, msg); err == nil {
			return nil
		}

		c.logger.Warn().Err(err).
			Str("topic", msg.Topic).
			Int64("offset", msg.Offset).
			Int("attempt", attempt).
			Int("max_attempts", c.cfg.MaxAttempts).
			Msg("kafka_handler_error")

		if attempt == c.cfg.MaxAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			backoff *= 2
		}
	}
	return err
}

// park writes a message to the dead letter queue after its attempts ran out.
func (c *Consumer) park(ctx context.Context, msg Message, cause error) error {
	envelope := event.DLQMessage{
		OriginalTopic: msg.Topic,
		Offset:        msg.Offset,
		Partition:     msg.Partition,
		Payload:       msg.Value,
		Error:         cause.Error(),
		FailedAt:      time.Now().UTC(),
		TenantID:      tenantOf(msg.Value),
	}

	if err := c.dlq.Publish(ctx, string(msg.Key), envelope); err != nil {
		return err
	}

	// Logged at error level because a message reaching the DLQ is an incident:
	// something the platform was asked to process could not be processed. DLQ
	// depth is also visible to Prometheus through kafka-exporter.
	c.logger.Error().
		Str("topic", msg.Topic).
		Str("dlq", c.cfg.DLQTopic).
		Int64("offset", msg.Offset).
		Str("cause", cause.Error()).
		Msg("kafka_message_dead_lettered")
	return nil
}

// tenantOf extracts the tenant from a payload so a dead letter can be traced
// back to its customer. Best effort: a payload that will not parse is exactly
// the kind that lands here.
func tenantOf(payload []byte) string {
	var probe struct {
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return ""
	}
	return probe.TenantID
}

// Close closes the consumer reader and its DLQ producer.
func (c *Consumer) Close() error {
	err := c.reader.Close()
	if dlqErr := c.dlq.Close(); err == nil {
		err = dlqErr
	}
	return err
}

// Stats returns reader statistics (lag, messages read, etc.).
func (c *Consumer) Stats() kafka.ReaderStats {
	return c.reader.Stats()
}

// How long to wait for a topic to exist and elect a leader before giving up.
const topicReadyWait = 60 * time.Second

// EnsureTopic creates a topic if it is missing and waits until it has a leader.
//
// Creation is idempotent: a topic that already exists comes back as
// TopicAlreadyExists, which is success. The wait is what matters as much as the
// creation — CreateTopics returns once the controller has accepted the record,
// before the partition has a leader, and a reader or writer that arrives in
// that window behaves as if the topic were not there.
func EnsureTopic(brokers []string, topic string, wait time.Duration, logger zerolog.Logger) error {
	if len(brokers) == 0 || topic == "" {
		return errors.New("a broker address and a topic are required")
	}

	conn, err := kafka.Dial("tcp", brokers[0])
	if err != nil {
		return fmt.Errorf("reach %s: %w", brokers[0], err)
	}
	defer conn.Close() //nolint:errcheck // closing on the way out

	switch err := conn.CreateTopics(kafka.TopicConfig{
		Topic:             topic,
		NumPartitions:     1,
		ReplicationFactor: 1,
	}); {
	case err == nil, errors.Is(err, kafka.TopicAlreadyExists):
	default:
		// Not fatal on its own: a cluster that forbids creation may still have
		// the topic, and the wait below is what decides.
		logger.Warn().Err(err).Str("topic", topic).Msg("kafka_topic_not_created")
	}

	deadline := time.Now().Add(wait)
	var last error
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		lead, err := kafka.DialLeader(ctx, "tcp", brokers[0], topic, 0)
		cancel()
		if err == nil {
			_ = lead.Close()
			return nil
		}
		last = err
		if time.Now().After(deadline) {
			return fmt.Errorf("topic %s has no leader after %s: %w", topic, wait, last)
		}
		time.Sleep(250 * time.Millisecond)
	}
}
