package kafka

import (
	"context"
	"encoding/json"
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

// ConsumerConfig holds Kafka consumer configuration.
type ConsumerConfig struct {
	Brokers     []string
	Topic       string
	GroupID     string
	MinBytes    int           // default 1B
	MaxBytes    int           // default 10MB
	MaxWait     time.Duration // default 500ms
	StartOffset int64         // kafka.FirstOffset or kafka.LastOffset

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
	startOffset := cfg.StartOffset
	if startOffset == 0 {
		startOffset = kafka.LastOffset
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = defaultMaxAttempts
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = defaultRetryBackoff
	}

	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:     cfg.Brokers,
		Topic:       cfg.Topic,
		GroupID:     cfg.GroupID,
		MinBytes:    minBytes,
		MaxBytes:    maxBytes,
		MaxWait:     maxWait,
		StartOffset: startOffset,
	})

	dlq := NewProducer(ProducerConfig{Brokers: cfg.Brokers, Topic: cfg.DLQTopic}, logger)

	return &Consumer{reader: r, dlq: dlq, cfg: cfg, logger: logger}, nil
}

// Run starts the consume loop. It blocks until ctx is cancelled, or until a
// message can be neither handled nor parked in the DLQ.
func (c *Consumer) Run(ctx context.Context, handler HandlerFunc) error {
	c.logger.Info().
		Str("topic", c.cfg.Topic).
		Str("group", c.cfg.GroupID).
		Str("dlq", c.cfg.DLQTopic).
		Int("max_attempts", c.cfg.MaxAttempts).
		Msg("kafka_consumer_started")

	for {
		km, err := c.reader.FetchMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown
			}
			return fmt.Errorf("kafka fetch: %w", err)
		}

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
