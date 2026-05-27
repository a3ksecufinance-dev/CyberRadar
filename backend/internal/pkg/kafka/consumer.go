package kafka

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
)

// ConsumerConfig holds Kafka consumer configuration.
type ConsumerConfig struct {
	Brokers       []string
	Topic         string
	GroupID       string
	MinBytes      int           // default 1B
	MaxBytes      int           // default 10MB
	MaxWait       time.Duration // default 500ms
	StartOffset   int64         // kafka.FirstOffset or kafka.LastOffset
	CommitOnError bool          // commit offset even when handler returns error
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

// HandlerFunc processes a single Kafka message. Return error to trigger DLQ routing.
type HandlerFunc func(ctx context.Context, msg Message) error

// Consumer reads from a Kafka topic and dispatches to a handler.
type Consumer struct {
	reader *kafka.Reader
	cfg    ConsumerConfig
	logger zerolog.Logger
}

// NewConsumer creates a new Kafka consumer.
func NewConsumer(cfg ConsumerConfig, logger zerolog.Logger) *Consumer {
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

	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:     cfg.Brokers,
		Topic:       cfg.Topic,
		GroupID:     cfg.GroupID,
		MinBytes:    minBytes,
		MaxBytes:    maxBytes,
		MaxWait:     maxWait,
		StartOffset: startOffset,
	})

	return &Consumer{reader: r, cfg: cfg, logger: logger}
}

// Run starts the consume loop. Blocks until ctx is cancelled.
func (c *Consumer) Run(ctx context.Context, handler HandlerFunc) error {
	c.logger.Info().
		Str("topic", c.cfg.Topic).
		Str("group", c.cfg.GroupID).
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

		if err := handler(ctx, msg); err != nil {
			c.logger.Error().Err(err).
				Str("topic", km.Topic).
				Int64("offset", km.Offset).
				Msg("kafka_handler_error")

			if !c.cfg.CommitOnError {
				continue // retry same message
			}
		}

		if err := c.reader.CommitMessages(ctx, km); err != nil {
			c.logger.Error().Err(err).Msg("kafka_commit_error")
		}
	}
}

// Close closes the consumer reader.
func (c *Consumer) Close() error {
	return c.reader.Close()
}

// Stats returns reader statistics (lag, messages read, etc.).
func (c *Consumer) Stats() kafka.ReaderStats {
	return c.reader.Stats()
}
