package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
)

// ProducerConfig holds Kafka producer configuration.
type ProducerConfig struct {
	Brokers  []string
	Topic    string
	Async    bool // fire-and-forget (higher throughput, lower durability)
	BatchMax int  // max messages per batch (default 100)
}

// Producer is a Kafka message producer.
type Producer struct {
	writer *kafka.Writer
	logger zerolog.Logger
}

// NewProducer creates a new Kafka producer.
func NewProducer(cfg ProducerConfig, logger zerolog.Logger) *Producer {
	batchMax := cfg.BatchMax
	if batchMax <= 0 {
		batchMax = 100
	}

	w := &kafka.Writer{
		Addr:                   kafka.TCP(cfg.Brokers...),
		Topic:                  cfg.Topic,
		Balancer:               &kafka.LeastBytes{},
		BatchSize:              batchMax,
		BatchTimeout:           5 * time.Millisecond,
		RequiredAcks:           kafka.RequireOne,
		Async:                  cfg.Async,
		AllowAutoTopicCreation: true,
		Completion: func(messages []kafka.Message, err error) {
			if err != nil {
				logger.Error().Err(err).Int("count", len(messages)).Msg("kafka_produce_error")
			}
		},
	}

	return &Producer{writer: w, logger: logger}
}

// Publish sends a single message to Kafka. key is optional (use "" for round-robin).
func (p *Producer) Publish(ctx context.Context, key string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("kafka producer marshal: %w", err)
	}

	msg := kafka.Message{Value: b}
	if key != "" {
		msg.Key = []byte(key)
	}

	if err := p.writer.WriteMessages(ctx, msg); err != nil {
		return fmt.Errorf("kafka producer write: %w", err)
	}
	return nil
}

// PublishRaw sends a pre-serialized byte slice.
func (p *Producer) PublishRaw(ctx context.Context, key string, value []byte) error {
	msg := kafka.Message{Value: value}
	if key != "" {
		msg.Key = []byte(key)
	}
	if err := p.writer.WriteMessages(ctx, msg); err != nil {
		return fmt.Errorf("kafka producer write: %w", err)
	}
	return nil
}

// PublishBatch sends multiple messages in a single round-trip.
func (p *Producer) PublishBatch(ctx context.Context, messages []kafka.Message) error {
	if err := p.writer.WriteMessages(ctx, messages...); err != nil {
		return fmt.Errorf("kafka producer batch write: %w", err)
	}
	return nil
}

// Close flushes and closes the writer.
func (p *Producer) Close() error {
	return p.writer.Close()
}
