package main

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/cyberradar/platform/internal/pkg/db"
	"github.com/cyberradar/platform/internal/pkg/event"
	"github.com/cyberradar/platform/internal/pkg/iocindex"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/services/pipeline/internal/enricher"
	"github.com/cyberradar/platform/services/pipeline/internal/processor"
	"github.com/cyberradar/platform/services/pipeline/internal/writer"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	logger := log.With().Str("service", "pipeline-worker").Logger()

	brokers := strings.Split(mustEnv("KAFKA_BROKERS"), ",")
	chDSN := mustEnv("CLICKHOUSE_DSN") // clickhouse://user:pass@host:9000/crp_audit
	groupID := envOrDefault("KAFKA_GROUP_ID", "crp-pipeline")
	batchStr := envOrDefault("CLICKHOUSE_BATCH_SIZE", "1000")
	batchSize := 1000
	if n := parseInt(batchStr); n > 0 {
		batchSize = n
	}

	// ── ClickHouse connection ─────────────────────────────────────────────────
	opts, err := clickhouse.ParseDSN(chDSN)
	if err != nil {
		logger.Fatal().Err(err).Str("dsn", chDSN).Msg("clickhouse dsn parse failed")
	}
	opts.DialTimeout = 10 * time.Second
	opts.MaxOpenConns = 10
	opts.MaxIdleConns = 5

	chConn, err := clickhouse.Open(opts)
	if err != nil {
		logger.Fatal().Err(err).Msg("clickhouse open failed")
	}
	defer chConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── Kafka producers ───────────────────────────────────────────────────────
	enrichedPub := pkgkafka.NewProducer(pkgkafka.ProducerConfig{
		Brokers: brokers,
		Topic:   event.TopicEnriched,
	}, logger)
	defer enrichedPub.Close()

	alertPub := pkgkafka.NewProducer(pkgkafka.ProducerConfig{
		Brokers: brokers,
		Topic:   event.TopicAlerts,
	}, logger)
	defer alertPub.Close()

	dlqPub := pkgkafka.NewProducer(pkgkafka.ProducerConfig{
		Brokers: brokers,
		Topic:   event.TopicDLQ,
		Async:   true, // DLQ can be async
	}, logger)
	defer dlqPub.Close()

	// ── Indicator index ───────────────────────────────────────────────────────
	// Matching indicators is the detection this platform is bought for, so a
	// deployment without it must say so loudly rather than report zero threats
	// and be believed. With DATABASE_URL set, a failure to load is fatal.
	iocMatcher := buildIOCMatcher(ctx, logger)

	// ── Pipeline components ───────────────────────────────────────────────────
	chWriter := writer.NewClickHouseWriter(chConn, logger, batchSize)
	geoEnricher := enricher.NewGeoEnricher()
	threatEnricher := enricher.NewThreatEnricher()

	proc := processor.NewProcessor(
		geoEnricher,
		threatEnricher,
		iocMatcher,
		chWriter,
		enrichedPub,
		alertPub,
		dlqPub,
		logger,
		processor.Config{FlushInterval: 5 * time.Second},
	)

	// Periodic ClickHouse flush goroutine
	go proc.RunFlushLoop(ctx)

	// ── Kafka consumer ────────────────────────────────────────────────────────
	consumer, err := pkgkafka.NewConsumer(pkgkafka.ConsumerConfig{
		Brokers:     brokers,
		Topic:       event.TopicNormalized,
		GroupID:     groupID,
		StartOffset: pkgkafka.FromTheBeginning,
		MaxBytes:    10 << 20,
		DLQTopic:    event.TopicDLQ,
	}, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("kafka consumer")
	}
	defer consumer.Close()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		logger.Info().Msg("shutdown signal received")
		cancel()
	}()

	logger.Info().
		Str("topic", event.TopicNormalized).
		Str("group", groupID).
		Int("batch_size", batchSize).
		Msg("pipeline-worker started")

	if err := consumer.Run(ctx, proc.Handle); err != nil {
		logger.Fatal().Err(err).Msg("consumer error")
	}

	logger.Info().Msg("pipeline-worker stopped")
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatal().Str("key", key).Msg("required env var missing")
	}
	return v
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseInt(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// buildIOCMatcher loads the indicator index, or returns nil when this
// deployment has no database to load it from.
//
// nil is a real answer: a pipeline can be run for throughput testing or in a
// lab with no threat intelligence at all. What must not happen is running one
// in production that way without noticing, which is why the absence is a
// warning naming exactly what is off.
func buildIOCMatcher(ctx context.Context, logger zerolog.Logger) processor.IOCMatcher {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		logger.Warn().Msg("no DATABASE_URL: indicator matching is off, and no rule keyed on ioc_matched can fire")
		return nil
	}

	pool, err := db.NewPostgresPool(ctx, db.DefaultPostgresConfig(dsn))
	if err != nil {
		logger.Fatal().Err(err).Msg("postgres connect failed: cannot load the indicator index")
	}

	cache := iocindex.NewCache(pool, iocindex.Config{
		Interval:   time.Duration(parseInt(envOrDefault("IOC_REFRESH_SECONDS", "60"))) * time.Second,
		MaxEntries: parseInt(envOrDefault("IOC_MAX_ENTRIES", "1000000")),
	}, logger)

	if err := cache.Start(ctx); err != nil {
		logger.Fatal().Err(err).Msg("indicator index failed to load")
	}
	return cache
}
