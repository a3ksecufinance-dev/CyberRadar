package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cyberradar/platform/internal/pkg/authmw"
	"github.com/cyberradar/platform/internal/pkg/db"
	pkgjwt "github.com/cyberradar/platform/internal/pkg/jwt"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/services/fraud/internal/handler"
	"github.com/cyberradar/platform/services/fraud/internal/repository"
	"github.com/cyberradar/platform/services/fraud/internal/service"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	logger := log.With().Str("service", "fraud-service").Logger()

	port := envOrDefault("SERVICE_PORT", "8020")
	jwtVerifier, err := pkgjwt.NewVerifierFromFile(mustEnv("JWT_PUBLIC_KEY_PATH"))
	if err != nil {
		log.Fatal().Err(err).Msg("load jwt public key")
	}
	dbURL := mustEnv("DATABASE_URL")
	brokers := strings.Split(mustEnv("KAFKA_BROKERS"), ",")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── PostgreSQL ────────────────────────────────────────────────────────────
	pool, err := db.NewPostgresPool(ctx, db.DefaultPostgresConfig(dbURL))
	if err != nil {
		logger.Fatal().Err(err).Msg("postgres connect failed")
	}
	defer pool.Close()

	// ── Kafka producer (publishes fraud events) ───────────────────────────────
	producer := pkgkafka.NewProducer(pkgkafka.ProducerConfig{
		Brokers: brokers,
		Topic:   "crp.events.fraud",
	}, logger)

	// ── Kafka consumer: ingest banking events from pipeline ───────────────────
	// Consumes crp.events.enriched for transaction events tagged as payment/wire/swift
	go consumeTopic(ctx, brokers, "crp.events.enriched", "crp-fraud-ingestor", logger)

	// ── Repositories / services ───────────────────────────────────────────────
	fraudRepo := repository.NewFraudRepository(pool)
	fraudSvc := service.NewFraudService(fraudRepo, producer, logger)
	fraudH := handler.NewFraudHandler(fraudSvc)

	// ── HTTP server ───────────────────────────────────────────────────────────
	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"fraud-service"}`)
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(authmw.RequireJWT(jwtVerifier, logger))
		r.Use(authmw.RequirePermissionByMethod("fraud"))
		fraudH.RegisterRoutes(r)
	})

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Info().Str("addr", srv.Addr).Msg("fraud-service started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("server error")
		}
	}()

	<-quit
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
	logger.Info().Msg("fraud-service stopped")
}

// consumeTopic reads from a Kafka topic and logs events (hook for future parsing).
func consumeTopic(ctx context.Context, brokers []string, topic, group string, logger zerolog.Logger) {
	consumer := pkgkafka.NewConsumer(pkgkafka.ConsumerConfig{
		Brokers: brokers,
		Topic:   topic,
		GroupID: group,
	}, logger)
	defer consumer.Close()

	_ = consumer.Run(ctx, func(ctx context.Context, msg pkgkafka.Message) error {
		logger.Debug().
			Str("topic", topic).
			Int("size", len(msg.Value)).
			Msg("fraud_kafka_event_received")
		return nil
	})
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
