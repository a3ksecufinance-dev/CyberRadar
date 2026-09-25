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
	"github.com/cyberradar/platform/internal/pkg/event"
	pkgjwt "github.com/cyberradar/platform/internal/pkg/jwt"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/internal/pkg/observe"
	"github.com/cyberradar/platform/services/collector/internal/handler"
	"github.com/cyberradar/platform/services/collector/internal/service"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	logger := log.With().Str("service", "collector-service").Logger()

	// Optional: with no collector configured this is a no-op, so a
	// missing collector never stops the service from starting.
	shutdownTracing, tracingErr := observe.InitTracing(context.Background(),
		"collector-service", envOrDefault("SERVICE_VERSION", "dev"),
		os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if tracingErr != nil {
		logger.Warn().Err(tracingErr).Msg("tracing disabled")
	}
	defer func() { _ = shutdownTracing(context.Background()) }()

	port := envOrDefault("SERVICE_PORT", "8005")
	jwtVerifier, err := pkgjwt.NewVerifierFromFile(mustEnv("JWT_PUBLIC_KEY_PATH"))
	if err != nil {
		log.Fatal().Err(err).Msg("load jwt public key")
	}
	brokers := strings.Split(mustEnv("KAFKA_BROKERS"), ",")

	producer := pkgkafka.NewProducer(pkgkafka.ProducerConfig{
		Brokers:  brokers,
		Topic:    event.TopicNormalized,
		BatchMax: 500,
	}, logger)
	defer producer.Close()

	// DLQ producer uses a separate writer
	dlqProducer := pkgkafka.NewProducer(pkgkafka.ProducerConfig{
		Brokers: brokers,
		Topic:   event.TopicDLQ,
	}, logger)
	defer dlqProducer.Close()

	collectorSvc := service.NewCollectorService(producer, logger)
	collectorHandler := handler.NewCollectorHandler(collectorSvc)

	r := chi.NewRouter()
	r.Use(observe.Middleware("collector-service"))
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))

	r.Handle("/metrics", observe.MetricsHandler())
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"collector-service"}`)
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(authmw.RequireJWT(jwtVerifier, logger))
		collectorHandler.RegisterRoutes(r)
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
		logger.Info().Str("addr", srv.Addr).Msg("collector-service started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("server error")
		}
	}()

	<-quit
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	logger.Info().Msg("collector-service stopped")
}

// ─── JWT middleware ───────────────────────────────────────────────────────────

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
