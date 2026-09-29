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
	"github.com/cyberradar/platform/internal/pkg/corsmw"
	"github.com/cyberradar/platform/internal/pkg/db"
	"github.com/cyberradar/platform/internal/pkg/event"
	pkgjwt "github.com/cyberradar/platform/internal/pkg/jwt"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/internal/pkg/kpi"
	"github.com/cyberradar/platform/internal/pkg/observe"
	"github.com/cyberradar/platform/services/ti/internal/handler"
	"github.com/cyberradar/platform/services/ti/internal/repository"
	"github.com/cyberradar/platform/services/ti/internal/service"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	logger := log.With().Str("service", "ti-service").Logger()

	// Optional: with no collector configured this is a no-op, so a
	// missing collector never stops the service from starting.
	shutdownTracing, tracingErr := observe.InitTracing(context.Background(),
		"ti-service", envOrDefault("SERVICE_VERSION", "dev"),
		os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if tracingErr != nil {
		logger.Warn().Err(tracingErr).Msg("tracing disabled")
	}
	defer func() { _ = shutdownTracing(context.Background()) }()

	port := envOrDefault("SERVICE_PORT", "8010")
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

	// The web interface signs users in against an external provider and sends
	// that provider's token. Without this the service accepts only tokens
	// signed by identity-service and answers every call from a browser 401.
	providerOpt, err := authmw.ProviderFromEnv(ctx, pool, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("identity provider")
	}

	// ── Repository ────────────────────────────────────────────────────────────
	iocRepo := repository.NewIOCRepository(pool)

	// ── TI service ────────────────────────────────────────────────────────────
	tiSvc := service.NewTIService(iocRepo, logger)
	tiHandler := handler.NewTIHandler(tiSvc)

	// ── IOC Matcher (Kafka consumer on crp.events.enriched) ──────────────────
	matcherConsumer, err := pkgkafka.NewConsumer(pkgkafka.ConsumerConfig{
		Brokers:     brokers,
		Topic:       event.TopicEnriched,
		GroupID:     "crp-ti-ioc-matcher",
		StartOffset: -1,
		DLQTopic:    event.TopicDLQ,
	}, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("kafka consumer")
	}

	hitPublisher := pkgkafka.NewProducer(pkgkafka.ProducerConfig{
		Brokers: brokers,
		Topic:   "crp.events.ti",
	}, logger)
	defer hitPublisher.Close()

	matcher := service.NewIOCMatcher(iocRepo, matcherConsumer, hitPublisher, logger)
	go func() {
		if err := matcher.Run(ctx); err != nil {
			logger.Error().Err(err).Msg("ioc_matcher_error")
		}
	}()

	// ── IOC expiry ticker (every 6 hours) ─────────────────────────────────────
	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := tiSvc.ExpireIOCs(ctx); err != nil {
					logger.Error().Err(err).Msg("expire_iocs_error")
				}
			}
		}
	}()

	// ── HTTP server ───────────────────────────────────────────────────────────
	// ── Report this domain's KPIs to the dashboard ────────────────────────────
	// PlatformOverview is assembled from the latest snapshot each domain
	// published. Nothing published any, so the overview answered zero for every
	// tenant — see internal/pkg/kpi.
	kpi.Start(ctx, kpi.Config{
		Brokers: brokers,
		Domain:  "ti",
		Tenants: kpi.TenantsFromPostgres(pool),
		Source:  tiSvc.KPISamples,
	}, logger)

	r := chi.NewRouter()
	// Before everything else: a browser sends a preflight without
	// credentials, so an OPTIONS that reaches the JWT middleware is
	// answered 401 and the browser blocks the real request.
	r.Use(corsmw.Middleware(corsmw.DefaultConfig(
		corsmw.OriginsFromEnv(os.Getenv("CORS_ALLOWED_ORIGINS")))))
	r.Use(observe.Middleware("ti-service"))
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))

	r.Handle("/metrics", observe.MetricsHandler())
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"ti-service"}`)
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(authmw.RequireJWT(jwtVerifier, logger, providerOpt))
		r.Use(authmw.RequirePermissionByMethod("threat_intel"))
		tiHandler.RegisterRoutes(r)
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
		logger.Info().Str("addr", srv.Addr).Msg("ti-service started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("server error")
		}
	}()

	<-quit
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
	logger.Info().Msg("ti-service stopped")
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
