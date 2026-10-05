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

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/cyberradar/platform/internal/pkg/authmw"
	"github.com/cyberradar/platform/internal/pkg/cache"
	"github.com/cyberradar/platform/internal/pkg/clientip"
	"github.com/cyberradar/platform/internal/pkg/corsmw"
	"github.com/cyberradar/platform/internal/pkg/db"
	"github.com/cyberradar/platform/internal/pkg/event"
	pkgjwt "github.com/cyberradar/platform/internal/pkg/jwt"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/internal/pkg/kpi"
	"github.com/cyberradar/platform/internal/pkg/observe"
	"github.com/cyberradar/platform/services/siem/internal/handler"
	"github.com/cyberradar/platform/services/siem/internal/repository"
	"github.com/cyberradar/platform/services/siem/internal/service"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	logger := log.With().Str("service", "siem-service").Logger()

	// Optional: with no collector configured this is a no-op, so a
	// missing collector never stops the service from starting.
	shutdownTracing, tracingErr := observe.InitTracing(context.Background(),
		"siem-service", envOrDefault("SERVICE_VERSION", "dev"),
		os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if tracingErr != nil {
		logger.Warn().Err(tracingErr).Msg("tracing disabled")
	}
	defer func() { _ = shutdownTracing(context.Background()) }()

	port := envOrDefault("SERVICE_PORT", "8008")
	jwtVerifier, err := pkgjwt.NewVerifierFromFile(mustEnv("JWT_PUBLIC_KEY_PATH"))
	if err != nil {
		log.Fatal().Err(err).Msg("load jwt public key")
	}
	dbURL := mustEnv("DATABASE_URL")
	chDSN := mustEnv("CLICKHOUSE_DSN")
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

	// ── ClickHouse ────────────────────────────────────────────────────────────
	opts, err := clickhouse.ParseDSN(chDSN)
	if err != nil {
		logger.Fatal().Err(err).Msg("clickhouse dsn parse failed")
	}
	opts.DialTimeout = 10 * time.Second
	chConn, err := clickhouse.Open(opts)
	if err != nil {
		logger.Fatal().Err(err).Msg("clickhouse open failed")
	}
	defer chConn.Close()

	// ── Redis ─────────────────────────────────────────────────────────────────
	// Threshold rules count across every replica, not inside one process.
	redisClient, err := cache.NewFromURL(ctx, os.Getenv("REDIS_URL"), logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("redis url invalid")
	}
	if redisClient != nil {
		defer redisClient.Close()
	}
	thresholds := cache.NewWindow(redisClient, "siem:threshold", logger)

	// ── Repositories ──────────────────────────────────────────────────────────
	ruleRepo := repository.NewRuleRepository(pool)
	alertRepo := repository.NewAlertRepository(chConn)
	caseRepo := repository.NewCaseRepository(pool)

	// ── SIEM service ──────────────────────────────────────────────────────────
	siemSvc := service.NewSIEMService(ruleRepo, alertRepo, caseRepo, logger)
	siemHandler := handler.NewSIEMHandler(siemSvc)

	// The detection content the platform ships, and the lineage from a tenant's
	// rules back to it. A detection engine with an empty rule table detects
	// nothing, and every customer writing the same fifteen rules from memory is
	// how nobody can say what the platform covers.
	libraryRepo := repository.NewLibraryRepository(pool)
	librarySvc := service.NewLibraryService(libraryRepo, ruleRepo, logger)
	libraryHandler := handler.NewLibraryHandler(librarySvc)

	// ── Rule Engine (Kafka consumer on crp.events.enriched) ──────────────────
	ruleConsumer, err := pkgkafka.NewConsumer(pkgkafka.ConsumerConfig{
		Brokers:     brokers,
		Topic:       event.TopicEnriched,
		GroupID:     "crp-siem-rule-engine",
		StartOffset: -1,
		DLQTopic:    event.TopicDLQ,
	}, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("kafka consumer")
	}

	alertPublisher := pkgkafka.NewProducer(pkgkafka.ProducerConfig{
		Brokers: brokers,
		Topic:   event.TopicAlerts,
	}, logger)
	defer alertPublisher.Close()

	ruleEngine := service.NewRuleEngine(ruleRepo, alertRepo, caseRepo, ruleConsumer, alertPublisher, thresholds, logger)
	go func() {
		if err := ruleEngine.Run(ctx); err != nil {
			logger.Error().Err(err).Msg("rule_engine_error")
		}
	}()

	// ── HTTP server ───────────────────────────────────────────────────────────
	// ── Report this domain's KPIs to the dashboard ────────────────────────────
	// PlatformOverview is assembled from the latest snapshot each domain
	// published. Nothing published any, so the overview answered zero for every
	// tenant — see internal/pkg/kpi.
	kpi.Start(ctx, kpi.Config{
		Brokers: brokers,
		Domain:  "siem",
		Tenants: kpi.TenantsFromPostgres(pool),
		Source:  siemSvc.KPISamples,
	}, logger)

	r := chi.NewRouter()
	// Before everything else: a browser sends a preflight without
	// credentials, so an OPTIONS that reaches the JWT middleware is
	// answered 401 and the browser blocks the real request.
	r.Use(corsmw.Middleware(corsmw.DefaultConfig(
		corsmw.OriginsFromEnv(os.Getenv("CORS_ALLOWED_ORIGINS")))))
	r.Use(observe.Middleware("siem-service"))
	r.Use(chimiddleware.RequestID)
	// The client address, from the forwarded chain, not from whatever the
	// caller wrote in a header. See internal/pkg/clientip.
	r.Use(clientip.Middleware())
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))

	r.Handle("/metrics", observe.MetricsHandler())
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"siem-service"}`)
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(authmw.RequireJWT(jwtVerifier, logger, providerOpt))
		siemHandler.RegisterRoutes(r)
		libraryHandler.RegisterRoutes(r)
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
		logger.Info().Str("addr", srv.Addr).Msg("siem-service started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("server error")
		}
	}()

	<-quit
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
	logger.Info().Msg("siem-service stopped")
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
