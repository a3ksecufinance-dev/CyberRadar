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
	"github.com/cyberradar/platform/internal/pkg/graphdb"
	pkgjwt "github.com/cyberradar/platform/internal/pkg/jwt"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/internal/pkg/kpi"
	"github.com/cyberradar/platform/internal/pkg/observe"
	"github.com/cyberradar/platform/services/attackpath/internal/handler"
	"github.com/cyberradar/platform/services/attackpath/internal/repository"
	"github.com/cyberradar/platform/services/attackpath/internal/service"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	logger := log.With().Str("service", "attackpath-service").Logger()

	// Optional: with no collector configured this is a no-op, so a
	// missing collector never stops the service from starting.
	shutdownTracing, tracingErr := observe.InitTracing(context.Background(),
		"attackpath-service", envOrDefault("SERVICE_VERSION", "dev"),
		os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if tracingErr != nil {
		logger.Warn().Err(tracingErr).Msg("tracing disabled")
	}
	defer func() { _ = shutdownTracing(context.Background()) }()

	port := envOrDefault("SERVICE_PORT", "8012")
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

	// ── Kafka producer (publishes graph events for downstream consumers) ───────
	producer := pkgkafka.NewProducer(pkgkafka.ProducerConfig{
		Brokers: brokers,
		Topic:   "crp.events.attackpath",
	}, logger)
	_ = producer

	// ── Repositories / services ───────────────────────────────────────────────
	graphRepo := repository.NewGraphRepository(pool)

	// ── Neo4j, when a deployment has one ──────────────────────────────────────
	//
	// Configuring NEO4J_URI turns on the mirror: every graph write goes to
	// PostgreSQL and then to Neo4j. Reads stay on PostgreSQL until
	// ATTACKPATH_GRAPH_READS is set to "neo4j", and that switch is only
	// defensible once `reconcile` reports parity for the tenants in question.
	//
	// Startup fails on an unreachable Neo4j rather than carrying on without
	// it: a mirror that is configured but silently not written drifts from the
	// source of truth, and a traversal on a drifted graph reports attack paths
	// that do not exist.
	var graphOpts []service.Option
	if cfg, configured := graphdb.FromEnv(os.Getenv); configured {
		neoStore, err := repository.NewNeo4jGraphStore(ctx, cfg, graphRepo)
		if err != nil {
			logger.Fatal().Err(err).Str("uri", cfg.URI).Msg("neo4j connect failed")
		}
		defer func() { _ = neoStore.Close(context.Background()) }()
		graphOpts = append(graphOpts, service.WithMirror(neoStore))

		reads := envOrDefault("ATTACKPATH_GRAPH_READS", "postgres")
		if reads == "neo4j" {
			graphOpts = append(graphOpts, service.WithGraphStore(neoStore))
		}
		logger.Info().Str("uri", cfg.URI).Str("reads", reads).Msg("neo4j graph mirror enabled")
	}

	attackSvc := service.NewAttackPathService(graphRepo, logger, graphOpts...)
	attackH := handler.NewAttackPathHandler(attackSvc)

	// ── HTTP server ───────────────────────────────────────────────────────────
	// ── Report this domain's KPIs to the dashboard ────────────────────────────
	// PlatformOverview is assembled from the latest snapshot each domain
	// published. Nothing published any, so the overview answered zero for every
	// tenant — see internal/pkg/kpi.
	kpi.Start(ctx, kpi.Config{
		Brokers: brokers,
		Domain:  "attackpath",
		Tenants: kpi.TenantsFromPostgres(pool),
		Source:  attackSvc.KPISamples,
	}, logger)

	r := chi.NewRouter()
	r.Use(observe.Middleware("attackpath-service"))
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(60 * time.Second)) // longer timeout: BFS can be slow

	r.Handle("/metrics", observe.MetricsHandler())
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"attackpath-service"}`)
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(authmw.RequireJWT(jwtVerifier, logger))
		r.Use(authmw.RequirePermissionByMethod("attack_paths"))
		attackH.RegisterRoutes(r)
	})

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Info().Str("addr", srv.Addr).Msg("attackpath-service started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("server error")
		}
	}()

	<-quit
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
	logger.Info().Msg("attackpath-service stopped")
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
