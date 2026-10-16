package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cyberradar/platform/internal/pkg/authmw"
	"github.com/cyberradar/platform/internal/pkg/clientip"
	"github.com/cyberradar/platform/internal/pkg/corsmw"
	"github.com/cyberradar/platform/internal/pkg/db"
	"github.com/cyberradar/platform/internal/pkg/graphdb"
	pkgjwt "github.com/cyberradar/platform/internal/pkg/jwt"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/internal/pkg/kpi"
	"github.com/cyberradar/platform/internal/pkg/observe"
	"github.com/cyberradar/platform/services/knowledgegraph/internal/handler"
	"github.com/cyberradar/platform/services/knowledgegraph/internal/repository"
	"github.com/cyberradar/platform/services/knowledgegraph/internal/service"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/segmentio/kafka-go"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	logger := log.With().Str("service", "knowledgegraph-service").Logger()

	// Optional: with no collector configured this is a no-op, so a
	// missing collector never stops the service from starting.
	shutdownTracing, tracingErr := observe.InitTracing(context.Background(),
		"knowledgegraph-service", envOrDefault("SERVICE_VERSION", "dev"),
		os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if tracingErr != nil {
		logger.Warn().Err(tracingErr).Msg("tracing disabled")
	}
	defer func() { _ = shutdownTracing(context.Background()) }()

	port := envOrDefault("SERVICE_PORT", "8013")
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

	// ── Repositories / services ───────────────────────────────────────────────
	kgRepo := repository.NewKGRepository(pool)

	// ── Neo4j, when a deployment has one ──────────────────────────────────────
	//
	// Configuring NEO4J_URI turns on the mirror: every entity and relationship
	// goes to PostgreSQL and then to Neo4j. Traversals stay on PostgreSQL until
	// KG_GRAPH_READS is set to "neo4j", and that switch is only defensible once
	// `kg-reconcile` reports parity for the tenants in question.
	//
	// Startup fails on an unreachable Neo4j rather than carrying on without it:
	// a mirror that is configured but silently not written drifts from the
	// source of truth, and a traversal on a drifted graph asserts connections
	// that do not exist.
	var kgOpts []service.Option
	if cfg, configured := graphdb.FromEnv(os.Getenv); configured {
		neoStore, err := repository.NewNeo4jGraphStore(ctx, cfg, kgRepo)
		if err != nil {
			logger.Fatal().Err(err).Str("uri", cfg.URI).Msg("neo4j connect failed")
		}
		defer func() { _ = neoStore.Close(context.Background()) }()
		kgOpts = append(kgOpts, service.WithMirror(neoStore))

		reads := envOrDefault("KG_GRAPH_READS", "postgres")
		if reads == "neo4j" {
			kgOpts = append(kgOpts, service.WithGraphReader(neoStore))
		}
		logger.Info().Str("uri", cfg.URI).Str("reads", reads).Msg("neo4j graph mirror enabled")
	}

	kgSvc := service.NewKGService(kgRepo, logger, kgOpts...)
	kgH := handler.NewKGHandler(kgSvc)

	// ── Kafka consumer: auto-ingest entities from enriched events ─────────────
	go func() {
		r := kafka.NewReader(kafka.ReaderConfig{
			Brokers:     brokers,
			Topic:       "crp.events.enriched",
			GroupID:     "crp-kg-ingestor",
			StartOffset: pkgkafka.OnlyNewEvents,
			MinBytes:    1,
			MaxBytes:    10 << 20,
			MaxWait:     time.Second,
			// A consumer that starts before its topic exists is assigned no
			// partitions, and without this it never notices when the topic
			// appears — it blocks on ReadMessage forever, with no error to show
			// for it. Seen for real: the dashboard's KPI ingestor started ahead of
			// the first producer and consumed nothing until it was restarted.
			WatchPartitionChanges: true,
		})
		defer r.Close()
		logger.Info().Msg("kg kafka consumer started")

		for {
			msg, err := r.ReadMessage(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				logger.Warn().Err(err).Msg("kg_kafka_read_error")
				time.Sleep(2 * time.Second)
				continue
			}

			var ev struct {
				TenantID  string         `json:"tenant_id"`
				EventType string         `json:"event_type"`
				Severity  string         `json:"severity"`
				RawEvent  map[string]any `json:"raw_event"`
			}
			if err := json.Unmarshal(msg.Value, &ev); err != nil {
				continue
			}
			tenantID, err := uuid.Parse(ev.TenantID)
			if err != nil {
				continue
			}
			ipSource, _ := ev.RawEvent["ip_source"].(string)
			kgSvc.IngestEvent(ctx, tenantID, "siem", ev.EventType, ev.Severity, ipSource)
		}
	}()

	// ── Kafka producer (publishes graph-change events) ────────────────────────
	_ = pkgkafka.NewProducer(pkgkafka.ProducerConfig{
		Brokers: brokers,
		Topic:   "crp.events.kg",
	}, logger)

	// ── HTTP server ───────────────────────────────────────────────────────────
	// ── Report this domain's KPIs to the dashboard ────────────────────────────
	// PlatformOverview is assembled from the latest snapshot each domain
	// published. Nothing published any, so the overview answered zero for every
	// tenant — see internal/pkg/kpi.
	kpi.Start(ctx, kpi.Config{
		Brokers: brokers,
		Domain:  "kg",
		Tenants: kpi.TenantsFromPostgres(pool),
		Source:  kgSvc.KPISamples,
	}, logger)

	r := chi.NewRouter()
	// Before everything else: a browser sends a preflight without
	// credentials, so an OPTIONS that reaches the JWT middleware is
	// answered 401 and the browser blocks the real request.
	r.Use(corsmw.Middleware(corsmw.DefaultConfig(
		corsmw.OriginsFromEnv(os.Getenv("CORS_ALLOWED_ORIGINS")))))
	r.Use(observe.Middleware("knowledgegraph-service"))
	r.Use(chimiddleware.RequestID)
	// The client address, from the forwarded chain, not from whatever the
	// caller wrote in a header. See internal/pkg/clientip.
	r.Use(clientip.Middleware())
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))

	r.Handle("/metrics", observe.MetricsHandler())
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"knowledgegraph-service"}`)
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(authmw.RequireJWT(jwtVerifier, logger, providerOpt))
		r.Use(authmw.RequirePermissionByMethod("knowledge_graph"))
		kgH.RegisterRoutes(r)
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
		logger.Info().Str("addr", srv.Addr).Msg("knowledgegraph-service started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("server error")
		}
	}()

	<-quit
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
	logger.Info().Msg("knowledgegraph-service stopped")
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
