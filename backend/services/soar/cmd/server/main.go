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
	pkgjwt "github.com/cyberradar/platform/internal/pkg/jwt"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/internal/pkg/kpi"
	"github.com/cyberradar/platform/internal/pkg/observe"
	"github.com/cyberradar/platform/internal/pkg/svcauth"
	"github.com/cyberradar/platform/services/soar/internal/handler"
	"github.com/cyberradar/platform/services/soar/internal/repository"
	"github.com/cyberradar/platform/services/soar/internal/service"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/segmentio/kafka-go"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	logger := log.With().Str("service", "soar-service").Logger()

	// Optional: with no collector configured this is a no-op, so a
	// missing collector never stops the service from starting.
	shutdownTracing, tracingErr := observe.InitTracing(context.Background(),
		"soar-service", envOrDefault("SERVICE_VERSION", "dev"),
		os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if tracingErr != nil {
		logger.Warn().Err(tracingErr).Msg("tracing disabled")
	}
	defer func() { _ = shutdownTracing(context.Background()) }()

	port := envOrDefault("SERVICE_PORT", "8014")
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

	// ── Remediation credentials ───────────────────────────────────────────────
	// The SOAR acts with no user behind it, on alerts belonging to any tenant,
	// so it authenticates with a platform-scoped service account and takes a
	// token per tenant. Its actions reach other services with that token and
	// nothing else — it holds no standing privilege of its own.
	tokens, err := svcauth.NewPool(svcauth.Config{
		IdentityURL:  mustEnv("IDENTITY_URL"),
		ClientID:     mustEnv("SOAR_CLIENT_ID"),
		ClientSecret: mustEnv("SOAR_CLIENT_SECRET"),
	})
	if err != nil {
		logger.Fatal().Err(err).Msg("service account setup failed")
	}

	// A service with no URL disables the actions that need it; they then fail
	// saying which service is unconfigured, rather than reporting a
	// containment that never happened.
	endpoints := service.Endpoints{
		// Without it the actions still run and each one logs that it could not
		// be recorded, which is the right order of priorities: a containment
		// that happened and was not written down beats one that did not happen.
		Audit:        os.Getenv("AUDIT_URL"),
		Netsec:       os.Getenv("NETSEC_URL"),
		Identity:     os.Getenv("IDENTITY_URL"),
		Asset:        os.Getenv("ASSET_URL"),
		ThreatIntel:  os.Getenv("TI_URL"),
		Vuln:         os.Getenv("VULN_URL"),
		Notification: os.Getenv("NOTIFICATION_URL"),
		SIEM:         os.Getenv("SIEM_URL"),
		IR:           os.Getenv("IR_URL"),
		AttackPath:   os.Getenv("ATTACKPATH_URL"),
	}
	dispatcher := service.NewHTTPDispatcher(endpoints, tokens, mustEnv("SOAR_CLIENT_ID"), logger)

	// ── Repositories / services ───────────────────────────────────────────────
	soarRepo := repository.NewSOARRepository(pool)
	soarSvc := service.NewSOARService(soarRepo, dispatcher, logger)
	soarH := handler.NewSOARHandler(soarSvc)

	// ── Kafka consumer: auto-trigger playbooks from alerts ────────────────────
	// Listens on crp.events.alerts (SIEM alerts), crp.events.ueba, crp.events.ti
	for _, topic := range []string{"crp.events.alerts", "crp.events.ueba", "crp.events.ti"} {
		go consumeTopic(ctx, brokers, topic, soarSvc, logger)
	}

	// ── Kafka producer (publishes soar events) ────────────────────────────────
	_ = pkgkafka.NewProducer(pkgkafka.ProducerConfig{
		Brokers: brokers,
		Topic:   "crp.events.soar",
	}, logger)

	// ── HTTP server ───────────────────────────────────────────────────────────
	// ── Report this domain's KPIs to the dashboard ────────────────────────────
	// PlatformOverview is assembled from the latest snapshot each domain
	// published. Nothing published any, so the overview answered zero for every
	// tenant — see internal/pkg/kpi.
	kpi.Start(ctx, kpi.Config{
		Brokers: brokers,
		Domain:  "soar",
		Tenants: kpi.TenantsFromPostgres(pool),
		Source:  soarSvc.KPISamples,
	}, logger)

	r := chi.NewRouter()
	// Before everything else: a browser sends a preflight without
	// credentials, so an OPTIONS that reaches the JWT middleware is
	// answered 401 and the browser blocks the real request.
	r.Use(corsmw.Middleware(corsmw.DefaultConfig(
		corsmw.OriginsFromEnv(os.Getenv("CORS_ALLOWED_ORIGINS")))))
	r.Use(observe.Middleware("soar-service"))
	r.Use(chimiddleware.RequestID)
	// The client address, from the forwarded chain, not from whatever the
	// caller wrote in a header. See internal/pkg/clientip.
	r.Use(clientip.Middleware())
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))

	r.Handle("/metrics", observe.MetricsHandler())
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"soar-service"}`)
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(authmw.RequireJWT(jwtVerifier, logger, providerOpt))
		r.Use(authmw.RequirePermissionByMethod("soar"))
		soarH.RegisterRoutes(r)
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
		logger.Info().Str("addr", srv.Addr).Msg("soar-service started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("server error")
		}
	}()

	<-quit
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
	logger.Info().Msg("soar-service stopped")
}

// consumeTopic reads from a Kafka topic and auto-triggers matching playbooks.
func consumeTopic(ctx context.Context, brokers []string, topic string, soarSvc *service.SOARService, logger zerolog.Logger) {
	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers: brokers,
		Topic:   topic,
		GroupID: "crp-soar-auto-trigger",
		// Deliberately only new events, and this is the one place where it is
		// the safe direction: replaying an alert means running its playbook
		// again, so a fresh group reading history would re-block addresses and
		// re-isolate hosts on the strength of what already happened.
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
	logger.Info().Str("topic", topic).Msg("soar kafka consumer started")

	for {
		msg, err := r.ReadMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Warn().Err(err).Str("topic", topic).Msg("soar_kafka_read_error")
			time.Sleep(2 * time.Second)
			continue
		}

		var ev struct {
			TenantID      string         `json:"tenant_id"`
			Severity      string         `json:"severity"`
			SourceService string         `json:"source_service"`
			EventType     string         `json:"event_type"`
			RawEvent      map[string]any `json:"raw_event"`
		}
		if err := json.Unmarshal(msg.Value, &ev); err != nil {
			continue
		}
		tenantID, err := uuid.Parse(ev.TenantID)
		if err != nil {
			continue
		}

		// Map topic → trigger type
		triggerType := "alert"
		switch topic {
		case "crp.events.ueba":
			triggerType = "anomaly"
		case "crp.events.ti":
			triggerType = "ioc_match"
		}

		triggerEvent := map[string]any{
			"event_type":     ev.EventType,
			"severity":       ev.Severity,
			"source_service": ev.SourceService,
		}
		for k, v := range ev.RawEvent {
			triggerEvent[k] = v
		}

		soarSvc.AutoTriggerFromEvent(ctx, tenantID, triggerType, ev.Severity, ev.SourceService, triggerEvent)
	}
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
