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

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/cyberradar/platform/internal/pkg/authmw"
	"github.com/cyberradar/platform/internal/pkg/db"
	pkgjwt "github.com/cyberradar/platform/internal/pkg/jwt"
	"github.com/cyberradar/platform/services/dashboard/internal/handler"
	"github.com/cyberradar/platform/services/dashboard/internal/model"
	"github.com/cyberradar/platform/services/dashboard/internal/repository"
	"github.com/cyberradar/platform/services/dashboard/internal/service"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	kafkago "github.com/segmentio/kafka-go"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	logger := log.With().Str("service", "dashboard-service").Logger()

	port := envOrDefault("SERVICE_PORT", "8015")
	jwtVerifier, err := pkgjwt.NewVerifierFromFile(mustEnv("JWT_PUBLIC_KEY_PATH"))
	if err != nil {
		log.Fatal().Err(err).Msg("load jwt public key")
	}
	dbURL := mustEnv("DATABASE_URL")
	chURL := mustEnv("CLICKHOUSE_URL")
	brokers := strings.Split(mustEnv("KAFKA_BROKERS"), ",")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── PostgreSQL ────────────────────────────────────────────────────────────
	pool, err := db.NewPostgresPool(ctx, db.DefaultPostgresConfig(dbURL))
	if err != nil {
		logger.Fatal().Err(err).Msg("postgres connect failed")
	}
	defer pool.Close()

	// ── ClickHouse ────────────────────────────────────────────────────────────
	chConn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{chURL},
		Auth: clickhouse.Auth{
			Database: "crp_dash",
			Username: envOrDefault("CLICKHOUSE_USER", "default"),
			Password: envOrDefault("CLICKHOUSE_PASSWORD", ""),
		},
		Settings: clickhouse.Settings{"max_execution_time": 30},
	})
	if err != nil {
		logger.Fatal().Err(err).Msg("clickhouse connect failed")
	}
	defer chConn.Close()

	// ── Repositories / services ───────────────────────────────────────────────
	dashRepo := repository.NewDashboardRepository(pool)
	kpiRepo := repository.NewKPIRepository(chConn)
	dashSvc := service.NewDashboardService(dashRepo, kpiRepo, logger)
	dashH := handler.NewDashboardHandler(dashSvc)

	// ── Kafka consumer: ingest KPI snapshots from all domain services ─────────
	// Each domain publishes a crp.events.kpi message with:
	//   {"tenant_id":"...", "domain":"siem", "metric_key":"open_alerts", "metric_value":42, "labels":{}}
	go func() {
		r := kafkago.NewReader(kafkago.ReaderConfig{
			Brokers:     brokers,
			Topic:       "crp.events.kpi",
			GroupID:     "crp-dashboard-kpi-ingestor",
			StartOffset: kafkago.LastOffset,
			MinBytes:    1,
			MaxBytes:    10 << 20,
			MaxWait:     time.Second,
		})
		defer r.Close()
		logger.Info().Msg("dashboard kpi consumer started")

		for {
			msg, err := r.ReadMessage(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				logger.Warn().Err(err).Msg("kpi_kafka_read_error")
				time.Sleep(2 * time.Second)
				continue
			}

			var snap struct {
				TenantID    string            `json:"tenant_id"`
				Domain      string            `json:"domain"`
				MetricKey   string            `json:"metric_key"`
				MetricValue float64           `json:"metric_value"`
				Labels      map[string]string `json:"labels"`
			}
			if err := json.Unmarshal(msg.Value, &snap); err != nil {
				continue
			}
			tenantID, err := uuid.Parse(snap.TenantID)
			if err != nil {
				continue
			}
			dashSvc.IngestKPISnapshot(ctx, model.KPISnapshot{
				TenantID:    tenantID,
				Domain:      snap.Domain,
				MetricKey:   snap.MetricKey,
				MetricValue: snap.MetricValue,
				Labels:      snap.Labels,
				SnappedAt:   time.Now().UTC(),
			})
		}
	}()

	// ── HTTP server ───────────────────────────────────────────────────────────
	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"dashboard-service"}`)
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(authmw.RequireJWT(jwtVerifier, logger))
		r.Use(authmw.RequirePermissionByMethod("reports"))
		dashH.RegisterRoutes(r)
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
		logger.Info().Str("addr", srv.Addr).Msg("dashboard-service started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("server error")
		}
	}()

	<-quit
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
	logger.Info().Msg("dashboard-service stopped")
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
