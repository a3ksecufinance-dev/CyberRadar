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
	"github.com/cyberradar/platform/internal/pkg/db"
	"github.com/cyberradar/platform/services/dashboard/internal/handler"
	"github.com/cyberradar/platform/services/dashboard/internal/model"
	"github.com/cyberradar/platform/services/dashboard/internal/repository"
	"github.com/cyberradar/platform/services/dashboard/internal/service"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	kafkago "github.com/segmentio/kafka-go"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	logger := log.With().Str("service", "dashboard-service").Logger()

	port     := envOrDefault("SERVICE_PORT", "8015")
	jwtSecret := mustEnv("JWT_SECRET")
	dbURL    := mustEnv("DATABASE_URL")
	chURL    := mustEnv("CLICKHOUSE_URL")
	brokers  := strings.Split(mustEnv("KAFKA_BROKERS"), ",")

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
	kpiRepo  := repository.NewKPIRepository(chConn)
	dashSvc  := service.NewDashboardService(dashRepo, kpiRepo, logger)
	dashH    := handler.NewDashboardHandler(dashSvc)

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
		r.Use(jwtMiddleware(jwtSecret, logger))
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

type jwtClaims struct {
	TenantID string   `json:"tid"`
	UserID   string   `json:"uid"`
	IsAdmin  bool     `json:"is_admin"`
	Roles    []string `json:"roles"`
	gojwt.RegisteredClaims
}

func jwtMiddleware(secret string, logger zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if len(auth) < 8 || auth[:7] != "Bearer " {
				http.Error(w, `{"error":{"code":"UNAUTHORIZED","message":"Missing Authorization"}}`, http.StatusUnauthorized)
				return
			}
			token, err := gojwt.ParseWithClaims(auth[7:], &jwtClaims{}, func(t *gojwt.Token) (any, error) {
				return []byte(secret), nil
			})
			if err != nil || !token.Valid {
				http.Error(w, `{"error":{"code":"UNAUTHORIZED","message":"Invalid token"}}`, http.StatusUnauthorized)
				return
			}
			claims := token.Claims.(*jwtClaims)
			if claims.TenantID == "" {
				http.Error(w, `{"error":{"code":"UNAUTHORIZED","message":"Missing tenant"}}`, http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), "tenant_id", claims.TenantID)
			ctx = context.WithValue(ctx, "user_id", claims.UserID)
			ctx = context.WithValue(ctx, "is_super_admin", claims.IsAdmin)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
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
