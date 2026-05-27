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
	"github.com/cyberradar/platform/internal/pkg/db"
	"github.com/cyberradar/platform/internal/pkg/event"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/services/ueba/internal/handler"
	"github.com/cyberradar/platform/services/ueba/internal/repository"
	"github.com/cyberradar/platform/services/ueba/internal/service"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	logger := log.With().Str("service", "ueba-service").Logger()

	port      := envOrDefault("SERVICE_PORT", "8009")
	jwtSecret := mustEnv("JWT_SECRET")
	dbURL     := mustEnv("DATABASE_URL")
	chDSN     := mustEnv("CLICKHOUSE_DSN")
	brokers   := strings.Split(mustEnv("KAFKA_BROKERS"), ",")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── PostgreSQL ────────────────────────────────────────────────────────────
	pool, err := db.NewPostgresPool(ctx, db.DefaultPostgresConfig(dbURL))
	if err != nil {
		logger.Fatal().Err(err).Msg("postgres connect failed")
	}
	defer pool.Close()

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

	// ── Repositories ──────────────────────────────────────────────────────────
	profileRepo  := repository.NewProfileRepository(pool)
	behaviorRepo := repository.NewBehaviorRepository(chConn)

	// ── UEBA service ──────────────────────────────────────────────────────────
	uebaSvc     := service.NewUEBAService(profileRepo, behaviorRepo, logger)
	uebaHandler := handler.NewUEBAHandler(uebaSvc)

	// ── Behavior Engine (Kafka consumer on crp.events.enriched) ───────────────
	engineConsumer := pkgkafka.NewConsumer(pkgkafka.ConsumerConfig{
		Brokers:     brokers,
		Topic:       event.TopicEnriched,
		GroupID:     "crp-ueba-engine",
		StartOffset: -1,
	}, logger)

	anomalyPublisher := pkgkafka.NewProducer(pkgkafka.ProducerConfig{
		Brokers: brokers,
		Topic:   "crp.events.ueba",
	}, logger)
	defer anomalyPublisher.Close()

	engine := service.NewBehaviorEngine(profileRepo, behaviorRepo, engineConsumer, anomalyPublisher, logger)
	go func() {
		if err := engine.Run(ctx); err != nil {
			logger.Error().Err(err).Msg("ueba_engine_error")
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
		fmt.Fprintf(w, `{"status":"ok","service":"ueba-service"}`)
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(jwtMiddleware(jwtSecret, logger))
		uebaHandler.RegisterRoutes(r)
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
		logger.Info().Str("addr", srv.Addr).Msg("ueba-service started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("server error")
		}
	}()

	<-quit
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
	logger.Info().Msg("ueba-service stopped")
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
