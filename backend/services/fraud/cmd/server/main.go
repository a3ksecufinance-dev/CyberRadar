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

	"github.com/cyberradar/platform/internal/pkg/db"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/services/fraud/internal/handler"
	"github.com/cyberradar/platform/services/fraud/internal/repository"
	"github.com/cyberradar/platform/services/fraud/internal/service"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	logger := log.With().Str("service", "fraud-service").Logger()

	port      := envOrDefault("SERVICE_PORT", "8020")
	jwtSecret := mustEnv("JWT_SECRET")
	dbURL     := mustEnv("DATABASE_URL")
	brokers   := strings.Split(mustEnv("KAFKA_BROKERS"), ",")

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
	fraudSvc  := service.NewFraudService(fraudRepo, producer, logger)
	fraudH    := handler.NewFraudHandler(fraudSvc)

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
		r.Use(jwtMiddleware(jwtSecret, logger))
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
