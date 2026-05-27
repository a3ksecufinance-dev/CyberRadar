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

	"github.com/cyberradar/platform/internal/pkg/db"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/services/apifw/internal/handler"
	"github.com/cyberradar/platform/services/apifw/internal/repository"
	"github.com/cyberradar/platform/services/apifw/internal/service"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/segmentio/kafka-go"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	logger := log.With().Str("service", "apifw-service").Logger()

	port      := envOrDefault("SERVICE_PORT", "8017")
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

	// ── Repositories / services ───────────────────────────────────────────────
	apifwRepo := repository.NewAPIFWRepository(pool)
	apifwSvc  := service.NewAPIFWService(apifwRepo, logger)
	apifwH    := handler.NewAPIFWHandler(apifwSvc)

	// ── Kafka consumer: fan-out events to webhooks ────────────────────────────
	// Listen on five event topics and deliver to matching tenant webhooks.
	eventTopics := []string{
		"crp.events.alerts",
		"crp.events.soar",
		"crp.events.ti",
		"crp.events.ueba",
		"crp.events.vuln",
	}
	for _, topic := range eventTopics {
		go consumeTopic(ctx, brokers, topic, apifwSvc, logger)
	}

	// ── Kafka producer (publishes apifw events) ───────────────────────────────
	_ = pkgkafka.NewProducer(pkgkafka.ProducerConfig{
		Brokers: brokers,
		Topic:   "crp.events.apifw",
	}, logger)

	// ── HTTP server ───────────────────────────────────────────────────────────
	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"apifw-service"}`)
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(jwtMiddleware(jwtSecret, logger))
		apifwH.RegisterRoutes(r)
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
		logger.Info().Str("addr", srv.Addr).Msg("apifw-service started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("server error")
		}
	}()

	<-quit
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
	logger.Info().Msg("apifw-service stopped")
}

// consumeTopic reads platform events and fans them out to matching tenant webhooks.
func consumeTopic(ctx context.Context, brokers []string, topic string, apifwSvc *service.APIFWService, logger zerolog.Logger) {
	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:     brokers,
		Topic:       topic,
		GroupID:     "crp-apifw-webhook-delivery",
		StartOffset: kafka.LastOffset,
		MinBytes:    1,
		MaxBytes:    10 << 20,
		MaxWait:     time.Second,
	})
	defer r.Close()
	logger.Info().Str("topic", topic).Msg("apifw kafka consumer started")

	for {
		msg, err := r.ReadMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Warn().Err(err).Str("topic", topic).Msg("apifw_kafka_read_error")
			time.Sleep(2 * time.Second)
			continue
		}

		var ev struct {
			TenantID  string         `json:"tenant_id"`
			EventType string         `json:"event_type"`
			Payload   map[string]any `json:"payload"`
		}
		if err := json.Unmarshal(msg.Value, &ev); err != nil {
			logger.Warn().Err(err).Str("topic", topic).Msg("apifw_kafka_decode_error")
			continue
		}
		tenantID, err := uuid.Parse(ev.TenantID)
		if err != nil {
			continue
		}

		// Map topic → canonical event type if not already set.
		eventType := ev.EventType
		if eventType == "" {
			switch topic {
			case "crp.events.alerts":
				eventType = "alert.created"
			case "crp.events.soar":
				eventType = "incident.created"
			case "crp.events.ti":
				eventType = "ioc.matched"
			case "crp.events.ueba":
				eventType = "anomaly.detected"
			case "crp.events.vuln":
				eventType = "vuln.found"
			default:
				eventType = topic
			}
		}

		payload := ev.Payload
		if payload == nil {
			_ = json.Unmarshal(msg.Value, &payload)
		}

		// Fan-out to all matching webhooks for this tenant asynchronously.
		go apifwSvc.DeliverWebhook(ctx, tenantID, eventType, payload)
	}
}

// ─── JWT middleware ───────────────────────────────────────────────────────────

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

// ─── Helpers ──────────────────────────────────────────────────────────────────

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
