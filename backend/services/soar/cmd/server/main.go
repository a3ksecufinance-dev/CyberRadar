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
	"github.com/cyberradar/platform/services/soar/internal/handler"
	"github.com/cyberradar/platform/services/soar/internal/repository"
	"github.com/cyberradar/platform/services/soar/internal/service"
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
	logger := log.With().Str("service", "soar-service").Logger()

	port      := envOrDefault("SERVICE_PORT", "8014")
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
	soarRepo := repository.NewSOARRepository(pool)
	soarSvc  := service.NewSOARService(soarRepo, logger)
	soarH    := handler.NewSOARHandler(soarSvc)

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
	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"soar-service"}`)
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(jwtMiddleware(jwtSecret, logger))
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
		Brokers:     brokers,
		Topic:       topic,
		GroupID:     "crp-soar-auto-trigger",
		StartOffset: kafka.LastOffset,
		MinBytes:    1,
		MaxBytes:    10 << 20,
		MaxWait:     time.Second,
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
