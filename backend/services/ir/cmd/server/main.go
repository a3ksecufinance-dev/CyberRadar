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

	"github.com/cyberradar/platform/internal/pkg/authctx"
	"github.com/cyberradar/platform/internal/pkg/db"
	"github.com/cyberradar/platform/services/ir/internal/handler"
	"github.com/cyberradar/platform/services/ir/internal/repository"
	"github.com/cyberradar/platform/services/ir/internal/service"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	kafka "github.com/segmentio/kafka-go"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	logger := log.With().Str("service", "ir-service").Logger()

	dbURL      := mustEnv("DATABASE_URL")
	jwtSecret  := mustEnv("JWT_SECRET")
	kafkaBroker := envOrDefault("KAFKA_BROKERS", "localhost:9092")
	port       := envOrDefault("SERVICE_PORT", "8026")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── PostgreSQL ────────────────────────────────────────────────────────────
	pool, err := db.NewPostgresPool(ctx, db.DefaultPostgresConfig(dbURL))
	if err != nil {
		logger.Fatal().Err(err).Msg("postgres connect failed")
	}
	defer pool.Close()

	// ── Kafka writer (IR events) ──────────────────────────────────────────────
	broker := strings.Split(kafkaBroker, ",")[0]
	kw := &kafka.Writer{
		Addr:         kafka.TCP(broker),
		Topic:        "crp.events.ir",
		Balancer:     &kafka.LeastBytes{},
		WriteTimeout: 5 * time.Second,
		ReadTimeout:  5 * time.Second,
	}
	defer kw.Close()

	// ── IR service stack ──────────────────────────────────────────────────────
	repo := repository.NewIRRepository(pool)
	svc  := service.NewIRService(repo, kw, logger)
	h    := handler.NewIRHandler(svc, logger)

	// ── HTTP server ───────────────────────────────────────────────────────────
	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"ir-service"}`)
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(jwtMiddleware(jwtSecret, logger))
		r.Mount("/ir", h.Routes())
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
		logger.Info().Str("addr", srv.Addr).Msg("ir-service started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("server error")
		}
	}()

	<-quit
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
	logger.Info().Msg("ir-service stopped")
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
			identity, claimsErr := authctx.Parse(claims.TenantID, claims.UserID, "", claims.Roles, claims.IsAdmin)
			if claimsErr != nil {
				logger.Warn().Err(claimsErr).Str("path", r.URL.Path).Msg("jwt_claims_invalid")
				http.Error(w, `{"error":{"code":"UNAUTHORIZED","message":"Invalid token claims"}}`,
					http.StatusUnauthorized)
				return
			}
			ctx := authctx.With(r.Context(), identity)
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
