package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	internaldb "github.com/cyberradar/platform/internal/pkg/db"
	"github.com/cyberradar/platform/services/tenant/internal/handler"
	"github.com/cyberradar/platform/services/tenant/internal/repository"
	"github.com/cyberradar/platform/services/tenant/internal/service"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// ─── Logger ──────────────────────────────────────────────
	logLevel := zerolog.DebugLevel
	if os.Getenv("LOG_LEVEL") == "info" {
		logLevel = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(logLevel)
	logger := log.With().Str("service", "tenant-service").Logger()

	// ─── Config ──────────────────────────────────────────────
	dsn := mustEnv("DATABASE_URL")
	port := envOrDefault("SERVICE_PORT", "8001")
	jwtSecret := mustEnv("JWT_SECRET")

	// ─── Database ────────────────────────────────────────────
	ctx := context.Background()
	dbPool, err := internaldb.NewPostgresPool(ctx, internaldb.DefaultPostgresConfig(dsn))
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to connect to postgres")
	}
	defer dbPool.Close()
	logger.Info().Msg("postgres connected")

	// ─── Wiring ──────────────────────────────────────────────
	tenantRepo := repository.NewTenantRepository(dbPool)
	tenantSvc := service.NewTenantService(tenantRepo, logger)
	tenantHandler := handler.NewTenantHandler(tenantSvc)

	// ─── Router ──────────────────────────────────────────────
	r := chi.NewRouter()

	// Global middleware
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))
	r.Use(chimiddleware.Compress(5))

	// Health endpoints (no auth required)
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"tenant-service"}`)
	})
	r.Get("/ready", func(w http.ResponseWriter, r *http.Request) {
		if err := dbPool.Ping(r.Context()); err != nil {
			http.Error(w, `{"status":"not_ready"}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ready"}`)
	})

	// API routes (JWT auth middleware applied)
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(jwtMiddleware(jwtSecret, logger))
		tenantHandler.RegisterRoutes(r)
	})

	// ─── Server ──────────────────────────────────────────────
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Info().Str("addr", srv.Addr).Msg("tenant-service started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("server error")
		}
	}()

	<-quit
	logger.Info().Msg("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error().Err(err).Msg("shutdown error")
	}
	logger.Info().Msg("tenant-service stopped")
}

type jwtClaims struct {
	TenantID string   `json:"tid"`
	UserID   string   `json:"uid"`
	IsAdmin  bool     `json:"is_admin"`
	Roles    []string `json:"roles"`
	gojwt.RegisteredClaims
}

func validateJWT(tokenStr, secret string) (*jwtClaims, error) {
	token, err := gojwt.ParseWithClaims(tokenStr, &jwtClaims{}, func(t *gojwt.Token) (any, error) {
		return []byte(secret), nil
	})
	if err != nil || !token.Valid {
		return nil, err
	}
	claims, ok := token.Claims.(*jwtClaims)
	if !ok {
		return nil, gojwt.ErrTokenInvalidClaims
	}
	return claims, nil
}

// jwtMiddleware validates JWT and injects tenant_id + roles into request context.
// SECURITY: tenant_id MUST come from the JWT — never from request body or query params.
func jwtMiddleware(secret string, logger zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if len(auth) < 8 || auth[:7] != "Bearer " {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":{"code":"UNAUTHORIZED","message":"Missing or invalid Authorization header"}}`,
					http.StatusUnauthorized)
				return
			}

			tokenStr := auth[7:]
			claims, err := validateJWT(tokenStr, secret)
			if err != nil {
				logger.Warn().Err(err).Str("path", r.URL.Path).Msg("jwt_invalid")
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":{"code":"UNAUTHORIZED","message":"Invalid or expired token"}}`,
					http.StatusUnauthorized)
				return
			}

			// Inject into context — downstream code reads from context only
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

// ─── Config helpers ───────────────────────────────────────────────────────────

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatal().Str("key", key).Msg("required environment variable is missing")
	}
	return v
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
