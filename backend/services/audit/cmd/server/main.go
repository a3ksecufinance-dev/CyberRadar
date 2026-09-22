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

	chdriver "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/cyberradar/platform/internal/pkg/authctx"
	internaldb "github.com/cyberradar/platform/internal/pkg/db"
	"github.com/cyberradar/platform/services/audit/internal/handler"
	"github.com/cyberradar/platform/services/audit/internal/repository"
	"github.com/cyberradar/platform/services/audit/internal/service"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// ─── Logger ──────────────────────────────────────────────
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	logger := log.With().Str("service", "audit-service").Logger()

	// ─── Config ──────────────────────────────────────────────
	port := envOrDefault("SERVICE_PORT", "8003")
	chDSN := mustEnv("CLICKHOUSE_DSN")
	jwtSecret := mustEnv("JWT_SECRET")

	// ─── ClickHouse ──────────────────────────────────────────
	ctx := context.Background()
	chOpts, err := parseClickHouseDSN(chDSN)
	if err != nil {
		logger.Fatal().Err(err).Msg("invalid clickhouse DSN")
	}

	chConn, err := internaldb.NewClickHouseConn(ctx, *chOpts)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to connect to clickhouse")
	}
	defer chConn.Close()
	logger.Info().Msg("clickhouse connected")

	// ─── Wiring ──────────────────────────────────────────────
	auditRepo := repository.NewAuditRepository(chConn)
	auditSvc := service.NewAuditService(auditRepo, logger)
	auditHandler := handler.NewAuditHandler(auditSvc)

	// ─── Router ──────────────────────────────────────────────
	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"audit-service"}`)
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(jwtMiddleware(jwtSecret, logger))
		auditHandler.RegisterRoutes(r)
	})

	// ─── Server ──────────────────────────────────────────────
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Info().Str("addr", srv.Addr).Msg("audit-service started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("server error")
		}
	}()

	<-quit
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	logger.Info().Msg("audit-service stopped")
}

// jwtClaims mirrors the platform JWT claims.
type jwtClaims struct {
	TenantID string   `json:"tid"`
	UserID   string   `json:"uid"`
	Email    string   `json:"email"`
	Roles    []string `json:"roles"`
	IsAdmin  bool     `json:"is_admin"`
	gojwt.RegisteredClaims
}

func jwtMiddleware(secret string, logger zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if len(auth) < 8 || auth[:7] != "Bearer " {
				http.Error(w, `{"error":{"code":"UNAUTHORIZED","message":"Missing Authorization"}}`,
					http.StatusUnauthorized)
				return
			}

			token, err := gojwt.ParseWithClaims(auth[7:], &jwtClaims{}, func(t *gojwt.Token) (any, error) {
				return []byte(secret), nil
			})
			if err != nil {
				http.Error(w, `{"error":{"code":"UNAUTHORIZED","message":"Invalid token"}}`,
					http.StatusUnauthorized)
				return
			}

			claims, ok := token.Claims.(*jwtClaims)
			if !ok || !token.Valid || claims.TenantID == "" {
				http.Error(w, `{"error":{"code":"UNAUTHORIZED","message":"Invalid token claims"}}`,
					http.StatusUnauthorized)
				return
			}

			identity, claimsErr := authctx.Parse(claims.TenantID, claims.UserID, claims.Email, claims.Roles, claims.IsAdmin)
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

// parseClickHouseDSN converts a clickhouse:// DSN to ClickHouseConfig.
func parseClickHouseDSN(dsn string) (*internaldb.ClickHouseConfig, error) {
	// Format: clickhouse://user:pass@host:port/db
	dsn = strings.TrimPrefix(dsn, "clickhouse://")
	parts := strings.SplitN(dsn, "@", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid DSN format")
	}

	userPass := strings.SplitN(parts[0], ":", 2)
	if len(userPass) != 2 {
		return nil, fmt.Errorf("invalid user:pass in DSN")
	}

	hostDB := strings.SplitN(parts[1], "/", 2)
	if len(hostDB) != 2 {
		return nil, fmt.Errorf("invalid host/db in DSN")
	}

	cfg := internaldb.DefaultClickHouseConfig(
		[]string{hostDB[0]},
		hostDB[1],
		userPass[0],
		userPass[1],
	)
	return &cfg, nil
}

// Ensure chdriver import is used.
var _ = chdriver.Open

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatal().Str("key", key).Msg("required environment variable missing")
	}
	return v
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
