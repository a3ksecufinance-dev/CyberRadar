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
	"github.com/cyberradar/platform/internal/pkg/authmw"
	internaldb "github.com/cyberradar/platform/internal/pkg/db"
	pkgjwt "github.com/cyberradar/platform/internal/pkg/jwt"
	"github.com/cyberradar/platform/services/audit/internal/handler"
	"github.com/cyberradar/platform/services/audit/internal/repository"
	"github.com/cyberradar/platform/services/audit/internal/service"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
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
	jwtVerifier, err := pkgjwt.NewVerifierFromFile(mustEnv("JWT_PUBLIC_KEY_PATH"))
	if err != nil {
		log.Fatal().Err(err).Msg("load jwt public key")
	}

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
		r.Use(authmw.RequireJWT(jwtVerifier, logger))
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
