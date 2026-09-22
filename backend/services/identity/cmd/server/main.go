package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cyberradar/platform/internal/pkg/authmw"
	internaldb "github.com/cyberradar/platform/internal/pkg/db"
	pkgjwt "github.com/cyberradar/platform/internal/pkg/jwt"
	"github.com/cyberradar/platform/services/identity/internal/handler"
	"github.com/cyberradar/platform/services/identity/internal/repository"
	"github.com/cyberradar/platform/services/identity/internal/service"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	logger := log.With().Str("service", "identity-service").Logger()

	// ─── Config ──────────────────────────────────────────────
	dsn := mustEnv("DATABASE_URL")
	port := envOrDefault("SERVICE_PORT", "8002")
	jwtVerifier, err := pkgjwt.NewVerifierFromFile(mustEnv("JWT_PUBLIC_KEY_PATH"))
	if err != nil {
		log.Fatal().Err(err).Msg("load jwt public key")
	}
	jwtExpiryMin := envOrDefaultInt("JWT_EXPIRY_MINUTES", 60)
	refreshExpHrs := envOrDefaultInt("JWT_REFRESH_EXPIRY_HOURS", 24)
	mfaIssuer := envOrDefault("MFA_ISSUER", "CyberRadar")

	// ─── Database ────────────────────────────────────────────
	ctx := context.Background()
	dbPool, err := internaldb.NewPostgresPool(ctx, internaldb.DefaultPostgresConfig(dsn))
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to connect to postgres")
	}
	defer dbPool.Close()
	logger.Info().Msg("postgres connected")

	// ─── Wiring ──────────────────────────────────────────────
	userRepo := repository.NewUserRepository(dbPool)
	roleRepo := repository.NewRoleRepository(dbPool)

	// The private key lives only here: identity is the platform's sole token issuer.
	jwtSigner, err := pkgjwt.NewSignerFromFile(
		mustEnv("JWT_PRIVATE_KEY_PATH"),
		time.Duration(jwtExpiryMin)*time.Minute,
		time.Duration(refreshExpHrs)*time.Hour,
	)
	if err != nil {
		logger.Fatal().Err(err).Msg("load jwt private key")
	}
	mfaSvc := service.NewMFAService(mfaIssuer)

	userSvc := service.NewUserService(userRepo, roleRepo, jwtSigner, mfaSvc, logger)

	authHandler := handler.NewAuthHandler(userSvc)
	userHandler := handler.NewUserHandler(userSvc)

	// ─── Router ──────────────────────────────────────────────
	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"identity-service"}`)
	})
	r.Get("/ready", func(w http.ResponseWriter, r *http.Request) {
		if err := dbPool.Ping(r.Context()); err != nil {
			http.Error(w, `{"status":"not_ready"}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ready"}`)
	})

	r.Route("/api/v1", func(r chi.Router) {
		// Public auth routes (no JWT required)
		authHandler.RegisterPublicRoutes(r)

		// Authenticated routes
		r.Group(func(r chi.Router) {
			r.Use(authmw.RequireJWT(jwtVerifier, logger))
			authHandler.RegisterProtectedRoutes(r)

			// User and identity administration; /auth/me and /auth/logout above
			// stay reachable by any authenticated caller.
			r.Group(func(r chi.Router) {
				r.Use(authmw.RequirePermissionByMethod("users"))
				userHandler.RegisterRoutes(r)
			})
		})
	})

	// ─── Server ──────────────────────────────────────────────
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
		logger.Info().Str("addr", srv.Addr).Msg("identity-service started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("server error")
		}
	}()

	<-quit
	logger.Info().Msg("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	logger.Info().Msg("identity-service stopped")
}

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

func envOrDefaultInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n <= 0 {
		return def
	}
	return n
}
