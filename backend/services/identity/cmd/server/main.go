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
	"github.com/cyberradar/platform/internal/pkg/observe"
	pkgvault "github.com/cyberradar/platform/internal/pkg/vault"
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

	// Optional: with no collector configured this is a no-op, so a
	// missing collector never stops the service from starting.
	shutdownTracing, tracingErr := observe.InitTracing(context.Background(),
		"identity-service", envOrDefault("SERVICE_VERSION", "dev"),
		os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if tracingErr != nil {
		logger.Warn().Err(tracingErr).Msg("tracing disabled")
	}
	defer func() { _ = shutdownTracing(context.Background()) }()

	// ─── Secrets ─────────────────────────────────────────────
	// Vault is optional: unconfigured, every value below comes from the
	// environment exactly as before.
	vaultClient, vaultErr := pkgvault.NewFromEnv()
	if vaultErr != nil {
		logger.Fatal().Err(vaultErr).Msg("vault is configured but unusable")
	}
	secrets := pkgvault.NewResolver(vaultClient, envOrDefault("VAULT_SECRET_PREFIX", "crp/identity"))
	logger.Info().Bool("vault", secrets.Enabled()).Msg("secret source")

	dsn, dsnFrom, err := secrets.Get(context.Background(), "database", "url", "DATABASE_URL")
	if err != nil {
		logger.Fatal().Err(err).Msg("resolve database url")
	}
	logger.Info().Str("source", string(dsnFrom)).Msg("database url resolved")

	// ─── Config ──────────────────────────────────────────────
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
	serviceAccountRepo := repository.NewServiceAccountRepository(dbPool)

	// The private key lives only here: identity is the platform's sole token
	// issuer. Vault is preferred because it keeps the key off the filesystem
	// and out of the container's environment entirely.
	accessTTL := time.Duration(jwtExpiryMin) * time.Minute
	refreshTTL := time.Duration(refreshExpHrs) * time.Hour

	var jwtSigner *pkgjwt.Signer
	if secrets.Enabled() {
		pem, _, keyErr := secrets.Get(context.Background(), "jwt", "private_key", "")
		if keyErr != nil {
			logger.Warn().Err(keyErr).Msg("jwt private key not in vault, falling back to file")
		} else if jwtSigner, err = pkgjwt.NewSigner([]byte(pem), accessTTL, refreshTTL); err != nil {
			logger.Fatal().Err(err).Msg("jwt private key from vault is unusable")
		} else {
			logger.Info().Str("source", string(pkgvault.FromVault)).Msg("jwt private key loaded")
		}
	}
	if jwtSigner == nil {
		jwtSigner, err = pkgjwt.NewSignerFromFile(mustEnv("JWT_PRIVATE_KEY_PATH"), accessTTL, refreshTTL)
		if err != nil {
			logger.Fatal().Err(err).Msg("load jwt private key")
		}
		logger.Info().Str("source", "file").Msg("jwt private key loaded")
	}
	mfaSvc := service.NewMFAService(mfaIssuer)

	userSvc := service.NewUserService(userRepo, roleRepo, jwtSigner, mfaSvc, logger)

	serviceAccountSvc := service.NewServiceAccountService(serviceAccountRepo, roleRepo, jwtSigner, logger)

	authHandler := handler.NewAuthHandler(userSvc)
	serviceAccountHandler := handler.NewServiceAccountHandler(serviceAccountSvc)
	userHandler := handler.NewUserHandler(userSvc)

	// ─── Router ──────────────────────────────────────────────
	r := chi.NewRouter()
	r.Use(observe.Middleware("identity-service"))
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))

	r.Handle("/metrics", observe.MetricsHandler())
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
		// Public auth routes: reached with a password or a client credential,
		// so they cannot sit behind RequireJWT.
		authHandler.RegisterPublicRoutes(r)
		serviceAccountHandler.RegisterPublicRoutes(r)

		// Authenticated routes
		r.Group(func(r chi.Router) {
			r.Use(authmw.RequireJWT(jwtVerifier, logger))
			authHandler.RegisterProtectedRoutes(r)

			// Machine credentials, gated per route by api_keys:*.
			serviceAccountHandler.RegisterProtectedRoutes(r)

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
