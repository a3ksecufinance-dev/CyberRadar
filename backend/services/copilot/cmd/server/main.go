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
	"github.com/cyberradar/platform/internal/pkg/db"
	pkgjwt "github.com/cyberradar/platform/internal/pkg/jwt"
	"github.com/cyberradar/platform/services/copilot/internal/handler"
	"github.com/cyberradar/platform/services/copilot/internal/repository"
	"github.com/cyberradar/platform/services/copilot/internal/service"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	logger := log.With().Str("service", "copilot-service").Logger()

	port := envOrDefault("SERVICE_PORT", "8016")
	jwtVerifier, err := pkgjwt.NewVerifierFromFile(mustEnv("JWT_PUBLIC_KEY_PATH"))
	if err != nil {
		log.Fatal().Err(err).Msg("load jwt public key")
	}
	dbURL := mustEnv("DATABASE_URL")
	anthropicKey := mustEnv("ANTHROPIC_API_KEY")

	// Service URL map for tool dispatcher (all optional — missing = tool returns unavailable)
	serviceURLs := map[string]string{}
	for svc, envKey := range map[string]string{
		"siem":       "SIEM_SERVICE_URL",
		"ueba":       "UEBA_SERVICE_URL",
		"ti":         "TI_SERVICE_URL",
		"vuln":       "VULN_SERVICE_URL",
		"attackpath": "ATTACKPATH_SERVICE_URL",
		"soar":       "SOAR_SERVICE_URL",
		"asset":      "ASSET_SERVICE_URL",
		"kg":         "KG_SERVICE_URL",
		"dashboard":  "DASHBOARD_SERVICE_URL",
	} {
		if v := os.Getenv(envKey); v != "" {
			serviceURLs[svc] = v
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── PostgreSQL ────────────────────────────────────────────────────────────
	pool, err := db.NewPostgresPool(ctx, db.DefaultPostgresConfig(dbURL))
	if err != nil {
		logger.Fatal().Err(err).Msg("postgres connect failed")
	}
	defer pool.Close()

	// ── Services ──────────────────────────────────────────────────────────────
	copilotRepo := repository.NewCopilotRepository(pool)
	dispatcher := service.NewToolDispatcher(serviceURLs)
	llmClient := service.NewLLMClient(anthropicKey, dispatcher, logger)
	copilotSvc := service.NewCopilotService(copilotRepo, llmClient, logger)
	copilotH := handler.NewCopilotHandler(copilotSvc)

	logger.Info().Int("configured_service_urls", len(serviceURLs)).Msg("tool_dispatcher_ready")

	// ── HTTP server ───────────────────────────────────────────────────────────
	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(120 * time.Second)) // LLM calls can take up to 90s

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"copilot-service"}`)
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(authmw.RequireJWT(jwtVerifier, logger))
		r.Use(authmw.RequirePermissionByMethod("copilot"))
		copilotH.RegisterRoutes(r)
	})

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 120 * time.Second, // LLM response can be large
		IdleTimeout:  60 * time.Second,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Info().Str("addr", srv.Addr).Msg("copilot-service started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("server error")
		}
	}()

	<-quit
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
	logger.Info().Msg("copilot-service stopped")
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
