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
	"github.com/cyberradar/platform/internal/pkg/observe"
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

	// Optional: with no collector configured this is a no-op, so a
	// missing collector never stops the service from starting.
	shutdownTracing, tracingErr := observe.InitTracing(context.Background(),
		"copilot-service", envOrDefault("SERVICE_VERSION", "dev"),
		os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if tracingErr != nil {
		logger.Warn().Err(tracingErr).Msg("tracing disabled")
	}
	defer func() { _ = shutdownTracing(context.Background()) }()

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

	// ── Retrieval ─────────────────────────────────────────────────────────────
	// Optional: with no embeddings server the Copilot still works, it just has
	// no recall of the tenant's own history. Point EMBEDDINGS_URL at a
	// self-hosted server to keep incident text inside the estate.
	embedder := buildEmbedder(ctx, copilotRepo, logger)

	copilotSvc := service.NewCopilotService(copilotRepo, llmClient, embedder, logger)
	copilotH := handler.NewCopilotHandler(copilotSvc)

	logger.Info().Int("configured_service_urls", len(serviceURLs)).Msg("tool_dispatcher_ready")

	// ── HTTP server ───────────────────────────────────────────────────────────
	r := chi.NewRouter()
	r.Use(observe.Middleware("copilot-service"))
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(120 * time.Second)) // LLM calls can take up to 90s

	r.Handle("/metrics", observe.MetricsHandler())
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

// buildEmbedder configures retrieval, or returns nil when it is not deployed.
//
// It checks the model's width against the column the index is built on before
// anything is written. A mismatch would otherwise be found one row at a time,
// at ingestion, long after the deployment looked healthy.
func buildEmbedder(ctx context.Context, repo *repository.CopilotRepository, logger zerolog.Logger) service.Embedder {
	url := os.Getenv("EMBEDDINGS_URL")
	if url == "" {
		logger.Warn().Msg("no EMBEDDINGS_URL: the copilot will answer without recall of this tenant's history")
		return nil
	}

	dimension, err := repo.EmbeddingDimension(ctx)
	if err != nil {
		logger.Fatal().Err(err).Msg("cannot read the embedding column's dimension")
	}

	embedder, err := service.NewHTTPEmbedder(service.EmbedderConfig{
		URL:       url,
		Model:     envOrDefault("EMBEDDINGS_MODEL", "BAAI/bge-large-en-v1.5"),
		APIKey:    os.Getenv("EMBEDDINGS_API_KEY"),
		Dimension: dimension,
	})
	if err != nil {
		logger.Fatal().Err(err).Msg("embeddings configuration invalid")
	}

	logger.Info().
		Str("url", url).
		Int("dimension", dimension).
		Msg("retrieval enabled")
	return embedder
}
