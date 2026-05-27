package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cyberradar/platform/internal/pkg/db"
	"github.com/cyberradar/platform/services/copilot/internal/handler"
	"github.com/cyberradar/platform/services/copilot/internal/repository"
	"github.com/cyberradar/platform/services/copilot/internal/service"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	logger := log.With().Str("service", "copilot-service").Logger()

	port       := envOrDefault("SERVICE_PORT", "8016")
	jwtSecret  := mustEnv("JWT_SECRET")
	dbURL      := mustEnv("DATABASE_URL")
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
	dispatcher  := service.NewToolDispatcher(serviceURLs)
	llmClient   := service.NewLLMClient(anthropicKey, dispatcher, logger)
	copilotSvc  := service.NewCopilotService(copilotRepo, llmClient, logger)
	copilotH    := handler.NewCopilotHandler(copilotSvc)

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
		r.Use(jwtMiddleware(jwtSecret, logger))
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
