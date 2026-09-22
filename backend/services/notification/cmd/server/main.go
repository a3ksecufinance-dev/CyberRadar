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
	"github.com/cyberradar/platform/services/notification/internal/handler"
	"github.com/cyberradar/platform/services/notification/internal/service"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	logger := log.With().Str("service", "notification-service").Logger()

	port      := envOrDefault("SERVICE_PORT", "8004")
	jwtSecret := mustEnv("JWT_SECRET")

	notifSvc     := service.NewNotificationService(logger)
	notifHandler := handler.NewNotificationHandler(notifSvc)

	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"notification-service"}`)
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(jwtMiddleware(jwtSecret, logger))
		notifHandler.RegisterRoutes(r)
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
		logger.Info().Str("addr", srv.Addr).Msg("notification-service started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("server error")
		}
	}()

	<-quit
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	logger.Info().Msg("notification-service stopped")
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
				http.Error(w, `{"error":{"code":"UNAUTHORIZED","message":"Missing Authorization"}}`,
					http.StatusUnauthorized)
				return
			}
			token, err := gojwt.ParseWithClaims(auth[7:], &jwtClaims{}, func(t *gojwt.Token) (any, error) {
				return []byte(secret), nil
			})
			if err != nil || !token.Valid {
				http.Error(w, `{"error":{"code":"UNAUTHORIZED","message":"Invalid token"}}`,
					http.StatusUnauthorized)
				return
			}
			claims := token.Claims.(*jwtClaims)
			if claims.TenantID == "" {
				http.Error(w, `{"error":{"code":"UNAUTHORIZED","message":"Missing tenant"}}`,
					http.StatusUnauthorized)
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
