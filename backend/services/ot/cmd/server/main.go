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

	"github.com/cyberradar/platform/internal/pkg/authmw"
	"github.com/cyberradar/platform/internal/pkg/db"
	pkgjwt "github.com/cyberradar/platform/internal/pkg/jwt"
	"github.com/cyberradar/platform/services/ot/internal/handler"
	"github.com/cyberradar/platform/services/ot/internal/repository"
	"github.com/cyberradar/platform/services/ot/internal/service"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	kafka "github.com/segmentio/kafka-go"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	logger := log.With().Str("service", "ot-service").Logger()

	dbURL := mustEnv("DATABASE_URL")
	jwtVerifier, err := pkgjwt.NewVerifierFromFile(mustEnv("JWT_PUBLIC_KEY_PATH"))
	if err != nil {
		log.Fatal().Err(err).Msg("load jwt public key")
	}
	kafkaBrokers := envOrDefault("KAFKA_BROKERS", "localhost:9092")
	port := envOrDefault("SERVICE_PORT", "8028")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := db.NewPostgresPool(ctx, db.DefaultPostgresConfig(dbURL))
	if err != nil {
		logger.Fatal().Err(err).Msg("postgres connect failed")
	}
	defer pool.Close()

	broker := strings.Split(kafkaBrokers, ",")[0]
	kw := &kafka.Writer{
		Addr:         kafka.TCP(broker),
		Topic:        "crp.events.ot",
		Balancer:     &kafka.LeastBytes{},
		WriteTimeout: 5 * time.Second,
		ReadTimeout:  5 * time.Second,
	}
	defer kw.Close()

	repo := repository.NewOTRepository(pool)
	svc := service.NewOTService(repo, kw, logger)
	h := handler.NewOTHandler(svc, logger)

	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"ot-service"}`)
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(authmw.RequireJWT(jwtVerifier, logger))
		r.Use(authmw.RequirePermissionByMethod("ot_assets"))
		r.Mount("/ot", h.Routes())
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
		logger.Info().Str("addr", srv.Addr).Msg("ot-service started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("server error")
		}
	}()

	<-quit
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
	logger.Info().Msg("ot-service stopped")
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
