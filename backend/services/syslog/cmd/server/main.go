package main

// main.go — CyberRadar Syslog Connector Service
//
// Listens on:
//   UDP  :5140  — RFC 5426 (syslog over UDP)
//   TCP  :5141  — RFC 6587 (syslog over TCP, octet-counting + newline-delimited)
//   TLS  :6514  — RFC 5425 (syslog over TLS)
//
// For each message:
//   1. Auto-detect format: RFC 3164 / RFC 5424 / CEF-over-syslog
//   2. Parse → internal Parsed struct
//   3. Map to NormalizedEvent (ECS-aligned CRP schema)
//   4. Publish to Kafka topic crp.events.normalized
//
// Health endpoint: HTTP :8031/health

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cyberradar/platform/services/syslog/internal/listener"
	"github.com/cyberradar/platform/services/syslog/internal/parser"
	"github.com/cyberradar/platform/services/syslog/internal/publisher"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if envOrDefault("LOG_LEVEL", "info") == "debug" {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	logger := log.With().Str("service", "syslog-connector").Logger()

	// ─── Configuration ───────────────────────────────────────
	healthPort := envOrDefault("HEALTH_PORT", "8031")
	udpAddr    := envOrDefault("SYSLOG_UDP_ADDR", ":5140")
	tcpAddr    := envOrDefault("SYSLOG_TCP_ADDR", ":5141")
	tlsAddr    := envOrDefault("SYSLOG_TLS_ADDR", ":6514")
	brokers    := strings.Split(mustEnv("KAFKA_BROKERS"), ",")
	tenantID   := envOrDefault("DEFAULT_TENANT_ID", "default")
	topic      := envOrDefault("KAFKA_TOPIC", "crp.events.normalized")

	// Optional TLS config (required only when TLS_CERT_FILE is set)
	tlsCertFile := os.Getenv("TLS_CERT_FILE")
	tlsKeyFile  := os.Getenv("TLS_KEY_FILE")

	// ─── Kafka publisher ─────────────────────────────────────
	pub := publisher.NewPublisher(brokers, topic, logger)
	defer pub.Close()

	// ─── Syslog message handler ──────────────────────────────
	handleMsg := func(ctx context.Context, p *parser.Parsed, sourceIP string) error {
		if err := pub.Publish(ctx, p, sourceIP, tenantID); err != nil {
			logger.Error().Err(err).
				Str("source_ip", sourceIP).
				Str("format", string(p.Format)).
				Msg("failed to publish to Kafka")
			return err
		}
		logger.Debug().
			Str("source_ip", sourceIP).
			Str("format", string(p.Format)).
			Str("hostname", p.Hostname).
			Int("severity", p.Severity).
			Str("message", truncate(p.Message, 120)).
			Msg("syslog event published")
		return nil
	}

	// ─── TLS configuration ───────────────────────────────────
	var tlsCfg *tls.Config
	if tlsCertFile != "" && tlsKeyFile != "" {
		var err error
		tlsCfg, err = listener.DevTLSConfig(tlsCertFile, tlsKeyFile)
		if err != nil {
			logger.Fatal().Err(err).Msg("failed to load TLS certificates")
		}
		logger.Info().Str("cert", tlsCertFile).Msg("TLS enabled")
	} else {
		logger.Warn().Msg("TLS_CERT_FILE not set — TLS listener disabled (set TLS_CERT_FILE + TLS_KEY_FILE to enable)")
		tlsAddr = "" // disable TLS listener
	}

	// ─── Syslog server ───────────────────────────────────────
	srv := listener.NewServer(listener.Config{
		UDPAddr:        udpAddr,
		TCPAddr:        tcpAddr,
		TLSAddr:        tlsAddr,
		TLSConfig:      tlsCfg,
		TenantID:       tenantID,
		MaxMessageSize: 65536,
		ReadTimeout:    30 * time.Second,
		Publisher:      pub,
		Logger:         logger,
	}, handleMsg)

	// ─── HTTP health endpoint ─────────────────────────────────
	httpSrv := &http.Server{
		Addr:         ":" + healthPort,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"syslog-connector","listeners":{"udp":"%s","tcp":"%s","tls":"%s"}}`,
			udpAddr, tcpAddr, tlsAddr)
	})
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		// Minimal Prometheus-compatible metrics stub
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "# HELP syslog_connector_up Whether the syslog connector is running\n")
		fmt.Fprintf(w, "# TYPE syslog_connector_up gauge\n")
		fmt.Fprintf(w, "syslog_connector_up 1\n")
	})

	go func() {
		logger.Info().Str("addr", ":"+healthPort).Msg("health endpoint started")
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error().Err(err).Msg("health server error")
		}
	}()

	// ─── Graceful shutdown ───────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		logger.Info().Msg("shutting down syslog connector...")
		cancel()

		shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutCancel()
		_ = httpSrv.Shutdown(shutCtx)
	}()

	logger.Info().
		Str("udp", udpAddr).
		Str("tcp", tcpAddr).
		Str("tls", coalesce(tlsAddr, "disabled")).
		Str("kafka_topic", topic).
		Msg("syslog connector started")

	if err := srv.Start(ctx); err != nil {
		logger.Fatal().Err(err).Msg("syslog server error")
	}

	logger.Info().Msg("syslog connector stopped")
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func coalesce(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
