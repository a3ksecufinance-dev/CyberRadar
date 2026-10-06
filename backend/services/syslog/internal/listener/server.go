package listener

// server.go — orchestrates all syslog listeners (UDP, TCP, TLS).

import (
	"context"
	"crypto/tls"
	"sync"
	"time"

	"github.com/cyberradar/platform/services/syslog/internal/parser"
	"github.com/cyberradar/platform/services/syslog/internal/publisher"
	"github.com/rs/zerolog"
)

// Config holds configuration for all syslog listeners.
type Config struct {
	UDPAddr   string // e.g. ":5140"
	TCPAddr   string // e.g. ":5141"
	TLSAddr   string // e.g. ":6514"
	TLSConfig *tls.Config

	TenantID       string // default tenant for messages without tenant info
	MaxMessageSize int    // bytes, default 64 KiB
	ReadTimeout    time.Duration

	Publisher *publisher.Publisher
	Logger    zerolog.Logger
}

// MessageHandler is the callback invoked for each successfully parsed message.
// It receives the parsed syslog event and the remote source IP.
type MessageHandler func(ctx context.Context, p *parser.Parsed, sourceIP string) error

// Server manages all syslog listeners.
type Server struct {
	cfg     Config
	handler MessageHandler
	wg      sync.WaitGroup
	logger  zerolog.Logger
}

// NewServer creates a new syslog server with the given config.
// handler is called for each valid syslog message received on any transport.
func NewServer(cfg Config, handler MessageHandler) *Server {
	if cfg.MaxMessageSize == 0 {
		cfg.MaxMessageSize = 64 * 1024 // 64 KiB per RFC 5425
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 5 * time.Second
	}
	return &Server{
		cfg:     cfg,
		handler: handler,
		logger:  cfg.Logger.With().Str("component", "syslog-server").Logger(),
	}
}

// Start starts all configured listeners. It blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	errCh := make(chan error, 3)

	// UDP listener
	if s.cfg.UDPAddr != "" {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.runUDP(ctx); err != nil {
				errCh <- err
			}
		}()
	}

	// TCP listener
	if s.cfg.TCPAddr != "" {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.runTCP(ctx); err != nil {
				errCh <- err
			}
		}()
	}

	// TLS listener
	if s.cfg.TLSAddr != "" && s.cfg.TLSConfig != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.runTLS(ctx); err != nil {
				errCh <- err
			}
		}()
	}

	// Wait for context cancellation or a fatal error
	select {
	case <-ctx.Done():
	case err := <-errCh:
		return err
	}

	s.wg.Wait()
	return nil
}

// handle parses a raw syslog message and dispatches it to the handler.
func (s *Server) handle(ctx context.Context, raw []byte, sourceIP string) {
	parsed, err := parser.Parse(raw, sourceIP)
	if err != nil {
		s.logger.Warn().Err(err).Str("source_ip", sourceIP).Msg("parse error")
		return
	}

	if err := s.handler(ctx, parsed, sourceIP); err != nil {
		s.logger.Error().Err(err).Str("source_ip", sourceIP).Msg("handler error")
	}
}
