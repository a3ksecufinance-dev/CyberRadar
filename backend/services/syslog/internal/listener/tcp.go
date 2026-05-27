package listener

// tcp.go — TCP syslog listener (RFC 6587).
// Supports two framing methods:
//   1. Octet-counting:  "<OCTET-COUNT> <MSG>\n"  (RFC 6587 §3.4.1)
//   2. Non-transparent: newline-delimited messages (RFC 6587 §3.4.2)
//
// The framing method is auto-detected per connection.

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

func (s *Server) runTCP(ctx context.Context) error {
	return s.listenAndServeStream(ctx, "tcp", s.cfg.TCPAddr)
}

// listenAndServeStream is shared by TCP and TLS (which passes its own listener).
func (s *Server) listenAndServeStream(ctx context.Context, network, addr string) error {
	ln, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	s.logger.Info().Str("addr", addr).Str("network", network).Msg("stream syslog listener started")

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.logger.Warn().Err(err).Msg("accept error")
			continue
		}
		go s.handleConn(ctx, conn)
	}
}

// handleConn processes all syslog messages from a single TCP/TLS connection.
func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	sourceIP := extractIP(conn.RemoteAddr().String())
	logger := s.logger.With().Str("remote", sourceIP).Logger()

	reader := bufio.NewReaderSize(conn, s.cfg.MaxMessageSize)

	// Peek first byte to detect framing:
	// If the first byte is a digit, assume octet-counting framing.
	// Otherwise, fall back to newline-delimited.
	first, err := reader.Peek(1)
	if err != nil {
		if err != io.EOF {
			logger.Warn().Err(err).Msg("peek error")
		}
		return
	}

	if first[0] >= '0' && first[0] <= '9' {
		// Octet-counting framing
		s.readOctetCounted(ctx, reader, conn, sourceIP, logger)
	} else {
		// Newline-delimited framing
		s.readNewlineDelimited(ctx, reader, conn, sourceIP, logger)
	}
}

// readOctetCounted reads RFC 6587 octet-counting framed messages.
// Format: "N <MSG>" where N is the byte count of <MSG>.
func (s *Server) readOctetCounted(ctx context.Context, reader *bufio.Reader, conn net.Conn, sourceIP string, logger zerolog.Logger) {
	log := s.logger.With().Str("remote", sourceIP).Logger()

	for {
		if ctx.Err() != nil {
			return
		}
		conn.SetReadDeadline(time.Now().Add(s.cfg.ReadTimeout)) //nolint:errcheck

		// Read the octet count (decimal digits followed by a space)
		countStr, err := reader.ReadString(' ')
		if err != nil {
			if err != io.EOF {
				log.Debug().Err(err).Msg("octet-count read error")
			}
			return
		}
		countStr = strings.TrimSpace(countStr)
		n, err := strconv.Atoi(countStr)
		if err != nil || n <= 0 || n > s.cfg.MaxMessageSize {
			log.Warn().Str("count", countStr).Msg("invalid octet count, closing connection")
			return
		}

		// Read exactly n bytes
		msg := make([]byte, n)
		if _, err := io.ReadFull(reader, msg); err != nil {
			log.Debug().Err(err).Msg("octet payload read error")
			return
		}

		msg = []byte(strings.TrimRight(string(msg), "\r\n"))
		if len(msg) > 0 {
			s.handle(ctx, msg, sourceIP)
		}
	}
}

// readNewlineDelimited reads newline-terminated syslog messages.
func (s *Server) readNewlineDelimited(ctx context.Context, reader *bufio.Reader, conn net.Conn, sourceIP string, _ interface{}) {
	log := s.logger.With().Str("remote", sourceIP).Logger()
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, s.cfg.MaxMessageSize), s.cfg.MaxMessageSize)

	for scanner.Scan() {
		if ctx.Err() != nil {
			return
		}
		conn.SetReadDeadline(time.Now().Add(s.cfg.ReadTimeout)) //nolint:errcheck

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		msg := make([]byte, len(line))
		copy(msg, line)
		s.handle(ctx, msg, sourceIP)
	}

	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		log.Debug().Err(err).Msg("scanner error")
	}
}
