package listener

// udp.go — UDP syslog listener (RFC 5426).
// Listens for datagrams on the configured UDP address.
// Each datagram is treated as a single syslog message (no framing needed).
//
// Max safe UDP syslog message: 65507 bytes (IPv4) or 65527 (IPv6),
// but RFC 5426 recommends 480 bytes; we support up to MaxMessageSize.

import (
	"context"
	"net"
	"strings"

	"github.com/rs/zerolog/log"
)

func (s *Server) runUDP(ctx context.Context) error {
	conn, err := net.ListenPacket("udp", s.cfg.UDPAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	s.logger.Info().Str("addr", s.cfg.UDPAddr).Msg("UDP syslog listener started")

	// Close the connection when context is cancelled
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	buf := make([]byte, s.cfg.MaxMessageSize)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil // graceful shutdown
			}
			// Log transient errors and continue
			log.Warn().Err(err).Msg("UDP read error")
			continue
		}

		if n == 0 {
			continue
		}

		// Copy message bytes (buf is reused)
		msg := make([]byte, n)
		copy(msg, buf[:n])

		sourceIP := extractIP(addr.String())
		go s.handle(ctx, msg, sourceIP)
	}
}

// extractIP returns just the IP part from "IP:port" or "IP".
func extractIP(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return strings.TrimSpace(addr)
}
