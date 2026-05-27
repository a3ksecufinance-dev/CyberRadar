package listener

// tls.go — TLS syslog listener (RFC 5425).
// Listens on the TLS address using the provided *tls.Config.
// Message framing is the same as TCP (octet-counting or newline-delimited).
//
// RFC 5425 mandates TLS 1.2+ and mutual authentication in production.
// In dev mode, a self-signed certificate is accepted on both sides.

import (
	"context"
	"crypto/tls"
	"net"
)

func (s *Server) runTLS(ctx context.Context) error {
	ln, err := tls.Listen("tcp", s.cfg.TLSAddr, s.cfg.TLSConfig)
	if err != nil {
		return err
	}
	defer ln.Close()

	s.logger.Info().Str("addr", s.cfg.TLSAddr).Msg("TLS syslog listener started (RFC 5425)")

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
			s.logger.Warn().Err(err).Msg("TLS accept error")
			continue
		}

		// TLS handshake check
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			conn.Close()
			continue
		}
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			s.logger.Warn().Err(err).Str("remote", conn.RemoteAddr().String()).Msg("TLS handshake failed")
			conn.Close()
			continue
		}

		// Log negotiated TLS version for auditing
		state := tlsConn.ConnectionState()
		s.logger.Debug().
			Str("remote", extractIP(conn.RemoteAddr().String())).
			Uint16("tls_version", state.Version).
			Str("cipher_suite", tls.CipherSuiteName(state.CipherSuite)).
			Msg("TLS connection established")

		go s.handleConn(ctx, conn)
	}
}

// LoadTLSConfig loads a TLS configuration from certificate and key files.
// In dev mode, InsecureSkipVerify is acceptable; disable in production.
func LoadTLSConfig(certFile, keyFile string, clientAuth tls.ClientAuthType) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   clientAuth,
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}, nil
}

// DevTLSConfig returns a permissive TLS config for development (no client cert required).
func DevTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	return LoadTLSConfig(certFile, keyFile, tls.NoClientCert)
}

// extractIPFromAddr returns just the IP part, needed since listener/udp.go also defines it
// but they are in the same package so we reuse the one from udp.go.
// (This file does not re-declare extractIP.)
var _ = net.SplitHostPort // ensure net package is used
