package db

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// ClickHouseConfig holds connection settings.
type ClickHouseConfig struct {
	Addr     []string
	Database string
	Username string
	Password string
	TLSEnabled bool
	MaxOpenConns     int
	MaxIdleConns     int
	ConnMaxLifetime  time.Duration
	DialTimeout      time.Duration
	ReadTimeout      time.Duration
}

// DefaultClickHouseConfig returns sensible defaults.
func DefaultClickHouseConfig(addr []string, db, user, password string) ClickHouseConfig {
	return ClickHouseConfig{
		Addr:            addr,
		Database:        db,
		Username:        user,
		Password:        password,
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: 60 * time.Minute,
		DialTimeout:     5 * time.Second,
		ReadTimeout:     30 * time.Second,
	}
}

// NewClickHouseConn creates and verifies a ClickHouse connection.
func NewClickHouseConn(ctx context.Context, cfg ClickHouseConfig) (driver.Conn, error) {
	opts := &clickhouse.Options{
		Addr: cfg.Addr,
		Auth: clickhouse.Auth{
			Database: cfg.Database,
			Username: cfg.Username,
			Password: cfg.Password,
		},
		MaxOpenConns:    cfg.MaxOpenConns,
		MaxIdleConns:    cfg.MaxIdleConns,
		ConnMaxLifetime: cfg.ConnMaxLifetime,
		DialTimeout:     cfg.DialTimeout,
		ReadTimeout:     cfg.ReadTimeout,
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
	}

	if cfg.TLSEnabled {
		opts.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	}

	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("open clickhouse: %w", err)
	}

	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping clickhouse: %w", err)
	}

	return conn, nil
}
