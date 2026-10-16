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
	Addr            []string
	Database        string
	Username        string
	Password        string
	TLSEnabled      bool
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	DialTimeout     time.Duration
	ReadTimeout     time.Duration
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

// CHTime renders a time for a {name:DateTime} query parameter.
//
// ClickHouse named parameters are bound as text, so a time.Time cannot be
// passed through as-is: the driver rejects it with "expected string value in
// NamedValue for query parameter" and the query never runs. Every read in the
// dashboard's KPI repository and the SIEM's alert repository failed this way.
//
// The value is normalised to UTC because the columns carry no zone of their own.
func CHTime(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05")
}

// CHTime64 is CHTime for a {name:DateTime64(3,'UTC')} parameter, which keeps
// milliseconds.
func CHTime64(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05.000")
}
