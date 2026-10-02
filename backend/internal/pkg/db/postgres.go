package db

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresConfig holds connection settings for PostgreSQL.
type PostgresConfig struct {
	DSN             string
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
}

// DefaultPostgresConfig returns sensible production defaults.
// DefaultPostgresConfig sizes one service's pool.
//
// The platform runs thirty services against one PostgreSQL. At the old
// defaults — 25 maximum, 5 minimum — that was 150 connections held idle before
// anything had happened and 750 wanted at peak, against a server whose default
// max_connections is 100. The platform could not start against a stock
// PostgreSQL, in Docker Compose as much as anywhere else; it failed with
// "sorry, too many clients already" on whichever services lost the race.
//
// The minimum is now 2, so the idle floor across the platform is 60 rather
// than 150, and both bounds can be set per service. A deployment still has to
// raise max_connections or put a pooler in front — thirty services cannot
// share a hundred connections at any pool size worth having — which is why
// deployments/docker-compose.yml sets it explicitly rather than leaving the
// next person to discover this the way it was discovered here.
func DefaultPostgresConfig(dsn string) PostgresConfig {
	return PostgresConfig{
		DSN:             dsn,
		MaxConns:        envInt32("DB_MAX_CONNS", 25),
		MinConns:        envInt32("DB_MIN_CONNS", 2),
		MaxConnLifetime: 30 * time.Minute,
		MaxConnIdleTime: 5 * time.Minute,
	}
}

// envInt32 reads a positive integer from the environment, falling back to def.
// A value that is not a positive integer is ignored rather than obeyed: a
// typo in a pool size should not silently give a service one connection.
func envInt32(key string, def int32) int32 {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return def
	}
	return int32(n)
}

// NewPostgresPool creates a pgxpool connection pool.
// The caller is responsible for calling pool.Close() on shutdown.
func NewPostgresPool(ctx context.Context, cfg PostgresConfig) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("parse postgres DSN: %w", err)
	}

	poolCfg.MaxConns = cfg.MaxConns
	poolCfg.MinConns = cfg.MinConns
	poolCfg.MaxConnLifetime = cfg.MaxConnLifetime
	poolCfg.MaxConnIdleTime = cfg.MaxConnIdleTime

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("create postgres pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	return pool, nil
}
