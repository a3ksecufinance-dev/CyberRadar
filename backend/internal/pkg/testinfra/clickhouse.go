package testinfra

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// ClickHouse hands the test a connection to a migrated ClickHouse.
//
// Unlike PostgreSQL, the databases are not cut per test: ClickHouse has no
// template mechanism, and creating the seven databases and eighteen tables
// takes long enough that doing it per test would dominate a suite. The
// migrations run once per process, and a test that writes rows is responsible
// for reading back only its own — which is what a tenant_id filter does anyway,
// so use a tenant of your own.
//
// TruncateClickHouse is there for a test that would rather start from nothing.
func ClickHouse(t *testing.T) driver.Conn {
	t.Helper()

	conn, err := sharedClickHouse()
	if err != nil {
		unavailable(t, "clickhouse", "ClickHouse", EnvClickHouse, err)
		return nil // unreachable
	}
	return conn
}

// TruncateClickHouse empties every table the migrations created.
//
// Call it from a test that counts rows rather than filtering them. It is not
// automatic: most tests scope their reads to their own tenant, and truncating
// between them would be a cost they do not need.
func TruncateClickHouse(t *testing.T, conn driver.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	rows, err := conn.Query(ctx, `
		SELECT database, name FROM system.tables
		 WHERE database LIKE 'crp_%' AND engine NOT LIKE '%View'`)
	if err != nil {
		t.Fatalf("list ClickHouse tables: %v", err)
	}
	defer rows.Close()

	var targets [][2]string
	for rows.Next() {
		var db, name string
		if err := rows.Scan(&db, &name); err != nil {
			t.Fatalf("scan ClickHouse tables: %v", err)
		}
		targets = append(targets, [2]string{db, name})
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("list ClickHouse tables: %v", err)
	}

	for _, tt := range targets {
		if err := conn.Exec(ctx, fmt.Sprintf("TRUNCATE TABLE `%s`.`%s`", tt[0], tt[1])); err != nil {
			t.Fatalf("truncate %s.%s: %v", tt[0], tt[1], err)
		}
	}
}

// pinger is the one thing pingUntilReady needs. driver.Conn satisfies it.
type pinger interface {
	Ping(context.Context) error
}

// pingUntilReady pings until the server answers, or the context runs out.
//
// A listening port is not a ready server. testcontainers declares the
// ClickHouse container ready as soon as 9000 accepts a connection, but a
// published port is bound by Docker's proxy the moment the container starts —
// before ClickHouse has a listener behind it. The first ping then lands on a
// socket that accepts and immediately resets.
//
// That is exactly how this failed in CI: "Container is ready" and "ping: read
// tcp [::1]->[::1]: connection reset by peer" logged in the same millisecond,
// on ::1, which is what localhost resolves to first on a GitHub runner.
//
// A single Ping under a two-minute deadline does not cover it: the deadline
// bounds one attempt, it does not produce a second. Only retrying does.
//
// The Kafka helper learned this and says so at length; the lesson was never
// carried across to ClickHouse, whose container comment asserts "the caller
// pings the server afterwards, which is the real check" — true, and not a
// check at all when it only gets one try.
//
// sync.Once makes the cost worse than one red test: the error is cached for
// the life of the process, so every ClickHouse test in that binary fails on a
// race that lasted a few hundred milliseconds.
func pingUntilReady(ctx context.Context, p pinger, interval time.Duration) error {
	started := time.Now()
	for attempt := 1; ; attempt++ {
		err := p.Ping(ctx)
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("no answer after %s and %d attempts: %w",
				time.Since(started).Round(time.Millisecond), attempt, err)
		case <-time.After(interval):
		}
	}
}

var (
	chOnce sync.Once
	chConn driver.Conn
	chErr  error
)

func sharedClickHouse() (driver.Conn, error) {
	chOnce.Do(func() {
		dsn := os.Getenv(EnvClickHouse)
		if dsn == "" {
			dsn, chErr = startClickHouseContainer()
			if chErr != nil {
				return
			}
		}

		opts, err := clickhouse.ParseDSN(dsn)
		if err != nil {
			chErr = fmt.Errorf("parse %s: %w", EnvClickHouse, err)
			return
		}
		conn, err := clickhouse.Open(opts)
		if err != nil {
			chErr = fmt.Errorf("open: %w", err)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := pingUntilReady(ctx, conn, 500*time.Millisecond); err != nil {
			chErr = fmt.Errorf("ping: %w", err)
			return
		}
		if err := migrateClickHouse(ctx, conn); err != nil {
			chErr = err
			return
		}
		chConn = conn
	})
	return chConn, chErr
}

// migrateClickHouse applies the ClickHouse migrations.
//
// One statement per Exec: ClickHouse's protocol takes a single statement, where
// PostgreSQL accepts a whole file. The migrations are written with
// IF NOT EXISTS throughout, so running them against a server that already has
// them is a no-op rather than an error — which is what makes reusing a shared
// instance across test binaries work.
func migrateClickHouse(ctx context.Context, conn driver.Conn) error {
	files, err := migrationFiles("clickhouse")
	if err != nil {
		return err
	}
	for _, f := range files {
		body, err := os.ReadFile(f) //nolint:gosec // a path migrationFiles built
		if err != nil {
			return fmt.Errorf("read %s: %w", f, err)
		}
		for _, stmt := range statements(string(body)) {
			if err := conn.Exec(ctx, strings.TrimSuffix(stmt, ";")); err != nil {
				return fmt.Errorf("apply %s: %w", shortName(f), err)
			}
		}
	}
	return nil
}
