package testinfra

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// templateName is the migrated database every test database is cut from.
const templateName = "crp_test_template"

// templateLockKey scopes the advisory lock that serialises template building
// across processes. An arbitrary constant; it only has to be the same number in
// every test binary.
const templateLockKey = 7312026

// Postgres hands the test its own migrated PostgreSQL database.
//
// Each call returns a database of its own, so two tests never see each other's
// rows and neither has to clean up after itself. It is cut from a template with
// CREATE DATABASE … TEMPLATE, which PostgreSQL does as a file copy: the full
// schema arrives in the time one migration would take to parse.
//
// The database is dropped when the test ends.
func Postgres(t *testing.T) *pgxpool.Pool {
	t.Helper()

	shared, err := sharedPostgres()
	if err != nil {
		unavailable(t, "postgres", "PostgreSQL", EnvPostgres, err)
		return nil // unreachable: unavailable always skips or fails
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	name := "crp_test_" + randSuffix()
	if err := shared.clone(ctx, name); err != nil {
		t.Fatalf("create the test database: %v", err)
	}

	pool, err := pgxpool.New(ctx, shared.dsnFor(name))
	if err != nil {
		_ = shared.drop(context.Background(), name)
		t.Fatalf("connect to %s: %v", name, err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		_ = shared.drop(context.Background(), name)
		t.Fatalf("ping %s: %v", name, err)
	}

	t.Cleanup(func() {
		pool.Close()
		// A fresh context: the test's own may already be cancelled, and a
		// database left behind would be found by the next run's sweep rather
		// than now, which is worse.
		dropCtx, dropCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer dropCancel()
		if err := shared.drop(dropCtx, name); err != nil {
			t.Logf("testinfra: could not drop %s: %v", name, err)
		}
	})
	return pool
}

// PostgresDSN is the connection string of a database Postgres would hand out,
// for a test that needs to give one to code that opens its own pool.
func PostgresDSN(t *testing.T) string {
	t.Helper()
	pool := Postgres(t)
	return pool.Config().ConnString()
}

// ─── The shared, once-per-process part ───────────────────────────────────────

type postgresServer struct {
	// adminDSN points at a database we are allowed to connect to in order to
	// create and drop others. Never the database under test.
	adminDSN string
}

var (
	pgOnce   sync.Once
	pgServer *postgresServer
	pgErr    error

	// cloneMu serialises CREATE DATABASE … TEMPLATE inside this process.
	// PostgreSQL refuses to copy a template another session is connected to,
	// and two parallel tests would otherwise race.
	cloneMu sync.Mutex
)

func sharedPostgres() (*postgresServer, error) {
	pgOnce.Do(func() {
		dsn := os.Getenv(EnvPostgres)
		if dsn == "" {
			dsn, pgErr = startPostgresContainer()
			if pgErr != nil {
				return
			}
		}
		s := &postgresServer{adminDSN: dsn}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if pgErr = s.ensureTemplate(ctx); pgErr != nil {
			return
		}
		pgServer = s
	})
	return pgServer, pgErr
}

// dsnFor rewrites the admin DSN to point at another database on the same
// server.
//
// The two shapes are told apart by the scheme, not by whether url.Parse
// returns an error. It does not: it reads `host=localhost dbname=x` as a
// relative path quite happily, so the error branch never ran and a key=value
// DSN came back as "/crp_test_x". The connection then failed somewhere else
// entirely, which is the kind of error that costs an afternoon.
func (s *postgresServer) dsnFor(db string) string {
	if !strings.HasPrefix(s.adminDSN, "postgres://") && !strings.HasPrefix(s.adminDSN, "postgresql://") {
		return replaceKeyValueDB(s.adminDSN, db)
	}
	u, err := url.Parse(s.adminDSN)
	if err != nil {
		return replaceKeyValueDB(s.adminDSN, db)
	}
	u.Path = "/" + db
	return u.String()
}

func replaceKeyValueDB(dsn, db string) string {
	fields := strings.Fields(dsn)
	found := false
	for i, f := range fields {
		if strings.HasPrefix(f, "dbname=") {
			fields[i] = "dbname=" + db
			found = true
		}
	}
	if !found {
		fields = append(fields, "dbname="+db)
	}
	return strings.Join(fields, " ")
}

// admin opens a single connection to the admin database.
//
// A connection rather than a pool: CREATE DATABASE and DROP DATABASE cannot run
// inside a transaction, and the advisory lock below has to be held and released
// on one session.
func (s *postgresServer) admin(ctx context.Context) (*pgx.Conn, error) {
	return pgx.Connect(ctx, s.adminDSN)
}

// ensureTemplate builds the migrated template, or confirms the one already
// there matches the migrations on disk.
//
// The fingerprint is what makes reuse safe. A template built before migration
// 000048 would hand every test a schema with five tables that no longer exist,
// and the tests would pass against a database that does not match production.
func (s *postgresServer) ensureTemplate(ctx context.Context) error {
	files, err := migrationFiles("postgres")
	if err != nil {
		return err
	}
	want, err := fingerprint(files)
	if err != nil {
		return err
	}

	conn, err := s.admin(ctx)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(context.Background())

	// Only one process builds the template; the others wait here and then find
	// it already correct.
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", templateLockKey); err != nil {
		return fmt.Errorf("take the template lock: %w", err)
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = conn.Exec(unlockCtx, "SELECT pg_advisory_unlock($1)", templateLockKey)
	}()

	if got, err := s.templateFingerprint(ctx); err == nil && got == want {
		return nil
	}

	// Stale or absent. Anything connected to it has to go first, or the DROP
	// blocks on a session from an earlier run.
	if err := s.dropForce(ctx, conn, templateName); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, `CREATE DATABASE `+quoteIdent(templateName)); err != nil {
		return fmt.Errorf("create %s: %w", templateName, err)
	}

	if err := s.migrateInto(ctx, templateName, files, want); err != nil {
		// Leave nothing half-migrated behind: a broken template would be
		// reused by every later run until somebody noticed.
		_ = s.dropForce(context.Background(), conn, templateName)
		return err
	}
	return nil
}

func (s *postgresServer) templateFingerprint(ctx context.Context) (string, error) {
	conn, err := pgx.Connect(ctx, s.dsnFor(templateName))
	if err != nil {
		return "", err
	}
	defer conn.Close(context.Background())

	var got string
	err = conn.QueryRow(ctx, `SELECT fingerprint FROM crp_test_schema`).Scan(&got)
	return got, err
}

// migrateInto applies every migration to a database, then records what it
// applied.
func (s *postgresServer) migrateInto(ctx context.Context, db string, files []string, mark string) error {
	conn, err := pgx.Connect(ctx, s.dsnFor(db))
	if err != nil {
		return fmt.Errorf("connect to %s: %w", db, err)
	}
	defer conn.Close(context.Background())

	for _, f := range files {
		body, err := os.ReadFile(f) //nolint:gosec // a path migrationFiles built
		if err != nil {
			return fmt.Errorf("read %s: %w", f, err)
		}
		if _, err := conn.Exec(ctx, string(body)); err != nil {
			// Name the file. "syntax error at or near" with no file is a
			// forty-eight-way guess.
			return fmt.Errorf("apply %s: %w", shortName(f), err)
		}
	}

	if _, err := conn.Exec(ctx,
		`CREATE TABLE crp_test_schema (fingerprint TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("record the fingerprint: %w", err)
	}
	if _, err := conn.Exec(ctx,
		`INSERT INTO crp_test_schema (fingerprint) VALUES ($1)`, mark); err != nil {
		return fmt.Errorf("record the fingerprint: %w", err)
	}
	return nil
}

// clone cuts a new database from the template.
func (s *postgresServer) clone(ctx context.Context, name string) error {
	cloneMu.Lock()
	defer cloneMu.Unlock()

	conn, err := s.admin(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())

	// Across processes, the same lock that guards building the template also
	// guards copying it: PostgreSQL refuses to copy a database another session
	// is connected to, and a concurrent rebuild would be exactly that.
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", templateLockKey); err != nil {
		return fmt.Errorf("take the template lock: %w", err)
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = conn.Exec(unlockCtx, "SELECT pg_advisory_unlock($1)", templateLockKey)
	}()

	_, err = conn.Exec(ctx,
		fmt.Sprintf(`CREATE DATABASE %s TEMPLATE %s`, quoteIdent(name), quoteIdent(templateName)))
	if err != nil {
		return fmt.Errorf("clone %s: %w", templateName, err)
	}
	return nil
}

func (s *postgresServer) drop(ctx context.Context, name string) error {
	conn, err := s.admin(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	return s.dropForce(ctx, conn, name)
}

// dropForce removes a database even if something is still connected.
//
// WITH (FORCE) is PostgreSQL 13 and later; this platform requires 16. Without
// it, one leaked connection from a failed test blocks the drop and the database
// accumulates.
func (s *postgresServer) dropForce(ctx context.Context, conn *pgx.Conn, name string) error {
	if _, err := conn.Exec(ctx, `DROP DATABASE IF EXISTS `+quoteIdent(name)+` WITH (FORCE)`); err != nil {
		return fmt.Errorf("drop %s: %w", name, err)
	}
	return nil
}

// quoteIdent quotes a database name.
//
// The names here are built by this package from a hex suffix, so they cannot
// carry anything hostile; quoting them anyway costs nothing and stops this from
// becoming a place where an injected name would work if someone later passed
// one in.
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

func shortName(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}
