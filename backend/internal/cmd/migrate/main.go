// Command migrate applies the PostgreSQL schema, once per file, and knows
// which files it has already applied.
//
// What it replaces: a loop over migrations/postgres/*.sql through psql. That
// works exactly once. The second run re-executes every file, and a file that
// is not idempotent — an ALTER TABLE, an INSERT of seed data, a CREATE INDEX
// without IF NOT EXISTS — fails or duplicates. So the local runner carried a
// guard that refused to migrate a database which already had the schema, which
// in turn meant a new migration could not be applied to a running
// installation: the only documented way forward was to drop the database and
// start over. For a platform meant to be deployed at a bank, that is not a
// migration story.
//
// With a version table, each file applies once and a new one applies on top.
//
//	migrate up                 apply everything not yet applied
//	migrate version            what the database is at
//	migrate baseline           mark an existing schema as up to date
//
// There are no down migrations, by decision rather than by omission. Most of
// these files create tables and most of the rest widen a column; the reverse
// of "the column now holds the customer's data" is not a DROP, it is a
// restore. Rolling forward is the only honest direction, so `down` is refused
// with that reason rather than quietly doing something destructive.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/stdlib"

	"database/sql"
)

func main() {
	var (
		dsn = flag.String("dsn", envOr("DATABASE_URL",
			"postgres://crp_user:crp_password_dev@localhost:5432/crp_foundation?sslmode=disable"),
			"PostgreSQL")
		dir   = flag.String("dir", envOr("CRP_MIGRATIONS_DIR", "migrations/postgres"), "where the files are")
		quiet = flag.Bool("quiet", false, "only report what changed")
	)
	flag.Parse()

	verb := flag.Arg(0)
	if verb == "" {
		verb = "up"
	}

	if err := run(verb, *dsn, *dir, *quiet); err != nil {
		fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
		os.Exit(1)
	}
}

func run(verb, dsn, dir string, quiet bool) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if _, err := os.Stat(abs); err != nil {
		return fmt.Errorf("no migrations at %s: %w", abs, err)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("open %s: %w", dsn, err)
	}
	defer db.Close() //nolint:errcheck // closing a pool on the way out
	if err := db.Ping(); err != nil {
		return fmt.Errorf("reach the database: %w", err)
	}

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("prepare the driver: %w", err)
	}
	m, err := migrate.NewWithDatabaseInstance("file://"+abs, "postgres", driver)
	if err != nil {
		return fmt.Errorf("read %s: %w", abs, err)
	}

	switch verb {
	case "up":
		return up(m, db, quiet)
	case "version":
		return version(m)
	case "baseline":
		return baseline(m, db, abs)
	case "down":
		return errors.New("there are no down migrations: this schema rolls forward only, " +
			"because the reverse of a migration that now holds customer data is a restore, not a DROP")
	default:
		return fmt.Errorf("unknown verb %q: up, version or baseline", verb)
	}
}

func up(m *migrate.Migrate, db *sql.DB, quiet bool) error {
	before, dirty, err := m.Version()
	nilVersion := errors.Is(err, migrate.ErrNilVersion)
	if err != nil && !nilVersion {
		return fmt.Errorf("read the current version: %w", err)
	}
	if dirty {
		return fmt.Errorf("the database is marked dirty at version %d: a migration failed half way, "+
			"so what it did and did not do has to be looked at by hand — nothing here will guess. "+
			"Once the schema is back to version %d by hand, clear the flag with "+
			"`UPDATE schema_migrations SET version=%d, dirty=false` and run up again",
			before, before-1, before-1)
	}

	// An installation that predates the version table: the tables are there and
	// nothing records them. Applying 000001 to it fails on the first index that
	// already exists — and a failed Up writes a dirty version 1, after which
	// `up` refuses (dirty) and `baseline` refuses (there is a version now).
	// That is a dead end reached by the first command an operator would run, so
	// the check happens here, before anything is applied.
	if nilVersion {
		has, err := hasSchema(db)
		if err != nil {
			return err
		}
		if has {
			return errors.New("this database already carries the schema but has no migration version: " +
				"it was migrated before the version table existed. Adopt it with `migrate baseline`, " +
				"then `migrate up` will have nothing to do")
		}
	}

	switch err := m.Up(); {
	case errors.Is(err, migrate.ErrNoChange):
		if !quiet {
			fmt.Printf("already at %d, nothing to apply\n", before)
		}
		return nil
	case err != nil:
		return fmt.Errorf("apply: %w", err)
	}

	after, _, err := m.Version()
	if err != nil {
		return fmt.Errorf("read the new version: %w", err)
	}
	fmt.Printf("applied %d → %d\n", before, after)
	return nil
}

func version(m *migrate.Migrate) error {
	v, dirty, err := m.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		fmt.Println("no migration has been applied")
		return nil
	}
	if err != nil {
		return err
	}
	state := ""
	if dirty {
		state = " (dirty — a migration failed half way)"
	}
	fmt.Printf("%d%s\n", v, state)
	return nil
}

// baseline adopts a database that already carries the schema.
//
// Every installation that predates this command is in that state: the tables
// are there and no version table says so. Running the files again would fail
// on the first CREATE TABLE without IF NOT EXISTS, so the version is recorded
// as if they had been applied — which they were, by the loop this command
// replaces.
//
// It refuses on an empty database, because then the right answer is `up`, and
// on one that already has a version, because then there is nothing to adopt.
func baseline(m *migrate.Migrate, db *sql.DB, dir string) error {
	switch v, dirty, err := m.Version(); {
	case errors.Is(err, migrate.ErrNilVersion):
		// What baseline is for.
	case err != nil:
		return err
	case dirty:
		return fmt.Errorf("this database has a dirty version %d, so something was applied half way "+
			"and baseline would hide it. Look at migration %d against the schema; if the schema is "+
			"whole and the row is only the record of a failed attempt, clear it with "+
			"`DELETE FROM schema_migrations` and run baseline again", v, v)
	default:
		return fmt.Errorf("this database is already at version %d; baseline is for one with no version", v)
	}

	has, err := hasSchema(db)
	if err != nil {
		return err
	}
	if !has {
		return errors.New("this database has no schema to adopt: run `migrate up` instead")
	}

	latest, err := latestVersion(dir)
	if err != nil {
		return err
	}
	if err := m.Force(int(latest)); err != nil {
		return fmt.Errorf("record version %d: %w", latest, err)
	}
	fmt.Printf("adopted the existing schema at version %d\n", latest)
	return nil
}

// hasSchema reports whether the platform schema is already there. `tenants` is
// the first table 000001 creates, so its presence means the files have run.
func hasSchema(db *sql.DB) (bool, error) {
	var has bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'tenants')`).Scan(&has); err != nil {
		return false, fmt.Errorf("look for the schema: %w", err)
	}
	return has, nil
}

// latestVersion is the highest numbered file on disk.
func latestVersion(dir string) (uint64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	var latest uint64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		var v uint64
		if _, err := fmt.Sscanf(e.Name(), "%d_", &v); err != nil {
			continue
		}
		if v > latest {
			latest = v
		}
	}
	if latest == 0 {
		return 0, fmt.Errorf("no numbered migration in %s", dir)
	}
	return latest, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// pgx registered as "pgx": the same driver the services use, so a DSN that
// works for them works here.
var _ = stdlib.GetDefaultDriver
