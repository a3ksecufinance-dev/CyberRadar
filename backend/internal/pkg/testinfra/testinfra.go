// Package testinfra gives a test real infrastructure: a migrated PostgreSQL, a
// migrated ClickHouse, a Kafka broker.
//
// It exists because of the reason seventeen of the thirty-two services had no
// test at all. In a service built as handler → service → repository, the code
// that is easy to get wrong is the SQL, and there was no way to run SQL in a
// test. So nobody wrote one, and the class of defect that only SQL produces —
// a nullable column scanned into a Go string, which compiles, passes review,
// and answers 500 the first time the column is empty — shipped twice.
//
// # Where the infrastructure comes from
//
// Resolved in this order, per dependency:
//
//  1. An instance this machine already runs, named by CRP_TEST_<X>_DSN. This is
//     what CI uses, through the service containers its workflow already
//     declares, and what a developer who ran scripts/dev-local.sh infra has.
//  2. A container started on demand, when a Docker daemon is reachable.
//  3. Neither, in which case the test SKIPS with a message naming exactly what
//     to set or start — unless CRP_TEST_REQUIRE_INFRA is set, where it FAILS.
//
// The third rule is the one that matters. A test that skips when its database
// is missing is the right behaviour on a laptop and the wrong behaviour in CI,
// where a suite that skipped everything reports the same green as a suite that
// passed. CI sets CRP_TEST_REQUIRE_INFRA=1, so the absence of infrastructure is
// a red build there and a one-line explanation here.
//
// # Why reuse comes before containers
//
// `go test ./...` runs each package as its own process. A helper that always
// started containers would start a set per package — thirty-odd times across
// this workspace — and the suite would take longer than anyone will wait.
// Pointing every package at one already-running instance costs nothing per
// package, which is why CI declares service containers and this resolves to
// them first. The container path is for the developer who has Docker and has
// not started anything; a dedicated CI job exercises it so it cannot rot.
package testinfra

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// Environment variables that point at infrastructure this machine already runs.
const (
	EnvPostgres   = "CRP_TEST_POSTGRES_DSN"
	EnvClickHouse = "CRP_TEST_CLICKHOUSE_DSN"
	EnvKafka      = "CRP_TEST_KAFKA_BROKERS"

	// EnvRequire turns a skip into a failure, for the dependencies it names.
	//
	// "all" (or "1") covers everything; otherwise a comma-separated list of
	// "postgres", "clickhouse", "kafka". It is a list rather than a flag
	// because a pipeline requires exactly what it provides: ours declares
	// PostgreSQL and ClickHouse service containers but no Kafka broker, so a
	// blanket flag would fail the Kafka tests for the pipeline's own omission
	// instead of for a defect.
	EnvRequire = "CRP_TEST_REQUIRE_INFRA"
)

// required reports whether this deployment has asked for a missing dependency
// to fail the test rather than skip it.
func required(dep string) bool {
	v := strings.TrimSpace(os.Getenv(EnvRequire))
	if v == "" {
		return false
	}
	if v == "1" || v == "all" || v == "true" {
		return true
	}
	for _, want := range strings.Split(v, ",") {
		if strings.EqualFold(strings.TrimSpace(want), dep) {
			return true
		}
	}
	return false
}

// unavailable ends the test the way this deployment has asked for: a failure
// where infrastructure is required, a skip with instructions where it is not.
//
// The message always names the variable to set and the command that starts the
// thing locally. "postgres not available" sends a reader to search; naming the
// two ways out does not.
func unavailable(t *testing.T, dep, what, envVar string, cause error) {
	t.Helper()
	msg := fmt.Sprintf(
		"%s is not available: %v\n"+
			"  point the tests at a running instance:  export %s=…\n"+
			"  or start one locally:                   backend/scripts/dev-local.sh infra\n"+
			"  or make a Docker daemon reachable, and this will start a container itself",
		what, cause, envVar)
	if required(dep) {
		t.Fatalf("%s\n  (%s names %s, so this is a failure rather than a skip)", msg, EnvRequire, dep)
	}
	t.Skip(msg)
}

// ─── Finding the repository ──────────────────────────────────────────────────

var (
	rootOnce sync.Once
	rootDir  string
	rootErr  error
)

// RepoRoot is the backend/ directory, found by walking up from the test's own
// working directory until go.work appears.
//
// Tests run in their package's directory, so a relative path to the migrations
// would be a different relative path in every package. Walking up to the file
// that defines the workspace gives every package the same answer.
func RepoRoot() (string, error) {
	rootOnce.Do(func() {
		dir, err := os.Getwd()
		if err != nil {
			rootErr = err
			return
		}
		for {
			if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
				rootDir = dir
				return
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				rootErr = fmt.Errorf("no go.work above %s: cannot locate the migrations", dir)
				return
			}
			dir = parent
		}
	})
	return rootDir, rootErr
}

// ─── Migrations ──────────────────────────────────────────────────────────────

// migrationFiles lists one engine's migrations, in the order they must run.
//
// Sorted by name, which is what the numbering is for. A file that sorts out of
// order would apply out of order, so the names are the contract.
//
// A `.down.sql` is skipped rather than applied. The repository has none today
// — the schema rolls forward only, see internal/cmd/migrate — but the glob
// would happily pick one up and undo the schema it had just built, and the
// failure would land in whichever test ran next.
func migrationFiles(engine string) ([]string, error) {
	root, err := RepoRoot()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(root, "migrations", engine)
	matches, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("no migration found in %s", dir)
	}
	up := upOnly(matches)
	if len(up) == 0 {
		return nil, fmt.Errorf("no up migration found in %s", dir)
	}
	sort.Strings(up)
	return up, nil
}

// upOnly drops the down migrations.
func upOnly(paths []string) []string {
	up := make([]string, 0, len(paths))
	for _, p := range paths {
		if strings.HasSuffix(p, ".down.sql") {
			continue
		}
		up = append(up, p)
	}
	return up
}

// fingerprint is the digest of a set of migrations: their names and their
// bytes.
//
// It is what tells a cached schema from a stale one. The same trick the
// detection catalogue uses for its content: a number somebody has to remember
// to bump is a number that will be wrong, so derive it from what it describes.
func fingerprint(paths []string) (string, error) {
	h := sha256.New()
	for _, p := range paths {
		body, err := os.ReadFile(p) //nolint:gosec // a path this package built
		if err != nil {
			return "", fmt.Errorf("read %s: %w", p, err)
		}
		fmt.Fprintf(h, "%s\n%d\n", filepath.Base(p), len(body))
		h.Write(body)
	}
	return hex.EncodeToString(h.Sum(nil))[:32], nil
}

// statements splits a migration file into executable statements.
//
// PostgreSQL accepts a whole file in one Exec, and ClickHouse does not — it
// takes one statement per call. Splitting on a semicolon at the end of a line
// handles every file in this repository; what it would get wrong is a
// semicolon inside a dollar-quoted body, so the split refuses to cut inside
// one rather than producing two broken halves.
func statements(sql string) []string {
	var out []string
	var cur strings.Builder
	inDollar := false

	for _, line := range strings.Split(sql, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") && !inDollar {
			continue
		}
		// A dollar-quoted body opens and closes with $$ or $tag$; counting the
		// markers on a line toggles the state for an odd number of them.
		if n := strings.Count(line, "$$"); n%2 == 1 {
			inDollar = !inDollar
		}
		cur.WriteString(line)
		cur.WriteString("\n")

		if !inDollar && strings.HasSuffix(trimmed, ";") {
			if s := strings.TrimSpace(cur.String()); s != "" {
				out = append(out, s)
			}
			cur.Reset()
		}
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		out = append(out, s)
	}
	return out
}

// randSuffix names a throwaway database or topic, uniquely across processes.
//
// The pid alone is not enough: two `go test` binaries can be assigned the same
// pid in different containers sharing one database server, and a collision
// here would have one test drop another's database mid-run.
func randSuffix() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is not a condition a test helper can fix, and the
		// pid still separates concurrent runs on one machine.
		return fmt.Sprintf("p%d", os.Getpid())
	}
	return hex.EncodeToString(b[:])
}
