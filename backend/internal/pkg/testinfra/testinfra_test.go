package testinfra

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// ─── The parts that need no infrastructure ───────────────────────────────────

// A migration file is split into the statements ClickHouse will accept one at a
// time, and a semicolon inside a dollar-quoted body does not cut it.
func TestStatementsSplitsOnlyWhereItMay(t *testing.T) {
	sql := `
-- a leading comment, which is not a statement
CREATE TABLE a (id INT);

CREATE FUNCTION f() RETURNS trigger AS $$
BEGIN
    NEW.x := 1;   -- a semicolon inside the body
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE b (id INT);
`
	got := statements(sql)
	if len(got) != 3 {
		t.Fatalf("%d statements, want 3:\n%s", len(got), strings.Join(got, "\n---\n"))
	}
	if !strings.Contains(got[1], "RETURN NEW;") || !strings.Contains(got[1], "LANGUAGE plpgsql") {
		t.Fatalf("the function body was cut in half:\n%s", got[1])
	}
	if !strings.HasPrefix(got[2], "CREATE TABLE b") {
		t.Fatalf("the statement after the function is wrong:\n%s", got[2])
	}
}

// The fingerprint is what tells a cached schema from a stale one, so it has to
// move when the migrations move and hold still when they do not.
func TestFingerprintFollowsTheContent(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "0001_a.sql")
	b := filepath.Join(dir, "0002_b.sql")
	write := func(p, body string) {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(a, "CREATE TABLE a (id INT);")
	write(b, "CREATE TABLE b (id INT);")

	first, err := fingerprint([]string{a, b})
	if err != nil {
		t.Fatal(err)
	}
	again, err := fingerprint([]string{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if first != again {
		t.Fatalf("the same files gave %s then %s", first, again)
	}

	write(b, "CREATE TABLE b (id BIGINT);")
	changed, err := fingerprint([]string{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if changed == first {
		t.Fatal("a changed migration left the fingerprint alone, so a stale template would be reused")
	}

	// A new file counts even when the existing ones are untouched: this is the
	// 000048 case, where the schema changed by addition.
	c := filepath.Join(dir, "0003_c.sql")
	write(c, "DROP TABLE a;")
	added, err := fingerprint([]string{a, b, c})
	if err != nil {
		t.Fatal(err)
	}
	if added == changed {
		t.Fatal("an added migration left the fingerprint alone")
	}
}

// The repository root is found by walking up, so a test in any package reaches
// the same migrations.
func TestRepoRootFindsTheWorkspace(t *testing.T) {
	root, err := RepoRoot()
	if err != nil {
		t.Fatalf("RepoRoot: %v", err)
	}
	for _, want := range []string{"go.work", "migrations/postgres", "migrations/clickhouse"} {
		if _, err := os.Stat(filepath.Join(root, want)); err != nil {
			t.Errorf("%s is not under the root this found (%s): %v", want, root, err)
		}
	}
}

// Both DSN shapes have to be redirected at another database, because a test
// that connected to the admin database would run its migrations over whatever
// the developer has there.
func TestDSNIsRedirectedToTheTestDatabase(t *testing.T) {
	cases := []struct{ in, want string }{
		{"postgres://u:p@localhost:5432/crp_foundation?sslmode=disable",
			"postgres://u:p@localhost:5432/crp_test_x?sslmode=disable"},
		{"host=localhost user=u dbname=crp_foundation sslmode=disable",
			"host=localhost user=u dbname=crp_test_x sslmode=disable"},
		{"host=localhost user=u sslmode=disable",
			"host=localhost user=u sslmode=disable dbname=crp_test_x"},
	}
	for _, c := range cases {
		s := &postgresServer{adminDSN: c.in}
		if got := s.dsnFor("crp_test_x"); got != c.want {
			t.Errorf("dsnFor(%q)\n  got  %q\n  want %q", c.in, got, c.want)
		}
	}
}

func TestQuoteIdent(t *testing.T) {
	if got := quoteIdent(`crp_test_a"b`); got != `"crp_test_a""b"` {
		t.Fatalf("quoteIdent gave %s", got)
	}
}

// ─── The parts that need PostgreSQL ──────────────────────────────────────────

// A test gets the schema the platform deploys, not an approximation of it.
func TestPostgresGivesTheMigratedSchema(t *testing.T) {
	pool := Postgres(t)
	ctx := context.Background()

	var tables int
	err := pool.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.tables
		 WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`).Scan(&tables)
	if err != nil {
		t.Fatalf("count tables: %v", err)
	}
	// One more than the platform's own count: crp_test_schema carries the
	// fingerprint. Asserting a floor rather than an exact number keeps this
	// test from failing on every new migration.
	if tables < 100 {
		t.Fatalf("%d tables — this is not a migrated schema", tables)
	}

	// The five tables dropped by 000048 must be gone. A template built before
	// that migration would still have them, which is exactly the staleness the
	// fingerprint exists to catch.
	for _, dead := range []string{
		"config_entries", "config_history", "notification_rules",
		"identity_privileges", "asset_scans",
	} {
		var exists bool
		err := pool.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM information_schema.tables
			                WHERE table_schema='public' AND table_name=$1)`, dead).Scan(&exists)
		if err != nil {
			t.Fatalf("look for %s: %v", dead, err)
		}
		if exists {
			t.Errorf("%s is still here: the template predates migration 000048", dead)
		}
	}

	// And the rows the migrations seed have to be there, or every test would
	// have to seed the permission catalogue itself.
	var perms int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM permissions`).Scan(&perms); err != nil {
		t.Fatalf("count permissions: %v", err)
	}
	if perms < 60 {
		t.Fatalf("%d permissions — the seeding migrations did not run", perms)
	}
}

// Two tests must not see each other's rows. This is the property that lets a
// suite run without every test cleaning up after itself.
func TestEachTestGetsItsOwnDatabase(t *testing.T) {
	ctx := context.Background()
	a := Postgres(t)
	b := Postgres(t)

	if a.Config().ConnString() == b.Config().ConnString() {
		t.Fatal("both calls returned the same database")
	}

	if _, err := a.Exec(ctx, `INSERT INTO tenants (name, slug) VALUES ('isolation', 'isolation-a')`); err != nil {
		t.Fatalf("insert into the first database: %v", err)
	}

	var seen int
	if err := b.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE slug = 'isolation-a'`).Scan(&seen); err != nil {
		t.Fatalf("read the second database: %v", err)
	}
	if seen != 0 {
		t.Fatalf("the second database can see the first one's row")
	}
}

// The template is built once and reused, so the second call must not pay for
// forty-eight migrations again.
func TestTheTemplateIsReused(t *testing.T) {
	first := Postgres(t)
	ctx := context.Background()

	var mark string
	if err := first.QueryRow(ctx, `SELECT fingerprint FROM crp_test_schema`).Scan(&mark); err != nil {
		t.Fatalf("read the fingerprint carried into the clone: %v", err)
	}

	files, err := migrationFiles("postgres")
	if err != nil {
		t.Fatal(err)
	}
	want, err := fingerprint(files)
	if err != nil {
		t.Fatal(err)
	}
	if mark != want {
		t.Fatalf("the clone carries fingerprint %s, the migrations on disk hash to %s", mark, want)
	}
}

// ─── The parts that need ClickHouse and Kafka ────────────────────────────────

// ClickHouse arrives migrated: the seven databases the platform writes to are
// there, with their tables.
func TestClickHouseGivesTheMigratedSchema(t *testing.T) {
	conn := ClickHouse(t)
	ctx := context.Background()

	rows, err := conn.Query(ctx, `
		SELECT database, count(*) FROM system.tables
		 WHERE database LIKE 'crp_%' GROUP BY database ORDER BY database`)
	if err != nil {
		t.Fatalf("list ClickHouse databases: %v", err)
	}
	defer rows.Close()

	seen := map[string]uint64{}
	for rows.Next() {
		var db string
		var n uint64
		if err := rows.Scan(&db, &n); err != nil {
			t.Fatal(err)
		}
		seen[db] = n
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	for _, db := range []string{"crp_audit", "crp_fabric", "crp_siem", "crp_ueba", "crp_ti", "crp_vuln", "crp_dash"} {
		if seen[db] == 0 {
			t.Errorf("%s has no table — the migrations did not run", db)
		}
	}
}

// A test gets a topic of its own, and never the platform's.
func TestKafkaGivesATopicOfItsOwn(t *testing.T) {
	a := Kafka(t)
	b := Kafka(t)

	if a.Topic == b.Topic {
		t.Fatal("two tests were handed the same topic")
	}
	for _, f := range []*KafkaFixture{a, b} {
		if !strings.HasPrefix(f.Topic, "crp.test.") {
			t.Fatalf("%s is not under the test prefix: a test must never write to a platform topic", f.Topic)
		}
	}

	// The topic exists: a writer that has to create it would hide a broker
	// that refused the creation.
	conn, _, err := controllerConn(a.Brokers)
	if err != nil {
		t.Fatalf("reach the controller: %v", err)
	}
	defer conn.Close()
	parts, err := conn.ReadPartitions(a.Topic)
	if err != nil {
		t.Fatalf("read partitions of %s: %v", a.Topic, err)
	}
	if len(parts) != 1 {
		t.Fatalf("%s has %d partitions, want 1", a.Topic, len(parts))
	}
}

// The require list is per dependency, because a pipeline requires exactly what
// it provides. Ours declares PostgreSQL and ClickHouse and no Kafka broker; a
// blanket flag would fail the Kafka tests for the pipeline's omission rather
// than for a defect.
func TestRequireIsPerDependency(t *testing.T) {
	cases := []struct {
		set  string
		want map[string]bool
	}{
		{"", map[string]bool{"postgres": false, "clickhouse": false, "kafka": false}},
		{"1", map[string]bool{"postgres": true, "clickhouse": true, "kafka": true}},
		{"all", map[string]bool{"postgres": true, "clickhouse": true, "kafka": true}},
		{"postgres,clickhouse", map[string]bool{"postgres": true, "clickhouse": true, "kafka": false}},
		{" Postgres , kafka ", map[string]bool{"postgres": true, "clickhouse": false, "kafka": true}},
	}
	for _, c := range cases {
		t.Setenv(EnvRequire, c.set)
		for dep, want := range c.want {
			if got := required(dep); got != want {
				t.Errorf("%s=%q: required(%s) = %v, want %v", EnvRequire, c.set, dep, got, want)
			}
		}
	}
}

// The real migrations are named for golang-migrate, so the list has to pick
// them up under that naming and has to leave a down migration alone. Nothing
// in the repository ships one, which is exactly why the guard needs a test:
// the day somebody adds one, the template would otherwise be built by applying
// the schema and then undoing part of it.
func TestTheListTakesTheUpMigrationsAndOnlyThose(t *testing.T) {
	files, err := migrationFiles("postgres")
	if err != nil {
		t.Fatalf("migrationFiles: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no migration listed")
	}
	for _, f := range files {
		if !strings.HasSuffix(f, ".up.sql") {
			t.Errorf("%s is not an up migration; golang-migrate would not apply it either", f)
		}
	}
	if !sort.StringsAreSorted(files) {
		t.Error("the files came back out of order, so they would apply out of order")
	}

	// And the filter itself, since the repository has nothing for it to drop.
	kept := upOnly([]string{"0001_a.up.sql", "0001_a.down.sql", "0002_b.up.sql"})
	if want := []string{"0001_a.up.sql", "0002_b.up.sql"}; !slices.Equal(kept, want) {
		t.Errorf("upOnly kept %v, want %v", kept, want)
	}
}
