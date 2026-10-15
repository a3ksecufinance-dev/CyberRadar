package repository

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// An asset is "covered" when the platform can show it is alive. That verdict
// drives the asset-coverage KPI, and it was wrong in one direction: telemetry
// naming a host by name left that host counted as a blind spot unless the
// address it used was already in the inventory. On the demonstration estate
// that was thirty assets marked as seen out of the fifty-three that were
// sending events, every one of whose hostnames the inventory already held.

func lastSeenTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn, required := os.LookupEnv("ASSET_TEST_DSN")
	if !required {
		dsn = "postgres://crp_user:crp_password_dev@localhost:5432/crp_fresh?sslmode=disable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err == nil {
		err = pool.Ping(ctx)
	}
	if err != nil {
		if required {
			t.Fatalf("ASSET_TEST_DSN is set to %s but it is not reachable: %v", dsn, err)
		}
		t.Skipf("no database at %s (set ASSET_TEST_DSN to require one): %v", dsn, err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// insertTenant creates a tenant of this test's own, so that the tenant
// boundary below is exercised against real rows rather than assumed.
func insertTenant(t *testing.T, pool *pgxpool.Pool, slug string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, id, slug)
	if err != nil {
		t.Fatalf("insert tenant %s: %v", slug, err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, id)
	})
	return id
}

// insertAsset puts one asset in the inventory and removes it afterwards.
func insertAsset(t *testing.T, pool *pgxpool.Pool, tenant uuid.UUID, hostname string, ips []string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `
		INSERT INTO assets (id, tenant_id, name, hostname, asset_type, ip_addresses, criticality, environment, status)
		VALUES ($1, $2, $3, $3, 'workstation', $4, 3, 'production', 'active')`,
		id, tenant, hostname, ips)
	if err != nil {
		t.Fatalf("insert asset %s: %v", hostname, err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM assets WHERE id = $1`, id)
	})
	return id
}

func lastSeenOf(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) *time.Time {
	t.Helper()
	var at *time.Time
	if err := pool.QueryRow(context.Background(),
		`SELECT last_seen_at FROM assets WHERE id = $1`, id).Scan(&at); err != nil {
		t.Fatalf("read last_seen_at: %v", err)
	}
	return at
}

func TestAnAssetNamedByTelemetryCountsAsSeen(t *testing.T) {
	pool := lastSeenTestDB(t)
	repo := NewAssetRepository(pool)
	tenant := insertTenant(t, pool, "crp-last-seen-"+uuid.NewString()[:8])

	// The asset the inventory knows by name, reachable at an address the
	// events do not use — a host behind DHCP, NAT, or simply recorded once.
	named := insertAsset(t, pool, tenant, "crp-last-seen-named", []string{"10.77.0.1"})
	other := insertAsset(t, pool, tenant, "crp-last-seen-other", []string{"10.77.0.2"})

	if got := lastSeenOf(t, pool, named); got != nil {
		t.Fatalf("the asset starts out never seen, got %v", got)
	}

	if err := repo.UpdateLastSeenByHostname(context.Background(), tenant, "crp-last-seen-named"); err != nil {
		t.Fatalf("touch by hostname: %v", err)
	}

	if got := lastSeenOf(t, pool, named); got == nil {
		t.Error("an event naming this host left it counted as never seen")
	}
	if got := lastSeenOf(t, pool, other); got != nil {
		t.Errorf("an unrelated asset was marked as seen: %v", got)
	}
}

// The tenant boundary holds: one customer's telemetry must not mark another
// customer's identically named host as alive.
func TestTouchingByHostnameStaysInsideTheTenant(t *testing.T) {
	pool := lastSeenTestDB(t)
	repo := NewAssetRepository(pool)
	mine := insertTenant(t, pool, "crp-ls-mine-"+uuid.NewString()[:8])
	theirs := insertTenant(t, pool, "crp-ls-theirs-"+uuid.NewString()[:8])

	const shared = "crp-last-seen-shared"
	ours := insertAsset(t, pool, mine, shared, []string{"10.78.0.1"})
	notOurs := insertAsset(t, pool, theirs, shared, []string{"10.78.0.1"})

	if err := repo.UpdateLastSeenByHostname(context.Background(), mine, shared); err != nil {
		t.Fatalf("touch by hostname: %v", err)
	}

	if got := lastSeenOf(t, pool, ours); got == nil {
		t.Error("our own asset was not marked as seen")
	}
	if got := lastSeenOf(t, pool, notOurs); got != nil {
		t.Errorf("another tenant's asset was marked as seen from our telemetry: %v", got)
	}
}
