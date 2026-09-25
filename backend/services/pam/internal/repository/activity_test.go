package repository

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testDB connects to the database these tests need.
//
// Skipping when none is reachable keeps the suite usable on a laptop, but a
// skip is indistinguishable from a pass in CI output, so setting PAM_TEST_DSN
// turns the skip into a failure. CI sets it.
func testDB(t *testing.T) (*PAMRepository, uuid.UUID, uuid.UUID) {
	t.Helper()

	dsn, required := os.LookupEnv("PAM_TEST_DSN")
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
			t.Fatalf("PAM_TEST_DSN is set to %s but it is not reachable: %v", dsn, err)
		}
		t.Skipf("no database at %s (set PAM_TEST_DSN to require one): %v", dsn, err)
	}
	t.Cleanup(pool.Close)

	// A tenant and an identity of our own, so the test never depends on seed
	// data and never collides with another test's rows.
	tenantID, identityID := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants (id, name, slug, status) VALUES ($1, $2, $3, 'active')`,
		tenantID, "test-"+tenantID.String()[:8], "test-"+tenantID.String()[:8])
	mustExec(t, pool, `INSERT INTO identities (id, tenant_id, username, email, identity_type, privilege_level, status)
		VALUES ($1, $2, $3, $4, 'user', 'standard', 'active')`,
		identityID, tenantID, "u-"+identityID.String()[:8], identityID.String()[:8]+"@test.local")
	t.Cleanup(func() {
		mustExec(t, pool, `DELETE FROM tenants WHERE id = $1`, tenantID) // cascades
	})

	return NewPAMRepository(pool), tenantID, identityID
}

func mustExec(t *testing.T, pool *pgxpool.Pool, q string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %.40s: %v", q, err)
	}
}

func TestActivityCountsTheDayItIsRecordedAgainst(t *testing.T) {
	repo, tenantID, identityID := testDB(t)
	now := time.Now().UTC()

	for i := 0; i < 3; i++ {
		if err := repo.RecordActivity(context.Background(), tenantID, identityID, now, 1, 0, 0); err != nil {
			t.Fatalf("RecordActivity: %v", err)
		}
	}

	w, err := repo.ReadActivityWindows(context.Background(), tenantID, identityID, now)
	if err != nil {
		t.Fatalf("ReadActivityWindows: %v", err)
	}
	if w.EventsToday != 3 || w.Events7d != 3 {
		t.Errorf("today=%d 7d=%d, want 3 and 3", w.EventsToday, w.Events7d)
	}
}

func TestActivityLeavesTheSevenDayWindow(t *testing.T) {
	// The defect this whole change exists for: a count that never leaves its
	// window is a lifetime total wearing a window's name.
	repo, tenantID, identityID := testDB(t)
	now := time.Now().UTC()
	ctx := context.Background()

	// Inside the window (today and six days back) and outside it (seven back).
	for _, daysAgo := range []int{0, 6} {
		if err := repo.RecordActivity(ctx, tenantID, identityID, now.AddDate(0, 0, -daysAgo), 1, 1, 0); err != nil {
			t.Fatalf("RecordActivity: %v", err)
		}
	}
	if err := repo.RecordActivity(ctx, tenantID, identityID, now.AddDate(0, 0, -7), 1, 1, 0); err != nil {
		t.Fatalf("RecordActivity: %v", err)
	}

	w, err := repo.ReadActivityWindows(ctx, tenantID, identityID, now)
	if err != nil {
		t.Fatalf("ReadActivityWindows: %v", err)
	}
	if w.Events7d != 2 {
		t.Errorf("events_7d = %d, want 2 — the day seven back is outside a 7-day window", w.Events7d)
	}
	if w.Anomalies7d != 2 {
		t.Errorf("anomalies_7d = %d, want 2", w.Anomalies7d)
	}
	if w.Anomalies30d != 3 {
		t.Errorf("anomalies_30d = %d, want 3 — seven days back is still inside 30", w.Anomalies30d)
	}
}

func TestActivityLeavesTheThirtyDayWindow(t *testing.T) {
	repo, tenantID, identityID := testDB(t)
	now := time.Now().UTC()
	ctx := context.Background()

	for _, daysAgo := range []int{29, 30} {
		if err := repo.RecordActivity(ctx, tenantID, identityID, now.AddDate(0, 0, -daysAgo), 1, 1, 1); err != nil {
			t.Fatalf("RecordActivity: %v", err)
		}
	}

	w, err := repo.ReadActivityWindows(ctx, tenantID, identityID, now)
	if err != nil {
		t.Fatalf("ReadActivityWindows: %v", err)
	}
	if w.Anomalies30d != 1 {
		t.Errorf("anomalies_30d = %d, want 1 — day 30 is outside a 30-day window", w.Anomalies30d)
	}
	if w.PrivSessions30d != 1 {
		t.Errorf("priv_sessions_30d = %d, want 1", w.PrivSessions30d)
	}
}

func TestEventsTodayIsOnlyToday(t *testing.T) {
	repo, tenantID, identityID := testDB(t)
	now := time.Now().UTC()
	ctx := context.Background()

	if err := repo.RecordActivity(ctx, tenantID, identityID, now, 2, 0, 0); err != nil {
		t.Fatalf("RecordActivity: %v", err)
	}
	if err := repo.RecordActivity(ctx, tenantID, identityID, now.AddDate(0, 0, -1), 5, 0, 0); err != nil {
		t.Fatalf("RecordActivity: %v", err)
	}

	w, err := repo.ReadActivityWindows(ctx, tenantID, identityID, now)
	if err != nil {
		t.Fatalf("ReadActivityWindows: %v", err)
	}
	if w.EventsToday != 2 {
		t.Errorf("events_today = %d, want 2 — yesterday leaked in", w.EventsToday)
	}
	if w.Events7d != 7 {
		t.Errorf("events_7d = %d, want 7", w.Events7d)
	}
}

func TestAnIdentityWithNoActivityReadsZero(t *testing.T) {
	repo, tenantID, identityID := testDB(t)

	w, err := repo.ReadActivityWindows(context.Background(), tenantID, identityID, time.Now().UTC())
	if err != nil {
		t.Fatalf("ReadActivityWindows on an untouched identity: %v", err)
	}
	if w != (ActivityWindows{}) {
		t.Errorf("windows = %+v, want all zero", w)
	}
}

func TestConcurrentRecordsAreNotLost(t *testing.T) {
	// The second defect: the profile row was read, incremented in memory and
	// written back whole, so two replicas handling the same identity lost one
	// another's counts. The increment now happens in the database.
	repo, tenantID, identityID := testDB(t)
	now := time.Now().UTC()
	const writers, each = 8, 25

	var wg sync.WaitGroup
	wg.Add(writers)
	for i := 0; i < writers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				if err := repo.RecordActivity(context.Background(), tenantID, identityID, now, 1, 0, 0); err != nil {
					t.Errorf("RecordActivity: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	w, err := repo.ReadActivityWindows(context.Background(), tenantID, identityID, now)
	if err != nil {
		t.Fatalf("ReadActivityWindows: %v", err)
	}
	if w.EventsToday != writers*each {
		t.Errorf("events_today = %d, want %d — increments were lost", w.EventsToday, writers*each)
	}
}

func TestActivityIsScopedToItsTenant(t *testing.T) {
	repoA, tenantA, identityA := testDB(t)
	_, tenantB, identityB := testDB(t)
	now := time.Now().UTC()

	if err := repoA.RecordActivity(context.Background(), tenantA, identityA, now, 4, 0, 0); err != nil {
		t.Fatalf("RecordActivity: %v", err)
	}

	w, err := repoA.ReadActivityWindows(context.Background(), tenantB, identityB, now)
	if err != nil {
		t.Fatalf("ReadActivityWindows: %v", err)
	}
	if w.EventsToday != 0 {
		t.Errorf("another tenant's identity reads %d events, want 0", w.EventsToday)
	}
}

func TestPurgeDropsOnlyRowsPastRetention(t *testing.T) {
	repo, tenantID, identityID := testDB(t)
	now := time.Now().UTC()
	ctx := context.Background()

	for _, daysAgo := range []int{0, 29, 40} {
		if err := repo.RecordActivity(ctx, tenantID, identityID, now.AddDate(0, 0, -daysAgo), 1, 0, 0); err != nil {
			t.Fatalf("RecordActivity: %v", err)
		}
	}

	if _, err := repo.PurgeActivityBefore(ctx, now.AddDate(0, 0, -30)); err != nil {
		t.Fatalf("PurgeActivityBefore: %v", err)
	}

	w, err := repo.ReadActivityWindows(ctx, tenantID, identityID, now)
	if err != nil {
		t.Fatalf("ReadActivityWindows: %v", err)
	}
	if w.Anomalies30d != 0 || w.EventsToday != 1 {
		t.Errorf("windows = %+v, want today intact", w)
	}
	// The 29-day-old row must have survived: it is still inside the window.
	if w.Events7d != 1 {
		t.Errorf("events_7d = %d, want 1", w.Events7d)
	}
	var remaining int
	if err := repo.db.QueryRow(ctx,
		`SELECT count(*) FROM identity_activity_daily WHERE tenant_id = $1`, tenantID).Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining != 2 {
		t.Errorf("%d rows left, want 2 — the purge took a row still inside the window", remaining)
	}
}
