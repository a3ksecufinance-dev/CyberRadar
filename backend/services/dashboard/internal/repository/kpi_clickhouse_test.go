package repository

import (
	"context"
	"os"
	"testing"
	"time"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"

	"github.com/cyberradar/platform/services/dashboard/internal/model"
)

// testCH connects to the ClickHouse these tests need.
//
// Skipping when none is reachable keeps the suite usable on a laptop, but a
// skip is indistinguishable from a pass in CI output, so setting
// DASHBOARD_TEST_CH turns the skip into a failure.
func testCH(t *testing.T) driver.Conn {
	t.Helper()

	dsn, required := os.LookupEnv("DASHBOARD_TEST_CH")
	if !required {
		dsn = "localhost:9000"
	}
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{dsn},
		Auth: clickhouse.Auth{Database: "default"},
	})
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err = conn.Ping(ctx)
	}
	if err != nil {
		if required {
			t.Fatalf("DASHBOARD_TEST_CH is set to %s but it is not reachable: %v", dsn, err)
		}
		t.Skipf("no ClickHouse at %s (set DASHBOARD_TEST_CH to require one): %v", dsn, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// The whole dashboard is assembled from these snapshots — PlatformOverview
// computes nothing of its own, it reads the latest reading each domain
// published. This exercises the write and the read-back against a real store.
func TestSnapshotRoundTrip(t *testing.T) {
	repo := NewKPIRepository(testCH(t))
	ctx := context.Background()
	tenantID := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	snaps := []model.KPISnapshot{
		{TenantID: tenantID, Domain: "siem", MetricKey: "open_alerts", MetricValue: 12, SnappedAt: now.Add(-2 * time.Minute)},
		{TenantID: tenantID, Domain: "siem", MetricKey: "open_alerts", MetricValue: 17, SnappedAt: now},
		{TenantID: tenantID, Domain: "siem", MetricKey: "critical_alerts", MetricValue: 3, SnappedAt: now},
		{TenantID: tenantID, Domain: "siem", MetricKey: "risk_score", MetricValue: 42, SnappedAt: now,
			Labels: map[string]string{"formula": "weighted"}},
		{TenantID: tenantID, Domain: "ti", MetricKey: "active_iocs", MetricValue: 900, SnappedAt: now},
	}
	if err := repo.InsertSnapshotBatch(ctx, snaps); err != nil {
		t.Fatalf("InsertSnapshotBatch: %v", err)
	}

	latest, err := repo.LatestSnapshots(ctx, tenantID, "siem")
	if err != nil {
		t.Fatalf("LatestSnapshots: %v", err)
	}
	// The newest reading wins: an overview showing a two-minute-old alert count
	// beside a current one would be incoherent.
	if latest["open_alerts"] != 17 {
		t.Errorf("open_alerts = %v, want the most recent value 17", latest["open_alerts"])
	}
	if latest["critical_alerts"] != 3 || latest["risk_score"] != 42 {
		t.Errorf("latest = %v", latest)
	}
	// A domain's snapshot must not leak into another's.
	if _, found := latest["active_iocs"]; found {
		t.Error("a ti metric appeared in the siem snapshot")
	}

	// And one tenant must never see another's numbers.
	other, err := repo.LatestSnapshots(ctx, uuid.New(), "siem")
	if err != nil {
		t.Fatalf("LatestSnapshots for another tenant: %v", err)
	}
	if len(other) != 0 {
		t.Errorf("another tenant saw %d metric(s)", len(other))
	}
}

func TestTimeSeriesReturnsThePointsInOrder(t *testing.T) {
	repo := NewKPIRepository(testCH(t))
	ctx := context.Background()
	tenantID := uuid.New()
	now := time.Now().UTC().Truncate(time.Hour)

	var snaps []model.KPISnapshot
	for i := 0; i < 5; i++ {
		snaps = append(snaps, model.KPISnapshot{
			TenantID: tenantID, Domain: "vuln", MetricKey: "critical_vulns",
			MetricValue: float64(10 + i),
			SnappedAt:   now.Add(time.Duration(i-5) * time.Hour),
		})
	}
	if err := repo.InsertSnapshotBatch(ctx, snaps); err != nil {
		t.Fatalf("InsertSnapshotBatch: %v", err)
	}

	points, err := repo.QueryTimeSeries(ctx, model.KPIQueryRequest{
		TenantID:  tenantID,
		Domain:    "vuln",
		MetricKey: "critical_vulns",
		Interval:  "1h",
		Since:     now.Add(-24 * time.Hour),
		Until:     now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("QueryTimeSeries: %v", err)
	}
	if len(points) == 0 {
		t.Fatal("no points returned for a metric that has five readings")
	}
	for i := 1; i < len(points); i++ {
		if points[i].Timestamp.Before(points[i-1].Timestamp) {
			t.Fatalf("points are not in chronological order: %v then %v",
				points[i-1].Timestamp, points[i].Timestamp)
		}
	}
}

// An unreported domain must read as absent, not as zero: the dashboard has to
// be able to tell "no alerts" from "the SIEM has not reported".
func TestUnreportedDomainIsEmpty(t *testing.T) {
	repo := NewKPIRepository(testCH(t))
	latest, err := repo.LatestSnapshots(context.Background(), uuid.New(), "ueba")
	if err != nil {
		t.Fatalf("LatestSnapshots: %v", err)
	}
	if len(latest) != 0 {
		t.Errorf("an unreported domain returned %d metric(s)", len(latest))
	}
}
