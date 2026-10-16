package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyberradar/platform/internal/pkg/testinfra"
	"github.com/cyberradar/platform/services/easm/internal/model"
)

// The EASM repository: the first test this service has ever had.
//
// Two classes of defect are invisible here without a database.
//
// The first is the tenant filter. Every read takes a tenant and every one of
// them compiles whether or not the WHERE clause uses it, so one omission turns
// one customer's external attack surface — the domains it owns, the leaked
// credentials it has not yet acknowledged — into another customer's dashboard.
//
// The second is a query that fails silently. This repository writes
// `_ = r.db.QueryRow(...).Scan(...)` fifteen times: a query that stops matching
// the schema returns zero rather than an error, and a dashboard of zeros is
// exactly what a clean external attack surface looks like. So the tests below
// assert numbers, not absence of error.

func repo(t *testing.T) (*EASMRepository, *pgxpool.Pool, uuid.UUID) {
	t.Helper()
	pool := testinfra.Postgres(t)
	return NewEASMRepository(pool), pool, testinfra.NewTenant(t, pool)
}

func asset(t *testing.T, r *EASMRepository, tenant uuid.UUID, value string) *model.EASMAsset {
	t.Helper()
	a, err := r.CreateAsset(context.Background(), tenant, &model.CreateAssetRequest{
		AssetType: model.AssetTypeDomain, Value: value,
		Source: "cert_transparency", Tags: []string{"externe"},
		Metadata: map[string]any{"registrar": "ovh"},
	})
	if err != nil {
		t.Fatalf("CreateAsset(%s): %v", value, err)
	}
	return a
}

func exposure(t *testing.T, r *EASMRepository, tenant uuid.UUID, assetID uuid.UUID, severity string) *model.EASMExposure {
	t.Helper()
	port := 8080
	e, err := r.CreateExposure(context.Background(), tenant, &model.CreateExposureRequest{
		AssetID: assetID, ExposureType: model.ExposureTypeAdminInterface,
		Port: &port, Protocol: "tcp",
		Title: "Interface d'administration exposée", Description: "Accessible depuis l'Internet",
		Severity: severity,
	})
	if err != nil {
		t.Fatalf("CreateExposure(%s): %v", severity, err)
	}
	return e
}

// ─── The round trip ──────────────────────────────────────────────────────────

// A created asset reads back as it was written, which is the one thing a test
// of a repository must establish before anything else: that the column list
// and the scan list agree.
func TestAnAssetReadsBackAsItWasWritten(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	made := asset(t, r, tenant, "banque.example")
	got, err := r.GetAsset(ctx, tenant, made.ID)
	if err != nil {
		t.Fatalf("GetAsset: %v", err)
	}
	if got == nil {
		t.Fatal("GetAsset found nothing")
	}
	if got.Value != "banque.example" || got.AssetType != model.AssetTypeDomain {
		t.Errorf("the asset is %s/%s", got.AssetType, got.Value)
	}
	if got.Source != "cert_transparency" {
		t.Errorf("source is %q", got.Source)
	}
	if got.Status != "active" {
		t.Errorf("status is %q, want active", got.Status)
	}
	if len(got.Tags) != 1 || got.Tags[0] != "externe" {
		t.Errorf("tags are %v", got.Tags)
	}
	if got.Metadata["registrar"] != "ovh" {
		t.Errorf("metadata is %v", got.Metadata)
	}
	if got.FirstSeenAt.IsZero() || got.LastSeenAt.IsZero() || got.CreatedAt.IsZero() {
		t.Error("the timestamps came back zero")
	}
	if got.ExposureCount != 0 {
		t.Errorf("exposure_count is %d for an asset with none", got.ExposureCount)
	}
}

// Every nullable column, left NULL, reads back. This is the defect class this
// repository is most exposed to: `source TEXT`, `port INT`, `protocol TEXT`,
// `description TEXT`, `breach_date DATE`, `affected_count INT`,
// `sample_data TEXT` and `similarity_score FLOAT` are all nullable, and a NULL
// scanned into a Go string or int is an error at read time — a 500 on a read,
// for a row that was accepted on write.
func TestEveryNullableColumnReadsBack(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	// An asset with no source, no tags and no metadata.
	bare, err := r.CreateAsset(ctx, tenant, &model.CreateAssetRequest{
		AssetType: model.AssetTypeIP, Value: "203.0.113.7",
	})
	if err != nil {
		t.Fatalf("CreateAsset with nothing optional: %v", err)
	}
	if bare.Source != "" {
		t.Errorf("source is %q, want empty", bare.Source)
	}
	if bare.Tags == nil {
		t.Error("tags came back nil rather than empty")
	}
	got, err := r.GetAsset(ctx, tenant, bare.ID)
	if err != nil {
		t.Fatalf("GetAsset of the bare asset: %v", err)
	}
	if got == nil || got.Value != "203.0.113.7" {
		t.Fatalf("the bare asset did not read back: %+v", got)
	}

	// An exposure with no port, no protocol and no description.
	exp, err := r.CreateExposure(ctx, tenant, &model.CreateExposureRequest{
		AssetID: bare.ID, ExposureType: model.ExposureTypeDanglingDNS,
		Title: "Enregistrement DNS orphelin", Severity: model.SeverityHigh,
	})
	if err != nil {
		t.Fatalf("CreateExposure with nothing optional: %v", err)
	}
	if exp.Port != nil {
		t.Errorf("port is %v, want nil", *exp.Port)
	}
	if exp.RemediatedAt != nil {
		t.Error("remediated_at is set on a fresh exposure")
	}
	exps, total, err := r.ListExposures(ctx, tenant, nil, "", nil, 1, 50)
	if err != nil {
		t.Fatalf("ListExposures: %v", err)
	}
	if total != 1 || len(exps) != 1 {
		t.Fatalf("ListExposures gave total=%d, %d rows", total, len(exps))
	}

	// A leak with no breach date, no count and no sample.
	leak, err := r.CreateLeak(ctx, tenant, &model.CreateLeakRequest{
		Source: "forum", Severity: model.SeverityCritical,
	})
	if err != nil {
		t.Fatalf("CreateLeak with nothing optional: %v", err)
	}
	if leak.BreachDate != nil || leak.AffectedCount != nil {
		t.Errorf("breach_date/affected_count came back set: %v / %v", leak.BreachDate, leak.AffectedCount)
	}
	if _, _, err := r.ListLeaks(ctx, tenant, nil, "", 1, 50); err != nil {
		t.Fatalf("ListLeaks: %v", err)
	}

	// A brand alert with no similarity score.
	alert, err := r.CreateBrandAlert(ctx, tenant, &model.CreateBrandAlertRequest{
		AlertType: model.AlertTypeTyposquatting, Value: "banque-example.com",
	})
	if err != nil {
		t.Fatalf("CreateBrandAlert with no score: %v", err)
	}
	if alert.SimilarityScore != nil {
		t.Errorf("similarity_score is %v, want nil", *alert.SimilarityScore)
	}
	if _, _, err := r.ListBrandAlerts(ctx, tenant, "", "", 1, 50); err != nil {
		t.Fatalf("ListBrandAlerts: %v", err)
	}

	// A scan that has not started: no started_at, no completed_at, no error.
	scan, err := r.CreateScan(ctx, tenant, &model.CreateScanRequest{
		ScanType: model.ScanTypePortScan, Targets: []string{"203.0.113.0/24"},
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	if scan.StartedAt != nil || scan.CompletedAt != nil {
		t.Error("a pending scan came back with start or completion times")
	}
	if got, err := r.GetScan(ctx, tenant, scan.ID); err != nil || got == nil {
		t.Fatalf("GetScan: %v / %v", got, err)
	}
	if _, _, err := r.ListScans(ctx, tenant.String(), 1, 50); err != nil {
		t.Fatalf("ListScans: %v", err)
	}
}

// Seeing the same asset again is an update, not a duplicate, and it brings the
// asset back from inactive. A discovery scan that ran twice must not report
// twice the attack surface.
func TestSeeingAnAssetAgainRevivesItRatherThanDuplicatingIt(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	first := asset(t, r, tenant, "banque.example")
	if _, err := r.UpdateAsset(ctx, tenant, first.ID, &model.UpdateAssetRequest{Status: "inactive"}); err != nil {
		t.Fatalf("UpdateAsset: %v", err)
	}

	again := asset(t, r, tenant, "banque.example")
	if again.ID != first.ID {
		t.Fatalf("the same asset was given a second id: %s then %s", first.ID, again.ID)
	}
	if again.Status != "active" {
		t.Errorf("status is %q after being seen again, want active", again.Status)
	}
	if !again.LastSeenAt.After(first.LastSeenAt) && !again.LastSeenAt.Equal(first.LastSeenAt) {
		t.Errorf("last_seen_at went backwards: %s then %s", first.LastSeenAt, again.LastSeenAt)
	}

	_, total, err := r.ListAssets(ctx, tenant, model.ListAssetsFilter{Page: 1, PageSize: 50})
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	if total != 1 {
		t.Errorf("%d assets after seeing one twice", total)
	}
}

// ─── The tenant boundary ─────────────────────────────────────────────────────

// Nothing one tenant wrote is reachable by another, through any read, update or
// delete. This is the test that would catch a missing tenant_id in a WHERE
// clause, and there is no other way to catch one.
func TestNothingCrossesTheTenantBoundary(t *testing.T) {
	ctx := context.Background()
	r, pool, mine := repo(t)
	theirs := testinfra.NewNamedTenant(t, pool, "Banque voisine")

	a := asset(t, r, mine, "banque.example")
	e := exposure(t, r, mine, a.ID, model.SeverityCritical)
	leak, err := r.CreateLeak(ctx, mine, &model.CreateLeakRequest{
		Source: "forum", Severity: model.SeverityCritical,
	})
	if err != nil {
		t.Fatalf("CreateLeak: %v", err)
	}
	alert, err := r.CreateBrandAlert(ctx, mine, &model.CreateBrandAlertRequest{
		AlertType: model.AlertTypePhishingDomain, Value: "banque-exemple.com",
	})
	if err != nil {
		t.Fatalf("CreateBrandAlert: %v", err)
	}
	scan, err := r.CreateScan(ctx, mine, &model.CreateScanRequest{
		ScanType: model.ScanTypeSubdomainEnum, Targets: []string{"banque.example"},
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}

	// Reads
	if got, err := r.GetAsset(ctx, theirs, a.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the asset: %v / %v", got, err)
	}
	if got, err := r.GetScan(ctx, theirs, scan.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the scan: %v / %v", got, err)
	}
	if rows, total, err := r.ListAssets(ctx, theirs, model.ListAssetsFilter{Page: 1, PageSize: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d assets (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListExposures(ctx, theirs, nil, "", nil, 1, 50); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d exposures (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListLeaks(ctx, theirs, nil, "", 1, 50); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d leaks (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListBrandAlerts(ctx, theirs, "", "", 1, 50); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d brand alerts (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListScans(ctx, theirs.String(), 1, 50); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d scans (total=%d): %v", len(rows), total, err)
	}

	// Writes
	if got, err := r.UpdateAsset(ctx, theirs, a.ID, &model.UpdateAssetRequest{Status: "inactive"}); err != nil || got != nil {
		t.Errorf("the neighbour updated the asset: %v / %v", got, err)
	}
	if got, err := r.RemediateExposure(ctx, theirs, e.ID); err != nil || got != nil {
		t.Errorf("the neighbour remediated the exposure: %v / %v", got, err)
	}
	if got, err := r.AcknowledgeLeak(ctx, theirs, leak.ID, uuid.New()); err != nil || got != nil {
		t.Errorf("the neighbour acknowledged the leak: %v / %v", got, err)
	}
	if got, err := r.UpdateBrandAlert(ctx, theirs, alert.ID, model.AlertStatusFalsePositive); err != nil || got != nil {
		t.Errorf("the neighbour closed the brand alert: %v / %v", got, err)
	}
	if err := r.DeleteAsset(ctx, theirs, a.ID); err == nil {
		t.Error("the neighbour deleted the asset")
	}

	// And after all of that, everything is still as it was.
	mineAsset, err := r.GetAsset(ctx, mine, a.ID)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if mineAsset == nil {
		t.Fatal("the asset is gone")
	}
	if mineAsset.Status != "active" {
		t.Errorf("status is %q — the neighbour's update landed", mineAsset.Status)
	}
	exps, _, err := r.ListExposures(ctx, mine, nil, "", nil, 1, 50)
	if err != nil {
		t.Fatalf("ListExposures: %v", err)
	}
	if len(exps) != 1 || exps[0].IsRemediated {
		t.Errorf("the exposure was remediated by the neighbour: %+v", exps)
	}
	leaks, _, err := r.ListLeaks(ctx, mine, nil, "", 1, 50)
	if err != nil {
		t.Fatalf("ListLeaks: %v", err)
	}
	if len(leaks) != 1 || leaks[0].IsAcknowledged {
		t.Errorf("the leak was acknowledged by the neighbour: %+v", leaks)
	}
}

// ─── The numbers ─────────────────────────────────────────────────────────────

// The statistics are computed by queries whose errors are discarded, so the
// only way a broken one shows up is a number that is wrong. Here the rows are
// known, so each number has one right answer.
func TestTheStatisticsCountWhatIsThere(t *testing.T) {
	ctx := context.Background()
	r, pool, tenant := repo(t)
	other := testinfra.NewNamedTenant(t, pool, "Banque voisine")

	// Two assets, one of them retired.
	a1 := asset(t, r, tenant, "banque.example")
	a2 := asset(t, r, tenant, "www.banque.example")
	if _, err := r.UpdateAsset(ctx, tenant, a2.ID, &model.UpdateAssetRequest{Status: "inactive"}); err != nil {
		t.Fatalf("UpdateAsset: %v", err)
	}

	// Four exposures: one critical, two high, one medium — and the medium one
	// remediated, so it must not count as open.
	exposure(t, r, tenant, a1.ID, model.SeverityCritical)
	exposure(t, r, tenant, a1.ID, model.SeverityHigh)
	exposure(t, r, tenant, a1.ID, model.SeverityHigh)
	fixed := exposure(t, r, tenant, a1.ID, model.SeverityMedium)
	if got, err := r.RemediateExposure(ctx, tenant, fixed.ID); err != nil || got == nil {
		t.Fatalf("RemediateExposure: %v / %v", got, err)
	}

	// A leak, acknowledged, and one not.
	for i, ack := range []bool{true, false} {
		count := 1000 * (i + 1)
		when := time.Date(2026, time.February, 1, 0, 0, 0, 0, time.UTC)
		l, err := r.CreateLeak(ctx, tenant, &model.CreateLeakRequest{
			Source: "forum", BreachDate: &when, DataTypes: []string{"email", "password"},
			AffectedCount: &count, SampleData: "a***@banque.example",
			Severity: model.SeverityHigh,
		})
		if err != nil {
			t.Fatalf("CreateLeak: %v", err)
		}
		if ack {
			user := testinfra.NewIdentity(t, pool, tenant)
			if got, err := r.AcknowledgeLeak(ctx, tenant, l.ID, user); err != nil || got == nil {
				t.Fatalf("AcknowledgeLeak: %v / %v", got, err)
			}
		}
	}

	// Two brand alerts, one dismissed.
	open, err := r.CreateBrandAlert(ctx, tenant, &model.CreateBrandAlertRequest{
		AlertType: model.AlertTypePhishingDomain, Value: "banque-exemple.com",
	})
	if err != nil {
		t.Fatalf("CreateBrandAlert: %v", err)
	}
	dismissed, err := r.CreateBrandAlert(ctx, tenant, &model.CreateBrandAlertRequest{
		AlertType: model.AlertTypeTyposquatting, Value: "banqe.example",
	})
	if err != nil {
		t.Fatalf("CreateBrandAlert: %v", err)
	}
	if got, err := r.UpdateBrandAlert(ctx, tenant, dismissed.ID, model.AlertStatusFalsePositive); err != nil || got == nil {
		t.Fatalf("UpdateBrandAlert: %v / %v", got, err)
	}
	_ = open

	// The neighbour's rows, which must change none of the numbers below.
	nb := asset(t, r, other, "voisine.example")
	exposure(t, r, other, nb.ID, model.SeverityCritical)

	stats, err := r.Stats(ctx, tenant)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"total_assets", stats.TotalAssets, 2},
		{"active_assets", stats.ActiveAssets, 1},
		{"total_exposures", stats.TotalExposures, 4},
		{"remediated_exposures", stats.RemediatedExposures, 1},
		{"open_leaks", stats.OpenLeaks, 1},
		{"open_alerts", stats.OpenAlerts, 1},
	} {
		if c.got != c.want {
			t.Errorf("%s is %d, want %d", c.name, c.got, c.want)
		}
	}
	if stats.ExposuresBySeverity[model.SeverityCritical] != 1 ||
		stats.ExposuresBySeverity[model.SeverityHigh] != 2 {
		t.Errorf("exposures by severity is %v, want 1 critical and 2 high", stats.ExposuresBySeverity)
	}
	if stats.ExposuresBySeverity[model.SeverityMedium] != 0 {
		t.Errorf("the remediated medium exposure is still counted: %v", stats.ExposuresBySeverity)
	}
	if stats.ScansByStatus["pending"] != 0 {
		t.Errorf("scans by status is %v for a tenant with no scan", stats.ScansByStatus)
	}

	// And the risk score the statistics embed: one critical at 25 and two high
	// at 10 each is 45, one open leak is 20, one open alert is 15.
	score := stats.RiskScore
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"critical_exposures", score.CriticalExposures, 1},
		{"high_exposures", score.HighExposures, 2},
		{"active_leaks", score.ActiveLeaks, 1},
		{"active_alerts", score.ActiveAlerts, 1},
		{"exposure_score", score.ExposureScore, 45},
		{"leak_score", score.LeakScore, 20},
		{"brand_score", score.BrandScore, 15},
	} {
		if c.got != c.want {
			t.Errorf("%s is %d, want %d", c.name, c.got, c.want)
		}
	}
	if score.OverallScore == 0 {
		t.Error("the overall score is zero although every component is above it")
	}
	if score.OverallScore > 100 {
		t.Errorf("the overall score is %d, above its own ceiling", score.OverallScore)
	}
}

// A tenant with nothing scores zero rather than failing. An aggregate over no
// rows is the case that breaks a scan into a non-nullable Go type, and a fresh
// customer is exactly that case — on their first login.
func TestAFreshTenantScoresZeroRatherThanFailing(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	score, err := r.ComputeRiskScore(ctx, tenant)
	if err != nil {
		t.Fatalf("ComputeRiskScore on an empty tenant: %v", err)
	}
	if score.OverallScore != 0 || score.AssetScore != 0 || score.ExposureScore != 0 {
		t.Errorf("an empty tenant scores %+v, want zeros", score)
	}
	if score.ComputedAt.IsZero() {
		t.Error("computed_at is zero")
	}

	stats, err := r.Stats(ctx, tenant)
	if err != nil {
		t.Fatalf("Stats on an empty tenant: %v", err)
	}
	if stats.TotalAssets != 0 || stats.TotalExposures != 0 {
		t.Errorf("an empty tenant has %+v", stats)
	}
	// The maps are built rather than left nil: a nil map serialises to null and
	// a dashboard that indexes into it gets nothing instead of zero.
	if stats.ScansByStatus == nil || stats.ExposuresBySeverity == nil {
		t.Error("the breakdown maps came back nil")
	}
}

// ─── Filters and paging ──────────────────────────────────────────────────────

// Each filter narrows what it says it narrows, and the total matches the rows:
// a count built from a different WHERE than the list is how the last page ends
// up empty while the total promises rows.
func TestEachFilterCountsWhatItLists(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	domain := asset(t, r, tenant, "banque.example")
	ip, err := r.CreateAsset(ctx, tenant, &model.CreateAssetRequest{
		AssetType: model.AssetTypeIP, Value: "203.0.113.7",
	})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if _, err := r.UpdateAsset(ctx, tenant, ip.ID, &model.UpdateAssetRequest{
		Status: "inactive", RiskScore: intp(80),
	}); err != nil {
		t.Fatalf("UpdateAsset: %v", err)
	}

	for _, c := range []struct {
		what   string
		filter model.ListAssetsFilter
		want   int
	}{
		{"no filter", model.ListAssetsFilter{Page: 1, PageSize: 50}, 2},
		{"by type", model.ListAssetsFilter{AssetType: model.AssetTypeDomain, Page: 1, PageSize: 50}, 1},
		{"by status", model.ListAssetsFilter{Status: "inactive", Page: 1, PageSize: 50}, 1},
		{"by minimum risk", model.ListAssetsFilter{MinRiskScore: intp(50), Page: 1, PageSize: 50}, 1},
		{"by a risk nobody reaches", model.ListAssetsFilter{MinRiskScore: intp(99), Page: 1, PageSize: 50}, 0},
	} {
		rows, total, err := r.ListAssets(ctx, tenant, c.filter)
		if err != nil {
			t.Fatalf("ListAssets %s: %v", c.what, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: total=%d, %d rows, want %d of each", c.what, total, len(rows), c.want)
		}
	}

	// Exposures: by asset, by severity, and by whether they are remediated.
	crit := exposure(t, r, tenant, domain.ID, model.SeverityCritical)
	exposure(t, r, tenant, ip.ID, model.SeverityLow)
	if _, err := r.RemediateExposure(ctx, tenant, crit.ID); err != nil {
		t.Fatalf("RemediateExposure: %v", err)
	}

	yes, no := true, false
	for _, c := range []struct {
		what       string
		assetID    *uuid.UUID
		severity   string
		remediated *bool
		want       int
	}{
		{"all", nil, "", nil, 2},
		{"on one asset", &domain.ID, "", nil, 1},
		{"critical only", nil, model.SeverityCritical, nil, 1},
		{"remediated only", nil, "", &yes, 1},
		{"still open", nil, "", &no, 1},
		{"open and critical", nil, model.SeverityCritical, &no, 0},
	} {
		rows, total, err := r.ListExposures(ctx, tenant, c.assetID, c.severity, c.remediated, 1, 50)
		if err != nil {
			t.Fatalf("ListExposures %s: %v", c.what, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: total=%d, %d rows, want %d of each", c.what, total, len(rows), c.want)
		}
	}

	// A remediated exposure carries when it was remediated, and an open one
	// does not: the column is what a report on time-to-remediate reads.
	rows, _, err := r.ListExposures(ctx, tenant, nil, "", &yes, 1, 50)
	if err != nil {
		t.Fatalf("ListExposures: %v", err)
	}
	if len(rows) != 1 || rows[0].RemediatedAt == nil {
		t.Errorf("the remediated exposure has no remediated_at: %+v", rows)
	}
	// And it names the asset it was found on, which is what a list has to show.
	if rows[0].AssetValue != "banque.example" {
		t.Errorf("the exposure names asset %q, want banque.example", rows[0].AssetValue)
	}
}

// Deleting an asset takes its exposures with it: an exposure on an asset that
// no longer exists would be a finding nobody can act on, and it would keep
// counting in the statistics.
func TestDeletingAnAssetTakesItsExposures(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	a := asset(t, r, tenant, "banque.example")
	exposure(t, r, tenant, a.ID, model.SeverityHigh)

	if err := r.DeleteAsset(ctx, tenant, a.ID); err != nil {
		t.Fatalf("DeleteAsset: %v", err)
	}
	if got, err := r.GetAsset(ctx, tenant, a.ID); err != nil || got != nil {
		t.Errorf("the asset is still there: %v / %v", got, err)
	}
	_, total, err := r.ListExposures(ctx, tenant, nil, "", nil, 1, 50)
	if err != nil {
		t.Fatalf("ListExposures: %v", err)
	}
	if total != 0 {
		t.Errorf("%d exposures survive their asset", total)
	}

	// And deleting it again is reported rather than silently accepted.
	if err := r.DeleteAsset(ctx, tenant, a.ID); err == nil {
		t.Error("deleting an asset twice reported success")
	}
}

func intp(n int) *int { return &n }
