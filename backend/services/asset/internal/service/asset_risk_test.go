package service

import (
	"context"
	"fmt"
	"math"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyberradar/platform/services/asset/internal/model"
	"github.com/cyberradar/platform/services/asset/internal/repository"
)

// The risk score exists twice: as ScoreAsset here, which explains it, and as
// an expression in the asset_risk view, which lets a hundred thousand assets
// be ordered and counted by it in the database. Two expressions of one formula
// is a cost, and this is what it buys back — a failure the moment they
// disagree, rather than a list ordered by one number and a detail page
// showing another.
//
// It is an integration test because the second implementation is SQL: there is
// nothing to check without a database that has the view.

// riskTestDB connects to the database this test needs.
//
// Skipping when none is reachable keeps the suite usable on a laptop, but a
// skip is indistinguishable from a pass in CI output, so setting ASSET_TEST_DSN
// turns the skip into a failure. CI sets it.
func riskTestDB(t *testing.T) *pgxpool.Pool {
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

// riskCase is one asset and the findings on it.
type riskCase struct {
	name        string
	criticality int
	assetType   string
	environment string
	cbs         bool
	swift       bool
	pci         bool
	everSeen    bool
	critical    int // open findings by severity
	high        int
	medium      int
	low         int
}

// The cases walk each term of the formula to its cap and past it, because a
// cap applied in one implementation and not the other agrees on every ordinary
// asset and diverges exactly on the ones that matter.
var riskCases = []riskCase{
	{name: "bare workstation", criticality: 1, assetType: "workstation", environment: "staging"},
	{name: "critical, never seen", criticality: 4, assetType: "server", environment: "production", everSeen: false},
	{name: "critical, seen", criticality: 4, assetType: "server", environment: "production", everSeen: true},
	{name: "one critical finding", criticality: 2, assetType: "server", environment: "production", everSeen: true, critical: 1},
	{name: "vuln term at its cap", criticality: 2, assetType: "server", environment: "production", everSeen: true, critical: 3},
	{name: "vuln term past its cap", criticality: 2, assetType: "server", environment: "production", everSeen: true, critical: 9, high: 4},
	{name: "mixed severities", criticality: 3, assetType: "database", environment: "production", everSeen: true, critical: 1, high: 1, medium: 2, low: 5},
	{name: "low findings only", criticality: 1, assetType: "printer", environment: "production", everSeen: true, low: 12},
	{name: "exposure term at its cap", criticality: 3, assetType: "server", environment: "production", everSeen: true, cbs: true, swift: true, pci: true},
	{name: "banking type, cbs", criticality: 4, assetType: "cbs_server", environment: "production", everSeen: true, cbs: true, critical: 1},
	{name: "swift gateway", criticality: 4, assetType: "swift_gateway", environment: "production", everSeen: true, swift: true, high: 2},
	{name: "hsm in pci scope", criticality: 4, assetType: "hsm", environment: "production", everSeen: true, pci: true},
	{name: "everything at once", criticality: 4, assetType: "atm", environment: "production", everSeen: false, cbs: true, swift: true, pci: true, critical: 5, high: 5, medium: 5, low: 5},
	{name: "non-production critical", criticality: 4, assetType: "server", environment: "staging", everSeen: true, critical: 1},
}

func TestTheStoredFormulaAndTheSQLFormulaAgree(t *testing.T) {
	pool := riskTestDB(t)
	ctx := context.Background()

	tenantID := seedRiskFixture(t, pool)
	repo := repository.NewAssetRepository(pool)

	list, err := repo.List(ctx, model.AssetFilter{TenantID: tenantID, Limit: 500})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Assets) != len(riskCases) {
		t.Fatalf("%d assets came back, seeded %d", len(list.Assets), len(riskCases))
	}

	for _, a := range list.Assets {
		t.Run(a.Name, func(t *testing.T) {
			// a.RiskScore is what SQL computed; ScoreAsset is what Go does
			// with the same counters, which SQL also supplied.
			fromGo, breakdown := ScoreAsset(a)
			if math.Abs(fromGo-a.RiskScore) > 0.0001 {
				t.Errorf("SQL says %.4f, Go says %.4f\n"+
					"  criticality %d, type %s, env %s, seen %t, cbs/swift/pci %t/%t/%t\n"+
					"  findings C%d H%d M%d L%d\n"+
					"  Go breakdown: crit %.2f vuln %.2f exposure %.2f behaviour %.2f context %.2f",
					a.RiskScore, fromGo,
					a.Criticality, a.AssetType, a.Environment, a.LastSeenAt != nil,
					a.IsCBSConnected, a.IsSWIFTConnected, a.IsPCIScope,
					a.VulnCritical, a.VulnHigh, a.VulnMedium, a.VulnLow,
					breakdown.CriticalityScore, breakdown.VulnScore,
					breakdown.ExposureScore, breakdown.BehaviorScore, breakdown.ContextScore)
			}
			if a.RiskScore < 0 || a.RiskScore > 10 {
				t.Errorf("risk_score = %.4f, outside 0–10", a.RiskScore)
			}
		})
	}
}

// A finding that is fixed must lower the score. Before the view, nothing moved
// it at all — which is the same symptom as a score that never improves, and
// worth a test of its own rather than trusting the counters alone.
func TestResolvingAFindingLowersTheScore(t *testing.T) {
	pool := riskTestDB(t)
	ctx := context.Background()

	tenantID := seedRiskFixture(t, pool)
	repo := repository.NewAssetRepository(pool)

	find := func() *model.Asset {
		t.Helper()
		list, err := repo.List(ctx, model.AssetFilter{TenantID: tenantID, Limit: 500, Search: "mixed severities"})
		if err != nil || len(list.Assets) == 0 {
			t.Fatalf("the seeded asset is missing: %v", err)
		}
		return list.Assets[0]
	}

	before := find()
	if before.VulnCritical == 0 {
		t.Fatalf("the fixture asset has no critical finding to resolve")
	}

	if _, err := pool.Exec(ctx,
		`UPDATE asset_vulnerabilities SET status = 'resolved', resolved_at = NOW()
		 WHERE tenant_id = $1 AND asset_id = $2`, tenantID, before.ID); err != nil {
		t.Fatalf("resolve findings: %v", err)
	}

	after := find()
	if after.VulnCritical != 0 || after.VulnHigh != 0 || after.VulnMedium != 0 || after.VulnLow != 0 {
		t.Errorf("resolved findings still count: C%d H%d M%d L%d",
			after.VulnCritical, after.VulnHigh, after.VulnMedium, after.VulnLow)
	}
	if after.RiskScore >= before.RiskScore {
		t.Errorf("score went from %.2f to %.2f after every finding was resolved",
			before.RiskScore, after.RiskScore)
	}
}

// seedRiskFixture writes the cases into their own tenant and removes them
// afterwards, so the test says nothing about whatever else the database holds.
func seedRiskFixture(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	tenantID := uuid.New()

	// Assets are keyed to a tenant by a foreign key, so the fixture needs one
	// of its own. Borrowing an existing tenant would put test rows in a
	// customer's estate.
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id, name, slug, status)
		VALUES ($1, $2, $3, 'active')`,
		tenantID, "asset risk fixture", "fixture-"+tenantID.String()[:8]); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	// The assets go in directly: this test is about the formula, not about the
	// create path, and going through the API would tie it to a running estate.
	for i, c := range riskCases {
		var lastSeen *time.Time
		if c.everSeen {
			now := time.Now().UTC()
			lastSeen = &now
		}
		assetID := uuid.New()
		if _, err := pool.Exec(ctx, `
			INSERT INTO assets (id, tenant_id, name, asset_type, criticality, environment,
			                    is_cbs_connected, is_swift_connected, is_pci_scope, last_seen_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			assetID, tenantID, c.name, c.assetType, c.criticality, c.environment,
			c.cbs, c.swift, c.pci, lastSeen); err != nil {
			t.Fatalf("seed asset %q: %v", c.name, err)
		}

		findings := []struct {
			severity string
			count    int
		}{
			{"CRITICAL", c.critical}, {"HIGH", c.high},
			{"MEDIUM", c.medium}, {"LOW", c.low},
		}
		for _, f := range findings {
			for n := 0; n < f.count; n++ {
				vulnID := uuid.New()
				if _, err := pool.Exec(ctx, `
					INSERT INTO vulnerabilities (id, tenant_id, title, cvss_score, cvss_severity)
					VALUES ($1,$2,$3,$4,$5)`,
					vulnID, tenantID,
					fmt.Sprintf("fixture %d/%s/%d", i, f.severity, n), 5.0, f.severity); err != nil {
					t.Fatalf("seed vulnerability: %v", err)
				}
				if _, err := pool.Exec(ctx, `
					INSERT INTO asset_vulnerabilities (tenant_id, asset_id, vuln_id, status)
					VALUES ($1,$2,$3,'open')`, tenantID, assetID, vulnID); err != nil {
					t.Fatalf("seed finding: %v", err)
				}
			}
		}
	}

	t.Cleanup(func() {
		// asset_vulnerabilities cascades from vulnerabilities, not from assets.
		ctx := context.Background()
		//nolint:errcheck // best effort: the tenant is unique to this run
		pool.Exec(ctx, `DELETE FROM asset_vulnerabilities WHERE tenant_id = $1`, tenantID)
		//nolint:errcheck // idem
		pool.Exec(ctx, `DELETE FROM vulnerabilities WHERE tenant_id = $1`, tenantID)
		//nolint:errcheck // idem
		pool.Exec(ctx, `DELETE FROM assets WHERE tenant_id = $1`, tenantID)
		//nolint:errcheck // idem
		pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	return tenantID
}
