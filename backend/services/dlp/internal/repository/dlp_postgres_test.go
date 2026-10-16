package repository

import (
	"context"
	"testing"

	"github.com/cyberradar/platform/internal/pkg/testinfra"
	"github.com/cyberradar/platform/services/dlp/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The DLP repository against a real PostgreSQL.
//
// Two things only a database can show. The first is the nullable column read
// into a Go string: it compiles, it passes vet, and it fails on every single
// call. The second is the identifier that arrives from the caller — a label, a
// policy, an asset — where the row written carries the caller's own tenant_id,
// so the tenant filter on the write proves nothing about what the write points
// at.

func repo(t *testing.T) (*DLPRepository, *pgxpool.Pool, uuid.UUID) {
	t.Helper()
	pool := testinfra.Postgres(t)
	return NewDLPRepository(pool), pool, testinfra.NewTenant(t, pool)
}

func label(t *testing.T, r *DLPRepository, tenant uuid.UUID, name, sensitivity string) *model.DLPLabel {
	t.Helper()
	l, err := r.CreateLabel(context.Background(), tenant, &model.CreateLabelRequest{
		Name: name, Description: "Étiquette de test", Sensitivity: sensitivity,
		RegexPatterns: []string{`\d{13,19}`}, Keywords: []string{"IBAN"},
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("CreateLabel(%s): %v", name, err)
	}
	return l
}

func asset(t *testing.T, r *DLPRepository, tenant uuid.UUID, name string, labelID *uuid.UUID) *model.DLPDataAsset {
	t.Helper()
	a, err := r.CreateAsset(context.Background(), tenant, &model.CreateAssetRequest{
		Name: name, AssetType: model.AssetTypeDatabase, Location: "pg://coffre/" + name,
		LabelID: labelID, DataCategories: []string{model.DataCategoryPII},
		RecordCount: 1200, SizeBytes: 4096, Owner: "equipe-donnees",
		Metadata: map[string]any{"région": "eu-west-3"},
	})
	if err != nil {
		t.Fatalf("CreateAsset(%s): %v", name, err)
	}
	return a
}

func policy(t *testing.T, r *DLPRepository, tenant uuid.UUID, name, action string) *model.DLPPolicy {
	t.Helper()
	p, err := r.CreatePolicy(context.Background(), tenant, &model.CreatePolicyRequest{
		Name: name, Description: "Politique de test", PolicyType: model.PolicyTypeExfiltration,
		SensitivityLevels: []string{model.SensitivityRestricted},
		DataCategories:    []string{model.DataCategoryPCI},
		Action:            action, Channels: []string{"email", "usb"},
		Conditions: map[string]any{"min_matches": 3},
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("CreatePolicy(%s): %v", name, err)
	}
	return p
}

// ─── The round trip ──────────────────────────────────────────────────────────

// Everything optional left out. This is the shape of the call that a real
// agent makes, and the shape that fails when a nullable column lands in a
// string.
func TestAViolationWithNothingOptionalReadsBack(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	v, err := r.CreateViolation(ctx, tenant, &model.ReportViolationRequest{
		ViolationType: model.PolicyTypeExfiltration,
		Severity:      model.SeverityHigh,
		ActionTaken:   model.ActionAlert,
	})
	if err != nil {
		t.Fatalf("CreateViolation with nothing optional: %v", err)
	}
	if v.Status != model.ViolationStatusOpen {
		t.Errorf("status is %q, want the schema's default", v.Status)
	}
	if v.MatchCount != 1 {
		t.Errorf("match_count is %d, want the 1 the repository substitutes", v.MatchCount)
	}
	if v.Channel != "" || v.UserIDSrc != "" || v.Endpoint != "" || v.Destination != "" || v.DataSnippet != "" {
		t.Errorf("an optional field came back filled: %+v", v)
	}

	// And the same row read through the list, which joins the policy name.
	rows, total, err := r.ListViolations(ctx, tenant, model.ListViolationsFilter{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("ListViolations: %v", err)
	}
	if total != 1 || len(rows) != 1 {
		t.Fatalf("%d violations listed (total=%d), want 1", len(rows), total)
	}
	if rows[0].ID != v.ID {
		t.Errorf("the list returned %s, want %s", rows[0].ID, v.ID)
	}
}

// A full violation keeps every field it was given, and the update keeps them.
func TestAFullViolationSurvivesAnUpdate(t *testing.T) {
	ctx := context.Background()
	r, pool, tenant := repo(t)
	l := label(t, r, tenant, "Carte bancaire", model.SensitivityRestricted)
	a := asset(t, r, tenant, "clients", &l.ID)
	p := policy(t, r, tenant, "Pas de PAN par courriel", model.ActionBlock)
	who := testinfra.NewIdentity(t, pool, tenant)

	v, err := r.CreateViolation(ctx, tenant, &model.ReportViolationRequest{
		PolicyID: &p.ID, AssetID: &a.ID, LabelID: &l.ID,
		ViolationType: model.PolicyTypeExfiltration, Channel: "email",
		Severity: model.SeverityCritical, UserIDSrc: "jdupont",
		Endpoint: "10.0.0.12", Destination: "gmail.com",
		DataSnippet: "4***-****-****-1234", MatchCount: 7,
		ActionTaken: model.ActionBlock,
	})
	if err != nil {
		t.Fatalf("CreateViolation: %v", err)
	}
	if v.MatchCount != 7 || v.Channel != "email" || v.Destination != "gmail.com" {
		t.Errorf("a field was lost on the way in: %+v", v)
	}
	if v.PolicyID == nil || *v.PolicyID != p.ID || v.AssetID == nil || *v.AssetID != a.ID {
		t.Errorf("the violation lost what it points at: %+v", v)
	}

	// Taken up, then resolved. The resolution stamps a date; being taken up
	// does not.
	taken, err := r.UpdateViolation(ctx, tenant, v.ID, &model.UpdateViolationRequest{
		Status: model.ViolationStatusInvestigating, InvestigatedBy: &who,
	})
	if err != nil {
		t.Fatalf("UpdateViolation(investigating): %v", err)
	}
	if taken == nil {
		t.Fatal("UpdateViolation returned nothing")
	}
	if taken.Status != model.ViolationStatusInvestigating {
		t.Errorf("status is %q", taken.Status)
	}
	if taken.InvestigatedBy == nil || *taken.InvestigatedBy != who {
		t.Errorf("investigated_by is %v", taken.InvestigatedBy)
	}
	if taken.ResolvedAt != nil {
		t.Error("a violation under investigation already carries a resolution date")
	}
	if taken.MatchCount != 7 || taken.DataSnippet != "4***-****-****-1234" {
		t.Errorf("the update lost a field it did not name: %+v", taken)
	}

	resolved, err := r.UpdateViolation(ctx, tenant, v.ID, &model.UpdateViolationRequest{
		Status: model.ViolationStatusResolved,
	})
	if err != nil || resolved == nil {
		t.Fatalf("UpdateViolation(resolved): %v", err)
	}
	if resolved.ResolvedAt == nil {
		t.Error("a resolved violation carries no resolution date")
	}
	if resolved.InvestigatedBy == nil {
		t.Error("the resolution forgot who investigated")
	}

	// An update that names nothing is refused rather than silently writing an
	// empty SET clause.
	if _, err := r.UpdateViolation(ctx, tenant, v.ID, &model.UpdateViolationRequest{}); err == nil {
		t.Error("an update naming no field was accepted")
	}
}

// The policy counter follows the violations that cite it.
func TestReportingAViolationCountsAgainstItsPolicy(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	p := policy(t, r, tenant, "Pas de PAN par courriel", model.ActionBlock)
	other := policy(t, r, tenant, "Pas d'export USB", model.ActionQuarantine)

	for i := 0; i < 3; i++ {
		if _, err := r.CreateViolation(ctx, tenant, &model.ReportViolationRequest{
			PolicyID: &p.ID, ViolationType: model.PolicyTypeExfiltration,
			Severity: model.SeverityHigh, ActionTaken: model.ActionAlert,
		}); err != nil {
			t.Fatalf("CreateViolation %d: %v", i, err)
		}
	}

	live, err := r.GetPolicy(ctx, tenant, p.ID)
	if err != nil || live == nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if live.ViolationCount != 3 {
		t.Errorf("violation_count is %d, want the 3 violations raised", live.ViolationCount)
	}
	untouched, err := r.GetPolicy(ctx, tenant, other.ID)
	if err != nil || untouched == nil {
		t.Fatalf("GetPolicy(other): %v", err)
	}
	if untouched.ViolationCount != 0 {
		t.Errorf("the other policy counts %d violations", untouched.ViolationCount)
	}

	stats, err := r.Stats(ctx, tenant)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.TotalViolations != 3 || stats.OpenViolations != 3 {
		t.Errorf("stats say %d total / %d open, want 3 / 3", stats.TotalViolations, stats.OpenViolations)
	}
	if stats.ViolationsBySeverity[model.SeverityHigh] != 3 {
		t.Errorf("severity breakdown is %v", stats.ViolationsBySeverity)
	}
	if len(stats.TopPolicies) == 0 || stats.TopPolicies[0].PolicyID != p.ID {
		t.Errorf("top policies are %+v, want ours first", stats.TopPolicies)
	}
}

// An asset carries the name of its label, and the label of another tenant is
// not a label this asset can carry.
func TestAnAssetCarriesTheNameOfItsOwnLabel(t *testing.T) {
	ctx := context.Background()
	r, pool, mine := repo(t)
	theirs := testinfra.NewNamedTenant(t, pool, "Banque voisine")

	ours := label(t, r, mine, "Interne", model.SensitivityInternal)
	foreign := label(t, r, theirs, "Projet Chimère", model.SensitivityTopSecret)

	a := asset(t, r, mine, "entrepot", &ours.ID)
	if a.LabelName != "Interne" {
		t.Errorf("the asset shows label %q, want its own", a.LabelName)
	}

	if got, err := r.CreateAsset(ctx, mine, &model.CreateAssetRequest{
		Name: "intrus", AssetType: model.AssetTypeDatabase, Location: "pg://x",
		LabelID: &foreign.ID,
	}); err == nil {
		t.Errorf("an asset was labelled with the neighbour's label: %+v", got)
	}
	if got, err := r.UpdateAsset(ctx, mine, a.ID, &model.UpdateAssetRequest{
		LabelID: &foreign.ID,
	}); err == nil && got != nil && got.LabelID != nil && *got.LabelID == foreign.ID {
		t.Errorf("the asset was relabelled with the neighbour's label, which is named %q", got.LabelName)
	}
}

// A scan names the asset it scanned, and the scan's outcome lands on that
// asset.
func TestAScanMovesTheAssetItNames(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	a := asset(t, r, tenant, "clients", nil)
	if a.ScanStatus != "pending" {
		t.Errorf("a fresh asset is %q, want pending", a.ScanStatus)
	}

	sc, err := r.CreateScan(ctx, tenant, &a.ID, uuid.Nil)
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	if sc.Status != "pending" || sc.ErrorText != "" {
		t.Errorf("a fresh scan is %+v", sc)
	}

	if err := r.UpdateScanStatus(ctx, tenant, sc.ID, "running", 0, 0, nil, ""); err != nil {
		t.Fatalf("UpdateScanStatus(running): %v", err)
	}
	if err := r.UpdateScanStatus(ctx, tenant, sc.ID, "completed", 42000, 3,
		[]string{"PII", "PCI"}, ""); err != nil {
		t.Fatalf("UpdateScanStatus(completed): %v", err)
	}
	if err := r.UpdateAssetScanStatus(ctx, tenant, a.ID, "violations_found", 3); err != nil {
		t.Fatalf("UpdateAssetScanStatus: %v", err)
	}

	scans, total, err := r.ListScans(ctx, tenant, &a.ID, 1, 10)
	if err != nil || total != 1 || len(scans) != 1 {
		t.Fatalf("ListScans: %d/%d %v", len(scans), total, err)
	}
	got := scans[0]
	if got.Status != "completed" || got.ItemsScanned != 42000 || got.ViolationsFound != 3 {
		t.Errorf("the scan reads back as %+v", got)
	}
	if len(got.LabelsDetected) != 2 {
		t.Errorf("labels_detected is %v", got.LabelsDetected)
	}
	if got.StartedAt == nil || got.CompletedAt == nil {
		t.Errorf("a completed scan has no start or no end: %+v", got)
	}

	live, err := r.GetAsset(ctx, tenant, a.ID)
	if err != nil || live == nil {
		t.Fatalf("GetAsset: %v", err)
	}
	if live.ScanStatus != "violations_found" {
		t.Errorf("the asset is %q after a scan that found three violations", live.ScanStatus)
	}
	if live.RiskScore != 30 {
		t.Errorf("risk_score is %d, want the 3×10 the scan added", live.RiskScore)
	}
	if live.LastScannedAt == nil {
		t.Error("the asset records no scan date")
	}
}

// The failed scan keeps the reason.
func TestAFailedScanKeepsItsReason(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	sc, err := r.CreateScan(ctx, tenant, nil, uuid.Nil)
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	if err := r.UpdateScanStatus(ctx, tenant, sc.ID, "failed", 10, 0, nil,
		"connexion refusée par le coffre"); err != nil {
		t.Fatalf("UpdateScanStatus(failed): %v", err)
	}
	scans, _, err := r.ListScans(ctx, tenant, nil, 1, 10)
	if err != nil || len(scans) != 1 {
		t.Fatalf("ListScans: %v", err)
	}
	if scans[0].ErrorText != "connexion refusée par le coffre" {
		t.Errorf("the failure reads %q", scans[0].ErrorText)
	}
}

// ─── The tenant boundary ─────────────────────────────────────────────────────

// Nothing a caller names lets them read, move, or charge anything that belongs
// to another customer.
func TestNothingCrossesTheTenantBoundary(t *testing.T) {
	ctx := context.Background()
	r, pool, mine := repo(t)
	theirs := testinfra.NewNamedTenant(t, pool, "Banque voisine")

	l := label(t, r, mine, "Carte bancaire", model.SensitivityRestricted)
	a := asset(t, r, mine, "clients", &l.ID)
	p := policy(t, r, mine, "Pas de PAN par courriel", model.ActionBlock)
	v, err := r.CreateViolation(ctx, mine, &model.ReportViolationRequest{
		PolicyID: &p.ID, AssetID: &a.ID, LabelID: &l.ID,
		ViolationType: model.PolicyTypeExfiltration, Severity: model.SeverityCritical,
		ActionTaken: model.ActionBlock,
	})
	if err != nil {
		t.Fatalf("CreateViolation: %v", err)
	}
	sc, err := r.CreateScan(ctx, mine, &a.ID, uuid.Nil)
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}

	// Reads
	if got, err := r.GetLabel(ctx, theirs, l.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the label: %v / %v", got, err)
	}
	if got, err := r.GetAsset(ctx, theirs, a.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the asset: %v / %v", got, err)
	}
	if got, err := r.GetPolicy(ctx, theirs, p.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the policy: %v / %v", got, err)
	}
	if rows, total, err := r.ListLabels(ctx, theirs, false, 1, 50); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d labels (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListAssets(ctx, theirs, model.ListAssetsFilter{Page: 1, PageSize: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d assets (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListPolicies(ctx, theirs, "", false, 1, 50); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d policies (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListViolations(ctx, theirs, model.ListViolationsFilter{Page: 1, PageSize: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d violations (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListScans(ctx, theirs, &a.ID, 1, 50); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d scans (total=%d): %v", len(rows), total, err)
	}

	// Writes that name one of our rows
	if got, err := r.UpdateLabel(ctx, theirs, l.ID, &model.UpdateLabelRequest{Name: "volé"}); err != nil || got != nil {
		t.Errorf("the neighbour renamed the label: %v / %v", got, err)
	}
	if got, err := r.UpdateAsset(ctx, theirs, a.ID, &model.UpdateAssetRequest{Owner: "eux"}); err != nil || got != nil {
		t.Errorf("the neighbour reassigned the asset: %v / %v", got, err)
	}
	if got, err := r.UpdatePolicy(ctx, theirs, p.ID, &model.UpdatePolicyRequest{Action: model.ActionLog}); err != nil || got != nil {
		t.Errorf("the neighbour downgraded the policy to log-only: %v / %v", got, err)
	}
	if got, err := r.UpdateViolation(ctx, theirs, v.ID, &model.UpdateViolationRequest{
		Status: model.ViolationStatusFalsePositive,
	}); err != nil || got != nil {
		t.Errorf("the neighbour dismissed our violation as a false positive: %v / %v", got, err)
	}

	// Writes that name one of our rows as a target, where the row written
	// would carry the neighbour's own tenant.
	if got, err := r.CreateScan(ctx, theirs, &a.ID, uuid.Nil); err == nil {
		t.Errorf("the neighbour queued a scan on our asset: %+v", got)
	}
	if err := r.UpdateAssetScanStatus(ctx, theirs, a.ID, "violations_found", 15); err == nil {
		t.Error("the neighbour drove our asset's risk score to 100")
	}
	if err := r.UpdateScanStatus(ctx, theirs, sc.ID, "failed", 0, 0, nil, "sabotage"); err == nil {
		t.Error("the neighbour failed our scan")
	}
	if got, err := r.CreateViolation(ctx, theirs, &model.ReportViolationRequest{
		PolicyID: &p.ID, ViolationType: model.PolicyTypeExfiltration,
		Severity: model.SeverityLow, ActionTaken: model.ActionLog,
	}); err == nil {
		t.Errorf("the neighbour charged a violation to our policy: %+v", got)
	}
	if got, err := r.CreateViolation(ctx, theirs, &model.ReportViolationRequest{
		AssetID: &a.ID, ViolationType: model.PolicyTypeExfiltration,
		Severity: model.SeverityLow, ActionTaken: model.ActionLog,
	}); err == nil {
		t.Errorf("the neighbour attached a violation to our asset: %+v", got)
	}

	// Our rows are exactly as we left them.
	liveAsset, err := r.GetAsset(ctx, mine, a.ID)
	if err != nil || liveAsset == nil {
		t.Fatalf("re-read the asset: %v", err)
	}
	if liveAsset.ScanStatus != "pending" || liveAsset.RiskScore != 0 || liveAsset.Owner != "equipe-donnees" {
		t.Errorf("the asset moved: %+v", liveAsset)
	}
	livePolicy, err := r.GetPolicy(ctx, mine, p.ID)
	if err != nil || livePolicy == nil {
		t.Fatalf("re-read the policy: %v", err)
	}
	if livePolicy.ViolationCount != 1 {
		t.Errorf("our policy counts %d violations, want the single one we raised", livePolicy.ViolationCount)
	}
	if livePolicy.Action != model.ActionBlock {
		t.Errorf("our policy now acts %q", livePolicy.Action)
	}
	liveScan, _, err := r.ListScans(ctx, mine, &a.ID, 1, 10)
	if err != nil {
		t.Fatalf("re-read the scans: %v", err)
	}
	if len(liveScan) != 1 || liveScan[0].Status != "pending" || liveScan[0].ErrorText != "" {
		t.Errorf("our scan reads %+v", liveScan)
	}
}

// ─── Lists and filters ───────────────────────────────────────────────────────

// Each filter counts what it lists: the total next to a filtered page is the
// total for that filter, not for the table.
func TestEachFilterCountsWhatItLists(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	a := asset(t, r, tenant, "clients", nil)
	b := asset(t, r, tenant, "archives", nil)
	p := policy(t, r, tenant, "Pas de PAN par courriel", model.ActionBlock)

	mk := func(assetID *uuid.UUID, sev, channel string) {
		t.Helper()
		if _, err := r.CreateViolation(ctx, tenant, &model.ReportViolationRequest{
			PolicyID: &p.ID, AssetID: assetID, ViolationType: model.PolicyTypeExfiltration,
			Channel: channel, Severity: sev, ActionTaken: model.ActionAlert,
		}); err != nil {
			t.Fatalf("CreateViolation: %v", err)
		}
	}
	mk(&a.ID, model.SeverityCritical, "email")
	mk(&a.ID, model.SeverityHigh, "usb")
	mk(&b.ID, model.SeverityLow, "email")

	for _, c := range []struct {
		name string
		f    model.ListViolationsFilter
		want int
	}{
		{"everything", model.ListViolationsFilter{}, 3},
		{"by asset", model.ListViolationsFilter{AssetID: &a.ID}, 2},
		{"by policy", model.ListViolationsFilter{PolicyID: &p.ID}, 3},
		{"by severity", model.ListViolationsFilter{Severity: model.SeverityCritical}, 1},
		{"by channel", model.ListViolationsFilter{Channel: "email"}, 2},
		{"by status", model.ListViolationsFilter{Status: model.ViolationStatusOpen}, 3},
		{"by a status nothing has", model.ListViolationsFilter{Status: model.ViolationStatusResolved}, 0},
	} {
		c.f.Page, c.f.PageSize = 1, 50
		rows, total, err := r.ListViolations(ctx, tenant, c.f)
		if err != nil {
			t.Fatalf("ListViolations(%s): %v", c.name, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: %d rows, total %d, want %d of each", c.name, len(rows), total, c.want)
		}
	}

	// Assets, the same way.
	risk := 1
	if _, err := r.UpdateAsset(ctx, tenant, a.ID, &model.UpdateAssetRequest{RiskScore: &risk}); err != nil {
		t.Fatalf("UpdateAsset: %v", err)
	}
	for _, c := range []struct {
		name string
		f    model.ListAssetsFilter
		want int
	}{
		{"everything", model.ListAssetsFilter{}, 2},
		{"by type", model.ListAssetsFilter{AssetType: model.AssetTypeDatabase}, 2},
		{"by a type nothing has", model.ListAssetsFilter{AssetType: model.AssetTypeEmail}, 0},
		{"by scan status", model.ListAssetsFilter{ScanStatus: "pending"}, 2},
		{"by minimum risk", model.ListAssetsFilter{MinRisk: &risk}, 1},
	} {
		c.f.Page, c.f.PageSize = 1, 50
		rows, total, err := r.ListAssets(ctx, tenant, c.f)
		if err != nil {
			t.Fatalf("ListAssets(%s): %v", c.name, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: %d rows, total %d, want %d of each", c.name, len(rows), total, c.want)
		}
	}
}

// A page below one is a first page, and paging loses nothing.
func TestPagingLosesNothing(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	for i := 0; i < 5; i++ {
		asset(t, r, tenant, string(rune('a'+i))+"-actif", nil)
	}

	seen := map[uuid.UUID]bool{}
	for page := 1; page <= 3; page++ {
		rows, total, err := r.ListAssets(ctx, tenant, model.ListAssetsFilter{Page: page, PageSize: 2})
		if err != nil {
			t.Fatalf("ListAssets(page %d): %v", page, err)
		}
		if total != 5 {
			t.Errorf("page %d says the total is %d", page, total)
		}
		for _, a := range rows {
			if seen[a.ID] {
				t.Errorf("%s came back on two pages", a.Name)
			}
			seen[a.ID] = true
		}
	}
	if len(seen) != 5 {
		t.Errorf("%d of 5 assets survived paging", len(seen))
	}

	first, _, err := r.ListAssets(ctx, tenant, model.ListAssetsFilter{Page: 1, PageSize: 2})
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	zeroth, _, err := r.ListAssets(ctx, tenant, model.ListAssetsFilter{Page: 0, PageSize: 2})
	if err != nil {
		t.Fatalf("ListAssets(page 0): %v", err)
	}
	if len(zeroth) != len(first) {
		t.Errorf("page 0 returned %d rows, page 1 returned %d", len(zeroth), len(first))
	}
}

// A label is created once and updated afterwards, under the unique index the
// schema puts on (tenant_id, name).
func TestCreatingTheSameLabelTwiceUpdatesIt(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	first := label(t, r, tenant, "Carte bancaire", model.SensitivityConfidential)

	second, err := r.CreateLabel(ctx, tenant, &model.CreateLabelRequest{
		Name: "Carte bancaire", Sensitivity: model.SensitivityRestricted,
		Color: "#FF0000", Keywords: []string{"PAN"},
	}, uuid.Nil)
	if err != nil {
		t.Fatalf("CreateLabel again: %v", err)
	}
	if second.ID != first.ID {
		t.Errorf("a second label was created: %s then %s", first.ID, second.ID)
	}
	if second.Sensitivity != model.SensitivityRestricted || second.Color != "#FF0000" {
		t.Errorf("the second call did not update the label: %+v", second)
	}
	if _, total, err := r.ListLabels(ctx, tenant, false, 1, 50); err != nil || total != 1 {
		t.Errorf("%d labels for one name: %v", total, err)
	}
}

// A fresh tenant gets zeros rather than an error.
func TestAFreshTenantGetsZerosRatherThanAnError(t *testing.T) {
	r, _, tenant := repo(t)
	stats, err := r.Stats(context.Background(), tenant)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.TotalAssets != 0 || stats.TotalPolicies != 0 || stats.TotalViolations != 0 {
		t.Errorf("a tenant with no data reports %+v", stats)
	}
	if stats.ViolationsBySeverity == nil || stats.ViolationsByType == nil {
		t.Error("the breakdowns are nil, which serialises as null rather than {}")
	}
}
