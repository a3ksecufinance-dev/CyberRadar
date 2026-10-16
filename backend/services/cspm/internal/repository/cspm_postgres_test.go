package repository

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyberradar/platform/internal/pkg/testinfra"
	"github.com/cyberradar/platform/services/cspm/internal/model"
)

// The cloud-posture repository: the first test this service has ever had.
//
// A posture score is the number a cloud team is judged on, and it is derived:
// findings raise a resource's risk, resources and findings set an account's
// score. So the question a test has to answer is not whether the arithmetic
// runs, but whose rows it runs over — because every identifier this repository
// takes (an account, a rule, a resource) arrives from the caller.

func repo(t *testing.T) (*CSPMRepository, *pgxpool.Pool, uuid.UUID) {
	t.Helper()
	pool := testinfra.Postgres(t)
	return NewCSPMRepository(pool), pool, testinfra.NewTenant(t, pool)
}

func account(t *testing.T, r *CSPMRepository, tenant uuid.UUID, name, id string) *model.CSPMAccount {
	t.Helper()
	a, err := r.RegisterAccount(context.Background(), tenant, &model.RegisterAccountRequest{
		Name: name, Description: "Compte de test", Provider: "aws",
		AccountID: id, Region: "eu-west-3", Environment: "production",
		Metadata: map[string]any{"équipe": "infra"},
	})
	if err != nil {
		t.Fatalf("RegisterAccount(%s): %v", name, err)
	}
	return a
}

func rule(t *testing.T, r *CSPMRepository, tenant uuid.UUID, ref, severity string) *model.CSPMRule {
	t.Helper()
	ru, err := r.CreateRule(context.Background(), tenant, &model.CreateRuleRequest{
		RuleID: ref, Title: "Règle " + ref, Description: "Description",
		Rationale: "Pourquoi", Remediation: "Comment",
		Provider: "aws", ResourceType: "s3_bucket", Framework: "cis",
		FrameworkSection: "2.1", Severity: severity,
	})
	if err != nil {
		t.Fatalf("CreateRule(%s): %v", ref, err)
	}
	return ru
}

func resource(t *testing.T, r *CSPMRepository, tenant, accountID uuid.UUID, uid string, public bool) *model.CSPMResource {
	t.Helper()
	res, err := r.UpsertResource(context.Background(), tenant, &model.UpsertResourceRequest{
		AccountID: accountID, ResourceUID: uid, Name: uid,
		ResourceType: "s3_bucket", Service: "s3", Region: "eu-west-3",
		Tags: map[string]any{"env": "prod"}, IsPublic: public,
	})
	if err != nil {
		t.Fatalf("UpsertResource(%s): %v", uid, err)
	}
	return res
}

// ─── The round trip ──────────────────────────────────────────────────────────

func TestEverythingWithNothingOptionalReadsBack(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	// An account with no description, no region and no environment named: the
	// environment carries a CHECK, so an empty string would be refused — the
	// repository defaults it to production instead.
	acc, err := r.RegisterAccount(ctx, tenant, &model.RegisterAccountRequest{
		Name: "Compte minimal", Provider: "gcp", AccountID: "projet-123",
	})
	if err != nil {
		t.Fatalf("RegisterAccount with nothing optional: %v", err)
	}
	if acc.Environment != "production" {
		t.Errorf("environment is %q, want the default production", acc.Environment)
	}
	if acc.Status != "active" {
		t.Errorf("status is %q", acc.Status)
	}
	if acc.PostureScore != 0 {
		t.Errorf("a fresh account scores %d", acc.PostureScore)
	}
	if got, err := r.GetAccount(ctx, tenant, acc.ID); err != nil || got == nil {
		t.Fatalf("GetAccount: %+v / %v", got, err)
	}
	if rows, err := r.ListAccounts(ctx, tenant, "", ""); err != nil || len(rows) != 1 {
		t.Fatalf("ListAccounts gave %d rows: %v", len(rows), err)
	}

	// A rule with no description, no rationale, no remediation, no section.
	ru, err := r.CreateRule(ctx, tenant, &model.CreateRuleRequest{
		RuleID: "CIS-1.1", Title: "Titre", Provider: "aws",
		ResourceType: "iam_root", Framework: "cis", Severity: "critical",
	})
	if err != nil {
		t.Fatalf("CreateRule with nothing optional: %v", err)
	}
	if rows, total, err := r.ListRules(ctx, tenant, "", "", "", 1, 50); err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("ListRules gave %d rows (total=%d): %v", len(rows), total, err)
	}

	// A resource with no name and no region.
	res, err := r.UpsertResource(ctx, tenant, &model.UpsertResourceRequest{
		AccountID: acc.ID, ResourceUID: "arn:aws:s3:::seau", ResourceType: "s3_bucket",
		Service: "s3",
	})
	if err != nil {
		t.Fatalf("UpsertResource with nothing optional: %v", err)
	}
	if got, err := r.GetResource(ctx, tenant, res.ID); err != nil || got == nil {
		t.Fatalf("GetResource: %+v / %v", got, err)
	}
	if rows, total, err := r.ListResources(ctx, tenant, model.ListResourcesFilter{Page: 1, PageSize: 50}); err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("ListResources gave %d rows (total=%d): %v", len(rows), total, err)
	}

	// A finding with no resource, no region and no evidence.
	f, err := r.ReportFinding(ctx, tenant, &model.ReportFindingRequest{
		AccountID: acc.ID, RuleID: ru.ID,
	})
	if err != nil {
		t.Fatalf("ReportFinding with nothing optional: %v", err)
	}
	if f.Status != "open" {
		t.Errorf("a fresh finding is %q", f.Status)
	}
	if f.RuleRef != "CIS-1.1" || f.Severity != "critical" {
		t.Errorf("the finding did not take the rule's reference and severity: %+v", f)
	}
	if rows, total, err := r.ListFindings(ctx, tenant, model.ListFindingsFilter{Page: 1, PageSize: 50}); err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("ListFindings gave %d rows (total=%d): %v", len(rows), total, err)
	}

	// A scan with no type named defaults rather than failing its CHECK.
	sc, err := r.CreateScan(ctx, tenant, acc.ID, "", uuid.Nil)
	if err != nil {
		t.Fatalf("CreateScan with no type: %v", err)
	}
	if sc.ScanType != "full" {
		t.Errorf("scan_type is %q, want the default full", sc.ScanType)
	}
	if sc.ErrorMessage != "" || sc.PostureScore != nil {
		t.Errorf("a pending scan carries %q / %v", sc.ErrorMessage, sc.PostureScore)
	}
	if rows, total, err := r.ListScans(ctx, tenant, acc.ID, 1, 50); err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("ListScans gave %d rows (total=%d): %v", len(rows), total, err)
	}
}

// Seeing the same resource again is an update, not a duplicate: a scan that
// runs hourly must not multiply the estate.
func TestSeeingAResourceAgainDoesNotDuplicateIt(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	acc := account(t, r, tenant, "prod", "111122223333")

	first := resource(t, r, tenant, acc.ID, "arn:aws:s3:::seau", false)
	second := resource(t, r, tenant, acc.ID, "arn:aws:s3:::seau", true)
	if second.ID != first.ID {
		t.Fatalf("the same resource was given two rows: %s and %s", first.ID, second.ID)
	}
	if !second.IsPublic {
		t.Error("the second sighting did not record that the bucket became public")
	}
	if _, total, err := r.ListResources(ctx, tenant, model.ListResourcesFilter{Page: 1, PageSize: 50}); err != nil || total != 1 {
		t.Errorf("%d resources after two sightings of one: %v", total, err)
	}
}

// ─── The derived numbers ─────────────────────────────────────────────────────

// A finding raises its resource's risk, and the account's posture falls by the
// weight of what is open. Both are the product claim of this service.
func TestFindingsDriveTheResourceRiskAndTheAccountPosture(t *testing.T) {
	c := context.Background()
	r, _, tenant := repo(t)
	acc := account(t, r, tenant, "prod", "111122223333")
	res := resource(t, r, tenant, acc.ID, "arn:aws:s3:::seau", true)

	crit := rule(t, r, tenant, "CIS-2.1", "critical")
	high := rule(t, r, tenant, "CIS-2.2", "high")

	for _, ru := range []*model.CSPMRule{crit, high} {
		if _, err := r.ReportFinding(c, tenant, &model.ReportFindingRequest{
			AccountID: acc.ID, RuleID: ru.ID, ResourceUID: res.ResourceUID,
			ResourceType: "s3_bucket", Region: "eu-west-3",
			Evidence: map[string]any{"acl": "public-read"},
		}); err != nil {
			t.Fatalf("ReportFinding: %v", err)
		}
	}

	// The resource: one critical at 40 and one high at 20.
	got, err := r.GetResource(c, tenant, res.ID)
	if err != nil || got == nil {
		t.Fatalf("GetResource: %v", err)
	}
	if got.RiskScore != 60 {
		t.Errorf("risk_score is %d, want 60", got.RiskScore)
	}
	if got.FindingCount != 2 {
		t.Errorf("finding_count is %d, want 2", got.FindingCount)
	}

	// The account: 100 − 15 − 8.
	if err := r.UpdateAccountPosture(c, tenant, acc.ID); err != nil {
		t.Fatalf("UpdateAccountPosture: %v", err)
	}
	after, err := r.GetAccount(c, tenant, acc.ID)
	if err != nil || after == nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if after.PostureScore != 77 {
		t.Errorf("posture_score is %d, want 77 (100 − 15 − 8)", after.PostureScore)
	}
	if after.CriticalCount != 1 || after.HighCount != 1 {
		t.Errorf("the counts are %d critical, %d high", after.CriticalCount, after.HighCount)
	}
	if after.ResourceCount != 1 {
		t.Errorf("resource_count is %d", after.ResourceCount)
	}
	if after.LastScannedAt == nil {
		t.Error("last_scanned_at was not set")
	}

	// Resolving a finding gives the posture back.
	open, _, err := r.ListFindings(c, tenant, model.ListFindingsFilter{
		Severity: "critical", Page: 1, PageSize: 10,
	})
	if err != nil || len(open) != 1 {
		t.Fatalf("ListFindings: %d rows, %v", len(open), err)
	}
	if _, err := r.UpdateFinding(c, tenant, open[0].ID, uuid.Nil, &model.UpdateFindingRequest{
		Status: "resolved",
	}); err != nil {
		t.Fatalf("UpdateFinding: %v", err)
	}
	if err := r.UpdateAccountPosture(c, tenant, acc.ID); err != nil {
		t.Fatalf("UpdateAccountPosture: %v", err)
	}
	healed, err := r.GetAccount(c, tenant, acc.ID)
	if err != nil || healed == nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if healed.PostureScore != 92 {
		t.Errorf("posture_score is %d after resolving the critical, want 92", healed.PostureScore)
	}
}

// Suppressing a finding takes it out of the open set and keeps the reason —
// which is what an auditor asks for when a control is waived.
func TestASuppressedFindingKeepsItsReason(t *testing.T) {
	ctx := context.Background()
	r, pool, tenant := repo(t)
	acc := account(t, r, tenant, "prod", "111122223333")
	ru := rule(t, r, tenant, "CIS-2.1", "high")
	// The same pool the repository writes through: testinfra.Postgres cuts a
	// fresh database on every call, so an identity created from a second one
	// would not exist where UpdateFinding looks for it.
	who := testinfra.NewIdentity(t, pool, tenant)

	f, err := r.ReportFinding(ctx, tenant, &model.ReportFindingRequest{
		AccountID: acc.ID, RuleID: ru.ID,
	})
	if err != nil {
		t.Fatalf("ReportFinding: %v", err)
	}

	suppressed, err := r.UpdateFinding(ctx, tenant, f.ID, who, &model.UpdateFindingRequest{
		Status: "suppressed", SuppressionReason: "Risque accepté par le comité",
	})
	if err != nil {
		t.Fatalf("UpdateFinding: %v", err)
	}
	if suppressed == nil {
		t.Fatal("UpdateFinding returned nothing")
	}
	if suppressed.Status != "suppressed" {
		t.Errorf("status is %q", suppressed.Status)
	}
	if suppressed.SuppressionReason == "" {
		t.Error("the suppression kept no reason, so nobody can tell why the control was waived")
	}
	if _, total, err := r.ListFindings(ctx, tenant, model.ListFindingsFilter{
		Status: "open", Page: 1, PageSize: 50,
	}); err != nil || total != 0 {
		t.Errorf("%d open findings after suppressing the only one: %v", total, err)
	}
}

// A scan records what it did, and a failed one records why.
func TestAScanRecordsItsOutcome(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)
	acc := account(t, r, tenant, "prod", "111122223333")

	done, err := r.CreateScan(ctx, tenant, acc.ID, "full", uuid.Nil)
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	if err := r.CompleteScan(ctx, done.ID, 120, 45, 7, 2, 83); err != nil {
		t.Fatalf("CompleteScan: %v", err)
	}
	got, err := r.GetScan(ctx, tenant, done.ID)
	if err != nil || got == nil {
		t.Fatalf("GetScan: %v", err)
	}
	if got.Status != "completed" {
		t.Errorf("status is %q", got.Status)
	}
	if got.ResourcesScanned != 120 || got.RulesEvaluated != 45 || got.FindingsNew != 7 || got.FindingsResolved != 2 {
		t.Errorf("the counts are %+v", got)
	}
	if got.PostureScore == nil || *got.PostureScore != 83 {
		t.Errorf("posture_score is %v", got.PostureScore)
	}
	if got.CompletedAt == nil {
		t.Error("completed_at was not set")
	}

	failed, err := r.CreateScan(ctx, tenant, acc.ID, "incremental", uuid.Nil)
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	if err := r.FailScan(ctx, failed.ID, "identifiants refusés par le fournisseur"); err != nil {
		t.Fatalf("FailScan: %v", err)
	}
	broken, err := r.GetScan(ctx, tenant, failed.ID)
	if err != nil || broken == nil {
		t.Fatalf("GetScan: %v", err)
	}
	if broken.Status != "failed" {
		t.Errorf("status is %q", broken.Status)
	}
	if broken.ErrorMessage == "" {
		t.Error("a failed scan left no message, so nobody can tell why the posture is stale")
	}
}

// Seeding the standard CIS rules reports how many it wrote, and re-seeding does
// not duplicate them. The count matters: the loop swallows each insert's error
// and only counts the ones that worked, so a wrong number is the only symptom
// a broken insert would have.
func TestSeedingTheStandardRulesIsIdempotent(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	n, err := r.SeedCISRules(ctx, tenant, "aws")
	if err != nil {
		t.Fatalf("SeedCISRules: %v", err)
	}
	if n == 0 {
		t.Fatal("seeding reported no rule written")
	}
	_, total, err := r.ListRules(ctx, tenant, "", "", "", 1, 200)
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if total != n {
		t.Errorf("seeding reported %d rules and %d are in the table", n, total)
	}

	again, err := r.SeedCISRules(ctx, tenant, "aws")
	if err != nil {
		t.Fatalf("SeedCISRules: %v", err)
	}
	if again != n {
		t.Errorf("the second seeding reported %d rather than %d", again, n)
	}
	_, after, err := r.ListRules(ctx, tenant, "", "", "", 1, 200)
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if after != total {
		t.Errorf("%d rules after seeding twice, want %d", after, total)
	}
}

// ─── The tenant boundary ─────────────────────────────────────────────────────

// Nothing one customer wrote is reachable by another, and — the part that needs
// a database to see — no identifier the caller supplies lets them attach
// anything to another customer's account or read another customer's rule.
func TestNothingCrossesTheTenantBoundary(t *testing.T) {
	ctx := context.Background()
	r, pool, mine := repo(t)
	theirs := testinfra.NewNamedTenant(t, pool, "Banque voisine")

	acc := account(t, r, mine, "prod", "111122223333")
	ru := rule(t, r, mine, "CIS-2.1", "critical")
	res := resource(t, r, mine, acc.ID, "arn:aws:s3:::seau", true)
	f, err := r.ReportFinding(ctx, mine, &model.ReportFindingRequest{
		AccountID: acc.ID, RuleID: ru.ID, ResourceUID: res.ResourceUID,
	})
	if err != nil {
		t.Fatalf("ReportFinding: %v", err)
	}
	sc, err := r.CreateScan(ctx, mine, acc.ID, "full", uuid.Nil)
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}

	// Reads
	if got, err := r.GetAccount(ctx, theirs, acc.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the account: %v / %v", got, err)
	}
	if got, err := r.GetResource(ctx, theirs, res.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the resource: %v / %v", got, err)
	}
	if got, err := r.GetScan(ctx, theirs, sc.ID); err != nil || got != nil {
		t.Errorf("the neighbour read the scan: %v / %v", got, err)
	}
	if rows, err := r.ListAccounts(ctx, theirs, "", ""); err != nil || len(rows) != 0 {
		t.Errorf("the neighbour listed %d accounts: %v", len(rows), err)
	}
	if rows, total, err := r.ListRules(ctx, theirs, "", "", "", 1, 50); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d rules (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListResources(ctx, theirs, model.ListResourcesFilter{Page: 1, PageSize: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d resources (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListFindings(ctx, theirs, model.ListFindingsFilter{Page: 1, PageSize: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d findings (total=%d): %v", len(rows), total, err)
	}
	if rows, total, err := r.ListScans(ctx, theirs, acc.ID, 1, 50); err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("the neighbour listed %d scans (total=%d): %v", len(rows), total, err)
	}

	// Writes that take an identifier from the caller. The row would carry the
	// neighbour's own tenant, so a tenant filter on the INSERT proves nothing:
	// what must be refused is the identifier.
	if got, err := r.UpsertResource(ctx, theirs, &model.UpsertResourceRequest{
		AccountID: acc.ID, ResourceUID: "arn:aws:s3:::intrus",
		ResourceType: "s3_bucket", Service: "s3",
	}); err == nil {
		t.Errorf("the neighbour attached a resource to our account: %v", got)
	}
	if got, err := r.ReportFinding(ctx, theirs, &model.ReportFindingRequest{
		AccountID: acc.ID, RuleID: ru.ID,
	}); err == nil {
		t.Errorf("the neighbour reported a finding against our account: %v", got)
	}
	if got, err := r.CreateScan(ctx, theirs, acc.ID, "full", uuid.Nil); err == nil {
		t.Errorf("the neighbour queued a scan on our account: %v", got)
	}
	if got, err := r.UpdateAccount(ctx, theirs, acc.ID, &model.UpdateAccountRequest{
		Name: "volé",
	}); err != nil || got != nil {
		t.Errorf("the neighbour renamed the account: %v / %v", got, err)
	}
	if got, err := r.UpdateFinding(ctx, theirs, f.ID, uuid.Nil, &model.UpdateFindingRequest{
		Status: "suppressed", SuppressionReason: "pas mon problème",
	}); err != nil || got != nil {
		t.Errorf("the neighbour suppressed our finding: %v / %v", got, err)
	}
	if err := r.UpdateAccountPosture(ctx, theirs, acc.ID); err != nil {
		t.Errorf("UpdateAccountPosture by the neighbour: %v", err)
	}

	// Our posture is what our own rows say, and the neighbour appears nowhere.
	if err := r.UpdateAccountPosture(ctx, mine, acc.ID); err != nil {
		t.Fatalf("UpdateAccountPosture: %v", err)
	}
	live, err := r.GetAccount(ctx, mine, acc.ID)
	if err != nil || live == nil {
		t.Fatalf("re-read the account: %v", err)
	}
	if live.Name != "prod" {
		t.Errorf("the account is now named %q", live.Name)
	}
	if live.CriticalCount != 1 {
		t.Errorf("critical_count is %d, want the one finding we raised", live.CriticalCount)
	}
	stats, err := r.Stats(ctx, mine)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	for _, ap := range stats.AccountPostures {
		if ap.OpenFindings != 1 {
			t.Errorf("our account shows %d open findings, want 1 — the neighbour's are counted", ap.OpenFindings)
		}
	}
}

// ─── The dashboard ───────────────────────────────────────────────────────────

func TestTheStatisticsCountWhatIsThere(t *testing.T) {
	ctx := context.Background()
	r, pool, tenant := repo(t)
	other := testinfra.NewNamedTenant(t, pool, "Banque voisine")

	acc := account(t, r, tenant, "prod", "111122223333")
	public := resource(t, r, tenant, acc.ID, "arn:aws:s3:::public", true)
	resource(t, r, tenant, acc.ID, "arn:aws:s3:::privé", false)

	crit := rule(t, r, tenant, "CIS-2.1", "critical")
	high := rule(t, r, tenant, "CIS-2.2", "high")
	for _, ru := range []*model.CSPMRule{crit, high} {
		if _, err := r.ReportFinding(ctx, tenant, &model.ReportFindingRequest{
			AccountID: acc.ID, RuleID: ru.ID, ResourceUID: public.ResourceUID,
		}); err != nil {
			t.Fatalf("ReportFinding: %v", err)
		}
	}
	if err := r.UpdateAccountPosture(ctx, tenant, acc.ID); err != nil {
		t.Fatalf("UpdateAccountPosture: %v", err)
	}

	// The neighbour's cloud, which must change nothing below.
	nbAcc := account(t, r, other, "voisin", "999988887777")
	nbRule := rule(t, r, other, "CIS-9.9", "critical")
	if _, err := r.ReportFinding(ctx, other, &model.ReportFindingRequest{
		AccountID: nbAcc.ID, RuleID: nbRule.ID,
	}); err != nil {
		t.Fatalf("ReportFinding: %v", err)
	}

	stats, err := r.Stats(ctx, tenant)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"total_accounts", stats.TotalAccounts, 1},
		{"total_resources", stats.TotalResources, 2},
		{"public_resources", stats.PublicResources, 1},
		{"open_findings", stats.OpenFindings, 2},
	} {
		if c.got != c.want {
			t.Errorf("%s is %d, want %d", c.name, c.got, c.want)
		}
	}
	if stats.FindingsBySeverity["critical"] != 1 || stats.FindingsBySeverity["high"] != 1 {
		t.Errorf("findings by severity is %v", stats.FindingsBySeverity)
	}
	if stats.AvgPostureScore != 77 {
		t.Errorf("avg_posture_score is %v, want 77", stats.AvgPostureScore)
	}
	if len(stats.AccountPostures) != 1 {
		t.Fatalf("%d account postures, want 1", len(stats.AccountPostures))
	}
	if stats.AccountPostures[0].OpenFindings != 2 {
		t.Errorf("the account shows %d open findings", stats.AccountPostures[0].OpenFindings)
	}
	if len(stats.TopViolatedRules) != 2 {
		t.Errorf("%d violated rules, want 2", len(stats.TopViolatedRules))
	}
}

func TestAFreshTenantGetsZerosRatherThanAnError(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	stats, err := r.Stats(ctx, tenant)
	if err != nil {
		t.Fatalf("Stats on an empty tenant: %v", err)
	}
	if stats.TotalAccounts != 0 || stats.TotalResources != 0 || stats.OpenFindings != 0 {
		t.Errorf("an empty tenant has %+v", stats)
	}
	if stats.AvgPostureScore != 0 {
		t.Errorf("avg_posture_score is %v with no account at all", stats.AvgPostureScore)
	}
	for name, m := range map[string]map[string]int{
		"findings_by_severity":  stats.FindingsBySeverity,
		"findings_by_provider":  stats.FindingsByProvider,
		"findings_by_framework": stats.FindingsByFramework,
	} {
		if m == nil {
			t.Errorf("%s came back nil rather than empty", name)
		}
	}
}

// ─── Filters ─────────────────────────────────────────────────────────────────

func TestEachFilterCountsWhatItLists(t *testing.T) {
	ctx := context.Background()
	r, _, tenant := repo(t)

	aws := account(t, r, tenant, "prod-aws", "111122223333")
	azure, err := r.RegisterAccount(ctx, tenant, &model.RegisterAccountRequest{
		Name: "prod-azure", Provider: "azure", AccountID: "abonnement-1",
		Environment: "staging",
	})
	if err != nil {
		t.Fatalf("RegisterAccount: %v", err)
	}

	if rows, err := r.ListAccounts(ctx, tenant, "aws", ""); err != nil || len(rows) != 1 {
		t.Errorf("the provider filter gave %d rows: %v", len(rows), err)
	}
	if rows, err := r.ListAccounts(ctx, tenant, "", "staging"); err != nil || len(rows) != 1 {
		t.Errorf("the environment filter gave %d rows: %v", len(rows), err)
	}
	if rows, err := r.ListAccounts(ctx, tenant, "gcp", ""); err != nil || len(rows) != 0 {
		t.Errorf("a provider nobody uses gave %d rows: %v", len(rows), err)
	}

	public := resource(t, r, tenant, aws.ID, "arn:aws:s3:::public", true)
	resource(t, r, tenant, aws.ID, "arn:aws:s3:::privé", false)
	yes, no := true, false
	for _, c := range []struct {
		what   string
		filter model.ListResourcesFilter
		want   int
	}{
		{"all", model.ListResourcesFilter{Page: 1, PageSize: 50}, 2},
		{"by account", model.ListResourcesFilter{AccountID: &aws.ID, Page: 1, PageSize: 50}, 2},
		{"by type", model.ListResourcesFilter{ResourceType: "s3_bucket", Page: 1, PageSize: 50}, 2},
		{"by service", model.ListResourcesFilter{Service: "s3", Page: 1, PageSize: 50}, 2},
		{"public only", model.ListResourcesFilter{IsPublic: &yes, Page: 1, PageSize: 50}, 1},
		{"private only", model.ListResourcesFilter{IsPublic: &no, Page: 1, PageSize: 50}, 1},
	} {
		rows, total, err := r.ListResources(ctx, tenant, c.filter)
		if err != nil {
			t.Fatalf("ListResources %s: %v", c.what, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: total=%d, %d rows, want %d of each", c.what, total, len(rows), c.want)
		}
	}

	ru := rule(t, r, tenant, "CIS-2.1", "critical")
	if _, err := r.ReportFinding(ctx, tenant, &model.ReportFindingRequest{
		AccountID: aws.ID, RuleID: ru.ID, ResourceUID: public.ResourceUID,
	}); err != nil {
		t.Fatalf("ReportFinding: %v", err)
	}
	for _, c := range []struct {
		what   string
		filter model.ListFindingsFilter
		want   int
	}{
		{"all", model.ListFindingsFilter{Page: 1, PageSize: 50}, 1},
		{"by account", model.ListFindingsFilter{AccountID: &aws.ID, Page: 1, PageSize: 50}, 1},
		{"by severity", model.ListFindingsFilter{Severity: "critical", Page: 1, PageSize: 50}, 1},
		{"by status", model.ListFindingsFilter{Status: "open", Page: 1, PageSize: 50}, 1},
		{"by framework", model.ListFindingsFilter{Framework: "cis", Page: 1, PageSize: 50}, 1},
		{"by another account", model.ListFindingsFilter{AccountID: &azure.ID, Page: 1, PageSize: 50}, 0},
	} {
		rows, total, err := r.ListFindings(ctx, tenant, c.filter)
		if err != nil {
			t.Fatalf("ListFindings %s: %v", c.what, err)
		}
		if total != c.want || len(rows) != c.want {
			t.Errorf("%s: total=%d, %d rows, want %d of each", c.what, total, len(rows), c.want)
		}
	}
}

// A finding that carries another tenant's id must not count against our
// posture, even when it points at our account.
//
// The write paths refuse such a row now, so the only way to put one there is to
// write it directly — which is the point: the row can exist for reasons the
// repository does not control (a release that predates the ownership check, a
// migration, an importer), and the dashboard still has to be right. The
// subquery behind AccountPostures counted FROM cspm_findings WHERE
// f.account_id=a.id with no tenant of its own, so one such row degraded the
// posture we show the customer.
func TestTheAccountPostureCountsOnlyOurOwnFindings(t *testing.T) {
	ctx := context.Background()
	r, pool, mine := repo(t)
	theirs := testinfra.NewNamedTenant(t, pool, "Banque voisine")

	acc := account(t, r, mine, "prod", "111122223333")
	ru := rule(t, r, mine, "CIS-2.1", "critical")
	if _, err := r.ReportFinding(ctx, mine, &model.ReportFindingRequest{
		AccountID: acc.ID, RuleID: ru.ID,
	}); err != nil {
		t.Fatalf("ReportFinding: %v", err)
	}

	if _, err := pool.Exec(ctx, `INSERT INTO cspm_findings
		(tenant_id, account_id, rule_id, rule_ref, title, severity, status)
		VALUES ($1,$2,$3,'CIS-2.1','Règle du voisin','critical','open')`,
		theirs, acc.ID, ru.ID); err != nil {
		t.Fatalf("plant the neighbour's finding: %v", err)
	}

	stats, err := r.Stats(ctx, mine)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if len(stats.AccountPostures) != 1 {
		t.Fatalf("%d account postures, want 1", len(stats.AccountPostures))
	}
	if got := stats.AccountPostures[0].OpenFindings; got != 1 {
		t.Errorf("our account shows %d open findings, want 1 — the neighbour's row is counted", got)
	}
	if stats.OpenFindings != 1 {
		t.Errorf("the tenant total is %d open findings, want 1", stats.OpenFindings)
	}
}
