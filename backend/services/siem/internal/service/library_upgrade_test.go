package service

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/cyberradar/platform/services/siem/internal/model"
)

// fieldOf finds one field of a plan, failing rather than returning a zero value
// that would make a wrong assertion pass.
func fieldOf(t *testing.T, plan *model.UpgradePlan, name string) model.UpgradeField {
	t.Helper()
	for _, f := range plan.Fields {
		if f.Field == name {
			return f
		}
	}
	t.Fatalf("the plan has no field %q: %#v", name, plan.Fields)
	return model.UpgradeField{}
}

// The whole reason for recording lineage: an upgrade brings the platform's
// improvements in and leaves the customer's decisions alone. A version bump that
// overwrote the tenant's own change would destroy exactly what the lineage was
// built to protect.
func TestAnUpgradeTakesOursAndKeepsTheirs(t *testing.T) {
	pool := libraryTestDB(t)
	svc, tenantID := libraryFixture(t, pool)
	ctx := context.Background()

	const code = "CRP-DIS-0001"
	ours := "Balayage réseau — seuil de la DSI"
	if _, err := svc.Adopt(ctx, tenantID, nil, code, &model.AdoptRequest{Name: &ours}); err != nil {
		t.Fatalf("adopt: %v", err)
	}

	// v2 raises the severity and widens the deduplication window; it leaves the
	// title alone.
	publishNextVersion(t, pool, code)

	plan, err := svc.UpgradePlan(ctx, tenantID, code)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.UpToDate {
		t.Fatal("a tenant on v1 with v2 published reports itself up to date")
	}
	if plan.FromVersion != 1 || plan.ToVersion != 2 {
		t.Fatalf("plan is v%d→v%d, want v1→v2", plan.FromVersion, plan.ToVersion)
	}
	if len(plan.Conflicts) != 0 {
		t.Fatalf("nothing is in dispute yet the plan reports conflicts: %v", plan.Conflicts)
	}

	if got := fieldOf(t, plan, "severity").Action; got != model.UpgradeTakeIncoming {
		t.Errorf("severity, which only we changed, is %q; want %q", got, model.UpgradeTakeIncoming)
	}
	if got := fieldOf(t, plan, "dedup_window_s").Action; got != model.UpgradeTakeIncoming {
		t.Errorf("dedup_window_s, which only we changed, is %q; want %q", got, model.UpgradeTakeIncoming)
	}
	if got := fieldOf(t, plan, "name").Action; got != model.UpgradeKeepTenant {
		t.Errorf("the name, which only the tenant changed, is %q; want %q", got, model.UpgradeKeepTenant)
	}

	result, err := svc.Upgrade(ctx, tenantID, code, &model.UpgradeRequest{ToVersion: 2})
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if result.Rule.Name != ours {
		t.Errorf("the upgrade overwrote the tenant's name: %q", result.Rule.Name)
	}

	// And afterwards the lineage reads against v2, with the tenant's one change
	// still reported as theirs.
	entries, err := svc.Catalogue(ctx, tenantID)
	if err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	entry := entryFor(t, entries, code)
	if entry.Adopted.AtVersion != 2 {
		t.Errorf("after the upgrade the lineage still reads v%d", entry.Adopted.AtVersion)
	}
	if entry.Adopted.UpdateAvailable {
		t.Error("a rule on the current version still reports an update available")
	}
	if entry.Adopted.UpgradedAt == nil {
		t.Error("the upgrade left no record of when it happened")
	}
	if len(entry.Adopted.Changes) != 1 || entry.Adopted.Changes[0].Field != "name" {
		t.Errorf("the difference after the upgrade should be the name alone: %#v", entry.Adopted.Changes)
	}
}

// Where both sides moved the same field, only the customer can say which one is
// their intent. Picking silently would be a vendor deciding a bank's detection
// threshold on its behalf.
func TestAConflictIsRefusedUntilSomeoneDecides(t *testing.T) {
	pool := libraryTestDB(t)
	svc, tenantID := libraryFixture(t, pool)
	ctx := context.Background()

	const code = "CRP-DIS-0001"
	critical := model.SeverityCritical
	if _, err := svc.Adopt(ctx, tenantID, nil, code, &model.AdoptRequest{Severity: &critical}); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	publishNextVersion(t, pool, code) // v2 moves severity too, to HIGH

	plan, err := svc.UpgradePlan(ctx, tenantID, code)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(plan.Conflicts) != 1 || plan.Conflicts[0] != "severity" {
		t.Fatalf("severity was changed on both sides, yet the conflicts are %v", plan.Conflicts)
	}
	if got := fieldOf(t, plan, "severity").Result; got != "" {
		t.Errorf("a conflict already names a result (%q); it has not been decided yet", got)
	}

	if _, err := svc.Upgrade(ctx, tenantID, code, &model.UpgradeRequest{}); err == nil {
		t.Fatal("the upgrade applied while a conflict was undecided")
	}

	result, err := svc.Upgrade(ctx, tenantID, code, &model.UpgradeRequest{
		ToVersion: 2,
		Resolve:   map[string]string{"severity": "tenant"},
		Notes:     "notre appétit est plus strict que le standard, décidé en comité",
	})
	if err != nil {
		t.Fatalf("upgrade with the conflict resolved: %v", err)
	}
	if result.Rule.Severity != model.SeverityCritical {
		t.Errorf("resolving in the tenant's favour still took ours: %s", result.Rule.Severity)
	}
	// The other field the catalogue moved comes in regardless: resolving one
	// conflict is not declining the upgrade.
	if got := fieldOf(t, result.Plan, "dedup_window_s").Action; got != model.UpgradeTakeIncoming {
		t.Errorf("dedup_window_s was %q, so the rest of the upgrade did not apply", got)
	}

	entries, err := svc.Catalogue(ctx, tenantID)
	if err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	entry := entryFor(t, entries, code)
	if entry.Adopted.Notes == "" {
		t.Error("the reason the conflict was resolved that way was not recorded")
	}
}

// Asking what an upgrade would do must not perform it. A plan a customer is
// still reading is not a decision they have taken.
func TestAPlanChangesNothing(t *testing.T) {
	pool := libraryTestDB(t)
	svc, tenantID := libraryFixture(t, pool)
	ctx := context.Background()

	const code = "CRP-EXE-0001"
	if _, err := svc.Adopt(ctx, tenantID, nil, code, &model.AdoptRequest{}); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	publishNextVersion(t, pool, code)

	for i := 0; i < 2; i++ {
		if _, err := svc.UpgradePlan(ctx, tenantID, code); err != nil {
			t.Fatalf("plan %d: %v", i, err)
		}
	}

	entry := entryFor(t, mustCatalogue(t, svc, tenantID), code)
	if entry.Adopted.AtVersion != 1 {
		t.Errorf("reading the plan moved the rule to v%d", entry.Adopted.AtVersion)
	}
	if entry.Adopted.UpgradedAt != nil {
		t.Error("reading the plan recorded an upgrade")
	}
}

func mustCatalogue(t *testing.T, svc *LibraryService, tenantID uuid.UUID) []*model.LibraryEntry {
	t.Helper()
	entries, err := svc.Catalogue(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	return entries
}

// A decision taken against one difference must not be applied to another. The
// catalogue can move while a customer is reviewing.
func TestADecisionCannotLandOnADifferentVersion(t *testing.T) {
	pool := libraryTestDB(t)
	svc, tenantID := libraryFixture(t, pool)
	ctx := context.Background()

	const code = "CRP-LAT-0001"
	if _, err := svc.Adopt(ctx, tenantID, nil, code, &model.AdoptRequest{}); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	publishNextVersion(t, pool, code)

	// The caller reviewed a plan for v3; what ships is v2.
	if _, err := svc.Upgrade(ctx, tenantID, code, &model.UpgradeRequest{ToVersion: 3}); err == nil {
		t.Fatal("a decision taken for v3 was applied to v2")
	}
}

// Upgrading a rule that is already current is a question, not an error: a caller
// that asks twice should get the same answer the second time.
func TestUpgradingWhatIsCurrentIsANoOp(t *testing.T) {
	pool := libraryTestDB(t)
	svc, tenantID := libraryFixture(t, pool)
	ctx := context.Background()

	const code = "CRP-EXF-0002"
	if _, err := svc.Adopt(ctx, tenantID, nil, code, &model.AdoptRequest{}); err != nil {
		t.Fatalf("adopt: %v", err)
	}

	result, err := svc.Upgrade(ctx, tenantID, code, &model.UpgradeRequest{})
	if err != nil {
		t.Fatalf("upgrade of a current rule: %v", err)
	}
	if !result.Plan.UpToDate {
		t.Error("a rule on the current version does not report itself up to date")
	}
	if len(result.Plan.Fields) != 0 {
		t.Errorf("an up-to-date plan lists %d fields to change", len(result.Plan.Fields))
	}
}

// There is nothing to upgrade on a detection the tenant never took, and saying
// so beats creating one by surprise.
func TestUpgradingSomethingNeverAdoptedIsRefused(t *testing.T) {
	pool := libraryTestDB(t)
	svc, tenantID := libraryFixture(t, pool)

	if _, err := svc.UpgradePlan(context.Background(), tenantID, "CRP-FRD-0001"); err == nil {
		t.Fatal("a plan was produced for a detection that was never adopted")
	}
}
