package repository

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyberradar/platform/internal/pkg/testinfra"
	"github.com/cyberradar/platform/services/tenant/internal/model"
)

// The first repository test in this service, and the one that proves
// internal/pkg/testinfra works from a service module rather than only from the
// package that defines it.
//
// What it covers is the promise the whole versioned-policy design rests on: a
// policy is never updated in place. Whether a finding breached its deadline is
// a claim about the policy in force when it was raised, so last quarter's
// breach report has to stay reproducible. An UPDATE would make it a fiction,
// and no unit test can tell the difference — only a database can.

func newTenant(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(context.Background(), `
		INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id`,
		"Test Bank", "test-"+uuid.NewString()[:8]).Scan(&id)
	if err != nil {
		t.Fatalf("create a tenant: %v", err)
	}
	return id
}

func policy(code string, critical int) *model.RemediationPolicy {
	return &model.RemediationPolicy{
		Code: code,
		Name: code,
		Deadlines: model.Deadlines{
			CriticalDays: critical,
			HighDays:     7,
			MediumDays:   30,
			LowDays:      90,
			MinimumDays:  1,
		},
	}
}

// The five presets the platform ships are there, and they belong to no tenant.
func TestPresetsAreShippedAndTenantless(t *testing.T) {
	repo := NewRemediationPolicyRepository(testinfra.Postgres(t))

	presets, err := repo.Presets(context.Background())
	if err != nil {
		t.Fatalf("Presets: %v", err)
	}
	if len(presets) != 5 {
		t.Fatalf("%d presets, want the 5 the migration seeds", len(presets))
	}

	want := map[string]bool{
		"banking_default": false, "exploit_aware": false,
		"pci_dss": false, "swift_cscf": false, "dora_critical": false,
	}
	for _, p := range presets {
		if p.TenantID != nil {
			t.Errorf("preset %s belongs to tenant %s; a preset is the platform's", p.Code, p.TenantID)
		}
		if _, ok := want[p.Code]; !ok {
			t.Errorf("unexpected preset %s", p.Code)
			continue
		}
		want[p.Code] = true
	}
	for code, seen := range want {
		if !seen {
			t.Errorf("preset %s is missing", code)
		}
	}
}

// The neutral preset must reproduce what the platform did before any of this
// was configurable: 3 / 7 / 30 / 90, and no ceiling at all.
//
// This is the promise that lets a customer adopt it without a single deadline
// moving. A test rather than a comment, because the day it stops being true is
// the day somebody's SLAs shift over a weekend.
func TestTheNeutralPresetMovesNoDeadline(t *testing.T) {
	repo := NewRemediationPolicyRepository(testinfra.Postgres(t))

	p, err := repo.Preset(context.Background(), "banking_default")
	if err != nil {
		t.Fatalf("Preset(banking_default): %v", err)
	}
	d := p.Deadlines
	if d.CriticalDays != 3 || d.HighDays != 7 || d.MediumDays != 30 || d.LowDays != 90 {
		t.Errorf("base deadlines are %d/%d/%d/%d, want 3/7/30/90",
			d.CriticalDays, d.HighDays, d.MediumDays, d.LowDays)
	}
	for name, ceiling := range map[string]*int{
		"exploited": d.ExploitedDays, "dmz": d.DMZDays,
		"cbs": d.CBSDays, "swift": d.SWIFTDays, "pci": d.PCIDays,
	} {
		if ceiling != nil {
			t.Errorf("the neutral preset sets a %s ceiling of %d; it must set none", name, *ceiling)
		}
	}
}

// A tenant that has adopted nothing has no policy of its own, and the
// repository says so with nil rather than an error. Services read that as
// "fall back to the standard".
func TestATenantWithoutAPolicyHasNone(t *testing.T) {
	pool := testinfra.Postgres(t)
	repo := NewRemediationPolicyRepository(pool)

	got, err := repo.Active(context.Background(), newTenant(t, pool))
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if got != nil {
		t.Fatalf("a tenant that adopted nothing was given policy %s", got.Code)
	}
}

// Setting a second policy closes the first instead of replacing it.
func TestSetClosesThePreviousVersionRatherThanReplacingIt(t *testing.T) {
	ctx := context.Background()
	pool := testinfra.Postgres(t)
	repo := NewRemediationPolicyRepository(pool)
	tenant := newTenant(t, pool)

	first, err := repo.Set(ctx, tenant, nil, policy("banking_default", 3))
	if err != nil {
		t.Fatalf("first Set: %v", err)
	}
	if first.Version != 1 {
		t.Fatalf("first version is %d, want 1", first.Version)
	}

	second, err := repo.Set(ctx, tenant, nil, policy("dora_critical", 2))
	if err != nil {
		t.Fatalf("second Set: %v", err)
	}
	if second.Version != 2 {
		t.Fatalf("second version is %d, want 2", second.Version)
	}

	// The old row is still there, closed — not overwritten.
	history, err := repo.History(ctx, tenant)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("%d versions in history, want 2: the previous one was replaced, not closed", len(history))
	}
	if history[0].Version != 2 || history[1].Version != 1 {
		t.Fatalf("history is not newest-first: %d then %d", history[0].Version, history[1].Version)
	}
	if history[1].EffectiveTo == nil {
		t.Error("version 1 is still open; two policies are in force at once")
	}
	if history[1].Deadlines.CriticalDays != 3 {
		t.Errorf("version 1 now reads %d critical days; it was recorded with 3, and last "+
			"quarter's breach report depends on it not moving", history[1].Deadlines.CriticalDays)
	}

	active, err := repo.Active(ctx, tenant)
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if active.Version != 2 || active.Code != "dora_critical" {
		t.Fatalf("active is %s v%d, want dora_critical v2", active.Code, active.Version)
	}
}

// The schema, not the code, guarantees one active policy per tenant. Asserted
// here because the application could be rewritten and the guarantee would still
// have to hold.
func TestTheSchemaRefusesTwoActivePolicies(t *testing.T) {
	ctx := context.Background()
	pool := testinfra.Postgres(t)
	repo := NewRemediationPolicyRepository(pool)
	tenant := newTenant(t, pool)

	if _, err := repo.Set(ctx, tenant, nil, policy("banking_default", 3)); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Go around the repository and insert a second open row directly.
	_, err := pool.Exec(ctx, `
		INSERT INTO remediation_policies
			(tenant_id, code, name, version,
			 critical_days, high_days, medium_days, low_days, minimum_days)
		VALUES ($1, 'smuggled', 'smuggled', 99, 1, 1, 1, 1, 1)`, tenant)
	if err == nil {
		t.Fatal("the schema accepted a second active policy for one tenant")
	}
}

// Two tenants each keep their own active policy: the unique index is partial
// on the tenant, not global.
func TestTwoTenantsEachKeepTheirOwn(t *testing.T) {
	ctx := context.Background()
	pool := testinfra.Postgres(t)
	repo := NewRemediationPolicyRepository(pool)

	a, b := newTenant(t, pool), newTenant(t, pool)
	if _, err := repo.Set(ctx, a, nil, policy("banking_default", 3)); err != nil {
		t.Fatalf("Set for the first tenant: %v", err)
	}
	if _, err := repo.Set(ctx, b, nil, policy("dora_critical", 2)); err != nil {
		t.Fatalf("Set for the second tenant: %v", err)
	}

	pa, err := repo.Active(ctx, a)
	if err != nil {
		t.Fatalf("Active(a): %v", err)
	}
	pb, err := repo.Active(ctx, b)
	if err != nil {
		t.Fatalf("Active(b): %v", err)
	}
	if pa.Deadlines.CriticalDays != 3 || pb.Deadlines.CriticalDays != 2 {
		t.Fatalf("the two tenants read %d and %d critical days, want 3 and 2",
			pa.Deadlines.CriticalDays, pb.Deadlines.CriticalDays)
	}
}
