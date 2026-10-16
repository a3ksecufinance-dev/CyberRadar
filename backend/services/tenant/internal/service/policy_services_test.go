package service

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/testinfra"
	"github.com/cyberradar/platform/services/tenant/internal/model"
	"github.com/cyberradar/platform/services/tenant/internal/repository"
)

// The four policy services.
//
// Each one does the same three things, and each one is worth testing for a
// different reason:
//
//   - Effective says what the tenant is scored under AND whether the tenant
//     chose it. An interface that could not tell the two apart would present
//     the platform's defaults as the customer's decision.
//   - Set bases the new version on what is in force, so moving one number does
//     not restate the rest. Getting that base wrong is how an omitted field
//     silently becomes zero.
//   - Each service refuses one configuration the schema accepts and the product
//     should not: a threshold above its own ceiling, a UEBA engine with every
//     signal off, a path ranking where every step is free, deadlines that run
//     backwards. Those refusals are the only thing standing between a customer
//     and a platform that reports nothing while appearing to work.

func newTenantRow(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(context.Background(), `
		INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id`,
		"Banque de test", "svc-"+uuid.NewString()[:8]).Scan(&id)
	if err != nil {
		t.Fatalf("create a tenant: %v", err)
	}
	return id
}

func f64(v float64) *float64 { return &v }
func i(v int) *int           { return &v }
func b(v bool) *bool         { return &v }

// ─── Risk profiles ───────────────────────────────────────────────────────────

func riskService(t *testing.T) (*RiskProfileService, uuid.UUID) {
	t.Helper()
	pool := testinfra.Postgres(t)
	return NewRiskProfileService(repository.NewRiskProfileRepository(pool), quiet()), newTenantRow(t, pool)
}

// A tenant that has not chosen is scored under the standard profile, and is
// told that it has not chosen.
func TestRiskEffectiveSaysWhetherTheTenantChose(t *testing.T) {
	ctx := context.Background()
	s, tenant := riskService(t)

	got, chosen, err := s.Effective(ctx, tenant)
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	if chosen {
		t.Error("a tenant that has set nothing is reported as having chosen")
	}
	if got.Code != DefaultProfileCode {
		t.Errorf("scored under %q, want %q", got.Code, DefaultProfileCode)
	}
	if got.TenantID != nil {
		t.Errorf("the standard profile came back owned by %v", got.TenantID)
	}

	if _, err := s.Set(ctx, tenant, nil, &model.SetRiskProfileRequest{
		Name:    "Notre appétit",
		Weights: &model.PartialRiskWeights{VulnCritical: f64(3)},
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, chosen, err = s.Effective(ctx, tenant)
	if err != nil {
		t.Fatalf("Effective after Set: %v", err)
	}
	if !chosen {
		t.Error("a tenant that has set a profile is reported as not having chosen")
	}
	if got.TenantID == nil || *got.TenantID != tenant {
		t.Errorf("the active profile belongs to %v, want %s", got.TenantID, tenant)
	}
}

// Set moves what the request named and leaves the other sixteen weights where
// the base had them. This is the property the whole partial-request design
// exists for.
func TestRiskSetMovesOnlyTheNamedWeights(t *testing.T) {
	ctx := context.Background()
	s, tenant := riskService(t)

	base, _, err := s.Effective(ctx, tenant)
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}

	got, err := s.Set(ctx, tenant, nil, &model.SetRiskProfileRequest{
		Weights: &model.PartialRiskWeights{VulnCritical: f64(3.5)},
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got.Weights.VulnCritical != 3.5 {
		t.Errorf("vuln_critical is %v, want 3.5", got.Weights.VulnCritical)
	}
	if got.Weights.VulnHigh != base.Weights.VulnHigh {
		t.Errorf("vuln_high moved from %v to %v", base.Weights.VulnHigh, got.Weights.VulnHigh)
	}
	if got.Weights.TotalCap != base.Weights.TotalCap {
		t.Errorf("total_cap moved from %v to %v", base.Weights.TotalCap, got.Weights.TotalCap)
	}
	if got.Name == "" {
		t.Error("a request with no name produced a nameless profile")
	}

	// A second version bases itself on the first, not on the standard profile:
	// the 3.5 survives a request that never mentions it.
	second, err := s.Set(ctx, tenant, nil, &model.SetRiskProfileRequest{
		Weights: &model.PartialRiskWeights{VulnHigh: f64(2)},
	})
	if err != nil {
		t.Fatalf("second Set: %v", err)
	}
	if second.Weights.VulnCritical != 3.5 {
		t.Errorf("the first version's vuln_critical became %v in the second", second.Weights.VulnCritical)
	}
	if second.Version != got.Version+1 {
		t.Errorf("version went %d then %d", got.Version, second.Version)
	}
	if second.BasedOn != got.BasedOn {
		t.Errorf("based_on changed from %q to %q without the request asking", got.BasedOn, second.BasedOn)
	}
}

// Naming a preset rebases on it, discarding what the tenant had — which is what
// "adopt the PCI profile" has to mean.
func TestRiskSetRebasesOnANamedPreset(t *testing.T) {
	ctx := context.Background()
	s, tenant := riskService(t)

	if _, err := s.Set(ctx, tenant, nil, &model.SetRiskProfileRequest{
		Weights: &model.PartialRiskWeights{VulnCritical: f64(9)},
	}); err != nil {
		t.Fatalf("first Set: %v", err)
	}

	got, err := s.Set(ctx, tenant, nil, &model.SetRiskProfileRequest{BasedOn: "pci_dss"})
	if err != nil {
		t.Fatalf("Set(pci_dss): %v", err)
	}
	if got.BasedOn != "pci_dss" {
		t.Errorf("based_on is %q, want pci_dss", got.BasedOn)
	}
	if got.Weights.VulnCritical == 9 {
		t.Error("rebasing on a preset kept the previous version's weight")
	}
	if got.Weights.PCIScope != 1.5 {
		t.Errorf("pci_scope is %v, want the preset's 1.5", got.Weights.PCIScope)
	}
}

func TestRiskSetRefusesAnUnknownPreset(t *testing.T) {
	ctx := context.Background()
	s, tenant := riskService(t)

	_, err := s.Set(ctx, tenant, nil, &model.SetRiskProfileRequest{BasedOn: "ne_existe_pas"})
	wantKind(t, err, apierrors.KindBadInput, "basing on an unknown preset")
}

// A threshold above the ceiling is a profile under which nothing is ever high
// risk. The schema accepts it; the service must not.
func TestRiskSetRefusesAThresholdNoAssetCouldReach(t *testing.T) {
	ctx := context.Background()
	s, tenant := riskService(t)

	_, err := s.Set(ctx, tenant, nil, &model.SetRiskProfileRequest{
		Weights: &model.PartialRiskWeights{TotalCap: f64(5), HighRiskThreshold: f64(8)},
	})
	wantKind(t, err, apierrors.KindBadInput, "a threshold above total_cap")

	// And nothing was recorded: a refusal that still wrote a version would
	// leave the tenant scored under the configuration it was told was refused.
	if _, chosen, err := s.Effective(ctx, tenant); err != nil || chosen {
		t.Errorf("the refused profile was recorded anyway (chosen=%v, err=%v)", chosen, err)
	}
}

func TestRiskPresetsAndHistory(t *testing.T) {
	ctx := context.Background()
	s, tenant := riskService(t)

	presets, err := s.Presets(ctx)
	if err != nil {
		t.Fatalf("Presets: %v", err)
	}
	if len(presets) != 4 {
		t.Errorf("%d presets, want 4", len(presets))
	}

	empty, err := s.History(ctx, tenant)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("a tenant that set nothing has %d versions of history", len(empty))
	}

	for n := 0; n < 3; n++ {
		if _, err := s.Set(ctx, tenant, nil, &model.SetRiskProfileRequest{
			Weights: &model.PartialRiskWeights{VulnHigh: f64(float64(n) + 1)},
		}); err != nil {
			t.Fatalf("Set %d: %v", n, err)
		}
	}
	history, err := s.History(ctx, tenant)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(history) != 3 {
		t.Fatalf("%d versions after three Sets", len(history))
	}
	// Newest first, and exactly one still in force.
	if history[0].Version != 3 {
		t.Errorf("the first entry is version %d, want the newest", history[0].Version)
	}
	live := 0
	for _, v := range history {
		if v.EffectiveTo == nil {
			live++
		}
	}
	if live != 1 {
		t.Errorf("%d versions are in force at once", live)
	}
}

// ─── Behaviour policies ──────────────────────────────────────────────────────

func behaviourService(t *testing.T) (*BehaviourPolicyService, uuid.UUID) {
	t.Helper()
	pool := testinfra.Postgres(t)
	return NewBehaviourPolicyService(repository.NewBehaviourPolicyRepository(pool), quiet()), newTenantRow(t, pool)
}

func TestBehaviourEffectiveFallsBackToTheStandardThresholds(t *testing.T) {
	ctx := context.Background()
	s, tenant := behaviourService(t)

	got, chosen, err := s.Effective(ctx, tenant)
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	if chosen || got.Code != DefaultBehaviourCode {
		t.Fatalf("a fresh tenant is detected under %q (chosen=%v), want %q",
			got.Code, chosen, DefaultBehaviourCode)
	}
	if !anySignalEnabled(got.Signals) {
		t.Error("the standard policy ships with every signal off")
	}
}

// One signal turned off survives, and the rest stay as they were.
func TestBehaviourSetTurnsOffOneSignalOnly(t *testing.T) {
	ctx := context.Background()
	s, tenant := behaviourService(t)

	got, err := s.Set(ctx, tenant, nil, &model.SetBehaviourPolicyRequest{
		Signals: &model.PartialSignals{OffHours: &model.PartialSignal{Enabled: b(false)}},
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got.Signals.OffHours.Enabled {
		t.Error("off_hours is still on")
	}
	if countDisabled(got.Signals) != 1 {
		t.Errorf("%d signals are off, want exactly the one that was named", countDisabled(got.Signals))
	}
	// The severity and score of the signal that was turned off are untouched:
	// turning it back on must restore what it was, not a zero.
	if got.Signals.OffHours.Score == 0 || got.Signals.OffHours.Severity == "" {
		t.Errorf("turning off_hours off also cleared its severity/score: %+v", got.Signals.OffHours)
	}
}

// Every signal off leaves a UEBA engine that detects nothing while reporting
// itself healthy. Refused, with a message that says why.
func TestBehaviourSetRefusesAnEngineThatDetectsNothing(t *testing.T) {
	ctx := context.Background()
	s, tenant := behaviourService(t)

	off := &model.PartialSignal{Enabled: b(false)}
	_, err := s.Set(ctx, tenant, nil, &model.SetBehaviourPolicyRequest{
		Signals: &model.PartialSignals{
			OffHours: off, NewCountry: off, NewIPPrefix: off, Velocity: off,
			BruteForce: off, PrivEscalation: off, LateralMovement: off, DataExfiltration: off,
		},
	})
	wantKind(t, err, apierrors.KindBadInput, "turning every signal off")
	if _, chosen, _ := s.Effective(ctx, tenant); chosen {
		t.Error("the refused policy was recorded anyway")
	}
}

func TestBehaviourSetRefusesAnUnknownPreset(t *testing.T) {
	ctx := context.Background()
	s, tenant := behaviourService(t)

	_, err := s.Set(ctx, tenant, nil, &model.SetBehaviourPolicyRequest{BasedOn: "inconnu"})
	wantKind(t, err, apierrors.KindBadInput, "basing on an unknown preset")
}

func TestBehaviourPresetsAndHistory(t *testing.T) {
	ctx := context.Background()
	s, tenant := behaviourService(t)

	presets, err := s.Presets(ctx)
	if err != nil {
		t.Fatalf("Presets: %v", err)
	}
	if len(presets) == 0 {
		t.Fatal("no behaviour presets are shipped")
	}
	if _, err := s.Set(ctx, tenant, nil, &model.SetBehaviourPolicyRequest{
		Thresholds: &model.PartialThresholds{VelocityThreshold: i(500)},
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	history, err := s.History(ctx, tenant)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(history) != 1 || history[0].Thresholds.VelocityThreshold != 500 {
		t.Fatalf("history is %d entries: %+v", len(history), history)
	}
}

// ─── Attack policies ─────────────────────────────────────────────────────────

func attackService(t *testing.T) (*AttackPolicyService, uuid.UUID) {
	t.Helper()
	pool := testinfra.Postgres(t)
	return NewAttackPolicyService(repository.NewAttackPolicyRepository(pool), quiet()), newTenantRow(t, pool)
}

func TestAttackEffectiveAndSet(t *testing.T) {
	ctx := context.Background()
	s, tenant := attackService(t)

	base, chosen, err := s.Effective(ctx, tenant)
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	if chosen {
		t.Error("a fresh tenant is reported as having chosen a ranking")
	}

	got, err := s.Set(ctx, tenant, nil, &model.SetAttackPolicyRequest{
		Weights: &model.PartialAttackWeights{HopDecay: f64(0.5)},
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got.Weights.HopDecay != 0.5 {
		t.Errorf("hop_decay is %v, want 0.5", got.Weights.HopDecay)
	}
	if got.Weights.BaseCost != base.Weights.BaseCost {
		t.Errorf("base_cost moved from %v to %v", base.Weights.BaseCost, got.Weights.BaseCost)
	}
}

// Every step free means every path scores the same, which is a ranking that has
// stopped ranking.
func TestAttackSetRefusesARankingThatRanksNothing(t *testing.T) {
	ctx := context.Background()
	s, tenant := attackService(t)

	zero := f64(0)
	_, err := s.Set(ctx, tenant, nil, &model.SetAttackPolicyRequest{
		Weights: &model.PartialAttackWeights{
			BaseCost: zero, ComplexityMedium: zero, ComplexityHigh: zero,
			PrivilegeLow: zero, PrivilegeHigh: zero,
		},
	})
	wantKind(t, err, apierrors.KindBadInput, "a policy where every step is free")
	if _, chosen, _ := s.Effective(ctx, tenant); chosen {
		t.Error("the refused policy was recorded anyway")
	}
}

// A ceiling that stops the impact score reaching ten is a warning, not a
// refusal: it is a defensible stance, just one worth a log line. Pinned so the
// distinction between the two does not quietly swap.
func TestAttackSetOnlyWarnsAboutAnUnreachableCeiling(t *testing.T) {
	ctx := context.Background()
	s, tenant := attackService(t)

	got, err := s.Set(ctx, tenant, nil, &model.SetAttackPolicyRequest{
		Weights: &model.PartialAttackWeights{
			ImpactCeiling: f64(4), CriticalSystemBonus: f64(1),
		},
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got.Weights.ImpactCeiling != 4 {
		t.Errorf("impact_ceiling is %v, want the 4 that was asked for", got.Weights.ImpactCeiling)
	}
}

func TestAttackSetRefusesAnUnknownPreset(t *testing.T) {
	ctx := context.Background()
	s, tenant := attackService(t)

	_, err := s.Set(ctx, tenant, nil, &model.SetAttackPolicyRequest{BasedOn: "inconnu"})
	wantKind(t, err, apierrors.KindBadInput, "basing on an unknown preset")
}

func TestAttackPresetsAndHistory(t *testing.T) {
	ctx := context.Background()
	s, tenant := attackService(t)

	if presets, err := s.Presets(ctx); err != nil || len(presets) == 0 {
		t.Fatalf("Presets gave %d entries, %v", len(presets), err)
	}
	if _, err := s.Set(ctx, tenant, nil, &model.SetAttackPolicyRequest{
		Weights: &model.PartialAttackWeights{ManyPathsBoost: f64(2)},
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	history, err := s.History(ctx, tenant)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(history) != 1 || history[0].Weights.ManyPathsBoost != 2 {
		t.Fatalf("history is %d entries: %+v", len(history), history)
	}
}

// ─── Remediation policies ────────────────────────────────────────────────────

func remediationService(t *testing.T) (*RemediationPolicyService, uuid.UUID) {
	t.Helper()
	pool := testinfra.Postgres(t)
	return NewRemediationPolicyService(repository.NewRemediationPolicyRepository(pool), quiet()), newTenantRow(t, pool)
}

func TestRemediationEffectiveAndSet(t *testing.T) {
	ctx := context.Background()
	s, tenant := remediationService(t)

	base, chosen, err := s.Effective(ctx, tenant)
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	if chosen {
		t.Error("a fresh tenant is reported as having chosen its deadlines")
	}

	got, err := s.Set(ctx, tenant, nil, &model.SetRemediationPolicyRequest{
		Deadlines: &model.PartialDeadlines{CriticalDays: i(3)},
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got.Deadlines.CriticalDays != 3 {
		t.Errorf("critical_days is %d, want 3", got.Deadlines.CriticalDays)
	}
	if got.Deadlines.LowDays != base.Deadlines.LowDays {
		t.Errorf("low_days moved from %d to %d", base.Deadlines.LowDays, got.Deadlines.LowDays)
	}
}

// Deadlines that run backwards are almost certainly a typo, and the schema
// would report them as a constraint name in a 500. Refused here, in words.
func TestRemediationSetRefusesDeadlinesThatRunBackwards(t *testing.T) {
	ctx := context.Background()
	s, tenant := remediationService(t)

	_, err := s.Set(ctx, tenant, nil, &model.SetRemediationPolicyRequest{
		Deadlines: &model.PartialDeadlines{CriticalDays: i(200), LowDays: i(5)},
	})
	wantKind(t, err, apierrors.KindBadInput, "a critical given longer than a low")
	if _, chosen, _ := s.Effective(ctx, tenant); chosen {
		t.Error("the refused policy was recorded anyway")
	}
}

// A floor above the critical deadline means no ceiling could ever apply, so the
// ceilings the customer configured would silently do nothing.
func TestRemediationSetRefusesAFloorAboveTheCriticalDeadline(t *testing.T) {
	ctx := context.Background()
	s, tenant := remediationService(t)

	_, err := s.Set(ctx, tenant, nil, &model.SetRemediationPolicyRequest{
		Deadlines: &model.PartialDeadlines{CriticalDays: i(7), MinimumDays: i(30)},
	})
	wantKind(t, err, apierrors.KindBadInput, "a floor above the critical deadline")
}

func TestRemediationSetRefusesAnUnknownPreset(t *testing.T) {
	ctx := context.Background()
	s, tenant := remediationService(t)

	_, err := s.Set(ctx, tenant, nil, &model.SetRemediationPolicyRequest{BasedOn: "inconnu"})
	wantKind(t, err, apierrors.KindBadInput, "basing on an unknown preset")
}

// A ceiling that was deliberately unset stays unset through the next version:
// this is the difference between "we do not treat the DMZ specially" and
// "we forgot to say", and it is the reason the merge does not use COALESCE.
func TestRemediationAClearedCeilingStaysCleared(t *testing.T) {
	ctx := context.Background()
	s, tenant := remediationService(t)

	with, err := s.Set(ctx, tenant, nil, &model.SetRemediationPolicyRequest{
		Deadlines: &model.PartialDeadlines{DMZDays: i(10)},
	})
	if err != nil {
		t.Fatalf("Set with a DMZ ceiling: %v", err)
	}
	if with.Deadlines.DMZDays == nil || *with.Deadlines.DMZDays != 10 {
		t.Fatalf("dmz_days is %v, want 10", with.Deadlines.DMZDays)
	}

	cleared, err := s.Set(ctx, tenant, nil, &model.SetRemediationPolicyRequest{
		Deadlines: &model.PartialDeadlines{ClearCeilings: []string{"dmz"}},
	})
	if err != nil {
		t.Fatalf("Set clearing the DMZ ceiling: %v", err)
	}
	if cleared.Deadlines.DMZDays != nil {
		t.Fatalf("dmz_days came back as %v after being cleared", *cleared.Deadlines.DMZDays)
	}

	// And a later version that never mentions the DMZ must not resurrect the
	// standard policy's ceiling.
	later, err := s.Set(ctx, tenant, nil, &model.SetRemediationPolicyRequest{
		Deadlines: &model.PartialDeadlines{HighDays: i(14)},
	})
	if err != nil {
		t.Fatalf("a later Set: %v", err)
	}
	if later.Deadlines.DMZDays != nil {
		t.Errorf("dmz_days reappeared as %v", *later.Deadlines.DMZDays)
	}
}

func TestRemediationPresetsAndHistory(t *testing.T) {
	ctx := context.Background()
	s, tenant := remediationService(t)

	presets, err := s.Presets(ctx)
	if err != nil {
		t.Fatalf("Presets: %v", err)
	}
	if len(presets) != 5 {
		t.Errorf("%d presets, want the 5 the migration seeds", len(presets))
	}
	if _, err := s.Set(ctx, tenant, nil, &model.SetRemediationPolicyRequest{
		Deadlines: &model.PartialDeadlines{MediumDays: i(45)},
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	history, err := s.History(ctx, tenant)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(history) != 1 || history[0].Deadlines.MediumDays != 45 {
		t.Fatalf("history is %d entries: %+v", len(history), history)
	}
}
