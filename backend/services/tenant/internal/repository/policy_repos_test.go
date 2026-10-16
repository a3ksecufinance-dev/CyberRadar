package repository

import (
	"context"
	"testing"

	"github.com/cyberradar/platform/internal/pkg/testinfra"
	"github.com/cyberradar/platform/services/tenant/internal/model"
)

// The other three policy repositories.
//
// They have the shape remediation_policy_postgres_test.go already proved —
// Presets, Preset, Active, History, Set, one active version per tenant — so
// what is tested here is what differs: how many presets each ships, and that
// each one's neutral preset really reproduces what the platform did before the
// setting existed.
//
// That last property is the promise the whole configurability decision rests
// on: making something configurable must not move a number on the day it
// ships. It is a comment in four migrations; here it is a test.

// ─── Risk profiles ───────────────────────────────────────────────────────────

func TestRiskProfilePresets(t *testing.T) {
	repo := NewRiskProfileRepository(testinfra.Postgres(t))
	presets, err := repo.Presets(context.Background())
	if err != nil {
		t.Fatalf("Presets: %v", err)
	}
	assertPresetCodes(t, "risk profile", codesOfRisk(presets),
		"balanced", "vulnerability_led", "pci_dss", "swift_cscf")
}

// The weights the asset service applied before any of this was configurable.
// Adopting `balanced` must not re-score a single asset.
//
// Every column is listed, not a sample: this reads the preset through the
// repository, so a scan that put vuln_high where vuln_critical belongs would
// show up here. The asset service has its own test that the seeded rows and
// its in-code DefaultRiskProfile agree; what that one cannot see is this
// mapping.
func TestTheBalancedRiskProfileMovesNoScore(t *testing.T) {
	repo := NewRiskProfileRepository(testinfra.Postgres(t))
	p, err := repo.Preset(context.Background(), "balanced")
	if err != nil {
		t.Fatalf("Preset(balanced): %v", err)
	}
	w := p.Weights
	for _, c := range []struct {
		name string
		got  float64
		want float64
	}{
		{"criticality_step", w.CriticalityStep, 1.0},
		{"criticality_cap", w.CriticalityCap, 3.0},
		{"vuln_critical", w.VulnCritical, 2.0},
		{"vuln_high", w.VulnHigh, 1.0},
		{"vuln_medium", w.VulnMedium, 0.4},
		{"vuln_low", w.VulnLow, 0.1},
		{"vuln_cap", w.VulnCap, 4.0},
		{"cbs_connected", w.CBSConnected, 1.0},
		{"swift_connected", w.SWIFTConnected, 1.0},
		{"pci_scope", w.PCIScope, 0.5},
		{"exposure_cap", w.ExposureCap, 2.0},
		{"never_seen", w.NeverSeen, 0.5},
		{"critical_production", w.CriticalProduction, 0.5},
		{"banking_type", w.BankingType, 0.5},
		{"context_cap", w.ContextCap, 1.0},
		{"total_cap", w.TotalCap, 10.0},
		{"high_risk_threshold", w.HighRiskThreshold, 7.0},
	} {
		if c.got != c.want {
			t.Errorf("%s is %v, want the %v the platform used before this was configurable", c.name, c.got, c.want)
		}
	}
}

func TestRiskProfileSetClosesThePreviousVersion(t *testing.T) {
	ctx := context.Background()
	pool := testinfra.Postgres(t)
	repo := NewRiskProfileRepository(pool)
	tenant := newTenant(t, pool)

	base, err := repo.Preset(ctx, "balanced")
	if err != nil {
		t.Fatalf("Preset: %v", err)
	}
	first, err := repo.Set(ctx, tenant, nil, &model.RiskProfile{
		Code: "balanced", Name: "balanced", Weights: base.Weights,
	})
	if err != nil {
		t.Fatalf("first Set: %v", err)
	}

	tighter := base.Weights
	tighter.HighRiskThreshold = 6
	if _, err := repo.Set(ctx, tenant, nil, &model.RiskProfile{
		Code: "balanced", Name: "balanced", Weights: tighter,
	}); err != nil {
		t.Fatalf("second Set: %v", err)
	}

	history, err := repo.History(ctx, tenant)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("%d versions, want 2", len(history))
	}
	if history[1].EffectiveTo == nil {
		t.Error("version 1 is still open")
	}
	if history[1].Weights.HighRiskThreshold != first.Weights.HighRiskThreshold {
		t.Error("version 1's threshold moved when version 2 was written")
	}
	active, err := repo.Active(ctx, tenant)
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if active.Weights.HighRiskThreshold != 6 {
		t.Errorf("active threshold is %v, want 6", active.Weights.HighRiskThreshold)
	}
}

// ─── Behaviour policies ──────────────────────────────────────────────────────

func TestBehaviourPolicyPresets(t *testing.T) {
	repo := NewBehaviourPolicyRepository(testinfra.Postgres(t))
	presets, err := repo.Presets(context.Background())
	if err != nil {
		t.Fatalf("Presets: %v", err)
	}
	assertPresetCodes(t, "behaviour policy", codesOfBehaviour(presets),
		"balanced", "round_the_clock", "privileged_watch", "low_noise")
}

// The thresholds and the eight signals the UEBA engine applied before this was
// configurable. model.DefaultBehaviourPolicy in the ueba service is the same
// set; if these two ever disagree, the engine's fallback and the database's
// standard are two different policies with one name.
func TestTheBalancedBehaviourPolicyMovesNoThreshold(t *testing.T) {
	repo := NewBehaviourPolicyRepository(testinfra.Postgres(t))
	p, err := repo.Preset(context.Background(), "balanced")
	if err != nil {
		t.Fatalf("Preset(balanced): %v", err)
	}
	th := p.Thresholds
	if th.MinHoursForBaseline != 3 || th.MinCountriesForBaseline != 1 {
		t.Errorf("baseline minimums are %d/%d, want 3/1", th.MinHoursForBaseline, th.MinCountriesForBaseline)
	}
	if th.VelocityThreshold != 80 || th.VelocityWindowS != 60 {
		t.Errorf("velocity is %d in %ds, want 80 in 60s", th.VelocityThreshold, th.VelocityWindowS)
	}
	if th.BruteForceThreshold != 5 || th.BruteForceWindowS != 300 {
		t.Errorf("brute force is %d in %ds, want 5 in 300s", th.BruteForceThreshold, th.BruteForceWindowS)
	}

	// All eight on, at the scores the engine used.
	for name, s := range map[string]model.Signal{
		"off_hours": p.Signals.OffHours, "new_country": p.Signals.NewCountry,
		"new_ip_prefix": p.Signals.NewIPPrefix, "velocity": p.Signals.Velocity,
		"brute_force": p.Signals.BruteForce, "priv_escalation": p.Signals.PrivEscalation,
		"lateral_movement": p.Signals.LateralMovement, "data_exfiltration": p.Signals.DataExfiltration,
	} {
		if !s.Enabled {
			t.Errorf("%s is off in the neutral preset; adopting it would stop a detection", name)
		}
	}
	if p.Signals.LateralMovement.Score != 8.5 || p.Signals.DataExfiltration.Score != 9 {
		t.Errorf("the two critical signals score %v and %v, want 8.5 and 9",
			p.Signals.LateralMovement.Score, p.Signals.DataExfiltration.Score)
	}
}

// A tenant running three shifts turns off-hours off. It must survive the round
// trip through the database, because the whole point of honouring it here is
// that they do not do it downstream in a mail rule where nobody can see it.
func TestASignalTurnedOffSurvivesTheRoundTrip(t *testing.T) {
	ctx := context.Background()
	pool := testinfra.Postgres(t)
	repo := NewBehaviourPolicyRepository(pool)
	tenant := newTenant(t, pool)

	base, err := repo.Preset(ctx, "balanced")
	if err != nil {
		t.Fatalf("Preset: %v", err)
	}
	signals := base.Signals
	signals.OffHours.Enabled = false

	if _, err := repo.Set(ctx, tenant, nil, &model.BehaviourPolicy{
		Code: "balanced", Name: "three shifts",
		Thresholds: base.Thresholds, Signals: signals,
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := repo.Active(ctx, tenant)
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if got.Signals.OffHours.Enabled {
		t.Error("off_hours came back on after a round trip through the database")
	}
	if !got.Signals.NewCountry.Enabled || !got.Signals.DataExfiltration.Enabled {
		t.Error("turning off_hours off turned other signals off in the database")
	}
}

// ─── Attack policies ─────────────────────────────────────────────────────────

func TestAttackPolicyPresets(t *testing.T) {
	repo := NewAttackPolicyRepository(testinfra.Postgres(t))
	presets, err := repo.Presets(context.Background())
	if err != nil {
		t.Fatalf("Presets: %v", err)
	}
	assertPresetCodes(t, "attack policy", codesOfAttack(presets),
		"balanced", "assume_breach", "exploitability_led", "crown_jewels")
}

// The constants the analyzer used before this was configurable. Adopting
// `balanced` must not re-rank a single path.
func TestTheBalancedAttackPolicyReRanksNothing(t *testing.T) {
	repo := NewAttackPolicyRepository(testinfra.Postgres(t))
	p, err := repo.Preset(context.Background(), "balanced")
	if err != nil {
		t.Fatalf("Preset(balanced): %v", err)
	}
	w := p.Weights
	for _, c := range []struct {
		name string
		got  float64
		want float64
	}{
		{"base_cost", w.BaseCost, 1},
		{"complexity_medium", w.ComplexityMedium, 0.5},
		{"complexity_high", w.ComplexityHigh, 1.5},
		{"privilege_low", w.PrivilegeLow, 0.3},
		{"privilege_high", w.PrivilegeHigh, 1},
		{"hop_decay", w.HopDecay, 0.85},
		{"impact_ceiling", w.ImpactCeiling, 9},
		{"unknown_target_impact", w.UnknownTargetImpact, 4.5},
	} {
		if c.got != c.want {
			t.Errorf("%s is %v, want the %v the analyzer used before this was configurable", c.name, c.got, c.want)
		}
	}
}

// assume_breach is the stance that says distance does not protect: a hop decay
// of exactly 1. A value stored as 1.0 and read back as 0.85 would be a silent
// re-ranking of every path.
func TestAssumeBreachKeepsItsHopDecayOfOne(t *testing.T) {
	repo := NewAttackPolicyRepository(testinfra.Postgres(t))
	p, err := repo.Preset(context.Background(), "assume_breach")
	if err != nil {
		t.Fatalf("Preset(assume_breach): %v", err)
	}
	if p.Weights.HopDecay != 1 {
		t.Fatalf("hop_decay is %v, want exactly 1: the stance is that distance does not protect",
			p.Weights.HopDecay)
	}
}

// ─── Shared ──────────────────────────────────────────────────────────────────

func assertPresetCodes(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: %d presets %v, want %d %v", what, len(got), got, len(want), want)
	}
	seen := map[string]bool{}
	for _, c := range got {
		seen[c] = true
	}
	for _, c := range want {
		if !seen[c] {
			t.Errorf("%s: preset %s is missing; got %v", what, c, got)
		}
	}
}

func codesOfRisk(ps []*model.RiskProfile) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		if p.TenantID != nil {
			out = append(out, p.Code+" (NOT A PRESET: belongs to a tenant)")
			continue
		}
		out = append(out, p.Code)
	}
	return out
}

func codesOfBehaviour(ps []*model.BehaviourPolicy) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		if p.TenantID != nil {
			out = append(out, p.Code+" (NOT A PRESET: belongs to a tenant)")
			continue
		}
		out = append(out, p.Code)
	}
	return out
}

func codesOfAttack(ps []*model.AttackPolicy) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		if p.TenantID != nil {
			out = append(out, p.Code+" (NOT A PRESET: belongs to a tenant)")
			continue
		}
		out = append(out, p.Code)
	}
	return out
}

// Every policy table carries the same partial unique index.
//
// remediation_policy_postgres_test.go proves behaviourally that the index
// refuses a second open row. This asserts that all four tables have one, which
// is the part a fifth policy added later would quietly miss: the service would
// work, and two versions would go live at once the first time two requests
// raced.
func TestEveryPolicyTableHasThePartialUniqueIndex(t *testing.T) {
	pool := testinfra.Postgres(t)
	ctx := context.Background()

	for _, table := range []string{
		"risk_profiles", "remediation_policies", "behaviour_policies", "attack_policies",
	} {
		var found bool
		err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_indexes
				 WHERE schemaname = 'public'
				   AND tablename  = $1
				   AND indexdef LIKE 'CREATE UNIQUE INDEX%'
				   AND indexdef LIKE '%(tenant_id)%'
				   AND indexdef LIKE '%effective_to IS NULL%')`, table).Scan(&found)
		if err != nil {
			t.Fatalf("look for the index on %s: %v", table, err)
		}
		if !found {
			t.Errorf("%s has no unique index on (tenant_id) WHERE effective_to IS NULL: "+
				"nothing stops two versions being in force at once", table)
		}
	}
}
