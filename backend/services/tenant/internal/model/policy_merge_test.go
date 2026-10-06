package model

import "testing"

// Apply is the merge behind every policy screen: the caller sends only what
// they changed, and the rest must come through untouched. A defect here writes
// a value nobody asked for into a customer's policy, silently — the screen
// shows what was sent, the database holds something else.
//
// Three properties, tested for all four policies:
//
//   - a nil partial changes nothing;
//   - a field the caller did not name is left alone;
//   - a field the caller named is written.
//
// Plus the one that is specific to deadlines: a ceiling can be *removed*, and
// removing it is not the same as not mentioning it. That distinction is what
// `CASE WHEN own.id IS NOT NULL` rather than `COALESCE` protects in SQL, and it
// has to hold here too or the two layers disagree.

func ptrI(v int) *int         { return &v }
func ptrF(v float64) *float64 { return &v }
func ptrB(v bool) *bool       { return &v }
func ptrS(v string) *string   { return &v }

// ─── Remediation deadlines ───────────────────────────────────────────────────

func baseDeadlines() Deadlines {
	return Deadlines{
		CriticalDays: 3, HighDays: 7, MediumDays: 30, LowDays: 90,
		ExploitedDays: ptrI(1), DMZDays: ptrI(7),
		CBSDays: nil, SWIFTDays: nil, PCIDays: ptrI(14),
		MinimumDays: 1,
	}
}

func TestDeadlinesNilPartialChangesNothing(t *testing.T) {
	base := baseDeadlines()
	var p *PartialDeadlines
	if got := p.Apply(base); got.CriticalDays != 3 || got.LowDays != 90 || *got.PCIDays != 14 {
		t.Fatalf("a nil partial changed the deadlines: %+v", got)
	}
}

func TestDeadlinesOnlyNamedFieldsMove(t *testing.T) {
	base := baseDeadlines()
	got := (&PartialDeadlines{CriticalDays: ptrI(2)}).Apply(base)

	if got.CriticalDays != 2 {
		t.Errorf("critical is %d, want the 2 the caller sent", got.CriticalDays)
	}
	for name, pair := range map[string][2]int{
		"high": {got.HighDays, 7}, "medium": {got.MediumDays, 30},
		"low": {got.LowDays, 90}, "minimum": {got.MinimumDays, 1},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s moved to %d without being named; it was %d", name, pair[0], pair[1])
		}
	}
	if got.ExploitedDays == nil || *got.ExploitedDays != 1 {
		t.Error("the exploited ceiling was dropped without being named")
	}
	if got.PCIDays == nil || *got.PCIDays != 14 {
		t.Error("the PCI ceiling was dropped without being named")
	}
}

// Setting a ceiling that was unset, and clearing one that was set, are
// different operations and both have to work.
func TestDeadlinesCeilingsAreSetAndCleared(t *testing.T) {
	base := baseDeadlines()

	got := (&PartialDeadlines{
		CBSDays:       ptrI(5),               // was unset
		ClearCeilings: []string{"exploited"}, // was 1
	}).Apply(base)

	if got.CBSDays == nil || *got.CBSDays != 5 {
		t.Error("a ceiling the caller set did not arrive")
	}
	if got.ExploitedDays != nil {
		t.Errorf("a cleared ceiling is still %d; clearing is not the same as not naming", *got.ExploitedDays)
	}
	if got.DMZDays == nil || *got.DMZDays != 7 {
		t.Error("clearing one ceiling cleared another")
	}
}

func TestDeadlinesEveryCeilingCanBeCleared(t *testing.T) {
	base := Deadlines{
		CriticalDays: 3, HighDays: 7, MediumDays: 30, LowDays: 90, MinimumDays: 1,
		ExploitedDays: ptrI(1), DMZDays: ptrI(2), CBSDays: ptrI(3),
		SWIFTDays: ptrI(4), PCIDays: ptrI(5),
	}
	got := (&PartialDeadlines{
		ClearCeilings: []string{"exploited", "dmz", "cbs", "swift", "pci"},
	}).Apply(base)

	for name, v := range map[string]*int{
		"exploited": got.ExploitedDays, "dmz": got.DMZDays, "cbs": got.CBSDays,
		"swift": got.SWIFTDays, "pci": got.PCIDays,
	} {
		if v != nil {
			t.Errorf("%s survived being cleared, at %d", name, *v)
		}
	}
}

// A ceiling named and cleared in the same request: clearing wins, because it is
// applied last. Asserted so that the order is a decision rather than an
// accident of the code's shape.
func TestClearingBeatsSettingInTheSameRequest(t *testing.T) {
	got := (&PartialDeadlines{
		CBSDays:       ptrI(5),
		ClearCeilings: []string{"cbs"},
	}).Apply(baseDeadlines())

	if got.CBSDays != nil {
		t.Fatalf("set and cleared in one request left %d; clearing is applied last", *got.CBSDays)
	}
}

// Apply must not reach back into the caller's own copy.
func TestApplyLeavesTheCallersBaseAlone(t *testing.T) {
	base := baseDeadlines()
	_ = (&PartialDeadlines{
		CriticalDays:  ptrI(99),
		ClearCeilings: []string{"exploited"},
	}).Apply(base)

	if base.CriticalDays != 3 {
		t.Errorf("the caller's base now reads %d critical days", base.CriticalDays)
	}
	if base.ExploitedDays == nil || *base.ExploitedDays != 1 {
		t.Error("the caller's base lost its exploited ceiling")
	}
}

// Deadlines that run backwards are almost certainly a typo, and saying so is
// more useful than a constraint violation reaching the caller as a 500.
func TestOrderedCatchesDeadlinesThatRunBackwards(t *testing.T) {
	cases := []struct {
		name string
		d    Deadlines
		want bool
	}{
		{"the shipped order", Deadlines{CriticalDays: 3, HighDays: 7, MediumDays: 30, LowDays: 90}, true},
		{"all equal is not backwards", Deadlines{CriticalDays: 5, HighDays: 5, MediumDays: 5, LowDays: 5}, true},
		{"critical slower than high", Deadlines{CriticalDays: 10, HighDays: 7, MediumDays: 30, LowDays: 90}, false},
		{"high slower than medium", Deadlines{CriticalDays: 3, HighDays: 40, MediumDays: 30, LowDays: 90}, false},
		{"medium slower than low", Deadlines{CriticalDays: 3, HighDays: 7, MediumDays: 95, LowDays: 90}, false},
	}
	for _, c := range cases {
		if got := c.d.Ordered(); got != c.want {
			t.Errorf("%s: Ordered() = %v, want %v", c.name, got, c.want)
		}
	}
}

// ─── Behaviour thresholds and signals ────────────────────────────────────────

func baseThresholds() Thresholds {
	return Thresholds{
		MinHoursForBaseline: 3, MinCountriesForBaseline: 1,
		VelocityThreshold: 80, VelocityWindowS: 60,
		BruteForceThreshold: 5, BruteForceWindowS: 300,
	}
}

func TestThresholdsOnlyNamedFieldsMove(t *testing.T) {
	var nilp *PartialThresholds
	if got := nilp.Apply(baseThresholds()); got != baseThresholds() {
		t.Fatalf("a nil partial changed the thresholds: %+v", got)
	}

	got := (&PartialThresholds{VelocityThreshold: ptrI(200)}).Apply(baseThresholds())
	if got.VelocityThreshold != 200 {
		t.Errorf("velocity is %d, want 200", got.VelocityThreshold)
	}
	want := baseThresholds()
	want.VelocityThreshold = 200
	if got != want {
		t.Errorf("naming one threshold moved another:\n got  %+v\n want %+v", got, want)
	}
}

func baseSignals() Signals {
	return Signals{
		OffHours:         Signal{Enabled: true, Severity: "MEDIUM", Score: 3.5},
		NewCountry:       Signal{Enabled: true, Severity: "HIGH", Score: 6.5},
		NewIPPrefix:      Signal{Enabled: true, Severity: "LOW", Score: 2},
		Velocity:         Signal{Enabled: true, Severity: "HIGH", Score: 5},
		BruteForce:       Signal{Enabled: true, Severity: "HIGH", Score: 6},
		PrivEscalation:   Signal{Enabled: true, Severity: "HIGH", Score: 7},
		LateralMovement:  Signal{Enabled: true, Severity: "CRITICAL", Score: 8.5},
		DataExfiltration: Signal{Enabled: true, Severity: "CRITICAL", Score: 9},
	}
}

// Turning one signal off is the decision an institution running three shifts
// makes about off-hours access. It must turn off that one and nothing else.
func TestSignalsOneCanBeTurnedOffAlone(t *testing.T) {
	got := (&PartialSignals{
		OffHours: &PartialSignal{Enabled: ptrB(false)},
	}).Apply(baseSignals())

	if got.OffHours.Enabled {
		t.Error("the signal the caller disabled is still on")
	}
	if got.OffHours.Severity != "MEDIUM" || got.OffHours.Score != 3.5 {
		t.Errorf("disabling a signal also changed its severity or score: %+v", got.OffHours)
	}
	for name, s := range map[string]Signal{
		"new_country": got.NewCountry, "velocity": got.Velocity,
		"brute_force": got.BruteForce, "lateral_movement": got.LateralMovement,
		"data_exfiltration": got.DataExfiltration, "priv_escalation": got.PrivEscalation,
		"new_ip_prefix": got.NewIPPrefix,
	} {
		if !s.Enabled {
			t.Errorf("disabling off_hours also disabled %s", name)
		}
	}
}

// Within one signal, the three fields are independent.
func TestSignalFieldsAreIndependent(t *testing.T) {
	got := (&PartialSignals{
		Velocity: &PartialSignal{Score: ptrF(9.5)},
	}).Apply(baseSignals())

	if got.Velocity.Score != 9.5 {
		t.Errorf("score is %v, want 9.5", got.Velocity.Score)
	}
	if !got.Velocity.Enabled {
		t.Error("changing a score disabled the signal")
	}
	if got.Velocity.Severity != "HIGH" {
		t.Errorf("changing a score moved the severity to %s", got.Velocity.Severity)
	}

	sev := (&PartialSignals{
		BruteForce: &PartialSignal{Severity: ptrS("CRITICAL")},
	}).Apply(baseSignals())
	if sev.BruteForce.Severity != "CRITICAL" || sev.BruteForce.Score != 6 {
		t.Errorf("changing a severity also moved the score: %+v", sev.BruteForce)
	}
}

func TestSignalsNilPartialChangesNothing(t *testing.T) {
	var p *PartialSignals
	if got := p.Apply(baseSignals()); got != baseSignals() {
		t.Fatal("a nil partial changed the signals")
	}
	// A named signal with nothing set inside it is also a no-op.
	if got := (&PartialSignals{Velocity: &PartialSignal{}}).Apply(baseSignals()); got != baseSignals() {
		t.Fatal("an empty PartialSignal changed the signal it named")
	}
}

// ─── Attack weights ──────────────────────────────────────────────────────────

func baseAttack() AttackWeights {
	return AttackWeights{
		BaseCost: 1, ComplexityMedium: 0.5, ComplexityHigh: 1.5,
		PrivilegeLow: 0.3, PrivilegeHigh: 1, HopDecay: 0.85,
		ImpactCeiling: 9, UnknownTargetImpact: 4.5,
		CriticalSystemBonus: 1, ManyPathsBoost: 0.3,
	}
}

func TestAttackWeightsOnlyNamedFieldsMove(t *testing.T) {
	var nilp *PartialAttackWeights
	if got := nilp.Apply(baseAttack()); got != baseAttack() {
		t.Fatal("a nil partial changed the weights")
	}

	got := (&PartialAttackWeights{HopDecay: ptrF(1)}).Apply(baseAttack())
	want := baseAttack()
	want.HopDecay = 1
	if got != want {
		t.Errorf("naming hop_decay moved something else:\n got  %+v\n want %+v", got, want)
	}
}

// Zero is a value a caller can mean: a hop decay of 0 says distance does not
// protect at all. A merge that treated zero as "unset" would silently refuse it.
func TestAttackWeightsAcceptAnExplicitZero(t *testing.T) {
	got := (&PartialAttackWeights{
		UnknownTargetImpact: ptrF(0),
		ManyPathsBoost:      ptrF(0),
	}).Apply(baseAttack())

	if got.UnknownTargetImpact != 0 {
		t.Errorf("an explicit 0 for unknown_target_impact was ignored, left at %v", got.UnknownTargetImpact)
	}
	if got.ManyPathsBoost != 0 {
		t.Errorf("an explicit 0 for many_paths_boost was ignored, left at %v", got.ManyPathsBoost)
	}
}

// ─── Risk weights ────────────────────────────────────────────────────────────

func baseRisk() RiskWeights {
	return RiskWeights{
		CriticalityStep: 1.5, CriticalityCap: 6,
		VulnCritical: 2, VulnHigh: 1, VulnMedium: 0.4, VulnLow: 0.1, VulnCap: 5,
		CBSConnected: 1.5, SWIFTConnected: 1.5, PCIScope: 1, ExposureCap: 3,
		NeverSeen: 0.5, CriticalProduction: 1, BankingType: 0.5, ContextCap: 2,
		TotalCap: 10, HighRiskThreshold: 7,
	}
}

func TestRiskWeightsOnlyNamedFieldsMove(t *testing.T) {
	var nilp *PartialRiskWeights
	if got := nilp.Apply(baseRisk()); got != baseRisk() {
		t.Fatal("a nil partial changed the weights")
	}

	got := (&PartialRiskWeights{VulnCritical: ptrF(3), TotalCap: ptrF(9)}).Apply(baseRisk())
	want := baseRisk()
	want.VulnCritical = 3
	want.TotalCap = 9
	if got != want {
		t.Errorf("naming two factors moved a third:\n got  %+v\n want %+v", got, want)
	}
}

func TestRiskWeightsAcceptAnExplicitZero(t *testing.T) {
	got := (&PartialRiskWeights{VulnLow: ptrF(0), NeverSeen: ptrF(0)}).Apply(baseRisk())
	if got.VulnLow != 0 || got.NeverSeen != 0 {
		t.Fatalf("an explicit 0 was ignored: vuln_low %v, never_seen %v", got.VulnLow, got.NeverSeen)
	}
}
