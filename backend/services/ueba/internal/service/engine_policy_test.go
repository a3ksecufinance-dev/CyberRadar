package service

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/cyberradar/platform/internal/pkg/event"
	"github.com/cyberradar/platform/services/ueba/internal/model"
)

// detect runs the detection with no engine state, which is all it uses: the
// decision is a function of the profile, the event, the counters and the policy.
func detect(
	profile *model.EntityProfile,
	ev *event.NormalizedEvent,
	velocity, failures int,
	policy *model.BehaviourPolicy,
) []*model.Anomaly {
	e := &BehaviorEngine{}
	return e.detectAnomalies(profile, ev, uuid.New(), uuid.New(), velocity, failures, policy)
}

func anomalyOf(as []*model.Anomaly, atype string) *model.Anomaly {
	for _, a := range as {
		if a.AnomalyType == atype {
			return a
		}
	}
	return nil
}

// readyProfile is an entity whose baseline covers every hour but the one it is
// being tested in.
//
// Written against the clock on purpose. A literal list of hours made the
// off-hours test pass or skip depending on what time the suite ran, and a skip
// reads like a pass in CI output.
func readyProfile() *model.EntityProfile {
	current := int32(time.Now().UTC().Hour())
	hours := make([]int32, 0, 23)
	for h := int32(0); h < 24; h++ {
		if h != current {
			hours = append(hours, h)
		}
	}
	return &model.EntityProfile{
		EntityType:      model.EntityTypeUser,
		BaselineReady:   true,
		NormalHours:     hours,
		NormalCountries: []string{"FR"},
	}
}

// insideBaseline is the same entity with the current hour in its normal set, so
// a test that does not mean to exercise off-hours does not trip it.
func insideBaseline() *model.EntityProfile {
	p := readyProfile()
	p.NormalHours = append(p.NormalHours, int32(time.Now().UTC().Hour()))
	return p
}

func str(s string) *string { return &s }

// Making the thresholds configurable has to be invisible on the day it ships.
// If the default moved a single detection, the first thing a customer would
// notice is that their alerting changed because the vendor refactored.
func TestTheDefaultPolicyIsExactlyWhatTheConstantsWere(t *testing.T) {
	p := model.DefaultBehaviourPolicy()

	if p.VelocityThreshold != 80 || p.VelocityWindowS != 60 {
		t.Errorf("velocity is %d/%ds, was 80/60s", p.VelocityThreshold, p.VelocityWindowS)
	}
	if p.BruteForceThreshold != 5 || p.BruteForceWindowS != 300 {
		t.Errorf("brute force is %d/%ds, was 5/300s", p.BruteForceThreshold, p.BruteForceWindowS)
	}
	if p.MinHoursForBaseline != 3 || p.MinCountriesForBaseline != 1 {
		t.Errorf("baseline readiness is %d hours / %d countries, was 3 / 1",
			p.MinHoursForBaseline, p.MinCountriesForBaseline)
	}

	for _, c := range []struct {
		atype    string
		severity string
		score    float64
	}{
		{model.AnomalyOffHoursAccess, model.SeverityMedium, 3.5},
		{model.AnomalyNewCountry, model.SeverityHigh, 6.5},
		{model.AnomalyNewIPPrefix, model.SeverityLow, 2.0},
		{model.AnomalyVelocitySpike, model.SeverityHigh, 5.0},
		{model.AnomalyBruteForce, model.SeverityHigh, 6.0},
		{model.AnomalyPrivEscalation, model.SeverityHigh, 7.0},
		{model.AnomalyLateralMovement, model.SeverityCritical, 8.5},
		{model.AnomalyDataExfiltration, model.SeverityCritical, 9.0},
	} {
		sig := p.Signal(c.atype)
		if !sig.Enabled || sig.Severity != c.severity || sig.Score != c.score {
			t.Errorf("%s is %+v, was {true %s %.1f}", c.atype, sig, c.severity, c.score)
		}
	}
}

// An institution running three shifts has no use for an off-hours alert that
// fires every night. Honouring that here is what stops them doing it downstream
// in a mail rule, where nobody can see that they did.
func TestASignalTurnedOffRaisesNothing(t *testing.T) {
	policy := model.DefaultBehaviourPolicy()
	profile := readyProfile()
	ev := &event.NormalizedEvent{EventID: uuid.New()}

	// The profile's baseline deliberately excludes the current hour, so this
	// fires while the signal is on. Proving it fires first is what makes the
	// assertion below mean "the switch worked" rather than "nothing happened".
	if got := detect(profile, ev, 0, 0, policy); anomalyOf(got, model.AnomalyOffHoursAccess) == nil {
		t.Fatal("an hour outside the baseline did not raise off-hours access")
	}

	off := policy.Signals[model.AnomalyOffHoursAccess]
	off.Enabled = false
	policy.Signals[model.AnomalyOffHoursAccess] = off

	if a := anomalyOf(detect(profile, ev, 0, 0, policy), model.AnomalyOffHoursAccess); a != nil {
		t.Errorf("a signal the tenant switched off still raised %+v", a)
	}
}

// The severity and the score on an anomaly are the institution's judgement, not
// a literal in the detection. A tenant who raised NEW_COUNTRY to CRITICAL must
// see CRITICAL on the alert, or the setting is decorative.
func TestTheSeverityAndScoreComeFromThePolicy(t *testing.T) {
	policy := model.DefaultBehaviourPolicy()
	policy.Signals[model.AnomalyNewCountry] = model.Signal{
		Enabled: true, Severity: model.SeverityCritical, Score: 8.0,
	}

	ev := &event.NormalizedEvent{EventID: uuid.New(), GeoCountry: str("RU")}
	a := anomalyOf(detect(insideBaseline(), ev, 0, 0, policy), model.AnomalyNewCountry)
	if a == nil {
		t.Fatal("a country outside the baseline raised nothing")
	}
	if a.Severity != model.SeverityCritical || a.Score != 8.0 {
		t.Errorf("the anomaly is %s/%.1f; the policy says CRITICAL/8.0", a.Severity, a.Score)
	}
}

// The counters' thresholds are the tenant's too, and the alert has to name the
// window they chose: "80/min" on an alert raised over five minutes is a number
// an analyst cannot reconcile with anything.
func TestTheCounterThresholdsAreTheTenantsAndSaySo(t *testing.T) {
	policy := model.DefaultBehaviourPolicy()
	policy.VelocityThreshold = 40
	policy.VelocityWindowS = 120
	policy.BruteForceThreshold = 3

	ev := &event.NormalizedEvent{EventID: uuid.New()}
	got := detect(insideBaseline(), ev, 40, 3, policy)

	spike := anomalyOf(got, model.AnomalyVelocitySpike)
	if spike == nil {
		t.Fatal("40 events did not trip a threshold of 40")
	}
	if spike.BaselineVal != "threshold=40/120s" {
		t.Errorf("the alert says %q; the tenant set 40 over 120s", spike.BaselineVal)
	}
	if anomalyOf(got, model.AnomalyBruteForce) == nil {
		t.Error("3 failures did not trip a threshold of 3")
	}

	// And one below the threshold raises nothing, so the comparison is real.
	if a := anomalyOf(detect(insideBaseline(), ev, 39, 2, policy), model.AnomalyVelocitySpike); a != nil {
		t.Errorf("39 events tripped a threshold of 40: %+v", a)
	}
}

// Detecting "unusual" against a baseline of one observation is how a platform
// greets a new joiner with four alerts on their first morning. How much history
// is enough is the institution's call.
func TestBaselineReadinessIsThePolicys(t *testing.T) {
	ev := &event.NormalizedEvent{EventID: uuid.New(), GeoCountry: str("FR")}

	strict := model.DefaultBehaviourPolicy()
	strict.MinHoursForBaseline = 6
	profile := &model.EntityProfile{
		EntityType:      model.EntityTypeUser,
		NormalHours:     []int32{1, 2, 3, 4},
		NormalCountries: []string{"FR"},
	}
	updateBaseline(profile, ev, strict)
	if profile.BaselineReady {
		t.Error("a baseline of five hours was called ready under a policy asking for six")
	}

	lenient := model.DefaultBehaviourPolicy()
	lenient.MinHoursForBaseline = 2
	profile2 := &model.EntityProfile{
		EntityType:      model.EntityTypeUser,
		NormalHours:     []int32{1},
		NormalCountries: []string{"FR"},
	}
	updateBaseline(profile2, ev, lenient)
	if !profile2.BaselineReady {
		t.Error("a baseline of two hours was not ready under a policy asking for two")
	}
}

// A policy that says nothing about an anomaly type must not have it default to
// firing. A missing setting quietly becoming a HIGH is how a configuration
// mistake turns into a pager at three in the morning.
func TestAnUnknownSignalDoesNotFire(t *testing.T) {
	policy := &model.BehaviourPolicy{
		VelocityThreshold: 1, VelocityWindowS: 60,
		BruteForceThreshold: 1, BruteForceWindowS: 300,
		MinHoursForBaseline: 1, MinCountriesForBaseline: 1,
		Signals: map[string]model.Signal{}, // says nothing about anything
	}
	ev := &event.NormalizedEvent{EventID: uuid.New(), GeoCountry: str("RU")}
	if got := detect(readyProfile(), ev, 999, 999, policy); len(got) != 0 {
		t.Errorf("a policy that configures no signal raised %d anomalies: %+v", len(got), got)
	}
}

// ─── Who the event is about ──────────────────────────────────────────────────

// The engine resolved an entity from user_id and asset_id alone. A log line
// carries a username, not a UUID, so every event was discarded one step after it
// arrived and ueba_profiles had zero rows on a platform that had ingested
// thousands of events. No baseline had ever been built.
func TestAUsernameIsAnIdentity(t *testing.T) {
	ev := &event.NormalizedEvent{TenantID: uuid.NewString(), UserName: str("m.durand")}
	id, name, kind := entityFrom(ev)
	if id == "" {
		t.Fatal("an event naming a user resolved to no entity")
	}
	if _, err := uuid.Parse(id); err != nil {
		t.Errorf("the derived identifier %q is not a UUID, and the profile table keys on one", id)
	}
	if name != "m.durand" || kind != model.EntityTypeUser {
		t.Errorf("resolved to %q/%s, want m.durand/user", name, kind)
	}
}

// The identifier has to be the same on every replica and across restarts, or an
// entity gets a fresh baseline each time and is never anomalous.
func TestADerivedIdentityIsStable(t *testing.T) {
	tenant := uuid.NewString()
	first, _, _ := entityFrom(&event.NormalizedEvent{TenantID: tenant, UserName: str("m.durand")})
	again, _, _ := entityFrom(&event.NormalizedEvent{TenantID: tenant, UserName: str("m.durand")})
	if first != again {
		t.Errorf("the same user resolved to %s then %s", first, again)
	}

	// A source that writes M.Durand on Monday and m.durand on Tuesday is
	// describing one person, not two.
	cased, _, _ := entityFrom(&event.NormalizedEvent{TenantID: tenant, UserName: str("M.Durand ")})
	if cased != first {
		t.Errorf("case and spacing produced a second identity: %s vs %s", cased, first)
	}
}

// One customer's "admin" must never be another's. A behavioural baseline leaking
// between tenants is both a wrong detection and a disclosure.
func TestADerivedIdentityIsScopedToItsTenant(t *testing.T) {
	a, _, _ := entityFrom(&event.NormalizedEvent{TenantID: uuid.NewString(), UserName: str("admin")})
	b, _, _ := entityFrom(&event.NormalizedEvent{TenantID: uuid.NewString(), UserName: str("admin")})
	if a == b {
		t.Error("the same username in two tenants resolved to one entity")
	}
}

// Where the source does give a UUID, it is used as it stands — deriving over it
// would orphan every profile the platform already has.
func TestARealIdentifierIsUsedAsItIs(t *testing.T) {
	real := uuid.NewString()
	id, name, kind := entityFrom(&event.NormalizedEvent{
		TenantID: uuid.NewString(), UserID: &real, UserName: str("m.durand"),
	})
	if id != real {
		t.Errorf("a real user_id was replaced by %s", id)
	}
	if name != "m.durand" || kind != model.EntityTypeUser {
		t.Errorf("resolved to %q/%s", name, kind)
	}
}

// Behaviour is a property of people before it is of machines: an event naming
// both is about what the person did.
func TestAUserWinsOverTheHost(t *testing.T) {
	_, name, kind := entityFrom(&event.NormalizedEvent{
		TenantID: uuid.NewString(), UserName: str("svc-swift"), AssetHostname: str("swift-gw-01"),
	})
	if kind != model.EntityTypeUser || name != "svc-swift" {
		t.Errorf("an event naming a user and a host profiled %q/%s", name, kind)
	}
}

// An event naming neither is not an entity, and inventing one would create a
// profile per event.
func TestAnEventNamingNobodyResolvesToNothing(t *testing.T) {
	if id, _, _ := entityFrom(&event.NormalizedEvent{TenantID: uuid.NewString()}); id != "" {
		t.Errorf("an event naming no user and no host resolved to %s", id)
	}
}
