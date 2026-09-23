package service

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cyberradar/platform/internal/pkg/cache"
	"github.com/cyberradar/platform/internal/pkg/event"
	"github.com/cyberradar/platform/services/siem/internal/model"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

func strp(s string) *string { return &s }

func baseEvent() *event.NormalizedEvent {
	return &event.NormalizedEvent{
		TenantID:   "00000000-0000-0000-0000-000000000001",
		Category:   event.CategorySecurity,
		Severity:   event.SeverityHigh,
		Action:     "login",
		SourceType: "syslog",
		Source:     "gateway-1",
		UserID:     strp("u-1"),
		UserName:   strp("alice"),
		IPSource:   strp("10.0.0.5"),
		RiskScore:  7.5,
	}
}

func TestMatchFieldOperators(t *testing.T) {
	ev := baseEvent()

	cases := []struct {
		name  string
		match model.FieldMatch
		want  bool
	}{
		{"eq matches", model.FieldMatch{Field: "action", Op: model.OpEq, Value: "login"}, true},
		{"eq is case-insensitive", model.FieldMatch{Field: "action", Op: model.OpEq, Value: "LOGIN"}, true},
		{"eq rejects other value", model.FieldMatch{Field: "action", Op: model.OpEq, Value: "logout"}, false},
		{"neq", model.FieldMatch{Field: "action", Op: model.OpNeq, Value: "logout"}, true},
		{"contains", model.FieldMatch{Field: "user_name", Op: model.OpContains, Value: "LIC"}, true},
		{"contains rejects", model.FieldMatch{Field: "user_name", Op: model.OpContains, Value: "bob"}, false},
		{"gt", model.FieldMatch{Field: "risk_score", Op: model.OpGt, Value: "5"}, true},
		{"gt rejects equal", model.FieldMatch{Field: "risk_score", Op: model.OpGt, Value: "7.5"}, false},
		{"gte accepts equal", model.FieldMatch{Field: "risk_score", Op: model.OpGte, Value: "7.5"}, true},
		{"exists on set field", model.FieldMatch{Field: "user_id", Op: model.OpExists, Value: ""}, true},
		{"exists on unset field", model.FieldMatch{Field: "geo_country", Op: model.OpExists, Value: ""}, false},

		// lt, lte and in are declared in the rule model, so a rule author can
		// select them; they must not silently behave as equality.
		{"lt", model.FieldMatch{Field: "risk_score", Op: model.OpLt, Value: "9"}, true},
		{"lt rejects greater", model.FieldMatch{Field: "risk_score", Op: model.OpLt, Value: "3"}, false},
		{"lt rejects equal", model.FieldMatch{Field: "risk_score", Op: model.OpLt, Value: "7.5"}, false},
		{"lte accepts equal", model.FieldMatch{Field: "risk_score", Op: model.OpLte, Value: "7.5"}, true},
		{"lte rejects greater", model.FieldMatch{Field: "risk_score", Op: model.OpLte, Value: "3"}, false},
		{"in matches a member", model.FieldMatch{Field: "action", Op: model.OpIn, Value: "logout,login,refresh"}, true},
		{"in tolerates spacing", model.FieldMatch{Field: "action", Op: model.OpIn, Value: "logout, login"}, true},
		{"in rejects a non-member", model.FieldMatch{Field: "action", Op: model.OpIn, Value: "logout,refresh"}, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := matchField(c.match, ev); got != c.want {
				t.Errorf("matchField(%s %s %q) = %v, want %v",
					c.match.Field, c.match.Op, c.match.Value, got, c.want)
			}
		})
	}
}

func TestGetField(t *testing.T) {
	ev := baseEvent()

	cases := map[string]string{
		"category":     "Security",
		"severity":     "HIGH",
		"action":       "login",
		"source_type":  "syslog",
		"user_id":      "u-1",
		"user_name":    "alice",
		"ip_source":    "10.0.0.5",
		"risk_score":   "7.50",
		"geo_country":  "", // nil pointer
		"unknown_name": "", // unrecognised field
	}

	for field, want := range cases {
		if got := getField(ev, field); got != want {
			t.Errorf("getField(%q) = %q, want %q", field, got, want)
		}
	}
}

func TestGetFieldNilPointersAreEmptyNotPanics(t *testing.T) {
	ev := &event.NormalizedEvent{TenantID: "t"}
	for _, f := range []string{
		"mitre_tactic", "mitre_technique", "user_id", "user_name",
		"ip_source", "ip_destination", "geo_country",
	} {
		if got := getField(ev, f); got != "" {
			t.Errorf("getField(%q) on an empty event = %q, want empty", f, got)
		}
	}
}

func newEngine() *RuleEngine {
	// A window with no Redis counts in process — which is what a unit test
	// wants, and what the engine falls back to when the cache is unreachable.
	return &RuleEngine{
		thresholds: cache.NewWindow(nil, "test:threshold", zerolog.Nop()),
		logger:     zerolog.Nop(),
	}
}

func thresholdRule(count, window int, groupBy ...string) *model.DetectionRule {
	return &model.DetectionRule{
		ID: uuid.New(),
		Conditions: model.RuleConditions{
			Threshold: &model.ThresholdCondition{
				Count: count, WindowSeconds: window, GroupBy: groupBy,
			},
		},
	}
}

func TestThresholdFiresOnlyAtCount(t *testing.T) {
	e := newEngine()
	rule := thresholdRule(3, 60, "user_name")
	ev := baseEvent()

	for i := 1; i <= 5; i++ {
		got := e.thresholdMet(context.Background(), rule, ev, rule.Conditions.Threshold)
		want := i >= 3
		if got != want {
			t.Errorf("event %d: thresholdMet = %v, want %v", i, got, want)
		}
	}
}

func TestThresholdIsolatesGroups(t *testing.T) {
	e := newEngine()
	rule := thresholdRule(2, 60, "user_name")

	alice := baseEvent()
	bob := baseEvent()
	bob.UserName = strp("bob")

	// One event each: neither group has reached the count of 2.
	if e.thresholdMet(context.Background(), rule, alice, rule.Conditions.Threshold) {
		t.Error("alice fired on her first event")
	}
	if e.thresholdMet(context.Background(), rule, bob, rule.Conditions.Threshold) {
		t.Error("bob fired on his first event — counters leaked across groups")
	}
	// Alice's second event reaches the count; bob's counter is untouched.
	if !e.thresholdMet(context.Background(), rule, alice, rule.Conditions.Threshold) {
		t.Error("alice did not fire on her second event")
	}
}

func TestThresholdIsolatesRules(t *testing.T) {
	e := newEngine()
	ruleA := thresholdRule(2, 60, "user_name")
	ruleB := thresholdRule(2, 60, "user_name")
	ev := baseEvent()

	e.thresholdMet(context.Background(), ruleA, ev, ruleA.Conditions.Threshold)
	if e.thresholdMet(context.Background(), ruleB, ev, ruleB.Conditions.Threshold) {
		t.Error("rule B fired on its first event — counters are shared between rules")
	}
}

func TestThresholdExpiresOutsideWindow(t *testing.T) {
	// The shortest window a rule can express is one second, so this test waits
	// one out rather than reaching into the counter to age it. It is the only
	// place that proves WindowSeconds reaches the counter as seconds.
	e := newEngine()
	rule := thresholdRule(2, 1, "user_name")
	ev := baseEvent()

	e.thresholdMet(context.Background(), rule, ev, rule.Conditions.Threshold)
	time.Sleep(1100 * time.Millisecond)

	if e.thresholdMet(context.Background(), rule, ev, rule.Conditions.Threshold) {
		t.Error("fired using an event older than the window")
	}
}

func TestEvaluateRequiresEveryFieldMatch(t *testing.T) {
	e := newEngine()
	ev := baseEvent()

	rule := &model.DetectionRule{
		ID: uuid.New(),
		Conditions: model.RuleConditions{FieldMatches: []model.FieldMatch{
			{Field: "category", Op: model.OpEq, Value: "Security"},
			{Field: "action", Op: model.OpEq, Value: "login"},
		}},
	}
	if !e.evaluate(context.Background(), rule, ev) {
		t.Error("rule with all conditions satisfied did not evaluate true")
	}

	rule.Conditions.FieldMatches = append(rule.Conditions.FieldMatches,
		model.FieldMatch{Field: "severity", Op: model.OpEq, Value: "LOW"})
	if e.evaluate(context.Background(), rule, ev) {
		t.Error("rule evaluated true although one condition failed")
	}
}

func TestEvaluateAppliesThresholdAfterFieldMatches(t *testing.T) {
	e := newEngine()
	ev := baseEvent()

	rule := &model.DetectionRule{
		ID: uuid.New(),
		Conditions: model.RuleConditions{
			FieldMatches: []model.FieldMatch{{Field: "action", Op: model.OpEq, Value: "login"}},
			Threshold:    &model.ThresholdCondition{Count: 2, WindowSeconds: 60, GroupBy: []string{"user_name"}},
		},
	}

	if e.evaluate(context.Background(), rule, ev) {
		t.Error("fired on the first event despite a threshold of 2")
	}
	if !e.evaluate(context.Background(), rule, ev) {
		t.Error("did not fire on the second event")
	}

	// A non-matching event must not advance the counter.
	other := baseEvent()
	other.Action = "logout"
	if e.evaluate(context.Background(), rule, other) {
		t.Error("an event failing the field match still fired")
	}
}

func TestDedupHashSeparatesTenants(t *testing.T) {
	// The dedup key must never collide across tenants: one tenant's alert
	// suppressing another's would hide a real detection.
	ruleID := uuid.New().String()

	a := dedupHash(ruleID, "10.0.0.5", "tenant-a")
	b := dedupHash(ruleID, "10.0.0.5", "tenant-b")
	if a == b {
		t.Error("same dedup key for two tenants")
	}
	if a != dedupHash(ruleID, "10.0.0.5", "tenant-a") {
		t.Error("dedup key is not stable for identical input")
	}
	if a == dedupHash(ruleID, "10.0.0.6", "tenant-a") {
		t.Error("same dedup key for two entities")
	}
	if a == dedupHash(uuid.New().String(), "10.0.0.5", "tenant-a") {
		t.Error("same dedup key for two rules")
	}
}

func TestEntityFromPrefersMostSpecific(t *testing.T) {
	ev := baseEvent()
	if typ, val := entityFrom(ev); typ != "user" || val != "u-1" {
		t.Errorf("entityFrom = (%s, %s), want (user, u-1)", typ, val)
	}

	ev.UserID = nil
	if typ, val := entityFrom(ev); typ != "ip" || val != "10.0.0.5" {
		t.Errorf("entityFrom without a user = (%s, %s), want (ip, 10.0.0.5)", typ, val)
	}

	ev.IPSource = nil
	if typ, val := entityFrom(ev); typ != "source" || val != "gateway-1" {
		t.Errorf("entityFrom with neither = (%s, %s), want (source, gateway-1)", typ, val)
	}
}

func TestThresholdIsSharedBetweenReplicas(t *testing.T) {
	// The reason the counter left process memory: with two replicas, a rule
	// needing three hits used to need three hits *on the same replica*. An
	// attacker load-balanced across them never tripped it.
	// Setting REDIS_TEST_URL makes a missing Redis a failure rather than a
	// skip, so this test cannot pass in CI by never running.
	url, required := os.LookupEnv("REDIS_TEST_URL")
	if !required {
		url = "redis://localhost:6379/9"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := cache.NewFromURL(ctx, url, zerolog.Nop())
	if err != nil || client == nil {
		t.Fatalf("REDIS_TEST_URL %q will not parse: %v", url, err)
	}
	defer client.Close()
	if err := client.Ping(ctx); err != nil {
		if required {
			t.Fatalf("REDIS_TEST_URL is set to %s but nothing answers there: %v", url, err)
		}
		t.Skipf("no Redis at %s: %v", url, err)
	}

	name := fmt.Sprintf("test:siem:%d", time.Now().UnixNano())
	replicaA := &RuleEngine{thresholds: cache.NewWindow(client, name, zerolog.Nop()), logger: zerolog.Nop()}
	replicaB := &RuleEngine{thresholds: cache.NewWindow(client, name, zerolog.Nop()), logger: zerolog.Nop()}

	rule := thresholdRule(3, 60, "user_name")
	ev := baseEvent()

	if replicaA.thresholdMet(context.Background(), rule, ev, rule.Conditions.Threshold) {
		t.Fatal("fired on the first hit")
	}
	if replicaB.thresholdMet(context.Background(), rule, ev, rule.Conditions.Threshold) {
		t.Fatal("fired on the second hit")
	}
	if !replicaA.thresholdMet(context.Background(), rule, ev, rule.Conditions.Threshold) {
		t.Error("three hits spread over two replicas did not reach a threshold of three")
	}
}
