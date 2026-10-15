package repository

import (
	"strings"
	"testing"
	"time"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/siem/internal/model"
	"github.com/google/uuid"
)

// What the query builder has to get right.
//
// Two of these properties fail silently if they break, which is why they are
// pinned here rather than left to an integration test: a tenant predicate
// that goes missing returns *more* rows, not an error, and a value
// concatenated into the statement works perfectly until someone types a
// quote.

func filterFor(t *testing.T) model.EventFilter {
	t.Helper()
	return model.EventFilter{TenantID: uuid.MustParse("11111111-1111-1111-1111-111111111111")}
}

func TestEveryQueryIsScopedToOneTenant(t *testing.T) {
	q, err := buildQuery(filterFor(t))
	if err != nil {
		t.Fatalf("buildQuery = %v", err)
	}
	if !strings.Contains(q.where, "tenant_id = {tenant:String}") {
		t.Fatalf("WHERE has no tenant predicate: %s\n"+
			"a search without one reads every tenant's events", q.where)
	}
	// First, so no later clause can be written before it by accident.
	if !strings.HasPrefix(q.where, "WHERE tenant_id = {tenant:String}") {
		t.Errorf("tenant predicate is not first: %s", q.where)
	}
}

// A repository reached without an authenticated tenant must build no query at
// all. Returning one scoped to the nil UUID would quietly match nothing;
// returning one unscoped would match everything.
func TestAFilterWithNoTenantIsRefused(t *testing.T) {
	if _, err := buildQuery(model.EventFilter{}); err == nil {
		t.Fatal("buildQuery with no tenant = nil error, want a refusal")
	}
}

// The injection test.
//
// Every caller-supplied value must travel as a named parameter. If any of
// these strings appears in the statement text, something concatenated it.
func TestNoCallerValueIsEverWrittenIntoTheStatement(t *testing.T) {
	nasty := "' OR 1=1 --"
	f := filterFor(t)
	f.Text = nasty
	f.Category = nasty
	f.Severity = nasty
	f.Outcome = nasty
	f.SourceType = nasty
	f.Source = nasty
	f.Action = nasty
	f.UserID = nasty
	f.IPSource = nasty
	f.IPDestination = nasty
	f.GeoCountry = nasty
	f.MitreTactic = nasty

	q, err := buildQuery(f)
	if err != nil {
		t.Fatalf("buildQuery = %v", err)
	}
	if strings.Contains(q.where, nasty) {
		t.Fatalf("the caller's text reached the statement:\n%s", q.where)
	}
	// No quote the builder did not write itself. The only ones it writes are
	// in the DateTime64 type annotations, so remove those and nothing should
	// be left: a surviving quote means a caller's value was concatenated.
	bare := strings.ReplaceAll(q.where, "DateTime64(3,'UTC')", "DateTime64")
	for _, fragment := range []string{"OR 1=1", "--", "'"} {
		if strings.Contains(bare, fragment) {
			t.Errorf("statement contains %q, so a value was concatenated:\n%s", fragment, q.where)
		}
	}
	// And the values must actually have been sent, not dropped.
	if len(q.params) < 13 {
		t.Errorf("sent %d parameters, want the tenant, the two bounds and "+
			"each of the twelve filters", len(q.params))
	}
}

// A search with no window named is still a bounded search. Unbounded, it
// reads every event the platform ever ingested.
func TestASearchWithoutAWindowIsStillBounded(t *testing.T) {
	q, err := buildQuery(filterFor(t))
	if err != nil {
		t.Fatalf("buildQuery = %v", err)
	}
	if !strings.Contains(q.where, "timestamp >= {from:") || !strings.Contains(q.where, "timestamp <= {to:") {
		t.Fatalf("WHERE has no time bounds: %s", q.where)
	}
	if span := q.to.Sub(q.from); span != model.DefaultEventWindow {
		t.Errorf("default window = %s, want %s", span, model.DefaultEventWindow)
	}
}

func TestAnExplicitWindowIsKept(t *testing.T) {
	from := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)
	f := filterFor(t)
	f.From, f.To = &from, &to

	q, err := buildQuery(f)
	if err != nil {
		t.Fatalf("buildQuery = %v", err)
	}
	if !q.from.Equal(from) || !q.to.Equal(to) {
		t.Errorf("window = %s..%s, want %s..%s", q.from, q.to, from, to)
	}
}

// A window wider than the cap is refused as bad input, not answered slowly.
// One analyst asking for five years stalls ingestion for everyone.
func TestAWindowWiderThanTheCapIsRefused(t *testing.T) {
	to := time.Now().UTC()
	from := to.Add(-model.MaxEventWindow - time.Hour)
	f := filterFor(t)
	f.From, f.To = &from, &to

	_, err := buildQuery(f)
	if err == nil {
		t.Fatal("buildQuery over the cap = nil error, want a refusal")
	}
	if !apierrors.IsKind(err, apierrors.KindBadInput) {
		t.Errorf("error = %v, want KindBadInput — the caller asked for too "+
			"much, the server is not broken", err)
	}
}

func TestAnInvertedWindowIsRefused(t *testing.T) {
	to := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	from := to.Add(time.Hour)
	f := filterFor(t)
	f.From, f.To = &from, &to

	_, err := buildQuery(f)
	if err == nil {
		t.Fatal("buildQuery with from after to = nil error, want a refusal")
	}
	if !apierrors.IsKind(err, apierrors.KindBadInput) {
		t.Errorf("error = %v, want KindBadInput", err)
	}
}

// Each optional filter must reach the WHERE clause. A filter silently
// dropped returns too many rows and looks like it worked.
func TestEachFilterReachesTheClause(t *testing.T) {
	risk := float32(7)
	cbs := uint8(1)
	swift := uint8(0)

	f := filterFor(t)
	f.Text = "siphon"
	f.Category = "Transaction"
	f.Severity = "HIGH"
	f.Outcome = "failure"
	f.SourceType = "cbs"
	f.Source = "core-01"
	f.Action = "transaction.flagged"
	f.UserID = "007-554120"
	f.IPSource = "10.0.0.1"
	f.IPDestination = "10.0.0.2"
	f.GeoCountry = "MA"
	f.MitreTactic = "TA0040"
	f.MinRiskScore = &risk
	f.MinThreatScore = &risk
	f.CBSImpact = &cbs
	f.SWIFTImpact = &swift
	f.IOCOnly = true

	q, err := buildQuery(f)
	if err != nil {
		t.Fatalf("buildQuery = %v", err)
	}
	for _, want := range []string{
		"positionCaseInsensitive(raw_event, {text:String}) > 0",
		"category = {category:String}",
		"severity = {sev", "outcome = {outcome:String}",
		"source_type = {stype:String}", "source = {source:String}",
		"action = {action:String}", "user_id = {uid:String}",
		"ip_source = {ipsrc:String}", "ip_destination = {ipdst:String}",
		"geo_country = {geo:String}", "mitre_tactic = {tactic:String}",
		"risk_score >= {minrisk:Float32}", "threat_score >= {minthreat:Float32}",
		"cbs_impact = {cbs:UInt8}", "swift_impact = {swift:UInt8}",
		"notEmpty(ioc_matched)",
	} {
		// severity's parameter name is abbreviated; match on the column.
		col := strings.SplitN(want, " ", 2)[0]
		if !strings.Contains(q.where, col) {
			t.Errorf("filter on %s never reached the clause:\n%s", col, q.where)
		}
	}
}

// Asking for zero is a question; not asking is not. A plain uint8 would make
// "events that do not touch the core banking system" unaskable.
func TestAskingForZeroIsNotTheSameAsNotAsking(t *testing.T) {
	zero := uint8(0)
	f := filterFor(t)
	f.CBSImpact = &zero

	q, err := buildQuery(f)
	if err != nil {
		t.Fatalf("buildQuery = %v", err)
	}
	if !strings.Contains(q.where, "cbs_impact = {cbs:UInt8}") {
		t.Errorf("cbs_impact=0 was dropped:\n%s", q.where)
	}

	none, err := buildQuery(filterFor(t))
	if err != nil {
		t.Fatalf("buildQuery = %v", err)
	}
	if strings.Contains(none.where, "cbs_impact") {
		t.Errorf("cbs_impact filtered when nobody asked:\n%s", none.where)
	}
}

func TestThePageIsClamped(t *testing.T) {
	cases := []struct {
		name                  string
		limit, offset         int
		wantLimit, wantOffset int
	}{
		{"unset takes the default", 0, 0, model.DefaultEventLimit, 0},
		{"a sane page is kept", 100, 200, 100, 200},
		{"the cap holds", 1_000_000, 0, model.MaxEventLimit, 0},
		{"a negative limit is not a page", -5, 0, model.DefaultEventLimit, 0},
		{"a negative offset is zero", 10, -5, 10, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := filterFor(t)
			f.Limit, f.Offset = c.limit, c.offset
			limit, offset := page(f)
			if limit != c.wantLimit || offset != c.wantOffset {
				t.Errorf("page = (%d, %d), want (%d, %d)", limit, offset, c.wantLimit, c.wantOffset)
			}
		})
	}
}
