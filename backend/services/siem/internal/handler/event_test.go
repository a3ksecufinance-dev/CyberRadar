package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/siem/internal/model"
)

// Turning a query string into a filter.
//
// Everything here arrives as text an analyst typed. The point of these cases
// is that a typo comes back as a 400 saying what to fix, not as a 500 saying
// nothing — and that the shorthand an analyst actually uses works.

func filterFromQuery(t *testing.T, rawQuery string) (model.EventFilter, error) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/siem/events?"+rawQuery, nil)
	return eventFilterFrom(r)
}

func TestAMalformedDateIsBadInputNotAnInternalError(t *testing.T) {
	for _, q := range []string{
		"from=hier",
		"from=2026-03-02",          // a date is not an RFC3339 instant
		"to=02/03/2026",            // and neither is this
		"from=2026-03-02T11:30:00", // no zone
	} {
		t.Run(q, func(t *testing.T) {
			_, err := filterFromQuery(t, q)
			if err == nil {
				t.Fatalf("%q was accepted, want a refusal", q)
			}
			if !apierrors.IsKind(err, apierrors.KindBadInput) {
				t.Errorf("%q gave %v, want KindBadInput — a 500 tells the "+
					"analyst nothing about their own typo", q, err)
			}
		})
	}
}

func TestAWellFormedWindowIsRead(t *testing.T) {
	f, err := filterFromQuery(t, "from=2026-03-01T00:00:00Z&to=2026-03-02T00:00:00Z")
	if err != nil {
		t.Fatalf("eventFilterFrom = %v", err)
	}
	if f.From == nil || !f.From.Equal(time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("from = %v", f.From)
	}
	if f.To == nil || !f.To.Equal(time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("to = %v", f.To)
	}
}

// window=6h is what an analyst types. It must produce the same filter as the
// two timestamps they would otherwise compute by hand.
func TestTheWindowShorthandSetsFrom(t *testing.T) {
	f, err := filterFromQuery(t, "window=6h&to=2026-03-02T12:00:00Z")
	if err != nil {
		t.Fatalf("eventFilterFrom = %v", err)
	}
	want := time.Date(2026, 3, 2, 6, 0, 0, 0, time.UTC)
	if f.From == nil || !f.From.Equal(want) {
		t.Errorf("from = %v, want %v", f.From, want)
	}
}

// An explicit from wins: the shorthand is a convenience, not an override.
func TestAnExplicitFromBeatsTheShorthand(t *testing.T) {
	f, err := filterFromQuery(t,
		"window=6h&from=2026-03-01T00:00:00Z&to=2026-03-02T12:00:00Z")
	if err != nil {
		t.Fatalf("eventFilterFrom = %v", err)
	}
	want := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	if f.From == nil || !f.From.Equal(want) {
		t.Errorf("from = %v, want the explicit %v", f.From, want)
	}
}

func TestAMalformedWindowIsBadInput(t *testing.T) {
	for _, q := range []string{"window=six-hours", "window=0s", "window=-2h"} {
		t.Run(q, func(t *testing.T) {
			_, err := filterFromQuery(t, q)
			if err == nil {
				t.Fatalf("%q was accepted, want a refusal", q)
			}
			if !apierrors.IsKind(err, apierrors.KindBadInput) {
				t.Errorf("%q gave %v, want KindBadInput", q, err)
			}
		})
	}
}

func TestMalformedNumbersAreBadInput(t *testing.T) {
	for _, q := range []string{
		"limit=beaucoup", "offset=-1", "limit=-1",
		"min_risk_score=haut", "min_threat_score=x",
		"cbs_impact=2", "swift_impact=oui",
	} {
		t.Run(q, func(t *testing.T) {
			_, err := filterFromQuery(t, q)
			if err == nil {
				t.Fatalf("%q was accepted, want a refusal", q)
			}
			if !apierrors.IsKind(err, apierrors.KindBadInput) {
				t.Errorf("%q gave %v, want KindBadInput", q, err)
			}
		})
	}
}

func TestTheFlagsAcceptBothSpellings(t *testing.T) {
	cases := map[string]uint8{"cbs_impact=1": 1, "cbs_impact=true": 1, "cbs_impact=0": 0, "cbs_impact=false": 0}
	for q, want := range cases {
		t.Run(q, func(t *testing.T) {
			f, err := filterFromQuery(t, q)
			if err != nil {
				t.Fatalf("eventFilterFrom = %v", err)
			}
			if f.CBSImpact == nil || *f.CBSImpact != want {
				t.Errorf("cbs_impact = %v, want %d", f.CBSImpact, want)
			}
		})
	}
	f, err := filterFromQuery(t, "")
	if err != nil {
		t.Fatalf("eventFilterFrom = %v", err)
	}
	if f.CBSImpact != nil {
		t.Errorf("cbs_impact = %v with nothing asked, want nil", f.CBSImpact)
	}
}

// No query parameter may name a tenant. The handler sets it from the token,
// and a filter built from the query must leave it empty so that a caller who
// writes ?tenant_id=… reads their own events and nobody else's.
func TestTheQueryStringCannotNameATenant(t *testing.T) {
	f, err := filterFromQuery(t,
		"tenant_id=22222222-2222-2222-2222-222222222222&tenant=22222222-2222-2222-2222-222222222222")
	if err != nil {
		t.Fatalf("eventFilterFrom = %v", err)
	}
	if f.TenantID.String() != "00000000-0000-0000-0000-000000000000" {
		t.Fatalf("the query string set the tenant to %s — it must come from "+
			"the authenticated context and nowhere else", f.TenantID)
	}
}

func TestTheTextAndFiltersAreCarried(t *testing.T) {
	f, err := filterFromQuery(t,
		"q=siphon&category=Transaction&severity=HIGH&user_id=007-554120&ioc=true&limit=100")
	if err != nil {
		t.Fatalf("eventFilterFrom = %v", err)
	}
	if f.Text != "siphon" || f.Category != "Transaction" || f.Severity != "HIGH" {
		t.Errorf("filter = %+v", f)
	}
	if f.UserID != "007-554120" {
		t.Errorf("user_id = %q", f.UserID)
	}
	if !f.IOCOnly {
		t.Error("ioc=true was dropped")
	}
	if f.Limit != 100 {
		t.Errorf("limit = %d, want 100", f.Limit)
	}
}
