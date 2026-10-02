package enricher

import (
	"testing"

	"github.com/cyberradar/platform/internal/pkg/event"
	"github.com/cyberradar/platform/internal/pkg/iocindex"
	"github.com/google/uuid"
)

func lowEvent() *event.NormalizedEvent {
	src := "198.51.100.23"
	return &event.NormalizedEvent{
		TenantID: uuid.New().String(),
		Action:   "network_connection",
		Category: event.CategoryNetwork,
		Severity: event.SeverityLow,
		Outcome:  event.OutcomeSuccess,
		IPSource: &src,
	}
}

func hit(severity string, e iocindex.Entry) iocindex.Hit {
	e.Type = iocindex.TypeIP
	e.Severity = severity
	return iocindex.Hit{
		Candidate: iocindex.Candidate{Type: iocindex.TypeIP, Value: "198.51.100.23", Field: "ip_destination"},
		Entry:     e,
	}
}

// Before this, the enricher returned an empty list with a comment saying it
// was a stub, so an event that reached a known command-and-control server
// scored exactly as low as the connector had labelled it.
func TestAMatchedIndicatorRaisesTheScore(t *testing.T) {
	ev := lowEvent()
	before := (&ThreatEnricher{}).Enrich(ev, nil)
	if before.ThreatScore > 2.0 {
		t.Fatalf("a LOW event scores %.1f before any match", before.ThreatScore)
	}

	after := (&ThreatEnricher{}).Enrich(ev, []iocindex.Hit{hit("CRITICAL", iocindex.Entry{ID: uuid.New()})})
	if after.ThreatScore < 9.0 {
		t.Errorf("threat_score = %.1f after a CRITICAL match, want at least 9", after.ThreatScore)
	}
	if after.RiskScore < 9.0 {
		t.Errorf("risk_score = %.1f after a CRITICAL match, want at least 9", after.RiskScore)
	}
	if len(after.IOCMatched) != 1 {
		t.Fatalf("ioc_matched = %v, want one entry", after.IOCMatched)
	}
	if after.IOCMatched[0] != "ip:198.51.100.23@ip_destination" {
		t.Errorf("ioc_matched[0] = %q, want the type, value and field", after.IOCMatched[0])
	}
}

// The score rises to a floor rather than accumulating. Adding would let two
// weak matches outweigh one certain one, and would make the threshold a rule
// compares against depend on how many fields happened to match.
func TestSeveralMatchesDoNotAccumulate(t *testing.T) {
	one := (&ThreatEnricher{}).Enrich(lowEvent(), []iocindex.Hit{
		hit("MEDIUM", iocindex.Entry{ID: uuid.New()}),
	})
	three := (&ThreatEnricher{}).Enrich(lowEvent(), []iocindex.Hit{
		hit("MEDIUM", iocindex.Entry{ID: uuid.New()}),
		hit("MEDIUM", iocindex.Entry{ID: uuid.New()}),
		hit("MEDIUM", iocindex.Entry{ID: uuid.New()}),
	})
	if three.ThreatScore != one.ThreatScore {
		t.Errorf("one MEDIUM match scores %.1f, three score %.1f", one.ThreatScore, three.ThreatScore)
	}
	if len(three.IOCMatched) != 3 {
		t.Errorf("ioc_matched holds %d entries, want all three recorded", len(three.IOCMatched))
	}
}

// The severest match sets the floor, whatever order the hits arrive in.
func TestTheSeverestMatchSetsTheFloor(t *testing.T) {
	result := (&ThreatEnricher{}).Enrich(lowEvent(), []iocindex.Hit{
		hit("LOW", iocindex.Entry{ID: uuid.New()}),
		hit("CRITICAL", iocindex.Entry{ID: uuid.New()}),
		hit("MEDIUM", iocindex.Entry{ID: uuid.New()}),
	})
	if result.ThreatScore < 9.0 {
		t.Errorf("threat_score = %.1f, want the CRITICAL floor", result.ThreatScore)
	}
}

// An event that already scores high is not lowered by matching a mild
// indicator: the floor is a floor.
func TestAMildMatchDoesNotLowerAHighScore(t *testing.T) {
	ev := lowEvent()
	ev.Severity = event.SeverityCritical
	plain := (&ThreatEnricher{}).Enrich(ev, nil)
	matched := (&ThreatEnricher{}).Enrich(ev, []iocindex.Hit{hit("LOW", iocindex.Entry{ID: uuid.New()})})
	if matched.ThreatScore < plain.ThreatScore {
		t.Errorf("score fell from %.1f to %.1f on a LOW match", plain.ThreatScore, matched.ThreatScore)
	}
}

// The feed knows the technique; the keyword heuristic guesses it. When both
// have an opinion, the feed wins.
func TestTheFeedsAttributionBeatsTheKeywordGuess(t *testing.T) {
	ev := lowEvent()
	ev.Action = "user_login"

	guessed := (&ThreatEnricher{}).Enrich(ev, nil)
	if guessed.MitreTechnique == "" {
		t.Fatal("the heuristic produced no technique, so there is nothing to override")
	}

	fromFeed := (&ThreatEnricher{}).Enrich(ev, []iocindex.Hit{
		hit("HIGH", iocindex.Entry{ID: uuid.New(), MitreTactic: "TA0011", MitreTechnique: "T1071.001"}),
	})
	if fromFeed.MitreTechnique != "T1071.001" || fromFeed.MitreTactic != "TA0011" {
		t.Errorf("technique %q / tactic %q, want the feed's",
			fromFeed.MitreTechnique, fromFeed.MitreTactic)
	}
}

// Empty, never nil: a consumer reading this field should not have to tell "no
// matches" from "this was never populated".
func TestNoMatchesIsAnEmptyListNotNil(t *testing.T) {
	result := (&ThreatEnricher{}).Enrich(lowEvent(), nil)
	if result.IOCMatched == nil {
		t.Error("ioc_matched is nil with no matches")
	}
	if len(result.IOCMatched) != 0 {
		t.Errorf("ioc_matched = %v with no matches", result.IOCMatched)
	}
}
