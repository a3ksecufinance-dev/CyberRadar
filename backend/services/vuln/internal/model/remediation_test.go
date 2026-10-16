package model

import (
	"testing"
	"time"
)

func days(n int) *int { return &n }

// Adopting the default policy must change nothing. Making a judgement
// configurable has to be invisible on the day it ships, or the first thing a
// customer notices is that their deadlines moved without anyone deciding it.
func TestTheDefaultPolicyIsExactlyWhatTheMapWas(t *testing.T) {
	p := DefaultRemediationPolicy()
	// The four numbers that were in model.SLADays, and the fallback that was a
	// hard-coded 90 beside them.
	for _, c := range []struct {
		severity string
		want     int
	}{
		{SeverityCritical, 3},
		{SeverityHigh, 7},
		{SeverityMedium, 30},
		{SeverityLow, 90},
		{"something nobody scored", 90},
	} {
		if got := p.DueDays(c.severity, FindingContext{}); got != c.want {
			t.Errorf("%s is %d days, was %d before this was configurable", c.severity, got, c.want)
		}
	}

	// And with no ceilings, no context can move it. A default that quietly
	// started applying advice would be the same failure the other way round.
	full := FindingContext{Exploited: true, DMZ: true, CBS: true, SWIFT: true, PCI: true}
	if got := p.DueDays(SeverityMedium, full); got != 30 {
		t.Errorf("the default policy tightened a medium to %d days on context alone", got)
	}
}

// A ceiling may bring a deadline forward. It may never push one out — an
// institution arguing itself more time for the assets it is most accountable
// for is the one outcome this must not permit.
func TestACeilingOnlyEverTightens(t *testing.T) {
	p := &RemediationPolicy{
		CriticalDays: 3, HighDays: 7, MediumDays: 30, LowDays: 90,
		PCIDays:     days(14),
		MinimumDays: 1,
	}
	inScope := FindingContext{PCI: true}

	// Medium is slower than the ceiling, so the ceiling applies.
	if got := p.DueDays(SeverityMedium, inScope); got != 14 {
		t.Errorf("a medium in card scope is %d days, want 14", got)
	}
	// Critical is already tighter than the ceiling, so it stays where it is.
	if got := p.DueDays(SeverityCritical, inScope); got != 3 {
		t.Errorf("a critical in card scope was relaxed to %d days by a 14-day ceiling", got)
	}
}

// Several conditions at once take the tightest, not the last one looked at and
// not their sum.
func TestTheTightestConditionWins(t *testing.T) {
	p := &RemediationPolicy{
		CriticalDays: 3, HighDays: 7, MediumDays: 30, LowDays: 90,
		ExploitedDays: days(1), DMZDays: days(7), PCIDays: days(14),
		MinimumDays: 1,
	}
	everything := FindingContext{Exploited: true, DMZ: true, PCI: true}
	if got := p.DueDays(SeverityLow, everything); got != 1 {
		t.Errorf("a low that is exploited, in the DMZ and in card scope is %d days, want 1", got)
	}

	// And the reasons name only what actually moved it, so a screen can say why.
	applied := p.Applied(SeverityLow, everything)
	if len(applied) != 3 {
		t.Errorf("three conditions moved the deadline, %d reported: %v", len(applied), applied)
	}
	// A critical is already inside the DMZ and card ceilings; only the exploited
	// one is doing any work, and claiming otherwise would be an explanation that
	// does not explain.
	if applied := p.Applied(SeverityCritical, everything); len(applied) != 1 || applied[0] != "exploited" {
		t.Errorf("a critical reports %v as what tightened it; only being exploited did", applied)
	}
}

// A deadline of zero days is not a commitment. It is a breach recorded at the
// moment the finding is, and it would make the breach counter meaningless.
func TestTheFloorHolds(t *testing.T) {
	p := &RemediationPolicy{
		CriticalDays: 3, HighDays: 7, MediumDays: 30, LowDays: 90,
		ExploitedDays: days(1),
		MinimumDays:   2,
	}
	if got := p.DueDays(SeverityCritical, FindingContext{Exploited: true}); got != 2 {
		t.Errorf("the floor gave %d days, want 2", got)
	}

	// Even a policy whose own floor is nonsense cannot produce a deadline in the
	// past: the schema forbids it, and the code does not rely on the schema.
	broken := &RemediationPolicy{CriticalDays: 0, HighDays: 0, MediumDays: 0, LowDays: 0, MinimumDays: 0}
	if got := broken.DueDays(SeverityCritical, FindingContext{}); got < 1 {
		t.Errorf("a policy of zeroes produced a deadline of %d days", got)
	}
}

// A condition with no ceiling set is a condition the institution chose not to
// treat specially. It must not fall through to some other policy's number.
func TestAConditionWithNoCeilingDoesNothing(t *testing.T) {
	p := &RemediationPolicy{
		CriticalDays: 3, HighDays: 7, MediumDays: 30, LowDays: 90,
		ExploitedDays: days(1),
		MinimumDays:   1,
	}
	// SWIFT has no ceiling here, so a SWIFT-connected asset is on the base.
	if got := p.DueDays(SeverityMedium, FindingContext{SWIFT: true}); got != 30 {
		t.Errorf("a condition with no ceiling moved a medium to %d days", got)
	}
	if applied := p.Applied(SeverityMedium, FindingContext{SWIFT: true}); len(applied) != 0 {
		t.Errorf("a condition with no ceiling is reported as having applied: %v", applied)
	}
}

// The deadline runs from when the finding was first seen. Counting from now
// would hand an open finding a fresh month every time a scan re-reported it —
// a breach that can never be reached.
func TestTheClockStartsWhenTheFindingWasFirstSeen(t *testing.T) {
	p := DefaultRemediationPolicy()
	first := timeAt(2026, 1, 10)
	due := p.DueAt(first, SeverityHigh, FindingContext{})
	if want := timeAt(2026, 1, 17); !due.Equal(want) {
		t.Errorf("due %s, want %s", due.Format("2006-01-02"), want.Format("2006-01-02"))
	}
}

func timeAt(y int, m int, d int) time.Time {
	return time.Date(y, time.Month(m), d, 0, 0, 0, 0, time.UTC)
}
