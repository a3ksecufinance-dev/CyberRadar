package model

import "time"

// RemediationPolicy is how long this institution gives itself to fix something.
//
// It replaces a map of four numbers in this package. Those numbers were never a
// fact about a vulnerability: they are what an institution committed to — to a
// regulator, to a card scheme, or to its own board — and that commitment is not
// the platform's to decide.
//
// The base is the severity. The ceilings only ever tighten it, which is how a
// policy reads out loud: "critical within three days, or twenty-four hours if it
// is being exploited".
type RemediationPolicy struct {
	Code    string `json:"code"`
	Version int    `json:"version"`
	// Chosen is false when the tenant has made no decision and is running on the
	// platform's standard deadlines.
	Chosen bool `json:"chosen"`

	CriticalDays int `json:"critical_days"`
	HighDays     int `json:"high_days"`
	MediumDays   int `json:"medium_days"`
	LowDays      int `json:"low_days"`

	// A nil ceiling means that condition does not tighten anything.
	ExploitedDays *int `json:"exploited_days,omitempty"`
	DMZDays       *int `json:"dmz_days,omitempty"`
	CBSDays       *int `json:"cbs_days,omitempty"`
	SWIFTDays     *int `json:"swift_days,omitempty"`
	PCIDays       *int `json:"pci_days,omitempty"`

	MinimumDays int `json:"minimum_days"`
}

// FindingContext is what the platform knows about a finding that can tighten its
// deadline.
//
// Every field here is populated by something. There is deliberately no
// "internet facing" flag: the asset inventory has no such column, and a ceiling
// keyed on a field nothing writes is a commitment that never applies — the
// policy would read stricter than the platform behaves.
type FindingContext struct {
	// Exploited is the vulnerability's own is_exploited, not a guess from CVSS.
	Exploited bool
	// DMZ is the asset's environment. The nearest thing to exposure the
	// inventory actually records.
	DMZ bool

	CBS   bool
	SWIFT bool
	PCI   bool
}

// DefaultRemediationPolicy is what the platform applied before any of this was
// configurable, and what it falls back to when no policy can be read.
//
// It carries no ceilings on purpose: adopting it changes not one deadline.
// Shipping the advice switched on would have made a configuration change move
// numbers behind the customer's back, which is the opposite of the point.
func DefaultRemediationPolicy() *RemediationPolicy {
	return &RemediationPolicy{
		Code:         "banking_default",
		Version:      1,
		CriticalDays: 3,
		HighDays:     7,
		MediumDays:   30,
		LowDays:      90,
		MinimumDays:  1,
	}
}

// BaseDays is the deadline the severity alone asks for.
//
// An unrecognised severity gets the slowest base rather than a hard-coded 90:
// the old code's fallback was the same number as low by coincidence, and a
// policy that stretches its low deadline should stretch the unknown with it.
func (p *RemediationPolicy) BaseDays(severity string) int {
	switch severity {
	case SeverityCritical:
		return p.CriticalDays
	case SeverityHigh:
		return p.HighDays
	case SeverityMedium:
		return p.MediumDays
	case SeverityLow:
		return p.LowDays
	default:
		return p.LowDays
	}
}

// DueDays is how long this finding has, under this policy.
//
// The ceilings are applied as a minimum and never as a multiplier: a condition
// can bring a deadline forward, never push it out. A policy that could extend a
// deadline because an asset happens to be in a regulated scope would be an
// institution arguing itself more time for the assets it is most accountable for.
func (p *RemediationPolicy) DueDays(severity string, c FindingContext) int {
	days := p.BaseDays(severity)

	tighten := func(ceiling *int, applies bool) {
		if applies && ceiling != nil && *ceiling < days {
			days = *ceiling
		}
	}
	tighten(p.ExploitedDays, c.Exploited)
	tighten(p.DMZDays, c.DMZ)
	tighten(p.CBSDays, c.CBS)
	tighten(p.SWIFTDays, c.SWIFT)
	tighten(p.PCIDays, c.PCI)

	// The floor. A deadline of zero days is not a commitment, it is a breach
	// recorded at the moment the finding is.
	if days < p.MinimumDays {
		days = p.MinimumDays
	}
	if days < 1 {
		days = 1
	}
	return days
}

// DueAt is the deadline itself, counted from when the finding was first seen
// rather than from now — a re-scan must not push an open finding's deadline out.
func (p *RemediationPolicy) DueAt(firstSeen time.Time, severity string, c FindingContext) time.Time {
	return firstSeen.AddDate(0, 0, p.DueDays(severity, c))
}

// Applied names the conditions that actually moved this deadline, so a screen
// can say why a finding is due on Thursday instead of in a month.
func (p *RemediationPolicy) Applied(severity string, c FindingContext) []string {
	base := p.BaseDays(severity)
	var reasons []string
	note := func(name string, ceiling *int, applies bool) {
		if applies && ceiling != nil && *ceiling < base {
			reasons = append(reasons, name)
		}
	}
	note("exploited", p.ExploitedDays, c.Exploited)
	note("dmz", p.DMZDays, c.DMZ)
	note("cbs", p.CBSDays, c.CBS)
	note("swift", p.SWIFTDays, c.SWIFT)
	note("pci", p.PCIDays, c.PCI)
	return reasons
}
