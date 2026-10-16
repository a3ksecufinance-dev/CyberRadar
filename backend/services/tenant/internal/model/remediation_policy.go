package model

import (
	"time"

	"github.com/google/uuid"
)

// RemediationPolicy is how long one institution gives itself to fix something.
//
// It lives beside RiskProfile and for the same reason: it is tenant
// configuration, not a domain object of any one analysis. The vulnerability
// service reads the deadlines in force through the tenant_remediation_policy
// view — a published shape rather than a shared table — and never writes them.
//
// The deadlines were four numbers in a Go map with a comment calling them
// "banking-grade". They are not a fact about a vulnerability: they are what an
// institution committed to, and that commitment differs between a retail bank
// and a payment processor and changes when a contract is renewed.
type RemediationPolicy struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    *uuid.UUID `json:"tenant_id,omitempty"`
	Code        string     `json:"code"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`

	BasedOn string `json:"based_on,omitempty"`

	Version       int        `json:"version"`
	EffectiveFrom time.Time  `json:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty"`

	Deadlines Deadlines `json:"deadlines"`

	Notes     string     `json:"notes,omitempty"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// Deadlines is the policy itself: a base per severity, and ceilings that can
// only tighten it.
//
// A nil ceiling is a condition the institution chose not to treat specially.
// It is a decision, not an absence, which is why it is a pointer rather than a
// zero that would read as "fix it today".
type Deadlines struct {
	CriticalDays int `json:"critical_days" validate:"min=1,max=3650"`
	HighDays     int `json:"high_days"     validate:"min=1,max=3650"`
	MediumDays   int `json:"medium_days"   validate:"min=1,max=3650"`
	LowDays      int `json:"low_days"      validate:"min=1,max=3650"`

	ExploitedDays *int `json:"exploited_days" validate:"omitempty,min=1,max=3650"`
	DMZDays       *int `json:"dmz_days"       validate:"omitempty,min=1,max=3650"`
	CBSDays       *int `json:"cbs_days"       validate:"omitempty,min=1,max=3650"`
	SWIFTDays     *int `json:"swift_days"     validate:"omitempty,min=1,max=3650"`
	PCIDays       *int `json:"pci_days"       validate:"omitempty,min=1,max=3650"`

	MinimumDays int `json:"minimum_days" validate:"min=1,max=365"`
}

// SetRemediationPolicyRequest adopts a standard policy, with or without changes.
//
// BasedOn alone adopts it as it ships. Deadlines alone adjusts the one in force.
// Both together is the common case: start from the regime that matches the
// institution's reporting, then move the one or two commitments it argues with.
type SetRemediationPolicyRequest struct {
	BasedOn string `json:"based_on" validate:"omitempty,max=40"`

	Name  string `json:"name"  validate:"omitempty,max=200"`
	Notes string `json:"notes" validate:"omitempty,max=4000"`

	Deadlines *PartialDeadlines `json:"deadlines"`
}

// PartialDeadlines is Deadlines with every field optional.
//
// The ceilings need a third state that a plain pointer cannot carry: left alone,
// set to a number, and deliberately cleared. ClearCeilings names the ones to
// remove, because a JSON null and an absent key are the same thing to Go's
// decoder — and a customer who means "stop treating card scope specially" must
// not be read as "say nothing about card scope".
type PartialDeadlines struct {
	CriticalDays *int `json:"critical_days" validate:"omitempty,min=1,max=3650"`
	HighDays     *int `json:"high_days"     validate:"omitempty,min=1,max=3650"`
	MediumDays   *int `json:"medium_days"   validate:"omitempty,min=1,max=3650"`
	LowDays      *int `json:"low_days"      validate:"omitempty,min=1,max=3650"`

	ExploitedDays *int `json:"exploited_days" validate:"omitempty,min=1,max=3650"`
	DMZDays       *int `json:"dmz_days"       validate:"omitempty,min=1,max=3650"`
	CBSDays       *int `json:"cbs_days"       validate:"omitempty,min=1,max=3650"`
	SWIFTDays     *int `json:"swift_days"     validate:"omitempty,min=1,max=3650"`
	PCIDays       *int `json:"pci_days"       validate:"omitempty,min=1,max=3650"`

	MinimumDays *int `json:"minimum_days" validate:"omitempty,min=1,max=365"`

	// ClearCeilings names ceilings to remove: "exploited", "dmz", "cbs",
	// "swift", "pci".
	ClearCeilings []string `json:"clear_ceilings" validate:"omitempty,dive,oneof=exploited dmz cbs swift pci"`
}

// Apply writes the deadlines the caller named onto a copy of base.
func (p *PartialDeadlines) Apply(base Deadlines) Deadlines {
	if p == nil {
		return base
	}
	set := func(dst *int, src *int) {
		if src != nil {
			*dst = *src
		}
	}
	set(&base.CriticalDays, p.CriticalDays)
	set(&base.HighDays, p.HighDays)
	set(&base.MediumDays, p.MediumDays)
	set(&base.LowDays, p.LowDays)
	set(&base.MinimumDays, p.MinimumDays)

	ceiling := func(dst **int, src *int) {
		if src != nil {
			v := *src
			*dst = &v
		}
	}
	ceiling(&base.ExploitedDays, p.ExploitedDays)
	ceiling(&base.DMZDays, p.DMZDays)
	ceiling(&base.CBSDays, p.CBSDays)
	ceiling(&base.SWIFTDays, p.SWIFTDays)
	ceiling(&base.PCIDays, p.PCIDays)

	for _, name := range p.ClearCeilings {
		switch name {
		case "exploited":
			base.ExploitedDays = nil
		case "dmz":
			base.DMZDays = nil
		case "cbs":
			base.CBSDays = nil
		case "swift":
			base.SWIFTDays = nil
		case "pci":
			base.PCIDays = nil
		}
	}
	return base
}

// Ordered reports whether the base deadlines run from tightest to slowest.
//
// The schema enforces it too, but a constraint violation reaches the caller as
// a 500 naming a constraint. A policy where a critical is given longer than a
// low is almost certainly a typo, and saying so is more useful than refusing.
func (d Deadlines) Ordered() bool {
	return d.CriticalDays <= d.HighDays && d.HighDays <= d.MediumDays && d.MediumDays <= d.LowDays
}
