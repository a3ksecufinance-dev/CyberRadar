package model

import (
	"time"

	"github.com/google/uuid"
)

// RiskProfile is one institution's risk appetite: what each factor of the asset
// risk score is worth, and where this institution draws the line it calls high
// risk.
//
// It lives under the tenant service because it is tenant configuration, not a
// domain object of any one analysis. The asset service reads the weights in
// force through the tenant_risk_profile view — a published shape rather than a
// shared table — and never writes them.
//
// The fields are fixed and the weights are not. That is the trade: full control
// over the judgement, none over the vocabulary. A customer who could write
// arbitrary expressions would get a number with no breakdown, no comparison
// between tenants, and nothing to show an auditor.
type RiskProfile struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    *uuid.UUID `json:"tenant_id,omitempty"`
	Code        string     `json:"code"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`

	// BasedOn names the standard profile this one started from, so the
	// difference from it is what a tenant shows an auditor.
	BasedOn string `json:"based_on,omitempty"`

	Version       int        `json:"version"`
	EffectiveFrom time.Time  `json:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty"`

	Weights RiskWeights `json:"weights"`

	Notes     string     `json:"notes,omitempty"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// RiskWeights is what a factor is worth. Every value is bounded 0–10 by the
// schema: a weight outside that is not a risk appetite, it is a typo.
type RiskWeights struct {
	CriticalityStep float64 `json:"criticality_step" validate:"min=0,max=10"`
	CriticalityCap  float64 `json:"criticality_cap"  validate:"min=0,max=10"`

	VulnCritical float64 `json:"vuln_critical" validate:"min=0,max=10"`
	VulnHigh     float64 `json:"vuln_high"     validate:"min=0,max=10"`
	VulnMedium   float64 `json:"vuln_medium"   validate:"min=0,max=10"`
	VulnLow      float64 `json:"vuln_low"      validate:"min=0,max=10"`
	VulnCap      float64 `json:"vuln_cap"      validate:"min=0,max=10"`

	CBSConnected   float64 `json:"cbs_connected"   validate:"min=0,max=10"`
	SWIFTConnected float64 `json:"swift_connected" validate:"min=0,max=10"`
	PCIScope       float64 `json:"pci_scope"       validate:"min=0,max=10"`
	ExposureCap    float64 `json:"exposure_cap"    validate:"min=0,max=10"`

	NeverSeen float64 `json:"never_seen" validate:"min=0,max=10"`

	CriticalProduction float64 `json:"critical_production" validate:"min=0,max=10"`
	BankingType        float64 `json:"banking_type"        validate:"min=0,max=10"`
	ContextCap         float64 `json:"context_cap"         validate:"min=0,max=10"`

	TotalCap          float64 `json:"total_cap"           validate:"min=1,max=10"`
	HighRiskThreshold float64 `json:"high_risk_threshold" validate:"min=0,max=10"`
}

// SetRiskProfileRequest adopts a standard profile, with or without changes.
//
// BasedOn alone adopts that profile as it ships. Weights alone adjusts the one
// in force. Both together is the common case: start from the profile that fits
// the institution's reporting, then move the two or three factors it argues
// with.
type SetRiskProfileRequest struct {
	// BasedOn is a standard profile's code. Empty keeps whatever is in force.
	BasedOn string `json:"based_on" validate:"omitempty,max=40"`

	// Name and Notes are how a risk function labels a decision. The notes are
	// what an auditor reads first: "why is this what you chose".
	Name  string `json:"name"  validate:"omitempty,max=200"`
	Notes string `json:"notes" validate:"omitempty,max=4000"`

	// Weights overrides individual factors. A nil pointer leaves the factor at
	// whatever the base profile says, so a caller adjusting one number does not
	// have to restate the other sixteen — and cannot silently zero them by
	// omission, which a plain struct would do.
	Weights *PartialRiskWeights `json:"weights"`
}

// PartialRiskWeights is RiskWeights with every factor optional.
type PartialRiskWeights struct {
	CriticalityStep *float64 `json:"criticality_step" validate:"omitempty,min=0,max=10"`
	CriticalityCap  *float64 `json:"criticality_cap"  validate:"omitempty,min=0,max=10"`

	VulnCritical *float64 `json:"vuln_critical" validate:"omitempty,min=0,max=10"`
	VulnHigh     *float64 `json:"vuln_high"     validate:"omitempty,min=0,max=10"`
	VulnMedium   *float64 `json:"vuln_medium"   validate:"omitempty,min=0,max=10"`
	VulnLow      *float64 `json:"vuln_low"      validate:"omitempty,min=0,max=10"`
	VulnCap      *float64 `json:"vuln_cap"      validate:"omitempty,min=0,max=10"`

	CBSConnected   *float64 `json:"cbs_connected"   validate:"omitempty,min=0,max=10"`
	SWIFTConnected *float64 `json:"swift_connected" validate:"omitempty,min=0,max=10"`
	PCIScope       *float64 `json:"pci_scope"       validate:"omitempty,min=0,max=10"`
	ExposureCap    *float64 `json:"exposure_cap"    validate:"omitempty,min=0,max=10"`

	NeverSeen *float64 `json:"never_seen" validate:"omitempty,min=0,max=10"`

	CriticalProduction *float64 `json:"critical_production" validate:"omitempty,min=0,max=10"`
	BankingType        *float64 `json:"banking_type"        validate:"omitempty,min=0,max=10"`
	ContextCap         *float64 `json:"context_cap"         validate:"omitempty,min=0,max=10"`

	TotalCap          *float64 `json:"total_cap"           validate:"omitempty,min=1,max=10"`
	HighRiskThreshold *float64 `json:"high_risk_threshold" validate:"omitempty,min=0,max=10"`
}

// Apply writes the factors the caller named onto a copy of base.
func (p *PartialRiskWeights) Apply(base RiskWeights) RiskWeights {
	if p == nil {
		return base
	}
	set := func(dst *float64, src *float64) {
		if src != nil {
			*dst = *src
		}
	}
	set(&base.CriticalityStep, p.CriticalityStep)
	set(&base.CriticalityCap, p.CriticalityCap)
	set(&base.VulnCritical, p.VulnCritical)
	set(&base.VulnHigh, p.VulnHigh)
	set(&base.VulnMedium, p.VulnMedium)
	set(&base.VulnLow, p.VulnLow)
	set(&base.VulnCap, p.VulnCap)
	set(&base.CBSConnected, p.CBSConnected)
	set(&base.SWIFTConnected, p.SWIFTConnected)
	set(&base.PCIScope, p.PCIScope)
	set(&base.ExposureCap, p.ExposureCap)
	set(&base.NeverSeen, p.NeverSeen)
	set(&base.CriticalProduction, p.CriticalProduction)
	set(&base.BankingType, p.BankingType)
	set(&base.ContextCap, p.ContextCap)
	set(&base.TotalCap, p.TotalCap)
	set(&base.HighRiskThreshold, p.HighRiskThreshold)
	return base
}
