package model

import (
	"time"

	"github.com/google/uuid"
)

// BehaviourPolicy is what one institution considers anomalous behaviour.
//
// It sits beside RiskProfile and RemediationPolicy for the same reason: it is
// tenant configuration, not a domain object of any one analysis. The behaviour
// engine reads the thresholds in force through the tenant_behaviour_policy view
// and never writes them.
//
// These were Go constants with a comment above them. Eighty events a minute,
// five failures in five, three distinct hours before a baseline is trusted —
// none of them are facts about human behaviour. A bank running three shifts
// across four time zones does not have the same answer as a regional one whose
// branches close at five.
type BehaviourPolicy struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    *uuid.UUID `json:"tenant_id,omitempty"`
	Code        string     `json:"code"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`

	BasedOn string `json:"based_on,omitempty"`

	Version       int        `json:"version"`
	EffectiveFrom time.Time  `json:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty"`

	Thresholds Thresholds `json:"thresholds"`
	Signals    Signals    `json:"signals"`

	Notes     string     `json:"notes,omitempty"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// Thresholds are the counters and the baseline readiness.
type Thresholds struct {
	// How much history makes a baseline worth detecting against. An entity seen
	// three times is not a pattern, and detecting "unusual" against one
	// observation is how a platform greets a new joiner with four alerts.
	MinHoursForBaseline     int `json:"min_hours_for_baseline"     validate:"min=1,max=24"`
	MinCountriesForBaseline int `json:"min_countries_for_baseline" validate:"min=1,max=50"`

	VelocityThreshold int `json:"velocity_threshold" validate:"min=1,max=100000"`
	VelocityWindowS   int `json:"velocity_window_s"   validate:"min=10,max=3600"`

	BruteForceThreshold int `json:"brute_force_threshold" validate:"min=1,max=10000"`
	BruteForceWindowS   int `json:"brute_force_window_s"   validate:"min=10,max=86400"`
}

// Signal is what one anomaly type is worth: whether it fires, how loud, and what
// it adds to the entity's score.
type Signal struct {
	Enabled  bool    `json:"enabled"`
	Severity string  `json:"severity" validate:"oneof=LOW MEDIUM HIGH CRITICAL"`
	Score    float64 `json:"score"    validate:"min=0,max=10"`
}

// Signals are the eight the engine can raise.
//
// Named fields rather than a map, so a type the engine knows and the policy has
// never heard of cannot exist: adding one to the engine fails to compile here
// until somebody decides what it is worth.
type Signals struct {
	OffHours         Signal `json:"off_hours"`
	NewCountry       Signal `json:"new_country"`
	NewIPPrefix      Signal `json:"new_ip_prefix"`
	Velocity         Signal `json:"velocity"`
	BruteForce       Signal `json:"brute_force"`
	PrivEscalation   Signal `json:"priv_escalation"`
	LateralMovement  Signal `json:"lateral_movement"`
	DataExfiltration Signal `json:"data_exfiltration"`
}

// SetBehaviourPolicyRequest adopts a standard policy, with or without changes.
type SetBehaviourPolicyRequest struct {
	BasedOn string `json:"based_on" validate:"omitempty,max=40"`

	Name  string `json:"name"  validate:"omitempty,max=200"`
	Notes string `json:"notes" validate:"omitempty,max=4000"`

	Thresholds *PartialThresholds `json:"thresholds"`
	Signals    *PartialSignals    `json:"signals"`
}

// PartialThresholds is Thresholds with every field optional, so adjusting one
// number does not mean restating the other five — and an omitted one cannot be
// silently read as zero.
type PartialThresholds struct {
	MinHoursForBaseline     *int `json:"min_hours_for_baseline"     validate:"omitempty,min=1,max=24"`
	MinCountriesForBaseline *int `json:"min_countries_for_baseline" validate:"omitempty,min=1,max=50"`

	VelocityThreshold *int `json:"velocity_threshold" validate:"omitempty,min=1,max=100000"`
	VelocityWindowS   *int `json:"velocity_window_s"   validate:"omitempty,min=10,max=3600"`

	BruteForceThreshold *int `json:"brute_force_threshold" validate:"omitempty,min=1,max=10000"`
	BruteForceWindowS   *int `json:"brute_force_window_s"   validate:"omitempty,min=10,max=86400"`
}

// PartialSignal is Signal with every field optional.
type PartialSignal struct {
	Enabled  *bool    `json:"enabled"`
	Severity *string  `json:"severity" validate:"omitempty,oneof=LOW MEDIUM HIGH CRITICAL"`
	Score    *float64 `json:"score"    validate:"omitempty,min=0,max=10"`
}

// PartialSignals is Signals with every entry optional.
type PartialSignals struct {
	OffHours         *PartialSignal `json:"off_hours"`
	NewCountry       *PartialSignal `json:"new_country"`
	NewIPPrefix      *PartialSignal `json:"new_ip_prefix"`
	Velocity         *PartialSignal `json:"velocity"`
	BruteForce       *PartialSignal `json:"brute_force"`
	PrivEscalation   *PartialSignal `json:"priv_escalation"`
	LateralMovement  *PartialSignal `json:"lateral_movement"`
	DataExfiltration *PartialSignal `json:"data_exfiltration"`
}

// Apply writes the thresholds the caller named onto a copy of base.
func (p *PartialThresholds) Apply(base Thresholds) Thresholds {
	if p == nil {
		return base
	}
	set := func(dst *int, src *int) {
		if src != nil {
			*dst = *src
		}
	}
	set(&base.MinHoursForBaseline, p.MinHoursForBaseline)
	set(&base.MinCountriesForBaseline, p.MinCountriesForBaseline)
	set(&base.VelocityThreshold, p.VelocityThreshold)
	set(&base.VelocityWindowS, p.VelocityWindowS)
	set(&base.BruteForceThreshold, p.BruteForceThreshold)
	set(&base.BruteForceWindowS, p.BruteForceWindowS)
	return base
}

// Apply writes the signals the caller named onto a copy of base.
func (p *PartialSignals) Apply(base Signals) Signals {
	if p == nil {
		return base
	}
	sig := func(dst *Signal, src *PartialSignal) {
		if src == nil {
			return
		}
		if src.Enabled != nil {
			dst.Enabled = *src.Enabled
		}
		if src.Severity != nil {
			dst.Severity = *src.Severity
		}
		if src.Score != nil {
			dst.Score = *src.Score
		}
	}
	sig(&base.OffHours, p.OffHours)
	sig(&base.NewCountry, p.NewCountry)
	sig(&base.NewIPPrefix, p.NewIPPrefix)
	sig(&base.Velocity, p.Velocity)
	sig(&base.BruteForce, p.BruteForce)
	sig(&base.PrivEscalation, p.PrivEscalation)
	sig(&base.LateralMovement, p.LateralMovement)
	sig(&base.DataExfiltration, p.DataExfiltration)
	return base
}
