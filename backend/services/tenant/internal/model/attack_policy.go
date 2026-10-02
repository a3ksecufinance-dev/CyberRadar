package model

import (
	"time"

	"github.com/google/uuid"
)

// AttackPolicy is what one institution considers hard for an attacker.
//
// It sits beside the risk appetite, the remediation deadlines and the
// behavioural thresholds, for the same reason: it is tenant configuration, not
// a domain object of any one analysis. The attack-path service applies the
// weightings through the tenant_attack_policy view and never decides them.
//
// These were Go constants. None of them are facts about attackers — they are a
// stance, and they decide which path an analyst is shown first, which is to say
// what gets fixed first.
type AttackPolicy struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    *uuid.UUID `json:"tenant_id,omitempty"`
	Code        string     `json:"code"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`

	BasedOn string `json:"based_on,omitempty"`

	Version       int        `json:"version"`
	EffectiveFrom time.Time  `json:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty"`

	Weights AttackWeights `json:"weights"`

	Notes     string     `json:"notes,omitempty"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// AttackWeights is the stance itself.
//
// Cost is friction: higher means the attacker is less likely to take that step,
// so the path ranks lower. Getting that direction wrong is the single easiest
// mistake to make here, which is why it is said in the field comments rather
// than left to the names.
type AttackWeights struct {
	// What a step costs before anything is known about it.
	BaseCost float64 `json:"base_cost" validate:"min=0.1,max=10"`
	// Added when the technique is of medium or high complexity.
	ComplexityMedium float64 `json:"complexity_medium" validate:"min=0,max=10"`
	ComplexityHigh   float64 `json:"complexity_high"   validate:"min=0,max=10"`
	// Added when the step needs some, or administrative, privilege.
	PrivilegeLow  float64 `json:"privilege_low"  validate:"min=0,max=10"`
	PrivilegeHigh float64 `json:"privilege_high" validate:"min=0,max=10"`

	// How much each extra hop multiplies a path's threat by. 1.0 is the
	// assume-breach stance: once inside, distance is not a control. Above 1
	// would make a longer path more threatening than a shorter one of the same
	// cost, which is the bug this formula exists to avoid.
	HopDecay float64 `json:"hop_decay" validate:"gt=0,max=1"`

	// What reaching a target is worth. The ceiling is normally below 10 so the
	// critical-system bonus has somewhere to go.
	ImpactCeiling float64 `json:"impact_ceiling" validate:"min=1,max=10"`
	// What to assume when the inventory records nothing about the target. High
	// treats an unknown as dangerous: safer, noisier.
	UnknownTargetImpact float64 `json:"unknown_target_impact" validate:"min=0,max=10"`
	CriticalSystemBonus float64 `json:"critical_system_bonus" validate:"min=0,max=10"`

	// Added as boost × ln(1 + paths). Zero means the number of ways in does not
	// move the scenario's risk at all.
	ManyPathsBoost float64 `json:"many_paths_boost" validate:"min=0,max=5"`
}

// SetAttackPolicyRequest adopts a standard stance, with or without changes.
type SetAttackPolicyRequest struct {
	BasedOn string `json:"based_on" validate:"omitempty,max=40"`

	Name  string `json:"name"  validate:"omitempty,max=200"`
	Notes string `json:"notes" validate:"omitempty,max=4000"`

	Weights *PartialAttackWeights `json:"weights"`
}

// PartialAttackWeights is AttackWeights with every value optional, so moving
// one does not mean restating the other nine — and an omitted one cannot be
// silently read as zero.
type PartialAttackWeights struct {
	BaseCost         *float64 `json:"base_cost"         validate:"omitempty,min=0.1,max=10"`
	ComplexityMedium *float64 `json:"complexity_medium" validate:"omitempty,min=0,max=10"`
	ComplexityHigh   *float64 `json:"complexity_high"   validate:"omitempty,min=0,max=10"`
	PrivilegeLow     *float64 `json:"privilege_low"     validate:"omitempty,min=0,max=10"`
	PrivilegeHigh    *float64 `json:"privilege_high"    validate:"omitempty,min=0,max=10"`

	HopDecay *float64 `json:"hop_decay" validate:"omitempty,gt=0,max=1"`

	ImpactCeiling       *float64 `json:"impact_ceiling"        validate:"omitempty,min=1,max=10"`
	UnknownTargetImpact *float64 `json:"unknown_target_impact" validate:"omitempty,min=0,max=10"`
	CriticalSystemBonus *float64 `json:"critical_system_bonus" validate:"omitempty,min=0,max=10"`

	ManyPathsBoost *float64 `json:"many_paths_boost" validate:"omitempty,min=0,max=5"`
}

// Apply writes the weights the caller named onto a copy of base.
func (p *PartialAttackWeights) Apply(base AttackWeights) AttackWeights {
	if p == nil {
		return base
	}
	set := func(dst *float64, src *float64) {
		if src != nil {
			*dst = *src
		}
	}
	set(&base.BaseCost, p.BaseCost)
	set(&base.ComplexityMedium, p.ComplexityMedium)
	set(&base.ComplexityHigh, p.ComplexityHigh)
	set(&base.PrivilegeLow, p.PrivilegeLow)
	set(&base.PrivilegeHigh, p.PrivilegeHigh)
	set(&base.HopDecay, p.HopDecay)
	set(&base.ImpactCeiling, p.ImpactCeiling)
	set(&base.UnknownTargetImpact, p.UnknownTargetImpact)
	set(&base.CriticalSystemBonus, p.CriticalSystemBonus)
	set(&base.ManyPathsBoost, p.ManyPathsBoost)
	return base
}
