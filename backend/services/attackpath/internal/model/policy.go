package model

import "math"

// AttackPolicy is what one institution considers hard for an attacker.
//
// These were Go constants: an edge costs 1.0, plus 1.5 if the technique is
// hard, plus 1.0 if it needs administrative rights; each extra hop takes 15%
// off a path's threat; reaching an unknown target is worth 4.5.
//
// None of them are facts about attackers. They are a stance. A team that has
// watched a red team cross the estate in an afternoon does not weigh "high
// complexity" the way one reasoning from CVSS does. And the numbers decide
// which path an analyst is shown first, which is to say what gets fixed first.
//
// The methods live here rather than in the analyzer so the formula is readable
// in one place, beside the values it reads — which is the whole argument for
// a fixed vocabulary with free weights over an expression language.
type AttackPolicy struct {
	Code    string `json:"code"`
	Version int    `json:"version"`
	// Chosen is false when the tenant is being scored on the platform's stance.
	Chosen bool `json:"chosen"`

	// What a step costs an attacker. Higher is more effort, so the path ranks
	// lower — cost is friction, not danger.
	BaseCost         float64 `json:"base_cost"`
	ComplexityMedium float64 `json:"complexity_medium"`
	ComplexityHigh   float64 `json:"complexity_high"`
	PrivilegeLow     float64 `json:"privilege_low"`
	PrivilegeHigh    float64 `json:"privilege_high"`

	// HopDecay is how much each extra hop multiplies a path's threat by. 1.0 is
	// the assume-breach stance: once inside, distance is not a control.
	HopDecay float64 `json:"hop_decay"`

	ImpactCeiling       float64 `json:"impact_ceiling"`
	UnknownTargetImpact float64 `json:"unknown_target_impact"`
	CriticalSystemBonus float64 `json:"critical_system_bonus"`

	ManyPathsBoost float64 `json:"many_paths_boost"`
}

// DefaultAttackPolicy is exactly what the analyzer applied before any of this
// was configurable, and what it falls back to when no policy can be read.
//
// Scoring on slightly wrong weightings beats refusing to score: a scenario run
// that failed because a configuration row was missing would be a worse outage
// than one ranked under the standard stance.
func DefaultAttackPolicy() *AttackPolicy {
	return &AttackPolicy{
		Code:                "balanced",
		Version:             1,
		BaseCost:            1.0,
		ComplexityMedium:    0.5,
		ComplexityHigh:      1.5,
		PrivilegeLow:        0.3,
		PrivilegeHigh:       1.0,
		HopDecay:            0.85,
		ImpactCeiling:       9.0,
		UnknownTargetImpact: 4.5,
		CriticalSystemBonus: 1.0,
		ManyPathsBoost:      0.3,
	}
}

// EdgeCost is what this step costs an attacker under this policy.
//
// Computed from the edge's own complexity and privilege requirement rather than
// read from the stored weight column: the weight is written once, when the edge
// is created, and a policy that only applied to edges discovered afterwards
// would re-rank half a graph and leave the other half alone.
func (p *AttackPolicy) EdgeCost(e *AttackEdge) float64 {
	// An edge the vocabulary says nothing about keeps the weight it was given.
	// Every edge the platform creates carries both fields, so this is reached
	// only by one imported with a cost and no account of where it came from —
	// and flattening those to the base would quietly erase whatever the import
	// knew that this vocabulary cannot say.
	if e.AttackComplexity == "" && e.PrivilegesRequired == "" && e.Weight > 0 {
		return e.Weight
	}

	cost := p.BaseCost
	switch e.AttackComplexity {
	case "MEDIUM":
		cost += p.ComplexityMedium
	case "HIGH":
		cost += p.ComplexityHigh
	}
	switch e.PrivilegesRequired {
	case "LOW":
		cost += p.PrivilegeLow
	case "HIGH":
		cost += p.PrivilegeHigh
	}
	return cost
}

// PathCost is what the whole route costs.
func (p *AttackPolicy) PathCost(edges []*AttackEdge) float64 {
	var total float64
	for _, e := range edges {
		total += p.EdgeCost(e)
	}
	return total
}

// PathScore is how threatening a path is: higher means easier for an attacker.
//
// Both extra hops and heavier edges make an attack harder, so both lower it. An
// earlier formula multiplied by hop count, so a five-hop path scored above a
// one-hop path of the same cost — it ranked the hardest attacks as the most
// dangerous, which is the wrong way round for a list worked from the top.
func (p *AttackPolicy) PathScore(totalCost float64, hopCount int) float64 {
	if hopCount < 1 {
		hopCount = 1
	}
	avgCost := totalCost / float64(hopCount)
	score := 10.0 / (1.0 + avgCost) * math.Pow(p.HopDecay, float64(hopCount-1))
	return math.Min(10.0, math.Max(0, score))
}

// Impact is what reaching this target would cost, from the target itself.
//
// Every path used to record a flat 7.0 regardless of what it reached, so impact
// carried no information and any ranking that used it was arbitrary.
func (p *AttackPolicy) Impact(target *AttackNode) float64 {
	impact := 0.0
	switch {
	case target.Criticality > 0:
		// Criticality is 1–4 in the asset model, mapped onto the ceiling.
		impact = math.Min(p.ImpactCeiling, float64(target.Criticality)/4.0*p.ImpactCeiling)
	case target.RiskScore > 0:
		impact = math.Min(p.ImpactCeiling, target.RiskScore)
	default:
		// Nothing recorded about the target. What to assume is a stance: high
		// treats an unknown as dangerous, which is safer and noisier.
		impact = p.UnknownTargetImpact
	}
	if target.IsCriticalSystem {
		impact += p.CriticalSystemBonus
	}
	return math.Min(10.0, impact)
}

// ScenarioRisk is the scenario's own score: its most threatening route, plus
// something for there being several ways in.
func (p *AttackPolicy) ScenarioRisk(scores []float64) float64 {
	if len(scores) == 0 {
		return 0
	}
	maxScore := 0.0
	for _, s := range scores {
		if s > maxScore {
			maxScore = s
		}
	}
	// More ways in is more risk, with diminishing return: the tenth route
	// matters less than the second.
	boost := math.Log1p(float64(len(scores))) * p.ManyPathsBoost
	return math.Min(10.0, maxScore+boost)
}
