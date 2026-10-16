package model

import (
	"math"
	"testing"
)

func edge(complexity, priv string) *AttackEdge {
	return &AttackEdge{AttackComplexity: complexity, PrivilegesRequired: priv}
}

// Making a judgement configurable has to be invisible on the day it ships. If
// the default moved one number, the first thing a customer would notice is that
// their attack paths re-ranked because the vendor refactored.
func TestTheDefaultStanceIsExactlyWhatTheConstantsWere(t *testing.T) {
	p := DefaultAttackPolicy()

	// computeEdgeWeight: 1.0 base, +0.5/+1.5 complexity, +0.3/+1.0 privilege.
	for _, c := range []struct {
		complexity, priv string
		want             float64
	}{
		{"LOW", "NONE", 1.0},
		{"MEDIUM", "LOW", 1.8},
		{"HIGH", "HIGH", 3.5},
		{"", "", 1.0},
	} {
		if got := p.EdgeCost(edge(c.complexity, c.priv)); math.Abs(got-c.want) > 1e-9 {
			t.Errorf("an edge %s/%s costs %v, was %v before this was configurable",
				c.complexity, c.priv, got, c.want)
		}
	}

	if p.HopDecay != 0.85 {
		t.Errorf("hop decay is %v, was 0.85", p.HopDecay)
	}
	// impactOf: criticality 4 mapped onto a ceiling of 9, plus 1 for a critical
	// system; an unrecorded target assumed at 4.5.
	if got := p.Impact(&AttackNode{Criticality: 4}); got != 9.0 {
		t.Errorf("a criticality-4 target is %v, was 9.0", got)
	}
	if got := p.Impact(&AttackNode{Criticality: 4, IsCriticalSystem: true}); got != 10.0 {
		t.Errorf("a critical system at criticality 4 is %v, was 10.0", got)
	}
	if got := p.Impact(&AttackNode{}); got != 4.5 {
		t.Errorf("a target the inventory knows nothing about is %v, was 4.5", got)
	}
}

// Cost is friction, not danger: a step an institution considers harder must
// make the path that uses it rank lower, not higher.
func TestHarderStepsRankAPathLower(t *testing.T) {
	p := DefaultAttackPolicy()
	easy := p.PathScore(p.PathCost([]*AttackEdge{edge("LOW", "NONE"), edge("LOW", "NONE")}), 2)
	hard := p.PathScore(p.PathCost([]*AttackEdge{edge("HIGH", "HIGH"), edge("HIGH", "HIGH")}), 2)
	if !(easy > hard) {
		t.Errorf("two easy hops score %v and two hard ones %v; difficulty is not reducing the score", easy, hard)
	}
}

// The whole point of making this configurable: a team that has watched a red
// team cross the estate should be able to say that distance does not protect
// them, and see the ranking change.
func TestAssumingBreachRanksALongPathHigher(t *testing.T) {
	standard := DefaultAttackPolicy()

	breach := DefaultAttackPolicy()
	breach.HopDecay = 1.0 // once inside, distance is not a control
	breach.ComplexityHigh = 0.6
	breach.PrivilegeHigh = 0.4

	route := []*AttackEdge{edge("HIGH", "HIGH"), edge("HIGH", "HIGH"), edge("HIGH", "HIGH")}

	under := func(p *AttackPolicy) float64 { return p.PathScore(p.PathCost(route), len(route)) }
	if !(under(breach) > under(standard)) {
		t.Errorf("a three-hop route of hard steps scores %v under assume-breach and %v under the standard stance; the stance is not reaching the ranking",
			under(breach), under(standard))
	}
}

// A decay of 1 means hop count stops counting against a path at all — the
// assume-breach position stated exactly.
func TestADecayOfOneMakesLengthFree(t *testing.T) {
	p := DefaultAttackPolicy()
	p.HopDecay = 1.0
	one := p.PathScore(2.0, 1)
	four := p.PathScore(8.0, 4) // same cost per hop
	if math.Abs(one-four) > 1e-9 {
		t.Errorf("with no decay a one-hop route scores %v and a four-hop route of the same cost per hop %v", one, four)
	}
}

// What to assume about a target nobody recorded is a stance, and it has to be
// able to go both ways: treat the unknown as dangerous, or concentrate on what
// is known to matter.
func TestTheUnknownTargetIsAStance(t *testing.T) {
	cautious := DefaultAttackPolicy()
	cautious.UnknownTargetImpact = 7.0
	focused := DefaultAttackPolicy()
	focused.UnknownTargetImpact = 2.0

	unknown := &AttackNode{}
	if !(cautious.Impact(unknown) > focused.Impact(unknown)) {
		t.Error("the stance on an unrecorded target does not change what it is worth")
	}
	// And it must not touch a target the inventory does describe.
	known := &AttackNode{Criticality: 3}
	if cautious.Impact(known) != focused.Impact(known) {
		t.Error("the unknown-target stance moved a target the inventory describes")
	}
}

// More ways in is more risk, with diminishing return — and an institution that
// disagrees must be able to switch it off entirely.
func TestTheManyPathsBoostCanBeSwitchedOff(t *testing.T) {
	p := DefaultAttackPolicy()
	many := []float64{6.0, 5.0, 4.0, 3.0, 2.0}
	one := []float64{6.0}
	if !(p.ScenarioRisk(many) > p.ScenarioRisk(one)) {
		t.Error("five ways in scores no higher than one under the standard stance")
	}

	p.ManyPathsBoost = 0
	if p.ScenarioRisk(many) != p.ScenarioRisk(one) {
		t.Errorf("with the boost at zero, five ways in still score %v against %v for one",
			p.ScenarioRisk(many), p.ScenarioRisk(one))
	}
	if p.ScenarioRisk(many) != 6.0 {
		t.Errorf("with no boost the scenario should be its best route, got %v", p.ScenarioRisk(many))
	}
}

// An edge the vocabulary says nothing about keeps the weight it was given.
// Flattening those to the base would quietly erase whatever an import knew.
func TestAnEdgeWithNoVocabularyKeepsItsWeight(t *testing.T) {
	p := DefaultAttackPolicy()
	imported := &AttackEdge{Weight: 7.5}
	if got := p.EdgeCost(imported); got != 7.5 {
		t.Errorf("an imported edge of weight 7.5 costs %v", got)
	}
	// But one the vocabulary does describe is recomputed, whatever the column
	// says — otherwise a stance would apply only to edges discovered after it
	// was adopted, re-ranking half a graph and leaving the other half alone.
	described := &AttackEdge{AttackComplexity: "LOW", PrivilegesRequired: "NONE", Weight: 7.5}
	if got := p.EdgeCost(described); got != 1.0 {
		t.Errorf("a described edge used its stored weight (%v) instead of the stance", got)
	}
}
