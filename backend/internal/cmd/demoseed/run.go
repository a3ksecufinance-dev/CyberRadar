package main

import (
	"context"
	"fmt"
)

// run creates the estate in dependency order.
//
// The order is not a preference. A finding needs its asset and its
// vulnerability, an incident names both assets and indicators, the attack
// graph stands on the asset identifiers, and the knowledge graph links the
// indicators to the assets. Each step therefore consumes what the ones above
// it recorded.
//
// The first two steps are the foundation and stop the run if they fail —
// everything else refers to them. From there on a failure costs its own
// section and no more, because a demonstration estate missing one domain is
// still worth looking at.
func (s *seeder) run(ctx context.Context) error {
	if err := s.seedAssets(ctx); err != nil {
		return err
	}
	if err := s.seedVulnerabilities(ctx); err != nil {
		return err
	}

	for _, stage := range []struct {
		name string
		fn   func(context.Context) error
	}{
		{"asset dependencies", s.seedAssetLinks},
		{"threat intelligence", s.seedThreatIntel},
		{"detection rules", s.seedRules},
		{"events", s.seedEvents},
		{"incidents", s.seedIncidents},
		{"attack graph", s.seedAttackGraph},
		{"compliance", s.seedCompliance},
		{"knowledge graph", s.seedKnowledgeGraph},
	} {
		if err := stage.fn(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.softFail(stage.name, err)
		}
	}

	fmt.Printf("\n%d objects written, %d left as they were\n", s.written, s.reused)
	return nil
}
