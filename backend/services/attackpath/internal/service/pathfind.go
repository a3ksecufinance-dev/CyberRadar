package service

import (
	"context"

	"github.com/cyberradar/platform/services/attackpath/internal/model"
	"github.com/google/uuid"
)

// PathFinder enumerates the routes from one entry point to a scenario's
// targets. It is what replaced loading the tenant's whole graph into the
// process on every run.
//
// Measured on a tenant of twenty thousand nodes and a hundred and thirty
// thousand edges, that load cost 462 ms from PostgreSQL and 5.8 s from Neo4j
// before the walk had started — per scenario, every time. The enumeration is
// bounded work; the load was not.
//
// A finder returns at most budget paths and reports whether more exist. Which
// ones it keeps when there are more is deliberately unspecified: a truncated
// answer makes no claim to completeness, and each store orders its own
// enumeration. Both stores order by hop count first, so a truncated run keeps
// the shortest routes — the ones the scoring ranks highest.
type PathFinder interface {
	FindPaths(ctx context.Context, scenario *model.AttackScenario,
		entryID uuid.UUID, budget int) ([]model.DiscoveredPath, bool, error)
}

// GraphPathFinder enumerates paths in a graph already in memory.
//
// It is the reference implementation the two stores are checked against, and
// what lets the traversal be tested on a graph built in a test with no database
// at all.
type GraphPathFinder struct{ graph *model.Graph }

// NewGraphPathFinder wraps an in-memory graph as a PathFinder.
func NewGraphPathFinder(g *model.Graph) *GraphPathFinder { return &GraphPathFinder{graph: g} }

func (f *GraphPathFinder) FindPaths(_ context.Context, scenario *model.AttackScenario,
	entryID uuid.UUID, budget int) ([]model.DiscoveredPath, bool, error) {

	targets := make(map[uuid.UUID]bool, len(scenario.TargetNodeIDs))
	for _, id := range scenario.TargetNodeIDs {
		targets[id] = true
	}
	found, truncated := walk(f.graph, scenario, entryID, targets, budget)
	return found, truncated, nil
}
