package service

import (
	"context"

	"github.com/cyberradar/platform/services/attackpath/internal/model"
	"github.com/google/uuid"
)

// GraphStore is the graph the analyzer reads and the record it writes.
//
// The analyzer depends on this rather than on *repository.GraphRepository so
// that where the graph lives is a deployment choice. PostgreSQL and Neo4j both
// satisfy it, and GraphPathFinder satisfies the traversal half over a graph
// built in a test, with no database at all.
type GraphStore interface {
	// PathFinder is the traversal itself: the store enumerates the routes from
	// an entry point to the scenario's targets and returns them, rather than
	// handing over the graph for the analyzer to walk.
	PathFinder

	SetScenarioStatus(ctx context.Context, scenarioID uuid.UUID, status string) error
	SavePaths(ctx context.Context, paths []*model.AttackPath) error
	UpdateScenarioResult(ctx context.Context, scenarioID uuid.UUID, outcome model.ScenarioOutcome) error
}
