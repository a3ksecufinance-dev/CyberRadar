package service

import (
	"context"

	"github.com/cyberradar/platform/services/attackpath/internal/model"
	"github.com/google/uuid"
)

// GraphStore is the graph the analyzer reads and the record it writes.
//
// The analyzer depends on this rather than on *repository.GraphRepository so
// that where the graph lives is a deployment choice. Today it is PostgreSQL; a
// Neo4j implementation satisfies the same interface and the traversal does not
// change. It is also what lets the traversal be tested on a graph built in a
// test rather than in a database.
type GraphStore interface {
	// LoadGraph returns every node and active edge for a tenant.
	//
	// Nodes come back too, not just edges: the traversal needs each node's
	// type to honour a scenario's include_types, and its criticality and flags
	// to score a path against what it actually reached.
	LoadGraph(ctx context.Context, tenantID uuid.UUID) (*model.Graph, error)

	SetScenarioStatus(ctx context.Context, scenarioID uuid.UUID, status string) error
	SavePaths(ctx context.Context, paths []*model.AttackPath) error
	UpdateScenarioResult(ctx context.Context, scenarioID uuid.UUID, pathCount int, shortestPath, criticalPath *int, riskScore float64, durationMS int) error
}
