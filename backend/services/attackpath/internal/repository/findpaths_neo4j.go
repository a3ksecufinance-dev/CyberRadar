package repository

import (
	"context"
	"fmt"

	"github.com/cyberradar/platform/services/attackpath/internal/model"
	"github.com/google/uuid"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// maxHopsCeiling is the largest max_hops a scenario may ask for. It matches the
// validator on CreateScenarioRequest, and is checked again here because the
// value is interpolated into the Cypher pattern: Neo4j will not take a
// variable-length bound as a parameter, so this is the one place a number from
// a request reaches the query text, and it does so only after being proved to
// be a small integer.
const maxHopsCeiling = 20

// FindPaths enumerates the routes from one entry point to a scenario's targets,
// in Neo4j.
//
// It restates the in-memory walk's semantics, and deliberately uses no plugin:
// APOC would prune repeated nodes during expansion rather than after, but
// requiring a plugin download at container start is not something an air-gapped
// deployment can do, and the measurements do not justify the dependency.
//
// The node-uniqueness test is the plain-Cypher one. Neo4j's variable-length
// patterns exclude a repeated *relationship*, not a repeated node, so without
// it a route could pass through the same host twice and be recorded as two
// separate attacks.
func (s *Neo4jGraphStore) FindPaths(ctx context.Context, scenario *model.AttackScenario,
	entryID uuid.UUID, budget int) ([]model.DiscoveredPath, bool, error) {

	if budget <= 0 {
		return nil, true, nil
	}
	maxHops := scenario.MaxHops
	if maxHops <= 0 {
		maxHops = 10
	}
	if maxHops > maxHopsCeiling {
		maxHops = maxHopsCeiling
	}
	includeTypes := scenario.IncludeTypes
	if includeTypes == nil {
		includeTypes = []string{}
	}

	// One more row than the budget, so hitting the cap can be told from
	// filling it exactly.
	res, err := s.query(ctx, fmt.Sprintf(`
		MATCH (entry:AttackNode {tenant_id: $tenant, id: $entry})
		MATCH path = (entry)-[:ATTACKS*1..%d]->(target:AttackNode {tenant_id: $tenant})
		WHERE target.id IN $targets
		  AND all(r IN relationships(path) WHERE r.tenant_id = $tenant AND r.is_active)
		  AND all(n IN nodes(path) WHERE n.tenant_id = $tenant)
		  AND all(n IN nodes(path)[1..-1]
		          WHERE n.id IN $targets OR size($types) = 0 OR n.node_type IN $types)
		  AND none(i IN range(0, size(nodes(path)) - 2)
		           WHERE nodes(path)[i] IN nodes(path)[i + 1..])
		RETURN [n IN nodes(path) | n.id] AS node_ids,
		       [r IN relationships(path) | r.id] AS edge_ids,
		       length(path) AS depth
		ORDER BY depth, node_ids
		LIMIT $limit`, maxHops),
		map[string]any{
			"tenant":  scenario.TenantID.String(),
			"entry":   entryID.String(),
			"targets": uuidStrings(scenario.TargetNodeIDs),
			"types":   includeTypes,
			"limit":   int64(budget + 1),
		})
	if err != nil {
		return nil, false, fmt.Errorf("find paths: %w", err)
	}

	var nodeSeqs, edgeSeqs [][]uuid.UUID
	for _, rec := range res.Records {
		nodeIDs, err := recUUIDs(rec, "node_ids")
		if err != nil {
			return nil, false, fmt.Errorf("find paths: %w", err)
		}
		edgeIDs, err := recUUIDs(rec, "edge_ids")
		if err != nil {
			return nil, false, fmt.Errorf("find paths: %w", err)
		}
		nodeSeqs = append(nodeSeqs, nodeIDs)
		edgeSeqs = append(edgeSeqs, edgeIDs)
	}

	truncated := len(nodeSeqs) > budget
	if truncated {
		nodeSeqs, edgeSeqs = nodeSeqs[:budget], edgeSeqs[:budget]
	}
	if len(nodeSeqs) == 0 {
		return nil, false, nil
	}

	// The nodes and edges themselves come from PostgreSQL, which is the source
	// of truth for what they hold. Reading them from Neo4j would mean a path
	// discovered against the mirror was also scored against it, so a drift in a
	// criticality or a CVE would change an analyst's ranking with nothing to
	// say why. Reconciliation reports such a drift; scoring must not depend on
	// it.
	found, err := s.GraphRepository.hydratePaths(ctx, scenario.TenantID, nodeSeqs, edgeSeqs)
	if err != nil {
		return nil, false, err
	}
	return found, truncated, nil
}

func recUUIDs(rec *neo4j.Record, key string) ([]uuid.UUID, error) {
	raw, _ := recValue(rec, key).([]any)
	out := make([]uuid.UUID, 0, len(raw))
	for _, v := range raw {
		str, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%s holds %T, want a string", key, v)
		}
		id, err := uuid.Parse(str)
		if err != nil {
			return nil, fmt.Errorf("%s %q: %w", key, str, err)
		}
		out = append(out, id)
	}
	return out, nil
}

// uuidStrings renders identifiers the way Neo4j stores them. It has no UUID
// type, so every identifier travels as text.
func uuidStrings(ids []uuid.UUID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	return out
}
