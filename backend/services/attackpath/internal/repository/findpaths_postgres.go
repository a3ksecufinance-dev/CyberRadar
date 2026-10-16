package repository

import (
	"context"
	"fmt"

	"github.com/cyberradar/platform/services/attackpath/internal/model"
	"github.com/google/uuid"
)

// FindPaths enumerates the routes from one entry point to a scenario's targets,
// in the database.
//
// This is what replaced LoadGraph on the scenario path. Loading the tenant's
// whole graph cost 462 ms before the walk began on a twenty-thousand-node
// tenant — every run, whatever the scenario asked for. Here nothing is
// transferred but the routes themselves, and the LIMIT stops the enumeration
// rather than trimming its result.
//
// The semantics are the in-memory walk's, restated in SQL:
//
//   - at most max_hops edges;
//   - no node twice on one path, so a cycle ends that branch rather than
//     looping — this is per path, not global, because the question is which
//     routes exist and two routes may legitimately share a node;
//   - only active edges;
//   - an intermediate node must satisfy include_types, a target need not;
//   - a target is recorded and then walked through, because a route may pass
//     one high-value system on its way to another.
//
// Rows come back shortest first, so a run that hits its budget keeps the
// shortest routes — the ones the scoring ranks highest — rather than whichever
// ones a depth-first walk happened to reach.
func (r *GraphRepository) FindPaths(ctx context.Context, scenario *model.AttackScenario,
	entryID uuid.UUID, budget int) ([]model.DiscoveredPath, bool, error) {

	if budget <= 0 {
		return nil, true, nil
	}
	maxHops := scenario.MaxHops
	if maxHops <= 0 {
		maxHops = 10
	}
	includeTypes := scenario.IncludeTypes
	if includeTypes == nil {
		includeTypes = []string{}
	}

	// One more row than the budget, so hitting the cap can be told from
	// filling it exactly.
	rows, err := r.db.Query(ctx, `
		WITH RECURSIVE walk(node_id, node_ids, edge_ids, depth, is_target) AS (
			SELECT e.target_id,
			       ARRAY[e.source_id, e.target_id]::uuid[],
			       ARRAY[e.id]::uuid[],
			       1,
			       e.target_id = ANY($3)
			FROM attack_edges e
			JOIN attack_nodes n ON n.id = e.target_id AND n.tenant_id = $1
			WHERE e.tenant_id = $1 AND e.source_id = $2 AND e.is_active
			  AND (e.target_id = ANY($3)
			       OR cardinality($5::text[]) = 0
			       OR n.node_type = ANY($5))
			UNION ALL
			SELECT e.target_id,
			       w.node_ids || e.target_id,
			       w.edge_ids || e.id,
			       w.depth + 1,
			       e.target_id = ANY($3)
			FROM walk w
			JOIN attack_edges e ON e.source_id = w.node_id AND e.tenant_id = $1 AND e.is_active
			JOIN attack_nodes n ON n.id = e.target_id AND n.tenant_id = $1
			WHERE w.depth < $4
			  AND NOT (e.target_id = ANY(w.node_ids))
			  AND (e.target_id = ANY($3)
			       OR cardinality($5::text[]) = 0
			       OR n.node_type = ANY($5))
		)
		SELECT node_ids, edge_ids
		FROM walk
		WHERE is_target
		ORDER BY depth, node_ids
		LIMIT $6`,
		scenario.TenantID, entryID, scenario.TargetNodeIDs, maxHops, includeTypes, budget+1)
	if err != nil {
		return nil, false, fmt.Errorf("find paths: %w", err)
	}
	defer rows.Close()

	var nodeSeqs, edgeSeqs [][]uuid.UUID
	for rows.Next() {
		var nodeIDs, edgeIDs []uuid.UUID
		if err := rows.Scan(&nodeIDs, &edgeIDs); err != nil {
			return nil, false, fmt.Errorf("scan path: %w", err)
		}
		nodeSeqs = append(nodeSeqs, nodeIDs)
		edgeSeqs = append(edgeSeqs, edgeIDs)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("find paths: %w", err)
	}

	truncated := len(nodeSeqs) > budget
	if truncated {
		nodeSeqs, edgeSeqs = nodeSeqs[:budget], edgeSeqs[:budget]
	}
	if len(nodeSeqs) == 0 {
		return nil, false, nil
	}

	found, err := r.hydratePaths(ctx, scenario.TenantID, nodeSeqs, edgeSeqs)
	if err != nil {
		return nil, false, err
	}
	return found, truncated, nil
}

// hydratePaths turns identifier sequences into the nodes and edges a path is
// scored from, fetching each distinct one once rather than per path.
func (r *GraphRepository) hydratePaths(ctx context.Context, tenantID uuid.UUID,
	nodeSeqs, edgeSeqs [][]uuid.UUID) ([]model.DiscoveredPath, error) {

	nodeIDs, edgeIDs := distinctIDs(nodeSeqs), distinctIDs(edgeSeqs)

	nodes, err := r.GetNodesByIDs(ctx, tenantID, nodeIDs)
	if err != nil {
		return nil, fmt.Errorf("find paths: load nodes: %w", err)
	}
	edges, err := r.getEdgesByIDs(ctx, tenantID, edgeIDs)
	if err != nil {
		return nil, fmt.Errorf("find paths: load edges: %w", err)
	}

	found := make([]model.DiscoveredPath, 0, len(nodeSeqs))
	for i := range nodeSeqs {
		path, err := assemblePath(nodeSeqs[i], edgeSeqs[i], nodes, edges)
		if err != nil {
			return nil, err
		}
		found = append(found, path)
	}
	return found, nil
}

func (r *GraphRepository) getEdgesByIDs(ctx context.Context, tenantID uuid.UUID,
	ids []uuid.UUID) (map[uuid.UUID]*model.AttackEdge, error) {

	out := make(map[uuid.UUID]*model.AttackEdge, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.db.Query(ctx,
		`SELECT id, tenant_id, source_id, target_id, edge_type,
		        attack_complexity, privileges_required, vuln_id, cve_id,
		        mitre_technique, weight, is_active, evidence_source,
		        properties, created_at, updated_at
		 FROM attack_edges WHERE tenant_id = $1 AND id = ANY($2)`, tenantID, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		e, err := scanEdge(rows)
		if err != nil {
			return nil, err
		}
		out[e.ID] = e
	}
	return out, rows.Err()
}

// distinctIDs flattens sequences into the set of identifiers they mention.
func distinctIDs(seqs [][]uuid.UUID) []uuid.UUID {
	seen := map[uuid.UUID]bool{}
	var out []uuid.UUID
	for _, seq := range seqs {
		for _, id := range seq {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}

// assemblePath builds one path, refusing rather than silently shortening it if
// something it names is missing: a path with a hole in it would be scored as if
// the hole were not there.
func assemblePath(nodeIDs, edgeIDs []uuid.UUID,
	nodes map[uuid.UUID]*model.AttackNode, edges map[uuid.UUID]*model.AttackEdge) (model.DiscoveredPath, error) {

	path := model.DiscoveredPath{
		Nodes: make([]*model.AttackNode, 0, len(nodeIDs)),
		Edges: make([]*model.AttackEdge, 0, len(edgeIDs)),
	}
	for _, id := range nodeIDs {
		n, ok := nodes[id]
		if !ok {
			return path, fmt.Errorf("find paths: node %s is on a path but not in the graph", id)
		}
		path.Nodes = append(path.Nodes, n)
	}
	for _, id := range edgeIDs {
		e, ok := edges[id]
		if !ok {
			return path, fmt.Errorf("find paths: edge %s is on a path but not in the graph", id)
		}
		path.Edges = append(path.Edges, e)
	}
	return path, nil
}
