package service

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/cyberradar/platform/services/attackpath/internal/model"
	"github.com/google/uuid"
)

// The traversal now happens in three places: in memory, in PostgreSQL and in
// Neo4j. The in-memory one is the reference the sixteen traversal tests pin
// down; this is what holds the two stores to it.
//
// Three implementations of the same walk is the cost of taking the graph off
// the request path — the alternative was loading the tenant's whole graph into
// the process on every run, which measured 462 ms from PostgreSQL and 5.8 s
// from Neo4j before any walking started. The test is what makes the cost safe.
func TestAllThreeFindersAgree(t *testing.T) {
	pool, pg := parityPostgres(t)
	neo := parityNeo4j(t, pg)
	ctx := context.Background()
	tenantID := parityTenant(t, pool)
	t.Cleanup(func() { _ = neo.DeleteTenantGraph(ctx, tenantID) })

	//  dmz ──► app ──► db(target)
	//   │       ▲        ▲
	//   │       │        │
	//   └────► jump ─────┘          and app ──► dmz, a cycle back to the entry
	//
	// The cycle matters: Neo4j's variable-length patterns exclude a repeated
	// relationship, not a repeated node, so without the uniqueness test it
	// would report routes the other two do not.
	nodes := map[string]*model.AttackNode{}
	for _, spec := range []struct {
		label    string
		nodeType string
		crit     int
	}{
		{"dmz", model.NodeTypeAsset, 2},
		{"app", model.NodeTypeAsset, 3},
		{"jump", model.NodeTypeService, 2},
		{"db", model.NodeTypeAsset, 4},
	} {
		n, err := pg.UpsertNode(ctx, tenantID, &model.CreateNodeRequest{
			RefID: uuid.New(), NodeType: spec.nodeType, Label: spec.label,
			Criticality: spec.crit, RiskScore: float64(spec.crit) * 2,
			IsInternetFacing: spec.label == "dmz",
			IsPrivileged:     spec.label == "jump",
		})
		if err != nil {
			t.Fatalf("UpsertNode %s: %v", spec.label, err)
		}
		nodes[spec.label] = n
	}
	for _, link := range [][3]string{
		{"dmz", "app", "LOW"}, {"app", "db", "MEDIUM"},
		{"dmz", "jump", "MEDIUM"}, {"jump", "db", "HIGH"},
		{"jump", "app", "LOW"}, {"app", "dmz", "HIGH"},
	} {
		if _, err := pg.UpsertEdge(ctx, tenantID, &model.CreateEdgeRequest{
			SourceID: nodes[link[0]].ID, TargetID: nodes[link[1]].ID,
			EdgeType: model.EdgeTypeNetworkAccess, AttackComplexity: link[2],
		}); err != nil {
			t.Fatalf("UpsertEdge %s→%s: %v", link[0], link[1], err)
		}
	}
	if _, _, err := neo.MirrorTenant(ctx, tenantID); err != nil {
		t.Fatalf("MirrorTenant: %v", err)
	}

	graph, err := pg.LoadGraph(ctx, tenantID)
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	finders := map[string]PathFinder{
		"memory":   NewGraphPathFinder(graph),
		"postgres": pg,
		"neo4j":    neo,
	}

	cases := []struct {
		name    string
		maxHops int
		types   []string
		targets []string
	}{
		{"two hops", 2, nil, []string{"db"}},
		{"four hops", 4, nil, []string{"db"}},
		{"one hop reaches nothing", 1, nil, []string{"db"}},
		{"assets only", 4, []string{model.NodeTypeAsset}, []string{"db"}},
		{"two targets", 4, nil, []string{"db", "app"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scenario := &model.AttackScenario{
				ID: uuid.New(), TenantID: tenantID, MaxHops: tc.maxHops,
				IncludeTypes: tc.types,
			}
			for _, label := range tc.targets {
				scenario.TargetNodeIDs = append(scenario.TargetNodeIDs, nodes[label].ID)
			}

			results := map[string][]string{}
			for name, finder := range finders {
				found, truncated, err := finder.FindPaths(ctx, scenario, nodes["dmz"].ID, maxPathsPerScenario)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if truncated {
					t.Fatalf("%s truncated on a graph of four nodes", name)
				}
				results[name] = describePaths(found)
			}

			reference := results["memory"]
			for _, store := range []string{"postgres", "neo4j"} {
				if !sameStringSets(reference, results[store]) {
					t.Errorf("%s disagrees with the in-memory reference:\n  memory: %v\n  %s: %v",
						store, reference, store, results[store])
				}
			}
			t.Logf("%d route(s): %v", len(reference), reference)
		})
	}
}

// A route must never pass through the same node twice: that is not a second
// attack, it is the same attack counted again.
func TestNoFinderWalksThroughANodeTwice(t *testing.T) {
	pool, pg := parityPostgres(t)
	neo := parityNeo4j(t, pg)
	ctx := context.Background()
	tenantID := parityTenant(t, pool)
	t.Cleanup(func() { _ = neo.DeleteTenantGraph(ctx, tenantID) })

	// a ⇄ b, and b ──► c: with relationship uniqueness alone, a→b→a→b→c is a
	// valid path because each edge is used once.
	ids := map[string]uuid.UUID{}
	for _, label := range []string{"a", "b", "c"} {
		n, err := pg.UpsertNode(ctx, tenantID, &model.CreateNodeRequest{
			RefID: uuid.New(), NodeType: model.NodeTypeAsset, Label: label, Criticality: 2,
		})
		if err != nil {
			t.Fatalf("UpsertNode: %v", err)
		}
		ids[label] = n.ID
	}
	for _, link := range [][2]string{{"a", "b"}, {"b", "a"}, {"b", "c"}} {
		if _, err := pg.UpsertEdge(ctx, tenantID, &model.CreateEdgeRequest{
			SourceID: ids[link[0]], TargetID: ids[link[1]], EdgeType: model.EdgeTypeNetworkAccess,
		}); err != nil {
			t.Fatalf("UpsertEdge: %v", err)
		}
	}
	if _, _, err := neo.MirrorTenant(ctx, tenantID); err != nil {
		t.Fatalf("MirrorTenant: %v", err)
	}

	scenario := &model.AttackScenario{
		ID: uuid.New(), TenantID: tenantID, MaxHops: 5,
		TargetNodeIDs: []uuid.UUID{ids["c"]},
	}
	for name, finder := range map[string]PathFinder{"postgres": pg, "neo4j": neo} {
		found, _, err := finder.FindPaths(ctx, scenario, ids["a"], maxPathsPerScenario)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(found) != 1 {
			t.Errorf("%s found %d route(s) from a to c, want the one: %v", name, len(found), describePaths(found))
		}
		for _, p := range found {
			seen := map[uuid.UUID]bool{}
			for _, n := range p.Nodes {
				if seen[n.ID] {
					t.Errorf("%s returned a route through %s twice", name, n.Label)
				}
				seen[n.ID] = true
			}
		}
	}
}

// describePaths reduces routes to what an analyst reads, so three
// implementations can be compared on their answers rather than on their order.
func describePaths(found []model.DiscoveredPath) []string {
	out := make([]string, 0, len(found))
	for _, p := range found {
		labels := make([]string, 0, len(p.Nodes))
		for _, n := range p.Nodes {
			labels = append(labels, n.Label)
		}
		out = append(out, fmt.Sprintf("%v cost=%.2f", labels, p.Cost()))
	}
	sort.Strings(out)
	return out
}

func sameStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
