package service

import (
	"context"
	"testing"

	"github.com/cyberradar/platform/services/attackpath/internal/model"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// ─── A graph built in the test, not in a database ─────────────────────────────

type builder struct {
	nodes  []*model.AttackNode
	edges  []*model.AttackEdge
	byName map[string]uuid.UUID
}

func newBuilder() *builder { return &builder{byName: map[string]uuid.UUID{}} }

func (b *builder) node(name string, opts ...func(*model.AttackNode)) uuid.UUID {
	n := &model.AttackNode{ID: uuid.New(), Label: name, NodeType: model.NodeTypeAsset}
	for _, o := range opts {
		o(n)
	}
	b.nodes = append(b.nodes, n)
	b.byName[name] = n.ID
	return n.ID
}

func (b *builder) edge(from, to string, opts ...func(*model.AttackEdge)) uuid.UUID {
	e := &model.AttackEdge{
		ID: uuid.New(), SourceID: b.byName[from], TargetID: b.byName[to],
		EdgeType: model.EdgeTypeNetworkAccess, Weight: 1, IsActive: true,
	}
	for _, o := range opts {
		o(e)
	}
	b.edges = append(b.edges, e)
	return e.ID
}

func (b *builder) graph() *model.Graph { return model.NewGraph(b.nodes, b.edges) }

func scenario(b *builder, maxHops int, entry string, targets ...string) *model.AttackScenario {
	s := &model.AttackScenario{
		ID: uuid.New(), TenantID: uuid.New(), MaxHops: maxHops,
		EntryNodeIDs: []uuid.UUID{b.byName[entry]},
	}
	for _, t := range targets {
		s.TargetNodeIDs = append(s.TargetNodeIDs, b.byName[t])
	}
	return s
}

func analyzer() *Analyzer { return NewAnalyzer(nil, zerolog.Nop()) }

func run(t *testing.T, b *builder, s *model.AttackScenario) ([]*model.AttackPath, bool) {
	t.Helper()
	targets := map[uuid.UUID]bool{}
	for _, id := range s.TargetNodeIDs {
		targets[id] = true
	}
	return analyzer().walk(b.graph(), s, s.EntryNodeIDs[0], targets, maxPathsPerScenario)
}

// ─── Traversal ────────────────────────────────────────────────────────────────

func TestFindsAPathToTheTarget(t *testing.T) {
	b := newBuilder()
	b.node("web")
	b.node("app")
	b.node("db")
	b.edge("web", "app")
	b.edge("app", "db")

	paths, _ := run(t, b, scenario(b, 5, "web", "db"))
	if len(paths) != 1 {
		t.Fatalf("%d paths, want 1", len(paths))
	}
	if paths[0].HopCount != 2 {
		t.Errorf("hop count = %d, want 2", paths[0].HopCount)
	}
}

func TestFindsEveryDistinctPath(t *testing.T) {
	b := newBuilder()
	b.node("web")
	b.node("a")
	b.node("b")
	b.node("db")
	b.edge("web", "a")
	b.edge("web", "b")
	b.edge("a", "db")
	b.edge("b", "db")

	paths, _ := run(t, b, scenario(b, 5, "web", "db"))
	if len(paths) != 2 {
		t.Errorf("%d paths, want 2 — both routes to the target", len(paths))
	}
}

func TestACycleDoesNotTrapTheWalk(t *testing.T) {
	b := newBuilder()
	b.node("a")
	b.node("b")
	b.node("target")
	b.edge("a", "b")
	b.edge("b", "a") // back edge
	b.edge("b", "target")

	paths, _ := run(t, b, scenario(b, 10, "a", "target"))
	if len(paths) != 1 {
		t.Errorf("%d paths, want 1", len(paths))
	}
}

func TestMaxHopsIsTheNumberOfHops(t *testing.T) {
	// A three-hop path must not come back from a two-hop budget. The previous
	// search skipped a state only past max_hops+1, so it returned paths one
	// hop longer than the scenario allowed.
	b := newBuilder()
	b.node("a")
	b.node("b")
	b.node("c")
	b.node("d")
	b.edge("a", "b")
	b.edge("b", "c")
	b.edge("c", "d")

	if paths, _ := run(t, b, scenario(b, 2, "a", "d")); len(paths) != 0 {
		t.Errorf("%d paths within 2 hops, want 0 — the target is 3 hops away", len(paths))
	}
	if paths, _ := run(t, b, scenario(b, 3, "a", "d")); len(paths) != 1 {
		t.Errorf("%d paths within 3 hops, want 1", len(paths))
	}
}

func TestInactiveEdgesAreNotWalked(t *testing.T) {
	b := newBuilder()
	b.node("a")
	b.node("target")
	b.edge("a", "target", func(e *model.AttackEdge) { e.IsActive = false })

	if paths, _ := run(t, b, scenario(b, 5, "a", "target")); len(paths) != 0 {
		t.Errorf("%d paths, want 0 — the only edge is inactive", len(paths))
	}
}

func TestIncludeTypesNarrowsTheWalk(t *testing.T) {
	// include_types was stored, returned by the API and never read: narrowing
	// a scenario to one node type silently changed nothing.
	b := newBuilder()
	b.node("a")
	b.node("jump", func(n *model.AttackNode) { n.NodeType = model.NodeTypeIdentity })
	b.node("target")
	b.edge("a", "jump")
	b.edge("jump", "target")

	s := scenario(b, 5, "a", "target")
	s.IncludeTypes = []string{model.NodeTypeAsset}

	if paths, _ := run(t, b, s); len(paths) != 0 {
		t.Errorf("%d paths, want 0 — the only route passes through an identity node", len(paths))
	}

	s.IncludeTypes = []string{model.NodeTypeAsset, model.NodeTypeIdentity}
	if paths, _ := run(t, b, s); len(paths) != 1 {
		t.Errorf("%d paths, want 1 once identity nodes are included", len(paths))
	}
}

func TestTruncationIsReported(t *testing.T) {
	// The cap used to return silently, so a scenario recorded "200 paths" with
	// no way to tell it from a graph that really had 200.
	b := newBuilder()
	b.node("entry")
	b.node("target")
	for i := 0; i < maxPathsPerScenario+50; i++ {
		name := "hop" + uuid.NewString()[:8]
		b.node(name)
		b.edge("entry", name)
		b.edge(name, "target")
	}

	paths, truncated := run(t, b, scenario(b, 5, "entry", "target"))
	if !truncated {
		t.Error("the cap was reached and not reported")
	}
	if len(paths) != maxPathsPerScenario {
		t.Errorf("%d paths, want the cap of %d", len(paths), maxPathsPerScenario)
	}
}

func TestAnEntryNodeOutsideTheGraphFindsNothing(t *testing.T) {
	b := newBuilder()
	b.node("target")
	s := &model.AttackScenario{
		ID: uuid.New(), TenantID: uuid.New(), MaxHops: 5,
		EntryNodeIDs:  []uuid.UUID{uuid.New()}, // not in the graph
		TargetNodeIDs: []uuid.UUID{b.byName["target"]},
	}
	if paths, _ := run(t, b, s); len(paths) != 0 {
		t.Errorf("%d paths from a node that is not in the graph, want 0", len(paths))
	}
}

// ─── What a path says ─────────────────────────────────────────────────────────

func TestAShorterPathIsMoreThreatening(t *testing.T) {
	// The previous formula multiplied by hop count, so a five-hop path scored
	// above a one-hop path of the same cost — it ranked the hardest attacks as
	// the most dangerous.
	short := pathScore(1.0, 1)
	long := pathScore(5.0, 5) // same cost per hop, five times as many hops

	if !(short > long) {
		t.Errorf("one hop scores %.2f, five hops %.2f — a longer path must not score higher", short, long)
	}
}

func TestACheaperPathIsMoreThreatening(t *testing.T) {
	if cheap, dear := pathScore(1.0, 2), pathScore(9.0, 2); !(cheap > dear) {
		t.Errorf("cost 1 scores %.2f, cost 9 scores %.2f — a costlier path must not score higher", cheap, dear)
	}
}

func TestPathScoreStaysInRange(t *testing.T) {
	for _, tc := range []struct {
		cost float64
		hops int
	}{
		{0, 1}, {0, 0}, {1000, 1}, {0.001, 30}, {-1, 3},
	} {
		if got := pathScore(tc.cost, tc.hops); got < 0 || got > 10 {
			t.Errorf("pathScore(%v, %d) = %v, want within 0..10", tc.cost, tc.hops, got)
		}
	}
}

func TestImpactComesFromTheTarget(t *testing.T) {
	// Every path used to record a flat 7.0 whatever it reached, so impact
	// carried no information at all.
	low := impactOf(&model.AttackNode{Criticality: 1})
	high := impactOf(&model.AttackNode{Criticality: 4})

	if !(high > low) {
		t.Errorf("criticality 4 scores %.1f, criticality 1 scores %.1f", high, low)
	}
	if crit := impactOf(&model.AttackNode{Criticality: 4, IsCriticalSystem: true}); crit <= high {
		t.Errorf("a critical system scores %.1f, no more than a plain criticality-4 node at %.1f", crit, high)
	}
	if got := impactOf(&model.AttackNode{}); got <= 0 || got > 10 {
		t.Errorf("a target with nothing recorded scores %.1f, want a usable middle value", got)
	}
}

func TestPathFlagsAreComputed(t *testing.T) {
	// These three were declared, persisted and read back by the API, and never
	// set: every path in the database recorded false for all of them.
	b := newBuilder()
	b.node("edge-server", func(n *model.AttackNode) { n.IsInternetFacing = true })
	b.node("admin", func(n *model.AttackNode) { n.IsPrivileged = true })
	b.node("crown-jewels", func(n *model.AttackNode) { n.IsCriticalSystem = true; n.Criticality = 4 })
	b.edge("edge-server", "admin", func(e *model.AttackEdge) {
		e.EdgeType = model.EdgeTypeExploit
		e.CVEID = "CVE-2024-3094"
	})
	b.edge("admin", "crown-jewels")

	paths, _ := run(t, b, scenario(b, 5, "edge-server", "crown-jewels"))
	if len(paths) != 1 {
		t.Fatalf("%d paths, want 1", len(paths))
	}
	p := paths[0]

	if !p.HasInternetEntry {
		t.Error("HasInternetEntry is false though the entry node faces the internet")
	}
	if !p.HasExploitStep {
		t.Error("HasExploitStep is false though the path crosses an exploit edge with a CVE")
	}
	if !p.HasPrivEsc {
		t.Error("HasPrivEsc is false though the path passes through a privileged node")
	}
	if p.PathType != model.PathTypePrivEscalation {
		t.Errorf("PathType = %q, want %q", p.PathType, model.PathTypePrivEscalation)
	}
	if p.Impact <= 7.0 {
		t.Errorf("Impact = %.1f for a critical, criticality-4 target — the old flat 7.0 is showing", p.Impact)
	}
}

func TestPathsKeepTheirOwnSequences(t *testing.T) {
	// The walk reuses its slices as it backtracks, so a path that kept a
	// reference would be rewritten by the next branch.
	b := newBuilder()
	b.node("a")
	b.node("x")
	b.node("y")
	b.node("t")
	b.edge("a", "x")
	b.edge("a", "y")
	b.edge("x", "t")
	b.edge("y", "t")

	paths, _ := run(t, b, scenario(b, 5, "a", "t"))
	if len(paths) != 2 {
		t.Fatalf("%d paths, want 2", len(paths))
	}
	if paths[0].NodeSequence[1] == paths[1].NodeSequence[1] {
		t.Errorf("both paths report the same middle node %v — the sequences are shared", paths[0].NodeSequence)
	}
	for _, p := range paths {
		if len(p.NodeSequence) != 3 || len(p.EdgeSequence) != 2 {
			t.Errorf("path has %d nodes and %d edges, want 3 and 2", len(p.NodeSequence), len(p.EdgeSequence))
		}
	}
}

func TestChokePointIsTheSharedNode(t *testing.T) {
	b := newBuilder()
	b.node("a")
	b.node("bottleneck")
	b.node("t1")
	b.node("t2")
	b.edge("a", "bottleneck")
	b.edge("bottleneck", "t1")
	b.edge("bottleneck", "t2")

	paths, _ := run(t, b, scenario(b, 5, "a", "t1", "t2"))
	computeChokePoints(paths)

	if len(paths) != 2 {
		t.Fatalf("%d paths, want 2", len(paths))
	}
	for _, p := range paths {
		if p.ChokePointNodeID == nil || *p.ChokePointNodeID != b.byName["bottleneck"] {
			t.Errorf("choke point = %v, want the shared node", p.ChokePointNodeID)
		}
	}
}

// ─── The store seam ───────────────────────────────────────────────────────────

type fakeStore struct {
	graph    *model.Graph
	statuses []string
	saved    []*model.AttackPath
	result   struct {
		pathCount int
		risk      float64
	}
}

func (s *fakeStore) LoadGraph(context.Context, uuid.UUID) (*model.Graph, error) { return s.graph, nil }
func (s *fakeStore) SetScenarioStatus(_ context.Context, _ uuid.UUID, status string) error {
	s.statuses = append(s.statuses, status)
	return nil
}
func (s *fakeStore) SavePaths(_ context.Context, paths []*model.AttackPath) error {
	s.saved = paths
	return nil
}
func (s *fakeStore) UpdateScenarioResult(_ context.Context, _ uuid.UUID, pathCount int, _, _ *int, risk float64, _ int) error {
	s.result.pathCount, s.result.risk = pathCount, risk
	return nil
}

func TestRunScenarioRecordsWhatItFound(t *testing.T) {
	// The analyzer depends on GraphStore, not on the PostgreSQL repository,
	// which is what will let a Neo4j implementation take its place — and what
	// lets this run with no database at all.
	b := newBuilder()
	b.node("web", func(n *model.AttackNode) { n.IsInternetFacing = true })
	b.node("db", func(n *model.AttackNode) { n.Criticality = 4 })
	b.edge("web", "db")

	store := &fakeStore{graph: b.graph()}
	s := scenario(b, 5, "web", "db")

	if err := NewAnalyzer(store, zerolog.Nop()).RunScenario(context.Background(), s); err != nil {
		t.Fatalf("RunScenario: %v", err)
	}

	if len(store.statuses) == 0 || store.statuses[0] != model.ScenarioStatusRunning {
		t.Errorf("statuses = %v, want the run marked running first", store.statuses)
	}
	if store.result.pathCount != 1 || len(store.saved) != 1 {
		t.Errorf("recorded %d paths and saved %d, want 1 and 1", store.result.pathCount, len(store.saved))
	}
	if store.result.risk <= 0 {
		t.Errorf("risk score = %.2f, want above zero for a reachable critical target", store.result.risk)
	}
}
