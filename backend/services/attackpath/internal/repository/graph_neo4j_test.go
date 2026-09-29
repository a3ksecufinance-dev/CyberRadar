package repository

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/cyberradar/platform/internal/pkg/graphdb"
	"github.com/cyberradar/platform/services/attackpath/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testNeo4j connects to the Neo4j these tests need.
//
// Skipping when none is reachable keeps the suite usable on a laptop, but a
// skip is indistinguishable from a pass in CI output, so setting
// ATTACKPATH_TEST_NEO4J turns the skip into a failure. CI sets it.
func testNeo4j(t *testing.T, pg *GraphRepository) *Neo4jGraphStore {
	t.Helper()

	uri, required := os.LookupEnv("ATTACKPATH_TEST_NEO4J")
	if !required {
		uri = "bolt://localhost:7687"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	store, err := NewNeo4jGraphStore(ctx, graphdb.Config{
		URI:      uri,
		Username: os.Getenv("NEO4J_USERNAME"),
		Password: os.Getenv("NEO4J_PASSWORD"),
	}, pg)
	if err != nil {
		if required {
			t.Fatalf("ATTACKPATH_TEST_NEO4J is set to %s but it is not usable: %v", uri, err)
		}
		t.Skipf("no Neo4j at %s (set ATTACKPATH_TEST_NEO4J to require one): %v", uri, err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	return store
}

// dropTenant removes a tenant's graph so a rerun starts from nothing.
func dropTenant(t *testing.T, s *Neo4jGraphStore, tenantID uuid.UUID) {
	t.Helper()
	if err := s.DeleteTenantGraph(context.Background(), tenantID); err != nil {
		t.Fatalf("clean tenant %s: %v", tenantID, err)
	}
}

func node(tenantID uuid.UUID, label string) *model.AttackNode {
	now := time.Now().UTC().Truncate(time.Millisecond)
	return &model.AttackNode{
		ID: uuid.New(), TenantID: tenantID, RefID: uuid.New(),
		NodeType: model.NodeTypeAsset, Label: label,
		RiskScore: 7, Criticality: 3,
		CreatedAt: now, LastUpdatedAt: now,
	}
}

func edge(tenantID uuid.UUID, src, dst *model.AttackNode) *model.AttackEdge {
	now := time.Now().UTC().Truncate(time.Millisecond)
	return &model.AttackEdge{
		ID: uuid.New(), TenantID: tenantID, SourceID: src.ID, TargetID: dst.ID,
		EdgeType: model.EdgeTypeNetworkAccess, AttackComplexity: "LOW",
		PrivilegesRequired: "NONE", Weight: 1, IsActive: true,
		EvidenceSource: "computed", CreatedAt: now, UpdatedAt: now,
	}
}

// The whole point of the store: what PostgreSQL accepted must come back out of
// Neo4j as the same graph, because the traversal reads it without knowing which
// store it came from.
func TestMirroredGraphReadsBack(t *testing.T) {
	s := testNeo4j(t, nil)
	ctx := context.Background()
	tenantID := uuid.New()
	dropTenant(t, s, tenantID)
	t.Cleanup(func() { dropTenant(t, s, tenantID) })

	entry := node(tenantID, "dmz-proxy")
	entry.IsInternetFacing = true
	entry.Properties = map[string]any{"zone": "dmz", "tags": []any{"external"}}
	middle := node(tenantID, "app-01")
	target := node(tenantID, "core-banking")
	target.IsCriticalSystem = true
	target.Criticality = 4
	target.HasKnownExploit = true

	for _, n := range []*model.AttackNode{entry, middle, target} {
		if err := s.MirrorNode(ctx, n); err != nil {
			t.Fatalf("MirrorNode %s: %v", n.Label, err)
		}
	}
	e1 := edge(tenantID, entry, middle)
	e2 := edge(tenantID, middle, target)
	e2.EdgeType = model.EdgeTypeExploit
	e2.AttackComplexity = "HIGH"
	e2.Weight = 2.5
	cve := uuid.New()
	e2.VulnID = &cve
	e2.CVEID = "CVE-2024-3400"
	for _, e := range []*model.AttackEdge{e1, e2} {
		if err := s.MirrorEdge(ctx, e); err != nil {
			t.Fatalf("MirrorEdge %s: %v", e.ID, err)
		}
	}

	g, err := s.LoadGraph(ctx, tenantID)
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	if len(g.Nodes) != 3 {
		t.Fatalf("loaded %d nodes, want 3", len(g.Nodes))
	}

	got := g.Nodes[target.ID]
	if got == nil {
		t.Fatal("the target node did not come back")
	}
	// These are the fields the traversal scores a path on. A mirror that
	// dropped them would still load a graph, and every path through it would
	// be ranked wrong.
	if got.Label != "core-banking" || got.Criticality != 4 ||
		!got.IsCriticalSystem || !got.HasKnownExploit || got.RiskScore != 7 {
		t.Errorf("target node came back as %+v", got)
	}
	if got.TenantID != tenantID {
		t.Errorf("tenant_id = %s, want %s", got.TenantID, tenantID)
	}

	if props := g.Nodes[entry.ID].Properties; props == nil || props["zone"] != "dmz" {
		t.Errorf("free-form properties did not survive the round trip: %v", props)
	}

	out := g.Out[middle.ID]
	if len(out) != 1 {
		t.Fatalf("%d edges leave the middle node, want 1", len(out))
	}
	if out[0].EdgeType != model.EdgeTypeExploit || out[0].Weight != 2.5 ||
		out[0].CVEID != "CVE-2024-3400" || out[0].VulnID == nil || *out[0].VulnID != cve {
		t.Errorf("edge came back as %+v", out[0])
	}
	if out[0].TargetID != target.ID {
		t.Errorf("edge points at %s, want %s", out[0].TargetID, target.ID)
	}
}

// A mirror is written repeatedly — every upsert of the same node writes it
// again. It must converge on one node rather than accumulate duplicates, or the
// graph grows on every scan and the traversal walks the same asset many times.
func TestMirroringTwiceUpdatesRatherThanDuplicates(t *testing.T) {
	s := testNeo4j(t, nil)
	ctx := context.Background()
	tenantID := uuid.New()
	dropTenant(t, s, tenantID)
	t.Cleanup(func() { dropTenant(t, s, tenantID) })

	n := node(tenantID, "app-01")
	if err := s.MirrorNode(ctx, n); err != nil {
		t.Fatalf("MirrorNode: %v", err)
	}
	n.Label = "app-01.paris"
	n.RiskScore = 9.5
	n.IsCompromised = true
	if err := s.MirrorNode(ctx, n); err != nil {
		t.Fatalf("MirrorNode again: %v", err)
	}

	g, err := s.LoadGraph(ctx, tenantID)
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	if len(g.Nodes) != 1 {
		t.Fatalf("%d nodes after mirroring the same node twice, want 1", len(g.Nodes))
	}
	got := g.Nodes[n.ID]
	if got.Label != "app-01.paris" || got.RiskScore != 9.5 || !got.IsCompromised {
		t.Errorf("the second mirror did not update the node: %+v", got)
	}

	// The same for an edge: re-mirroring must move the weight, not add a
	// second relationship the traversal would count twice.
	other := node(tenantID, "db-01")
	if err := s.MirrorNode(ctx, other); err != nil {
		t.Fatalf("MirrorNode: %v", err)
	}
	e := edge(tenantID, n, other)
	if err := s.MirrorEdge(ctx, e); err != nil {
		t.Fatalf("MirrorEdge: %v", err)
	}
	e.Weight = 3.5
	if err := s.MirrorEdge(ctx, e); err != nil {
		t.Fatalf("MirrorEdge again: %v", err)
	}
	g, err = s.LoadGraph(ctx, tenantID)
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	if len(g.Out[n.ID]) != 1 {
		t.Fatalf("%d edges after mirroring the same edge twice, want 1", len(g.Out[n.ID]))
	}
	if g.Out[n.ID][0].Weight != 3.5 {
		t.Errorf("weight = %v, want the updated 3.5", g.Out[n.ID][0].Weight)
	}
}

// In PostgreSQL the tenant is a column in every WHERE. In Cypher it is a
// property with no schema behind it, so this is the test that stands in for
// what the relational schema used to guarantee.
func TestATenantNeverSeesAnothersGraph(t *testing.T) {
	s := testNeo4j(t, nil)
	ctx := context.Background()
	bankA, bankB := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{bankA, bankB} {
		dropTenant(t, s, id)
		tenantID := id
		t.Cleanup(func() { dropTenant(t, s, tenantID) })
	}

	aEntry, aTarget := node(bankA, "a-dmz"), node(bankA, "a-core")
	bEntry, bTarget := node(bankB, "b-dmz"), node(bankB, "b-core")
	for _, n := range []*model.AttackNode{aEntry, aTarget, bEntry, bTarget} {
		if err := s.MirrorNode(ctx, n); err != nil {
			t.Fatalf("MirrorNode: %v", err)
		}
	}
	if err := s.MirrorEdge(ctx, edge(bankA, aEntry, aTarget)); err != nil {
		t.Fatalf("MirrorEdge: %v", err)
	}
	if err := s.MirrorEdge(ctx, edge(bankB, bEntry, bTarget)); err != nil {
		t.Fatalf("MirrorEdge: %v", err)
	}

	g, err := s.LoadGraph(ctx, bankA)
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	if len(g.Nodes) != 2 {
		t.Fatalf("tenant A loaded %d nodes, want its own 2", len(g.Nodes))
	}
	for id, n := range g.Nodes {
		if n.TenantID != bankA {
			t.Errorf("node %s belongs to tenant %s", id, n.TenantID)
		}
	}
	if _, leaked := g.Nodes[bEntry.ID]; leaked {
		t.Error("tenant A loaded a node belonging to tenant B")
	}
	if len(g.Out[aEntry.ID]) != 1 || len(g.Out[bEntry.ID]) != 0 {
		t.Errorf("tenant A's adjacency contains tenant B's edges: %v", g.Out)
	}
}

// An edge whose endpoints Neo4j does not have must be refused. Without the
// check the MERGE matches nothing and reports success: PostgreSQL would hold a
// path that the Neo4j traversal cannot see, and nothing would say so.
func TestMirroringAnEdgeWithoutItsNodesIsRefused(t *testing.T) {
	s := testNeo4j(t, nil)
	ctx := context.Background()
	tenantID := uuid.New()
	dropTenant(t, s, tenantID)
	t.Cleanup(func() { dropTenant(t, s, tenantID) })

	src, dst := node(tenantID, "src"), node(tenantID, "dst")
	if err := s.MirrorNode(ctx, src); err != nil {
		t.Fatalf("MirrorNode: %v", err)
	}
	// dst was never mirrored.
	if err := s.MirrorEdge(ctx, edge(tenantID, src, dst)); err == nil {
		t.Fatal("mirroring an edge to a missing node reported success")
	}

	// And an edge must not cross tenants even when both nodes exist.
	otherTenant := uuid.New()
	dropTenant(t, s, otherTenant)
	t.Cleanup(func() { dropTenant(t, s, otherTenant) })
	foreign := node(otherTenant, "foreign")
	if err := s.MirrorNode(ctx, foreign); err != nil {
		t.Fatalf("MirrorNode: %v", err)
	}
	crossing := edge(tenantID, src, foreign)
	if err := s.MirrorEdge(ctx, crossing); err == nil {
		t.Fatal("an edge into another tenant's node was accepted")
	}
}

// Inactive edges must not reach the traversal, same as in PostgreSQL: an edge
// that has been retired is a path that no longer exists.
func TestInactiveEdgesAreNotLoaded(t *testing.T) {
	s := testNeo4j(t, nil)
	ctx := context.Background()
	tenantID := uuid.New()
	dropTenant(t, s, tenantID)
	t.Cleanup(func() { dropTenant(t, s, tenantID) })

	src, dst := node(tenantID, "src"), node(tenantID, "dst")
	for _, n := range []*model.AttackNode{src, dst} {
		if err := s.MirrorNode(ctx, n); err != nil {
			t.Fatalf("MirrorNode: %v", err)
		}
	}
	e := edge(tenantID, src, dst)
	e.IsActive = false
	if err := s.MirrorEdge(ctx, e); err != nil {
		t.Fatalf("MirrorEdge: %v", err)
	}

	g, err := s.LoadGraph(ctx, tenantID)
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	if len(g.Nodes) != 2 {
		t.Fatalf("loaded %d nodes, want 2", len(g.Nodes))
	}
	if len(g.Out[src.ID]) != 0 {
		t.Errorf("an inactive edge reached the traversal: %+v", g.Out[src.ID])
	}
}

// The compromise flag decides where a traversal starts. A mirror that does not
// carry it traverses from the wrong place.
func TestCompromiseFlagIsMirrored(t *testing.T) {
	s := testNeo4j(t, nil)
	ctx := context.Background()
	tenantID := uuid.New()
	dropTenant(t, s, tenantID)
	t.Cleanup(func() { dropTenant(t, s, tenantID) })

	n := node(tenantID, "laptop-42")
	if err := s.MirrorNode(ctx, n); err != nil {
		t.Fatalf("MirrorNode: %v", err)
	}
	if err := s.MirrorCompromised(ctx, tenantID, n.ID, true); err != nil {
		t.Fatalf("MirrorCompromised: %v", err)
	}
	g, err := s.LoadGraph(ctx, tenantID)
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	if !g.Nodes[n.ID].IsCompromised {
		t.Error("the compromise flag did not reach Neo4j")
	}

	// A node another tenant owns must not be reachable by id alone.
	if err := s.MirrorCompromised(ctx, uuid.New(), n.ID, true); err == nil {
		t.Error("another tenant marked this node compromised")
	}
}

// ─── Reconciliation, against both stores ──────────────────────────────────────

// testPostgres is the same DSN-gated pattern as the other repository tests.
func testPostgres(t *testing.T) *GraphRepository {
	t.Helper()

	dsn, required := os.LookupEnv("ATTACKPATH_TEST_DSN")
	if !required {
		dsn = "postgres://crp_user:crp_password_dev@localhost:5432/crp_fresh?sslmode=disable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err == nil {
		err = pool.Ping(ctx)
	}
	if err != nil {
		if required {
			t.Fatalf("ATTACKPATH_TEST_DSN is set to %s but it is not reachable: %v", dsn, err)
		}
		t.Skipf("no database at %s (set ATTACKPATH_TEST_DSN to require one): %v", dsn, err)
	}
	t.Cleanup(pool.Close)
	return NewGraphRepository(pool)
}

// seedTenant puts a tenant row in place: attack_nodes references it.
func seedTenant(t *testing.T, pg *GraphRepository) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := pg.db.Exec(context.Background(),
		`INSERT INTO tenants (id, name, slug, status) VALUES ($1, $2, $3, 'active')`,
		id, "recon-"+id.String()[:8], "recon-"+id.String()[:8])
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pg.db.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, id)
	})
	return id
}

// Reconciliation is what makes the read switch safe: pointing the traversal at
// Neo4j is only defensible once this reports parity. So it has to actually
// detect a divergence, not just report zero.
func TestReconcileDetectsDivergenceAndParity(t *testing.T) {
	pg := testPostgres(t)
	s := testNeo4j(t, pg)
	ctx := context.Background()
	tenantID := seedTenant(t, pg)
	dropTenant(t, s, tenantID)
	t.Cleanup(func() { dropTenant(t, s, tenantID) })

	srcNode, err := pg.UpsertNode(ctx, tenantID, &model.CreateNodeRequest{
		RefID: uuid.New(), NodeType: model.NodeTypeAsset, Label: "dmz-proxy",
		RiskScore: 6, Criticality: 2, IsInternetFacing: true,
	})
	if err != nil {
		t.Fatalf("UpsertNode: %v", err)
	}
	dstNode, err := pg.UpsertNode(ctx, tenantID, &model.CreateNodeRequest{
		RefID: uuid.New(), NodeType: model.NodeTypeAsset, Label: "core-banking",
		RiskScore: 9, Criticality: 4, IsCriticalSystem: true,
	})
	if err != nil {
		t.Fatalf("UpsertNode: %v", err)
	}
	if _, err := pg.UpsertEdge(ctx, tenantID, &model.CreateEdgeRequest{
		SourceID: srcNode.ID, TargetID: dstNode.ID, EdgeType: model.EdgeTypeNetworkAccess,
	}); err != nil {
		t.Fatalf("UpsertEdge: %v", err)
	}

	// Nothing has been mirrored yet, so everything PostgreSQL holds is missing.
	d, err := s.Reconcile(ctx, tenantID)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if d.InParity() {
		t.Fatal("reconciliation reported parity against an empty Neo4j")
	}
	if len(d.NodesOnlyInPostgres) != 2 || len(d.EdgesOnlyInPostgres) != 1 {
		t.Errorf("divergence = %+v, want 2 nodes and 1 edge only in postgres", d)
	}

	nodes, edges, err := s.MirrorTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("MirrorTenant: %v", err)
	}
	if nodes != 2 || edges != 1 {
		t.Errorf("MirrorTenant wrote %d nodes and %d edges, want 2 and 1", nodes, edges)
	}

	d, err = s.Reconcile(ctx, tenantID)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !d.InParity() {
		t.Fatalf("after a full mirror the stores still disagree: %+v", d)
	}

	// A field changed on one side only must be reported, not averaged away:
	// a node whose criticality differs ranks every path through it differently.
	if _, err := s.query(ctx,
		`MATCH (n:AttackNode {tenant_id: $tenant, id: $id}) SET n.criticality = 1`,
		map[string]any{"tenant": tenantID.String(), "id": dstNode.ID.String()}); err != nil {
		t.Fatalf("drift the node: %v", err)
	}
	d, err = s.Reconcile(ctx, tenantID)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(d.NodesDiffering) != 1 || d.NodesDiffering[0] != dstNode.ID {
		t.Errorf("a changed criticality was not reported: %+v", d)
	}
	if d.NodesInPostgres != 2 || d.NodesInNeo4j != 2 {
		t.Errorf("counts = %d/%d, want 2/2", d.NodesInPostgres, d.NodesInNeo4j)
	}
}

// The traversal must read the same graph from either store: that is what makes
// the switch a deployment choice rather than a behaviour change.
func TestBothStoresLoadTheSameGraph(t *testing.T) {
	pg := testPostgres(t)
	s := testNeo4j(t, pg)
	ctx := context.Background()
	tenantID := seedTenant(t, pg)
	dropTenant(t, s, tenantID)
	t.Cleanup(func() { dropTenant(t, s, tenantID) })

	var created []*model.AttackNode
	for i, label := range []string{"dmz", "app", "db"} {
		n, err := pg.UpsertNode(ctx, tenantID, &model.CreateNodeRequest{
			RefID: uuid.New(), NodeType: model.NodeTypeAsset, Label: label,
			RiskScore: float64(i + 5), Criticality: i + 1,
		})
		if err != nil {
			t.Fatalf("UpsertNode %s: %v", label, err)
		}
		created = append(created, n)
	}
	for i := 0; i < len(created)-1; i++ {
		if _, err := pg.UpsertEdge(ctx, tenantID, &model.CreateEdgeRequest{
			SourceID: created[i].ID, TargetID: created[i+1].ID,
			EdgeType: model.EdgeTypeNetworkAccess, AttackComplexity: "MEDIUM",
		}); err != nil {
			t.Fatalf("UpsertEdge: %v", err)
		}
	}
	if _, _, err := s.MirrorTenant(ctx, tenantID); err != nil {
		t.Fatalf("MirrorTenant: %v", err)
	}

	fromPG, err := s.GraphRepository.LoadGraph(ctx, tenantID)
	if err != nil {
		t.Fatalf("postgres LoadGraph: %v", err)
	}
	fromNeo, err := s.LoadGraph(ctx, tenantID)
	if err != nil {
		t.Fatalf("neo4j LoadGraph: %v", err)
	}

	if len(fromPG.Nodes) != len(fromNeo.Nodes) {
		t.Fatalf("%d nodes from postgres, %d from neo4j", len(fromPG.Nodes), len(fromNeo.Nodes))
	}
	for id, want := range fromPG.Nodes {
		got := fromNeo.Nodes[id]
		if got == nil {
			t.Fatalf("node %s is missing from neo4j", id)
		}
		if got.Label != want.Label || got.Criticality != want.Criticality ||
			got.RiskScore != want.RiskScore || got.NodeType != want.NodeType {
			t.Errorf("node %s: postgres %+v, neo4j %+v", id, want, got)
		}
	}
	for src, wantEdges := range fromPG.Out {
		gotEdges := fromNeo.Out[src]
		if len(gotEdges) != len(wantEdges) {
			t.Fatalf("node %s: %d edges from postgres, %d from neo4j", src, len(wantEdges), len(gotEdges))
		}
		for i := range wantEdges {
			if gotEdges[i].TargetID != wantEdges[i].TargetID ||
				gotEdges[i].Weight != wantEdges[i].Weight ||
				gotEdges[i].EdgeType != wantEdges[i].EdgeType {
				t.Errorf("edge from %s: postgres %+v, neo4j %+v", src, wantEdges[i], gotEdges[i])
			}
		}
	}
}
