package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cyberradar/platform/internal/pkg/graphdb"
	"github.com/cyberradar/platform/services/knowledgegraph/internal/model"
	"github.com/google/uuid"
)

// kgTestNeo4j connects to the Neo4j these tests need.
//
// Skipping when none is reachable keeps the suite usable on a laptop, but a
// skip is indistinguishable from a pass in CI output, so setting
// KG_TEST_NEO4J turns the skip into a failure. CI sets it.
func kgTestNeo4j(t *testing.T, pg *KGRepository) *Neo4jGraphStore {
	t.Helper()

	uri, required := os.LookupEnv("KG_TEST_NEO4J")
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
			t.Fatalf("KG_TEST_NEO4J is set to %s but it is not usable: %v", uri, err)
		}
		t.Skipf("no Neo4j at %s (set KG_TEST_NEO4J to require one): %v", uri, err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	return store
}

// bothStores gives a tenant seeded in PostgreSQL and mirrored into Neo4j.
func bothStores(t *testing.T) (*KGRepository, *Neo4jGraphStore, uuid.UUID) {
	t.Helper()
	pool, repo := kgTestDB(t)
	tenantID := kgTenant(t, pool)
	neo := kgTestNeo4j(t, repo)
	if err := neo.DeleteTenantGraph(context.Background(), tenantID); err != nil {
		t.Fatalf("clean neo4j: %v", err)
	}
	t.Cleanup(func() { _ = neo.DeleteTenantGraph(context.Background(), tenantID) })
	return repo, neo, tenantID
}

// A traversal must give the same answer whichever store it reads, because that
// is what makes where the graph lives a deployment choice rather than a change
// of behaviour. The walk itself is shared; this checks the two adjacency
// queries agree.
func TestTheTraversalFindsTheSameNeighborsFromEitherStore(t *testing.T) {
	repo, neo, tenantID := bothStores(t)
	ctx := context.Background()

	//  actor ──USES──► ip ──COMMUNICATES_WITH──► asset ──BELONGS_TO──► person
	//                   ▲
	//      domain ──RESOLVES_TO──┘
	ip := entity(t, repo, tenantID, model.EntityTypeIP, "203.0.113.7")
	asset := entity(t, repo, tenantID, model.EntityTypeAsset, "web-front-01")
	person := entity(t, repo, tenantID, model.EntityTypeIdentity, "m.dupont")
	actor := entity(t, repo, tenantID, model.EntityTypeThreatActor, "FIN7")
	domain := entity(t, repo, tenantID, model.EntityTypeDomain, "evil.example")
	relate(t, repo, tenantID, ip, asset, model.RelCommunicatesWith)
	relate(t, repo, tenantID, asset, person, model.RelBelongsTo)
	relate(t, repo, tenantID, actor, ip, model.RelUses)
	relate(t, repo, tenantID, domain, ip, model.RelResolvesTo)

	if _, _, err := neo.MirrorTenant(ctx, tenantID); err != nil {
		t.Fatalf("MirrorTenant: %v", err)
	}

	for _, direction := range []string{"both", "outbound", "inbound"} {
		for _, hops := range []int{1, 2, 3} {
			q := model.NeighborQuery{
				TenantID: tenantID, EntityID: ip.ID, MaxHops: hops, Direction: direction,
			}
			fromPG, err := repo.Neighbors(ctx, q)
			if err != nil {
				t.Fatalf("postgres %s/%d: %v", direction, hops, err)
			}
			fromNeo, err := neo.Neighbors(ctx, q)
			if err != nil {
				t.Fatalf("neo4j %s/%d: %v", direction, hops, err)
			}
			if a, b := describe(fromPG), describe(fromNeo); !sameStrings(a, b) {
				t.Errorf("%s at %d hop(s) differs:\n  postgres: %v\n  neo4j:    %v", direction, hops, a, b)
			}
		}
	}

	// A filter must narrow the same way on both sides.
	q := model.NeighborQuery{
		TenantID: tenantID, EntityID: ip.ID, MaxHops: 3, Direction: "both",
		RelTypes: []string{model.RelUses, model.RelResolvesTo},
	}
	fromPG, err := repo.Neighbors(ctx, q)
	if err != nil {
		t.Fatalf("postgres filtered: %v", err)
	}
	fromNeo, err := neo.Neighbors(ctx, q)
	if err != nil {
		t.Fatalf("neo4j filtered: %v", err)
	}
	if len(fromPG) != 2 {
		t.Fatalf("the filtered walk found %v — the fixture is wrong, not the stores", describe(fromPG))
	}
	if a, b := describe(fromPG), describe(fromNeo); !sameStrings(a, b) {
		t.Errorf("filtered walk differs:\n  postgres: %v\n  neo4j:    %v", a, b)
	}
}

// Validity windows have to be read the same way on both sides, or an analyst
// sees a connection in one deployment and not in another.
func TestValidityWindowsAgreeAcrossStores(t *testing.T) {
	repo, neo, tenantID := bothStores(t)
	ctx := context.Background()

	root := entity(t, repo, tenantID, model.EntityTypeIP, "root")
	future := entity(t, repo, tenantID, model.EntityTypeAsset, "not-yet")
	past := entity(t, repo, tenantID, model.EntityTypeAsset, "expired")
	current := entity(t, repo, tenantID, model.EntityTypeAsset, "current")

	tomorrow := time.Now().UTC().Add(24 * time.Hour)
	yesterday := time.Now().UTC().Add(-24 * time.Hour)
	var written []*model.KGRelationship
	for _, c := range []struct {
		dst         *model.KGEntity
		from, until *time.Time
	}{
		{future, &tomorrow, nil},
		{past, nil, &yesterday},
		{current, &yesterday, &tomorrow},
	} {
		rel, err := repo.UpsertRelationship(ctx, tenantID, &model.UpsertRelationshipRequest{
			SourceID: root.ID, TargetID: c.dst.ID, RelationshipType: model.RelConnectTo,
			EvidenceSource: model.SourceManual, ValidFrom: c.from, ValidUntil: c.until,
		})
		if err != nil {
			t.Fatalf("UpsertRelationship %s: %v", c.dst.Name, err)
		}
		written = append(written, rel)
	}

	// The out-of-window relationships are mirrored explicitly. MirrorTenant
	// copies only what is in force, so relying on it would make this pass by
	// never having written the very rows it is meant to exclude.
	for _, e := range []*model.KGEntity{root, future, past, current} {
		if err := neo.MirrorEntity(ctx, e); err != nil {
			t.Fatalf("MirrorEntity %s: %v", e.Name, err)
		}
	}
	for _, rel := range written {
		if err := neo.MirrorRelationship(ctx, rel); err != nil {
			t.Fatalf("MirrorRelationship: %v", err)
		}
	}

	q := model.NeighborQuery{TenantID: tenantID, EntityID: root.ID, MaxHops: 2, Direction: "both"}
	fromPG, err := repo.Neighbors(ctx, q)
	if err != nil {
		t.Fatalf("postgres: %v", err)
	}
	fromNeo, err := neo.Neighbors(ctx, q)
	if err != nil {
		t.Fatalf("neo4j: %v", err)
	}
	if got := names(fromPG); len(got) != 1 || got[0] != "current" {
		t.Fatalf("postgres walked %v, want only the relationship in force", got)
	}
	if a, b := describe(fromPG), describe(fromNeo); !sameStrings(a, b) {
		t.Errorf("validity windows read differently:\n  postgres: %v\n  neo4j:    %v", a, b)
	}
}

// In PostgreSQL the tenant is a column in every WHERE. In Cypher it is a
// property with no schema behind it, so this stands in for what the relational
// schema used to guarantee.
func TestNeo4jTraversalStaysInsideOneTenant(t *testing.T) {
	pool, repo := kgTestDB(t)
	neo := kgTestNeo4j(t, repo)
	ctx := context.Background()
	bankA, bankB := kgTenant(t, pool), kgTenant(t, pool)
	for _, id := range []uuid.UUID{bankA, bankB} {
		tenantID := id
		if err := neo.DeleteTenantGraph(ctx, tenantID); err != nil {
			t.Fatalf("clean: %v", err)
		}
		t.Cleanup(func() { _ = neo.DeleteTenantGraph(context.Background(), tenantID) })
	}

	aRoot := entity(t, repo, bankA, model.EntityTypeIP, "shared-looking-ip")
	aLeaf := entity(t, repo, bankA, model.EntityTypeAsset, "a-asset")
	relate(t, repo, bankA, aRoot, aLeaf, model.RelCommunicatesWith)
	bRoot := entity(t, repo, bankB, model.EntityTypeIP, "shared-looking-ip")
	bLeaf := entity(t, repo, bankB, model.EntityTypeAsset, "b-asset")
	relate(t, repo, bankB, bRoot, bLeaf, model.RelCommunicatesWith)

	for _, id := range []uuid.UUID{bankA, bankB} {
		if _, _, err := neo.MirrorTenant(ctx, id); err != nil {
			t.Fatalf("MirrorTenant: %v", err)
		}
	}

	neighbors, err := neo.Neighbors(ctx, model.NeighborQuery{
		TenantID: bankA, EntityID: aRoot.ID, MaxHops: 3, Direction: "both",
	})
	if err != nil {
		t.Fatalf("Neighbors: %v", err)
	}
	if got := names(neighbors); len(got) != 1 || got[0] != "a-asset" {
		t.Errorf("tenant A walked %v", got)
	}

	// And an entity of another tenant must not be reachable by identifier.
	foreign, err := neo.Neighbors(ctx, model.NeighborQuery{
		TenantID: bankA, EntityID: bRoot.ID, MaxHops: 3, Direction: "both",
	})
	if err != nil {
		t.Fatalf("Neighbors: %v", err)
	}
	if len(foreign) != 0 {
		t.Errorf("tenant A reached %v through tenant B's entity", names(foreign))
	}
}

// Reconciliation is what makes the read switch safe, so it has to actually
// detect a divergence rather than only report zero.
func TestReconcileDetectsDivergenceAndParity(t *testing.T) {
	repo, neo, tenantID := bothStores(t)
	ctx := context.Background()

	a := entity(t, repo, tenantID, model.EntityTypeIP, "203.0.113.7")
	b := entity(t, repo, tenantID, model.EntityTypeAsset, "web-front-01")
	rel := relate(t, repo, tenantID, a, b, model.RelCommunicatesWith)

	d, err := neo.Reconcile(ctx, tenantID)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if d.InParity() {
		t.Fatal("reconciliation reported parity against an empty Neo4j")
	}
	if len(d.EntitiesOnlyInPostgres) != 2 || len(d.RelsOnlyInPostgres) != 1 {
		t.Errorf("divergence = %+v, want 2 entities and 1 relationship only in postgres", d)
	}

	entities, rels, err := neo.MirrorTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("MirrorTenant: %v", err)
	}
	if entities != 2 || rels != 1 {
		t.Errorf("MirrorTenant wrote %d entities and %d relationships, want 2 and 1", entities, rels)
	}

	if d, err = neo.Reconcile(ctx, tenantID); err != nil {
		t.Fatalf("Reconcile: %v", err)
	} else if !d.InParity() {
		t.Fatalf("after a full mirror the stores still disagree: %+v", d)
	}

	// A field changed on one side only must be reported, not averaged away.
	if _, err := neo.query(ctx,
		`MATCH (n:KGEntity {tenant_id: $tenant, id: $id}) SET n.risk_score = 0.5`,
		map[string]any{"tenant": tenantID.String(), "id": a.ID.String()}); err != nil {
		t.Fatalf("drift the entity: %v", err)
	}
	if d, err = neo.Reconcile(ctx, tenantID); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(d.EntitiesDiffering) != 1 || d.EntitiesDiffering[0] != a.ID {
		t.Errorf("a changed risk score was not reported: %+v", d)
	}

	// A deletion must reach the mirror, or the traversal keeps walking a
	// connection that no longer exists.
	if err := repo.DeleteRelationship(ctx, tenantID, rel.ID); err != nil {
		t.Fatalf("DeleteRelationship: %v", err)
	}
	if d, err = neo.Reconcile(ctx, tenantID); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(d.RelsOnlyInNeo4j) != 1 {
		t.Errorf("a deleted relationship still in neo4j was not reported: %+v", d)
	}
	if err := neo.MirrorRelationshipDeleted(ctx, tenantID, rel.ID); err != nil {
		t.Fatalf("MirrorRelationshipDeleted: %v", err)
	}
	if d, err = neo.Reconcile(ctx, tenantID); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(d.RelsOnlyInNeo4j) != 0 {
		t.Errorf("the mirrored deletion did not remove it: %+v", d)
	}
}

// A relationship whose endpoints Neo4j does not have must be refused. Without
// the check the MERGE matches nothing and reports success: PostgreSQL would
// hold a connection the Neo4j traversal cannot see, and nothing would say so.
func TestMirroringARelationshipWithoutItsEntitiesIsRefused(t *testing.T) {
	repo, neo, tenantID := bothStores(t)
	ctx := context.Background()

	a := entity(t, repo, tenantID, model.EntityTypeIP, "known")
	b := entity(t, repo, tenantID, model.EntityTypeAsset, "never-mirrored")
	rel := relate(t, repo, tenantID, a, b, model.RelCommunicatesWith)

	if err := neo.MirrorEntity(ctx, a); err != nil {
		t.Fatalf("MirrorEntity: %v", err)
	}
	if err := neo.MirrorRelationship(ctx, rel); err == nil {
		t.Fatal("mirroring a relationship to a missing entity reported success")
	}
}

// The subgraph the graph view draws must be the same from either store.
func TestSubgraphAgreesAcrossStores(t *testing.T) {
	repo, neo, tenantID := bothStores(t)
	ctx := context.Background()

	a := entity(t, repo, tenantID, model.EntityTypeIP, "a")
	b := entity(t, repo, tenantID, model.EntityTypeAsset, "b")
	c := entity(t, repo, tenantID, model.EntityTypeIdentity, "c")
	outside := entity(t, repo, tenantID, model.EntityTypeAsset, "outside")
	relate(t, repo, tenantID, a, b, model.RelCommunicatesWith)
	relate(t, repo, tenantID, b, c, model.RelBelongsTo)
	relate(t, repo, tenantID, c, outside, model.RelConnectTo)
	if _, _, err := neo.MirrorTenant(ctx, tenantID); err != nil {
		t.Fatalf("MirrorTenant: %v", err)
	}

	ids := []uuid.UUID{a.ID, b.ID, c.ID}
	fromPG, err := repo.Subgraph(ctx, tenantID, ids)
	if err != nil {
		t.Fatalf("postgres Subgraph: %v", err)
	}
	fromNeo, err := neo.Subgraph(ctx, tenantID, ids)
	if err != nil {
		t.Fatalf("neo4j Subgraph: %v", err)
	}
	if len(fromPG.Entities) != 3 || len(fromPG.Relationships) != 2 {
		t.Fatalf("postgres subgraph = %d entities, %d relationships — the fixture is wrong",
			len(fromPG.Entities), len(fromPG.Relationships))
	}
	if len(fromNeo.Entities) != len(fromPG.Entities) ||
		len(fromNeo.Relationships) != len(fromPG.Relationships) {
		t.Errorf("subgraphs differ: postgres %d/%d, neo4j %d/%d",
			len(fromPG.Entities), len(fromPG.Relationships),
			len(fromNeo.Entities), len(fromNeo.Relationships))
	}
	// A relationship leaving the requested set must not be drawn by either.
	for _, rel := range fromNeo.Relationships {
		if rel.TargetID == outside.ID || rel.SourceID == outside.ID {
			t.Error("the subgraph included a relationship to an entity outside the request")
		}
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// describe reduces a traversal to what an analyst reads, so two stores can be
// compared on their answers rather than on their row order.
func describe(neighbors []model.KGNeighbor) []string {
	out := make([]string, 0, len(neighbors))
	for _, n := range neighbors {
		out = append(out, fmt.Sprintf("%s via %s at %d hop(s), path %d",
			n.Entity.Name, n.Relationship.RelationshipType, n.Depth, len(n.Path)))
	}
	return out
}

func sameStrings(a, b []string) bool {
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
