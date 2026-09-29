package repository

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/cyberradar/platform/services/knowledgegraph/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// kgTestDB connects to the database these tests need.
//
// Skipping when none is reachable keeps the suite usable on a laptop, but a
// skip is indistinguishable from a pass in CI output, so setting KG_TEST_DSN
// turns the skip into a failure. CI sets it.
func kgTestDB(t *testing.T) (*pgxpool.Pool, *KGRepository) {
	t.Helper()

	dsn, required := os.LookupEnv("KG_TEST_DSN")
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
			t.Fatalf("KG_TEST_DSN is set to %s but it is not reachable: %v", dsn, err)
		}
		t.Skipf("no database at %s (set KG_TEST_DSN to require one): %v", dsn, err)
	}
	t.Cleanup(pool.Close)
	return pool, NewKGRepository(pool)
}

func kgTenant(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	slug := "kg-" + id.String()[:8]
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (id, name, slug, status) VALUES ($1, $2, $3, 'active')`,
		id, slug, slug); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		for _, table := range []string{"kg_observations", "kg_relationships", "kg_entities"} {
			_, _ = pool.Exec(ctx, `DELETE FROM `+table+` WHERE tenant_id = $1`, id)
		}
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, id)
	})
	return id
}

func entity(t *testing.T, r *KGRepository, tenantID uuid.UUID, kind, name string) *model.KGEntity {
	t.Helper()
	e, err := r.UpsertEntity(context.Background(), tenantID, &model.UpsertEntityRequest{
		EntityType: kind, Name: name, RiskScore: 5, Confidence: 1,
	})
	if err != nil {
		t.Fatalf("UpsertEntity %s: %v", name, err)
	}
	return e
}

func relate(t *testing.T, r *KGRepository, tenantID uuid.UUID, src, dst *model.KGEntity, relType string) *model.KGRelationship {
	t.Helper()
	rel, err := r.UpsertRelationship(context.Background(), tenantID, &model.UpsertRelationshipRequest{
		SourceID: src.ID, TargetID: dst.ID, RelationshipType: relType,
		EvidenceSource: model.SourceManual,
	})
	if err != nil {
		t.Fatalf("UpsertRelationship %s→%s: %v", src.Name, dst.Name, err)
	}
	return rel
}

// names reduces a traversal to what it actually found, for readable failures.
func names(neighbors []model.KGNeighbor) []string {
	out := make([]string, 0, len(neighbors))
	for _, n := range neighbors {
		out = append(out, n.Entity.Name)
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// "both" is the default in the handler and the only direction Enrich uses, and
// it was invalid SQL: PostgreSQL rejected the query outright, so every
// neighbour lookup made with the defaults failed. This is the test that keeps
// it from coming back.
func TestBothDirectionsAreWalked(t *testing.T) {
	pool, repo := kgTestDB(t)
	tenantID := kgTenant(t, pool)
	ctx := context.Background()

	//  actor ──USES──► ip ──COMMUNICATES_WITH──► asset ──BELONGS_TO──► person
	ip := entity(t, repo, tenantID, model.EntityTypeIP, "203.0.113.7")
	asset := entity(t, repo, tenantID, model.EntityTypeAsset, "web-front-01")
	person := entity(t, repo, tenantID, model.EntityTypeIdentity, "m.dupont")
	actor := entity(t, repo, tenantID, model.EntityTypeThreatActor, "FIN7")
	relate(t, repo, tenantID, ip, asset, model.RelCommunicatesWith)
	relate(t, repo, tenantID, asset, person, model.RelBelongsTo)
	relate(t, repo, tenantID, actor, ip, model.RelUses)

	both, err := repo.Neighbors(ctx, model.NeighborQuery{
		TenantID: tenantID, EntityID: ip.ID, MaxHops: 2, Direction: "both",
	})
	if err != nil {
		t.Fatalf("Neighbors both: %v", err)
	}
	got := names(both)
	// Walking both ways from the IP reaches the actor that uses it as well as
	// the asset it talked to — which is the whole question an analyst is
	// asking.
	for _, want := range []string{"web-front-01", "FIN7", "m.dupont"} {
		if !contains(got, want) {
			t.Errorf("walking both directions did not reach %s: %v", want, got)
		}
	}

	out, err := repo.Neighbors(ctx, model.NeighborQuery{
		TenantID: tenantID, EntityID: ip.ID, MaxHops: 2, Direction: "outbound",
	})
	if err != nil {
		t.Fatalf("Neighbors outbound: %v", err)
	}
	if contains(names(out), "FIN7") {
		t.Errorf("an outbound walk reached an entity only an inbound edge leads to: %v", names(out))
	}

	in, err := repo.Neighbors(ctx, model.NeighborQuery{
		TenantID: tenantID, EntityID: ip.ID, MaxHops: 2, Direction: "inbound",
	})
	if err != nil {
		t.Fatalf("Neighbors inbound: %v", err)
	}
	if got := names(in); len(got) != 1 || got[0] != "FIN7" {
		t.Errorf("inbound walk = %v, want only FIN7", got)
	}
}

// Each entity comes back at the fewest hops that reach it, with the path that
// got there. An analyst reads depth as "how close is this".
func TestDepthAndPathAreTheShortestOnes(t *testing.T) {
	pool, repo := kgTestDB(t)
	tenantID := kgTenant(t, pool)
	ctx := context.Background()

	//  a ──► b ──► d
	//   └────────► d   (also directly, so d is one hop, not two)
	a := entity(t, repo, tenantID, model.EntityTypeAsset, "a")
	b := entity(t, repo, tenantID, model.EntityTypeAsset, "b")
	d := entity(t, repo, tenantID, model.EntityTypeAsset, "d")
	relate(t, repo, tenantID, a, b, model.RelConnectTo)
	relate(t, repo, tenantID, b, d, model.RelConnectTo)
	relate(t, repo, tenantID, a, d, model.RelAssociatedWith)

	neighbors, err := repo.Neighbors(ctx, model.NeighborQuery{
		TenantID: tenantID, EntityID: a.ID, MaxHops: 3, Direction: "outbound",
	})
	if err != nil {
		t.Fatalf("Neighbors: %v", err)
	}
	if len(neighbors) != 2 {
		t.Fatalf("reached %v, want b and d exactly once each", names(neighbors))
	}
	for _, n := range neighbors {
		if n.Depth != 1 {
			t.Errorf("%s is at depth %d, want 1", n.Entity.Name, n.Depth)
		}
		if len(n.Path) != 2 || n.Path[0] != a.ID || n.Path[1] != n.Entity.ID {
			t.Errorf("%s has path %v, want [a %s]", n.Entity.Name, n.Path, n.Entity.Name)
		}
	}

	// And the hop limit is honoured: one hop must not reach d's own neighbour.
	e := entity(t, repo, tenantID, model.EntityTypeAsset, "e")
	relate(t, repo, tenantID, d, e, model.RelConnectTo)
	oneHop, err := repo.Neighbors(ctx, model.NeighborQuery{
		TenantID: tenantID, EntityID: a.ID, MaxHops: 1, Direction: "outbound",
	})
	if err != nil {
		t.Fatalf("Neighbors: %v", err)
	}
	if contains(names(oneHop), "e") {
		t.Errorf("a one-hop walk returned a two-hop entity: %v", names(oneHop))
	}
}

// rel_types was parsed by the handler, carried by the service and ignored by
// the traversal: restricting a query to one relationship type returned the same
// answer as asking for everything.
func TestRelationshipTypeFilterIsApplied(t *testing.T) {
	pool, repo := kgTestDB(t)
	tenantID := kgTenant(t, pool)
	ctx := context.Background()

	root := entity(t, repo, tenantID, model.EntityTypeIP, "root-ip")
	talked := entity(t, repo, tenantID, model.EntityTypeAsset, "talked-to")
	owned := entity(t, repo, tenantID, model.EntityTypeIdentity, "owner")
	relate(t, repo, tenantID, root, talked, model.RelCommunicatesWith)
	relate(t, repo, tenantID, root, owned, model.RelBelongsTo)

	filtered, err := repo.Neighbors(ctx, model.NeighborQuery{
		TenantID: tenantID, EntityID: root.ID, MaxHops: 2, Direction: "both",
		RelTypes: []string{model.RelCommunicatesWith},
	})
	if err != nil {
		t.Fatalf("Neighbors: %v", err)
	}
	if got := names(filtered); len(got) != 1 || got[0] != "talked-to" {
		t.Errorf("filtering on COMMUNICATES_WITH returned %v", got)
	}

	// An empty or blank filter must not filter everything away.
	for _, relTypes := range [][]string{nil, {}, {""}, {"  "}} {
		all, err := repo.Neighbors(ctx, model.NeighborQuery{
			TenantID: tenantID, EntityID: root.ID, MaxHops: 2, Direction: "both",
			RelTypes: relTypes,
		})
		if err != nil {
			t.Fatalf("Neighbors %v: %v", relTypes, err)
		}
		if len(all) != 2 {
			t.Errorf("rel_types=%v returned %v, want both neighbours", relTypes, names(all))
		}
	}
}

// valid_from was recorded and never checked, so a relationship declared
// effective next month was already being traversed today — and an expired one
// had to be excluded too.
func TestOnlyRelationshipsInForceAreWalked(t *testing.T) {
	pool, repo := kgTestDB(t)
	tenantID := kgTenant(t, pool)
	ctx := context.Background()

	root := entity(t, repo, tenantID, model.EntityTypeIP, "root")
	future := entity(t, repo, tenantID, model.EntityTypeAsset, "not-yet")
	past := entity(t, repo, tenantID, model.EntityTypeAsset, "expired")
	now := entity(t, repo, tenantID, model.EntityTypeAsset, "current")

	tomorrow := time.Now().UTC().Add(24 * time.Hour)
	yesterday := time.Now().UTC().Add(-24 * time.Hour)
	mustRelate := func(dst *model.KGEntity, from, until *time.Time) {
		if _, err := repo.UpsertRelationship(ctx, tenantID, &model.UpsertRelationshipRequest{
			SourceID: root.ID, TargetID: dst.ID, RelationshipType: model.RelConnectTo,
			EvidenceSource: model.SourceManual, ValidFrom: from, ValidUntil: until,
		}); err != nil {
			t.Fatalf("UpsertRelationship %s: %v", dst.Name, err)
		}
	}
	mustRelate(future, &tomorrow, nil)
	mustRelate(past, nil, &yesterday)
	mustRelate(now, &yesterday, &tomorrow)

	neighbors, err := repo.Neighbors(ctx, model.NeighborQuery{
		TenantID: tenantID, EntityID: root.ID, MaxHops: 2, Direction: "both",
	})
	if err != nil {
		t.Fatalf("Neighbors: %v", err)
	}
	if got := names(neighbors); len(got) != 1 || got[0] != "current" {
		t.Errorf("walked %v, want only the relationship in force", got)
	}

	// Listing must agree with traversing, or the graph view draws one thing
	// and the relationship list says another.
	rels, err := repo.ListRelationships(ctx, tenantID, root.ID, "both")
	if err != nil {
		t.Fatalf("ListRelationships: %v", err)
	}
	if len(rels) != 1 {
		t.Errorf("listing returned %d relationship(s), traversal walked 1", len(rels))
	}
}

// One tenant's graph must never appear in another's traversal.
func TestATenantNeverWalksIntoAnothersGraph(t *testing.T) {
	pool, repo := kgTestDB(t)
	bankA, bankB := kgTenant(t, pool), kgTenant(t, pool)
	ctx := context.Background()

	aRoot := entity(t, repo, bankA, model.EntityTypeIP, "shared-looking-ip")
	aLeaf := entity(t, repo, bankA, model.EntityTypeAsset, "a-asset")
	relate(t, repo, bankA, aRoot, aLeaf, model.RelCommunicatesWith)

	bRoot := entity(t, repo, bankB, model.EntityTypeIP, "shared-looking-ip")
	bLeaf := entity(t, repo, bankB, model.EntityTypeAsset, "b-asset")
	relate(t, repo, bankB, bRoot, bLeaf, model.RelCommunicatesWith)

	neighbors, err := repo.Neighbors(ctx, model.NeighborQuery{
		TenantID: bankA, EntityID: aRoot.ID, MaxHops: 3, Direction: "both",
	})
	if err != nil {
		t.Fatalf("Neighbors: %v", err)
	}
	if got := names(neighbors); len(got) != 1 || got[0] != "a-asset" {
		t.Errorf("tenant A walked %v", got)
	}
	for _, n := range neighbors {
		if n.Entity.TenantID != bankA {
			t.Errorf("entity %s belongs to tenant %s", n.Entity.Name, n.Entity.TenantID)
		}
	}
}
