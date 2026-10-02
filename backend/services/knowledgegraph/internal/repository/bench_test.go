package repository

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/cyberradar/platform/services/knowledgegraph/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These benchmarks exist to decide a design question rather than to chase a
// number: the roadmap says the traversal should be pushed into Cypher, and the
// only way to know whether that is worth doing — or possible without losing the
// validity window — is to measure what the hop-by-hop expansion actually costs
// against each store on a graph large enough to matter.
//
// They build a graph once and reuse it, so run them with -benchtime=Nx rather
// than a duration.

const (
	benchEntities = 20000
	benchDegree   = 8
	benchCluster  = 150
)

// seedBenchGraph builds a tenant shaped like a real estate rather than a
// random graph: entities sit in clusters — a subnet, a business line — densely
// connected inside and sparsely joined across, with a few hubs.
//
// The shape matters more than the size. A uniformly random graph of this
// degree reaches everything in two hops, so the traversal hits its cap
// immediately and the benchmark measures nothing past one hop; a hub-and-spoke
// graph does the same. Clusters give a typical entity a neighbourhood that
// grows the way an analyst's does.
func seedBenchGraph(tb testing.TB, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID) {
	tb.Helper()
	ctx := context.Background()

	tenantID := uuid.New()
	slug := "bench-" + tenantID.String()[:8]
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (id, name, slug, status) VALUES ($1,$2,$3,'active')`,
		tenantID, slug, slug); err != nil {
		tb.Fatalf("seed tenant: %v", err)
	}
	// KG_BENCH_KEEP leaves the fixture in place so a plan can be inspected
	// against the same graph the numbers came from.
	if os.Getenv("KG_BENCH_KEEP") == "" {
		tb.Cleanup(func() {
			for _, table := range []string{"kg_observations", "kg_relationships", "kg_entities"} {
				_, _ = pool.Exec(context.Background(), `DELETE FROM `+table+` WHERE tenant_id = $1`, tenantID)
			}
			_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID)
		})
	} else {
		tb.Logf("KG_BENCH_KEEP is set: tenant %s is left in place", tenantID)
	}

	ids := make([]uuid.UUID, benchEntities)
	entityRows := make([][]any, 0, benchEntities)
	for i := range ids {
		ids[i] = uuid.New()
		entityRows = append(entityRows, []any{
			ids[i], tenantID, model.EntityTypeAsset, fmt.Sprintf("host-%05d", i),
			float64(i % 10), 1.0, []string{},
		})
	}
	if _, err := pool.CopyFrom(ctx,
		pgx.Identifier{"kg_entities"},
		[]string{"id", "tenant_id", "entity_type", "name", "risk_score", "confidence", "tags"},
		pgx.CopyFromRows(entityRows)); err != nil {
		tb.Fatalf("copy entities: %v", err)
	}

	rng := rand.New(rand.NewSource(1))
	seen := map[[2]int]bool{}
	relRows := make([][]any, 0, benchEntities*benchDegree)
	add := func(i, j int) {
		if i == j || seen[[2]int{i, j}] {
			return
		}
		seen[[2]int{i, j}] = true
		relRows = append(relRows, []any{
			uuid.New(), tenantID, ids[i], ids[j], model.RelConnectTo,
			1.0, 1.0, model.SourceComputed,
		})
	}
	for i := range ids {
		base := (i / benchCluster) * benchCluster
		size := min(benchCluster, benchEntities-base)
		for d := 0; d < benchDegree-1; d++ {
			add(i, base+rng.Intn(size))
		}
		// One edge in twenty leaves the cluster, which is what keeps the graph
		// connected without collapsing every distance to two.
		if rng.Intn(20) == 0 {
			add(i, rng.Intn(benchEntities))
		}
	}
	if _, err := pool.CopyFrom(ctx,
		pgx.Identifier{"kg_relationships"},
		[]string{"id", "tenant_id", "source_id", "target_id", "relationship_type",
			"weight", "confidence", "evidence_source"},
		pgx.CopyFromRows(relRows)); err != nil {
		tb.Fatalf("copy relationships: %v", err)
	}
	tb.Logf("seeded %d entities and %d relationships", len(entityRows), len(relRows))

	return tenantID, ids[0]
}

func benchNeighbors(b *testing.B, walkFrom func(context.Context, model.NeighborQuery) ([]model.KGNeighbor, error),
	tenantID, rootID uuid.UUID, hops int) {
	ctx := context.Background()
	q := model.NeighborQuery{TenantID: tenantID, EntityID: rootID, MaxHops: hops, Direction: "both"}

	// One untimed run to report the size of the answer: a traversal that finds
	// nothing is fast and meaningless.
	warm, err := walkFrom(ctx, q)
	if err != nil {
		b.Skipf("%d hop(s): %v", hops, err)
	}
	b.ReportMetric(float64(len(warm)), "neighbours")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := walkFrom(ctx, q); err != nil {
			b.Fatalf("hop %d: %v", hops, err)
		}
	}
}

func BenchmarkNeighbors(b *testing.B) {
	pool, repo := kgTestDB(b)
	tenantID, rootID := seedBenchGraph(b, pool)
	neo := kgTestNeo4j(b, repo)
	ctx := context.Background()
	if err := neo.DeleteTenantGraph(ctx, tenantID); err != nil {
		b.Fatalf("clean neo4j: %v", err)
	}
	if os.Getenv("KG_BENCH_KEEP") == "" {
		b.Cleanup(func() { _ = neo.DeleteTenantGraph(context.Background(), tenantID) })
	}

	start := time.Now()
	entities, rels, err := neo.MirrorTenant(ctx, tenantID)
	if err != nil {
		b.Fatalf("MirrorTenant: %v", err)
	}
	b.Logf("mirrored %d entities and %d relationships in %s", entities, rels, time.Since(start).Round(time.Millisecond))

	for _, hops := range []int{1, 2, 3, 4} {
		b.Run(fmt.Sprintf("postgres/%dhop", hops), func(b *testing.B) {
			benchNeighbors(b, repo.Neighbors, tenantID, rootID, hops)
		})
		b.Run(fmt.Sprintf("neo4j/%dhop", hops), func(b *testing.B) {
			benchNeighbors(b, neo.Neighbors, tenantID, rootID, hops)
		})
	}
}

// BenchmarkAdjacency isolates the store from the walk.
//
// The walk is shared, so a difference between the two stores can only come from
// this one query and from decoding its result. Measuring it separately is what
// says which of the two a difference is: a slow query is a query to fix, while
// slow decoding is the price of the store's data model and no amount of Cypher
// will change it.
func BenchmarkAdjacency(b *testing.B) {
	pool, repo := kgTestDB(b)
	tenantID, rootID := seedBenchGraph(b, pool)
	neo := kgTestNeo4j(b, repo)
	ctx := context.Background()
	if err := neo.DeleteTenantGraph(ctx, tenantID); err != nil {
		b.Fatalf("clean neo4j: %v", err)
	}
	if os.Getenv("KG_BENCH_KEEP") == "" {
		b.Cleanup(func() { _ = neo.DeleteTenantGraph(context.Background(), tenantID) })
	}
	if _, _, err := neo.MirrorTenant(ctx, tenantID); err != nil {
		b.Fatalf("MirrorTenant: %v", err)
	}

	// A frontier the size of a third hop, built once from the real graph.
	seed, err := repo.Neighbors(ctx, model.NeighborQuery{
		TenantID: tenantID, EntityID: rootID, MaxHops: 2, Direction: "both",
	})
	if err != nil {
		b.Fatalf("seed frontier: %v", err)
	}
	frontier := make([]uuid.UUID, 0, len(seed))
	for _, n := range seed {
		frontier = append(frontier, n.Entity.ID)
	}
	b.Logf("frontier of %d entities", len(frontier))

	b.Run("postgres", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rels, err := repo.adjacentRelationships(ctx, tenantID, frontier, "both", nil)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportMetric(float64(len(rels)), "rels")
		}
	})
	b.Run("neo4j", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rels, err := neo.adjacentRelationships(ctx, tenantID, frontier, "both", nil)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportMetric(float64(len(rels)), "rels")
		}
	})
	b.Run("neo4j-query-only", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := neo.adjacencyRecords(ctx, tenantID, frontier, "both", nil); err != nil {
				b.Fatal(err)
			}
		}
	})
}
