package service

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/cyberradar/platform/services/attackpath/internal/model"
	"github.com/cyberradar/platform/services/attackpath/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These benchmarks exist to decide a design question rather than to chase a
// number. The roadmap says the traversal should be pushed into Cypher so that
// it runs where the data is instead of loading the tenant's whole graph into
// the process. Whether that pays depends on two things this measures: what
// LoadGraph actually costs, and how the two stores compare at the same work.
//
// They build a graph once and reuse it, so run them with -benchtime=Nx.

const (
	benchNodes   = 20000
	benchDegree  = 8
	benchCluster = 150
)

// seedBenchGraph builds a tenant shaped like a real estate rather than a random
// graph: nodes sit in clusters — a subnet, a business line — densely connected
// inside and sparsely joined across. The shape matters more than the size: a
// uniformly random graph of this degree reaches everything in two hops, so a
// traversal measures nothing past one.
func seedBenchGraph(tb testing.TB, pool *pgxpool.Pool) (tenantID uuid.UUID, ids []uuid.UUID) {
	tb.Helper()
	ctx := context.Background()

	tenantID = uuid.New()
	slug := "apbench-" + tenantID.String()[:8]
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (id, name, slug, status) VALUES ($1,$2,$3,'active')`,
		tenantID, slug, slug); err != nil {
		tb.Fatalf("seed tenant: %v", err)
	}
	if os.Getenv("AP_BENCH_KEEP") == "" {
		tb.Cleanup(func() {
			for _, table := range []string{"attack_paths", "attack_scenarios", "attack_edges", "attack_nodes"} {
				_, _ = pool.Exec(context.Background(), `DELETE FROM `+table+` WHERE tenant_id = $1`, tenantID)
			}
			_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID)
		})
	} else {
		tb.Logf("AP_BENCH_KEEP is set: tenant %s is left in place", tenantID)
	}

	ids = make([]uuid.UUID, benchNodes)
	nodeRows := make([][]any, 0, benchNodes)
	for i := range ids {
		ids[i] = uuid.New()
		nodeRows = append(nodeRows, []any{
			ids[i], tenantID, uuid.New(), model.NodeTypeAsset,
			fmt.Sprintf("host-%05d", i), float64(i % 10), i%4 + 1,
		})
	}
	if _, err := pool.CopyFrom(ctx,
		pgx.Identifier{"attack_nodes"},
		[]string{"id", "tenant_id", "ref_id", "node_type", "label", "risk_score", "criticality"},
		pgx.CopyFromRows(nodeRows)); err != nil {
		tb.Fatalf("copy nodes: %v", err)
	}

	rng := rand.New(rand.NewSource(1))
	seen := map[[2]int]bool{}
	edgeRows := make([][]any, 0, benchNodes*benchDegree)
	add := func(i, j int) {
		if i == j || seen[[2]int{i, j}] {
			return
		}
		seen[[2]int{i, j}] = true
		edgeRows = append(edgeRows, []any{
			uuid.New(), tenantID, ids[i], ids[j], model.EdgeTypeNetworkAccess,
			"LOW", "NONE", 1.0 + rng.Float64(), "computed",
		})
	}
	for i := range ids {
		base := (i / benchCluster) * benchCluster
		size := min(benchCluster, benchNodes-base)
		for d := 0; d < benchDegree-1; d++ {
			add(i, base+rng.Intn(size))
		}
		if rng.Intn(20) == 0 {
			add(i, rng.Intn(benchNodes))
		}
	}
	if _, err := pool.CopyFrom(ctx,
		pgx.Identifier{"attack_edges"},
		[]string{"id", "tenant_id", "source_id", "target_id", "edge_type",
			"attack_complexity", "privileges_required", "weight", "evidence_source"},
		pgx.CopyFromRows(edgeRows)); err != nil {
		tb.Fatalf("copy edges: %v", err)
	}
	tb.Logf("seeded %d nodes and %d edges", len(nodeRows), len(edgeRows))
	return tenantID, ids
}

// BenchmarkLoadGraph is the cost the roadmap wants removed from the hot path:
// every scenario run pulls the tenant's whole graph into the process first.
func BenchmarkLoadGraph(b *testing.B) {
	pool, repo := benchStores(b)
	tenantID, _ := seedBenchGraph(b, pool)
	ctx := context.Background()

	neo := parityNeo4j(b, repo)
	if err := neo.DeleteTenantGraph(ctx, tenantID); err != nil {
		b.Fatalf("clean neo4j: %v", err)
	}
	if os.Getenv("AP_BENCH_KEEP") == "" {
		b.Cleanup(func() { _ = neo.DeleteTenantGraph(context.Background(), tenantID) })
	}
	start := time.Now()
	nodes, edges, err := neo.MirrorTenant(ctx, tenantID)
	if err != nil {
		b.Fatalf("MirrorTenant: %v", err)
	}
	b.Logf("mirrored %d nodes and %d edges in %s", nodes, edges, time.Since(start).Round(time.Millisecond))

	b.Run("postgres", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			g, err := repo.LoadGraph(ctx, tenantID)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportMetric(float64(len(g.Nodes)), "nodes")
		}
	})
	b.Run("neo4j", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			g, err := neo.LoadGraph(ctx, tenantID)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportMetric(float64(len(g.Nodes)), "nodes")
		}
	})
}

func benchStores(tb testing.TB) (*pgxpool.Pool, *repository.GraphRepository) {
	tb.Helper()
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
			tb.Fatalf("ATTACKPATH_TEST_DSN is set to %s but it is not reachable: %v", dsn, err)
		}
		tb.Skipf("no database at %s: %v", dsn, err)
	}
	tb.Cleanup(pool.Close)
	return pool, repository.NewGraphRepository(pool)
}

// BenchmarkFindPaths is the point of the change: the routes are enumerated in
// the store, and nothing but the routes crosses the wire.
//
// "loadgraph+walk" is what it replaced — the tenant's whole graph pulled into
// the process on every scenario run, then walked in memory. It is kept here as
// the baseline so the claim is a measurement rather than an assertion.
func BenchmarkFindPaths(b *testing.B) {
	pool, repo := benchStores(b)
	tenantID, ids := seedBenchGraph(b, pool)
	ctx := context.Background()

	neo := parityNeo4j(b, repo)
	if err := neo.DeleteTenantGraph(ctx, tenantID); err != nil {
		b.Fatalf("clean neo4j: %v", err)
	}
	if os.Getenv("AP_BENCH_KEEP") == "" {
		b.Cleanup(func() { _ = neo.DeleteTenantGraph(context.Background(), tenantID) })
	}
	start := time.Now()
	nodes, edges, err := neo.MirrorTenant(ctx, tenantID)
	if err != nil {
		b.Fatalf("MirrorTenant: %v", err)
	}
	b.Logf("mirrored %d nodes and %d edges in %s", nodes, edges, time.Since(start).Round(time.Millisecond))

	// An entry and a target in the same cluster, four hops apart at most:
	// the shape of a scenario an analyst actually writes.
	scenario := &model.AttackScenario{
		ID: uuid.New(), TenantID: tenantID, MaxHops: 4,
		TargetNodeIDs: []uuid.UUID{ids[benchCluster-1]},
	}
	entryID := ids[0]

	report := func(b *testing.B, found []model.DiscoveredPath) {
		b.ReportMetric(float64(len(found)), "routes")
	}

	b.Run("postgres", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			found, _, err := repo.FindPaths(ctx, scenario, entryID, maxPathsPerScenario)
			if err != nil {
				b.Fatal(err)
			}
			report(b, found)
		}
	})
	b.Run("neo4j", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			found, _, err := neo.FindPaths(ctx, scenario, entryID, maxPathsPerScenario)
			if err != nil {
				b.Fatal(err)
			}
			report(b, found)
		}
	})
	b.Run("loadgraph+walk", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			g, err := repo.LoadGraph(ctx, tenantID)
			if err != nil {
				b.Fatal(err)
			}
			found, _, err := NewGraphPathFinder(g).FindPaths(ctx, scenario, entryID, maxPathsPerScenario)
			if err != nil {
				b.Fatal(err)
			}
			report(b, found)
		}
	})
}
