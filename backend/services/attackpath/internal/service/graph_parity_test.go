package service

import (
	"context"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/cyberradar/platform/internal/pkg/graphdb"
	"github.com/cyberradar/platform/services/attackpath/internal/model"
	"github.com/cyberradar/platform/services/attackpath/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// The traversal is written against GraphStore precisely so that where the graph
// lives is a deployment choice. This is the test that makes that true rather
// than merely stated: the same scenario, on the same graph, run once from
// PostgreSQL and once from Neo4j, must find the same attack paths.
//
// It needs both stores. As elsewhere in this repository, a skip is
// indistinguishable from a pass in CI output, so setting ATTACKPATH_TEST_DSN
// and ATTACKPATH_TEST_NEO4J turns each skip into a failure. CI sets both.
func TestTheTraversalFindsTheSamePathsFromEitherStore(t *testing.T) {
	pool, pg := parityPostgres(t)
	neo := parityNeo4j(t, pg)
	ctx := context.Background()

	tenantID := parityTenant(t, pool)
	t.Cleanup(func() { _ = neo.DeleteTenantGraph(ctx, tenantID) })

	// A shape with more than one route to the target, so an implementation
	// that loses an edge is caught rather than merely finding "a" path:
	//
	//   dmz ──► app ──► db(target)
	//    └────► jump ──► db
	labels := []string{"dmz", "app", "jump", "db"}
	nodes := map[string]*model.AttackNode{}
	for i, label := range labels {
		n, err := pg.UpsertNode(ctx, tenantID, &model.CreateNodeRequest{
			RefID: uuid.New(), NodeType: model.NodeTypeAsset, Label: label,
			RiskScore: float64(i + 4), Criticality: i%4 + 1,
			IsInternetFacing: label == "dmz",
			IsCriticalSystem: label == "db",
		})
		if err != nil {
			t.Fatalf("UpsertNode %s: %v", label, err)
		}
		nodes[label] = n
	}
	links := [][3]string{
		{"dmz", "app", "LOW"}, {"app", "db", "MEDIUM"},
		{"dmz", "jump", "MEDIUM"}, {"jump", "db", "HIGH"},
	}
	for _, l := range links {
		if _, err := pg.UpsertEdge(ctx, tenantID, &model.CreateEdgeRequest{
			SourceID: nodes[l[0]].ID, TargetID: nodes[l[1]].ID,
			EdgeType: model.EdgeTypeNetworkAccess, AttackComplexity: l[2],
		}); err != nil {
			t.Fatalf("UpsertEdge %s→%s: %v", l[0], l[1], err)
		}
	}
	if _, _, err := neo.MirrorTenant(ctx, tenantID); err != nil {
		t.Fatalf("MirrorTenant: %v", err)
	}
	if d, err := neo.Reconcile(ctx, tenantID); err != nil {
		t.Fatalf("Reconcile: %v", err)
	} else if !d.InParity() {
		t.Fatalf("the stores diverged before the traversal even ran: %+v", d)
	}

	fromPostgres := runAndCollect(t, pg, pg, tenantID, nodes)
	fromNeo4j := runAndCollect(t, pg, neo, tenantID, nodes)

	if len(fromPostgres) == 0 {
		t.Fatal("the traversal found no path at all — the fixture is wrong, not the stores")
	}
	if len(fromPostgres) != len(fromNeo4j) {
		t.Fatalf("postgres found %d path(s), neo4j %d\n  postgres: %v\n  neo4j:    %v",
			len(fromPostgres), len(fromNeo4j), fromPostgres, fromNeo4j)
	}
	for i := range fromPostgres {
		if fromPostgres[i] != fromNeo4j[i] {
			t.Errorf("path %d differs:\n  postgres: %s\n  neo4j:    %s", i, fromPostgres[i], fromNeo4j[i])
		}
	}
}

// runAndCollect runs one scenario against one store and returns what it found,
// as comparable strings. Scenario and path records are written to PostgreSQL in
// both cases: only the graph moves to Neo4j.
func runAndCollect(t *testing.T, pg *repository.GraphRepository, store GraphStore,
	tenantID uuid.UUID, nodes map[string]*model.AttackNode) []string {
	t.Helper()
	ctx := context.Background()

	sc, err := pg.CreateScenario(ctx, tenantID, nil, &model.CreateScenarioRequest{
		Name:          fmt.Sprintf("parity-%d", time.Now().UnixNano()),
		EntryNodeIDs:  []uuid.UUID{nodes["dmz"].ID},
		TargetNodeIDs: []uuid.UUID{nodes["db"].ID},
		MaxHops:       5,
	})
	if err != nil {
		t.Fatalf("CreateScenario: %v", err)
	}
	if err := NewAnalyzer(store, nil, zerolog.Nop()).RunScenario(ctx, sc); err != nil {
		t.Fatalf("RunScenario: %v", err)
	}

	paths, _, err := pg.ListPaths(ctx, model.PathFilter{TenantID: tenantID, ScenarioID: &sc.ID, Limit: 100})
	if err != nil {
		t.Fatalf("ListPaths: %v", err)
	}

	// The path identifier is generated per run, so compare what the analyst
	// actually reads: the route, its length, its score and its flags.
	byLabel := map[uuid.UUID]string{}
	for label, n := range nodes {
		byLabel[n.ID] = label
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		route := make([]string, 0, len(p.NodeSequence))
		for _, id := range p.NodeSequence {
			route = append(route, byLabel[id])
		}
		out = append(out, fmt.Sprintf("%v hops=%d score=%.4f likelihood=%.4f impact=%.4f type=%s internet=%t exploit=%t privesc=%t",
			route, p.HopCount, p.PathScore, p.Likelihood, p.Impact, p.PathType,
			p.HasInternetEntry, p.HasExploitStep, p.HasPrivEsc))
	}
	sort.Strings(out)
	return out
}

// ─── Fixtures ─────────────────────────────────────────────────────────────────

func parityPostgres(t *testing.T) (*pgxpool.Pool, *repository.GraphRepository) {
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
	return pool, repository.NewGraphRepository(pool)
}

func parityNeo4j(t testing.TB, pg *repository.GraphRepository) *repository.Neo4jGraphStore {
	t.Helper()
	uri, required := os.LookupEnv("ATTACKPATH_TEST_NEO4J")
	if !required {
		uri = "bolt://localhost:7687"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	store, err := repository.NewNeo4jGraphStore(ctx, graphdb.Config{
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

func parityTenant(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	slug := "parity-" + id.String()[:8]
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (id, name, slug, status) VALUES ($1, $2, $3, 'active')`,
		id, slug, slug); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		for _, table := range []string{"attack_paths", "attack_scenarios", "attack_edges", "attack_nodes"} {
			_, _ = pool.Exec(ctx, `DELETE FROM `+table+` WHERE tenant_id = $1`, id)
		}
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, id)
	})
	return id
}
