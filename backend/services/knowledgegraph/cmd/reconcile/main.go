// Command reconcile compares the knowledge graph in PostgreSQL with the one in
// Neo4j and reports what they disagree about.
//
// It is the safety gate of the Neo4j migration. Mirrored writes can fail — the
// mirror is deliberately not allowed to fail a write to the source of truth —
// so the two stores can drift, and a traversal reading a drifted graph asserts
// connections that do not exist, or misses the ones that do. Pointing reads at
// Neo4j (KG_GRAPH_READS=neo4j) is only defensible once this reports parity for
// the tenants concerned.
//
//	# what differs, for every active tenant
//	kg-reconcile
//
//	# copy PostgreSQL over Neo4j first, then verify
//	kg-reconcile -backfill
//
//	# one tenant, machine-readable, for a scheduled check
//	kg-reconcile -tenant 0b3f… -json
//
// It exits non-zero when the stores disagree, so a scheduled run is an alert
// rather than a log line nobody reads.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/cyberradar/platform/internal/pkg/db"
	"github.com/cyberradar/platform/internal/pkg/graphdb"
	"github.com/cyberradar/platform/internal/pkg/kpi"
	"github.com/cyberradar/platform/services/knowledgegraph/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	var (
		tenantFlag = flag.String("tenant", "", "reconcile one tenant (default: every active tenant)")
		backfill   = flag.Bool("backfill", false, "copy PostgreSQL's graph into Neo4j before comparing")
		asJSON     = flag.Bool("json", false, "emit the divergence report as JSON")
		timeout    = flag.Duration("timeout", 10*time.Minute, "overall deadline")
	)
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if err := run(ctx, *tenantFlag, *backfill, *asJSON); err != nil {
		fmt.Fprintln(os.Stderr, "kg-reconcile:", err)
		os.Exit(2)
	}
}

func run(ctx context.Context, tenantFlag string, backfill, asJSON bool) error {
	dsn := os.Getenv("DATABASE_URL")
	cfg, configured := graphdb.FromEnv(os.Getenv)
	if dsn == "" || !configured {
		return fmt.Errorf("DATABASE_URL and NEO4J_URI are both required")
	}

	pool, err := db.NewPostgresPool(ctx, db.DefaultPostgresConfig(dsn))
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer pool.Close()

	store, err := repository.NewNeo4jGraphStore(ctx, cfg, repository.NewKGRepository(pool))
	if err != nil {
		return err
	}
	defer func() { _ = store.Close(context.Background()) }()

	tenants, err := tenantList(ctx, pool, tenantFlag)
	if err != nil {
		return err
	}
	if len(tenants) == 0 {
		return fmt.Errorf("no active tenant to reconcile")
	}

	reports := make([]*repository.GraphDivergence, 0, len(tenants))
	diverged := 0
	for _, tenantID := range tenants {
		if backfill {
			entities, rels, err := store.MirrorTenant(ctx, tenantID)
			if err != nil {
				return fmt.Errorf("backfill %s: %w", tenantID, err)
			}
			if !asJSON {
				fmt.Printf("%s  backfilled %d entities, %d relationships\n", tenantID, entities, rels)
			}
		}
		d, err := store.Reconcile(ctx, tenantID)
		if err != nil {
			return err
		}
		reports = append(reports, d)
		if !d.InParity() {
			diverged++
		}
		if !asJSON {
			report(d)
		}
	}

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(reports); err != nil {
			return err
		}
	}

	if diverged > 0 {
		// A non-zero exit is the point: a scheduled reconciliation that always
		// succeeds tells an operator nothing.
		return fmt.Errorf("%d of %d tenant(s) diverged", diverged, len(tenants))
	}
	if !asJSON {
		fmt.Printf("\n%d tenant(s) in parity — reads may be switched to neo4j\n", len(tenants))
	}
	return nil
}

func tenantList(ctx context.Context, pool *pgxpool.Pool, tenantFlag string) ([]uuid.UUID, error) {
	if tenantFlag != "" {
		id, err := uuid.Parse(tenantFlag)
		if err != nil {
			return nil, fmt.Errorf("tenant %q: %w", tenantFlag, err)
		}
		return []uuid.UUID{id}, nil
	}
	return kpi.TenantsFromPostgres(pool)(ctx)
}

func report(d *repository.GraphDivergence) {
	status := "in parity"
	if !d.InParity() {
		status = fmt.Sprintf("%d difference(s)", d.Count())
	}
	fmt.Printf("%s  postgres %d entities / %d relationships · neo4j %d / %d — %s\n",
		d.TenantID, d.EntitiesInPostgres, d.RelationshipsInPostgres,
		d.EntitiesInNeo4j, d.RelationshipsInNeo4j, status)

	line := func(label string, ids []uuid.UUID) {
		if len(ids) == 0 {
			return
		}
		fmt.Printf("    %-32s %d", label, len(ids))
		for i, id := range ids {
			if i == 5 {
				fmt.Printf("  …")
				break
			}
			fmt.Printf("  %s", id)
		}
		fmt.Println()
	}
	line("entities only in postgres", d.EntitiesOnlyInPostgres)
	line("entities only in neo4j", d.EntitiesOnlyInNeo4j)
	line("entities differing", d.EntitiesDiffering)
	line("relationships only in postgres", d.RelsOnlyInPostgres)
	line("relationships only in neo4j", d.RelsOnlyInNeo4j)
	line("relationships differing", d.RelsDiffering)
}
