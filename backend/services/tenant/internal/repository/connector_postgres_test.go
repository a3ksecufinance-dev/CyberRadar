package repository

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/testinfra"
	"github.com/cyberradar/platform/services/tenant/internal/model"
)

// The registry holds what somebody declared about a source of telemetry. Two
// things matter about it beyond storing rows: one customer must never see or
// touch another's, and a partial update must not quietly revert the fields it
// did not mention — which is the usual way a configuration screen destroys a
// setting somebody made yesterday.

func connectorRepo(t *testing.T) (*ConnectorRepository, *pgxpool.Pool) {
	t.Helper()
	pool := testinfra.Postgres(t)
	return NewConnectorRepository(pool), pool
}

func aTenant(t *testing.T, pool *pgxpool.Pool, slug string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, id, slug); err != nil {
		t.Fatalf("insert tenant %s: %v", slug, err)
	}
	return id
}

func aConnector(name string) *model.CreateConnectorRequest {
	return &model.CreateConnectorRequest{
		Name:       name,
		SourceType: "firewall",
		Format:     "cef",
		Config:     json.RawMessage(`{"host":"10.0.0.1","port":514}`),
	}
}

func TestAConnectorIsRegisteredAndReadBack(t *testing.T) {
	repo, pool := connectorRepo(t)
	ctx := context.Background()
	tenant := aTenant(t, pool, "reg-"+uuid.NewString()[:8])

	created, err := repo.Create(ctx, tenant, aConnector("pare-feu-siege"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.Name != "pare-feu-siege" || created.Format != "cef" {
		t.Errorf("stored %q/%q, want pare-feu-siege/cef", created.Name, created.Format)
	}
	if !created.Enabled {
		t.Error("a connector is collected unless somebody says otherwise")
	}
	if created.SilentAfter.Hours() != 1 {
		t.Errorf("default silence threshold is %s, want 1h", created.SilentAfter)
	}

	read, err := repo.Get(ctx, tenant, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(read.Config) != `{"host": "10.0.0.1", "port": 514}` && string(read.Config) != `{"host":"10.0.0.1","port":514}` {
		t.Errorf("config came back as %s", read.Config)
	}
}

// A name is what an operator types when something is wrong. Two sources of one
// tenant sharing one wastes the minutes that matter.
func TestTwoConnectorsOfOneTenantCannotShareAName(t *testing.T) {
	repo, pool := connectorRepo(t)
	ctx := context.Background()
	tenant := aTenant(t, pool, "dup-"+uuid.NewString()[:8])

	if _, err := repo.Create(ctx, tenant, aConnector("pare-feu-siege")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := repo.Create(ctx, tenant, aConnector("pare-feu-siege")); err == nil {
		t.Fatal("the registry accepted a duplicate name")
	}
}

// Two customers may both call their firewall the same thing.
func TestTwoTenantsMayUseTheSameConnectorName(t *testing.T) {
	repo, pool := connectorRepo(t)
	ctx := context.Background()
	mine := aTenant(t, pool, "mine-"+uuid.NewString()[:8])
	theirs := aTenant(t, pool, "theirs-"+uuid.NewString()[:8])

	if _, err := repo.Create(ctx, mine, aConnector("pare-feu-siege")); err != nil {
		t.Fatalf("Create for the first tenant: %v", err)
	}
	if _, err := repo.Create(ctx, theirs, aConnector("pare-feu-siege")); err != nil {
		t.Fatalf("a second tenant was refused a name the first had used: %v", err)
	}
}

// The boundary, from the other side: a tenant must not reach a connector that
// is not its own, by id or otherwise.
func TestAConnectorIsInvisibleToAnotherTenant(t *testing.T) {
	repo, pool := connectorRepo(t)
	ctx := context.Background()
	mine := aTenant(t, pool, "a-"+uuid.NewString()[:8])
	theirs := aTenant(t, pool, "b-"+uuid.NewString()[:8])

	c, err := repo.Create(ctx, mine, aConnector("pare-feu-siege"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := repo.Get(ctx, theirs, c.ID); !apierrors.IsKind(err, apierrors.KindNotFound) {
		t.Errorf("another tenant read the connector: err=%v", err)
	}
	if _, err := repo.Update(ctx, theirs, c.ID, &model.UpdateConnectorRequest{
		Name: ptr("renamed-by-a-stranger"),
	}); !apierrors.IsKind(err, apierrors.KindNotFound) {
		t.Errorf("another tenant renamed the connector: err=%v", err)
	}
	if err := repo.Delete(ctx, theirs, c.ID); !apierrors.IsKind(err, apierrors.KindNotFound) {
		t.Errorf("another tenant deleted the connector: err=%v", err)
	}

	if still, err := repo.Get(ctx, mine, c.ID); err != nil {
		t.Errorf("the owner lost its connector: %v", err)
	} else if still.Name != "pare-feu-siege" {
		t.Errorf("the connector was renamed to %q by someone else", still.Name)
	}
}

// Disabling a connector must not revert its configuration. A caller that
// sends one field is saying nothing about the others, and treating silence as
// "set it to the zero value" is how yesterday's settings disappear.
func TestAPartialUpdateLeavesTheRestAlone(t *testing.T) {
	repo, pool := connectorRepo(t)
	ctx := context.Background()
	tenant := aTenant(t, pool, "upd-"+uuid.NewString()[:8])

	created, err := repo.Create(ctx, tenant, aConnector("pare-feu-siege"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	updated, err := repo.Update(ctx, tenant, created.ID, &model.UpdateConnectorRequest{
		Enabled: boolPtr(false),
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Enabled {
		t.Error("the connector is still enabled")
	}
	if updated.Name != "pare-feu-siege" {
		t.Errorf("the name became %q", updated.Name)
	}
	if updated.SourceType != "firewall" || updated.Format != "cef" {
		t.Errorf("type/format became %q/%q", updated.SourceType, updated.Format)
	}
	if len(updated.Config) == 0 || string(updated.Config) == "{}" {
		t.Errorf("the configuration was emptied: %s", updated.Config)
	}
	if updated.SilentAfter.Hours() != 1 {
		t.Errorf("the silence threshold became %s", updated.SilentAfter)
	}
}

// ptr for strings already exists in this package; this is its bool twin.
func boolPtr(v bool) *bool { return &v }
