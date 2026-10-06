package testinfra

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NewTenant inserts a tenant and returns its id.
//
// Nearly every repository test needs one, because nearly every table in the
// platform carries a tenant_id that references tenants(id). Written once here
// rather than copied into fifteen service modules, where the copies would
// drift and each would be slightly wrong about the columns.
//
// The slug is random, so two tests in the same database — or the same test run
// twice against a shared instance — do not collide on the unique index.
func NewTenant(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	return NewNamedTenant(t, pool, "Banque de test")
}

// NewNamedTenant is NewTenant with a name a failure message can tell apart.
func NewNamedTenant(t *testing.T, pool *pgxpool.Pool, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(context.Background(), `
		INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id`,
		name, "t-"+uuid.NewString()[:12]).Scan(&id)
	if err != nil {
		t.Fatalf("testinfra: create a tenant: %v", err)
	}
	return id
}

// NewIdentity inserts a user in a tenant and returns its id.
//
// A table that records who did something references identities(id), so a test
// that passes a random UUID as the author is refused by the foreign key — and
// a test that works around that by passing nil stops covering the column.
func NewIdentity(t *testing.T, pool *pgxpool.Pool, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	short := uuid.NewString()[:8]
	var id uuid.UUID
	err := pool.QueryRow(context.Background(), `
		INSERT INTO identities (tenant_id, username, email, display_name)
		VALUES ($1, $2, $3, $4) RETURNING id`,
		tenantID, "u-"+short, "u-"+short+"@example.test", "Utilisateur de test").Scan(&id)
	if err != nil {
		t.Fatalf("testinfra: create an identity: %v", err)
	}
	return id
}
