package repository

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// superAdminTestDB connects to the database these tests need.
//
// Skipping when none is reachable keeps the suite usable on a laptop, but a
// skip is indistinguishable from a pass in CI output, so setting
// IDENTITY_TEST_DSN turns the skip into a failure. CI sets it.
func superAdminTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()

	dsn, required := os.LookupEnv("IDENTITY_TEST_DSN")
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
			t.Fatalf("IDENTITY_TEST_DSN is set to %s but it is not reachable: %v", dsn, err)
		}
		t.Skipf("no database at %s (set IDENTITY_TEST_DSN to require one): %v", dsn, err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// super_admin used to hold no permission at all: 000029 left it out of the
// matrix because the code bypassed the check for it. The bypass is gone, so
// the matrix is now the only record of what a platform operator may do — and
// a permission added by a later migration without a matching grant would take
// authority away from the account that is supposed to have all of it.
//
// This test is what makes that a build failure rather than a 403 in
// production. When it fails, grant the named permissions to super_admin in the
// migration that introduced them.
func TestSuperAdminHoldsEveryPermission(t *testing.T) {
	pool := superAdminTestDB(t)
	ctx := context.Background()

	rows, err := pool.Query(ctx, `
		SELECT p.resource || ':' || p.action
		FROM permissions p
		WHERE NOT EXISTS (
			SELECT 1
			FROM role_permissions rp
			JOIN roles r ON r.id = rp.role_id
			WHERE rp.permission_id = p.id AND r.name = 'super_admin'
		)
		ORDER BY 1`)
	if err != nil {
		t.Fatalf("query ungranted permissions: %v", err)
	}
	defer rows.Close()

	var missing []string
	for rows.Next() {
		var perm string
		if err := rows.Scan(&perm); err != nil {
			t.Fatalf("scan: %v", err)
		}
		missing = append(missing, perm)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}

	if len(missing) > 0 {
		t.Errorf("super_admin is missing %d permission(s): %v", len(missing), missing)
	}

	// A matrix that is empty would also pass the check above, so confirm the
	// catalogue is actually populated.
	var total int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM permissions`).Scan(&total); err != nil {
		t.Fatalf("count permissions: %v", err)
	}
	if total == 0 {
		t.Fatal("the permission catalogue is empty — migrations did not run")
	}
}

// The role is the authority; the column describes the identity. They must not
// disagree, or the platform is back to two administrators.
func TestSuperAdminRoleAndPrivilegeLevelAgree(t *testing.T) {
	pool := superAdminTestDB(t)

	var disagreeing int
	err := pool.QueryRow(context.Background(), `
		SELECT COUNT(*)
		FROM identities i
		WHERE (i.privilege_level = 'super_admin') <> EXISTS (
			SELECT 1 FROM identity_roles ir
			JOIN roles r ON r.id = ir.role_id
			WHERE ir.identity_id = i.id AND r.name = 'super_admin'
		)`).Scan(&disagreeing)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if disagreeing > 0 {
		t.Errorf("%d identity(ies) hold the super_admin role without the privilege level, or the reverse", disagreeing)
	}
}
