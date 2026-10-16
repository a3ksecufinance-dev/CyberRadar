package rbac

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// rbacTestDB connects to the database these tests need.
//
// Skipping when none is reachable keeps the suite usable on a laptop, but a
// skip is indistinguishable from a pass in CI output, so setting RBAC_TEST_DSN
// turns the skip into a failure. CI sets it.
func rbacTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()

	dsn, required := os.LookupEnv("RBAC_TEST_DSN")
	if !required {
		dsn = "postgres://crp_user:crp_password_dev@localhost:5432/crp_foundation?sslmode=disable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err == nil {
		err = pool.Ping(ctx)
	}
	if err != nil {
		if required {
			t.Fatalf("RBAC_TEST_DSN is set to %s but it is not reachable: %v", dsn, err)
		}
		t.Skipf("no database at %s (set RBAC_TEST_DSN to require one): %v", dsn, err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedPerson creates a tenant and one identity holding a role, and returns the
// email it can be resolved by.
func seedPerson(t *testing.T, pool *pgxpool.Pool, roleName, privilege string) (string, uuid.UUID) {
	t.Helper()
	ctx := context.Background()

	tenantID := uuid.New()
	slug := "rbac-" + tenantID.String()[:8]
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (id, name, slug, status) VALUES ($1,$2,$3,'active')`,
		tenantID, slug, slug); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	identityID := uuid.New()
	email := slug + "@bank.example"
	if _, err := pool.Exec(ctx, `
		INSERT INTO identities (id, tenant_id, username, email, display_name, identity_type, privilege_level, status)
		VALUES ($1,$2,$3,$4,$5,'user',$6,'active')`,
		identityID, tenantID, slug, email, "Test Person", privilege); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	if roleName != "" {
		if _, err := pool.Exec(ctx, `
			INSERT INTO identity_roles (identity_id, role_id)
			SELECT $1, id FROM roles WHERE name = $2`, identityID, roleName); err != nil {
			t.Fatalf("assign role: %v", err)
		}
	}

	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM identity_roles WHERE identity_id = $1`, identityID)
		_, _ = pool.Exec(c, `DELETE FROM identities WHERE id = $1`, identityID)
		_, _ = pool.Exec(c, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})
	return email, tenantID
}

// The whole point: the provider says who signed in, and this says what they
// may do — from the platform's own matrix, not from the provider's roles.
func TestPermissionsComeFromThePlatformMatrix(t *testing.T) {
	pool := rbacTestDB(t)
	email, tenantID := seedPerson(t, pool, "soc_analyst_l1", "standard")

	grant, err := NewResolver(pool).ByEmail(context.Background(), email)
	if err != nil {
		t.Fatalf("ByEmail: %v", err)
	}
	if grant.TenantID != tenantID {
		t.Errorf("tenant = %s, want %s", grant.TenantID, tenantID)
	}
	if len(grant.Roles) != 1 || grant.Roles[0] != "soc_analyst_l1" {
		t.Errorf("roles = %v", grant.Roles)
	}
	if len(grant.Permissions) == 0 {
		t.Fatal("no permissions: the role carries none, or the matrix was not read")
	}
	if grant.IsAdmin {
		t.Error("a standard identity was marked cross-tenant")
	}
}

// An account the directory knows and the platform does not gets nothing. An
// account added to a company directory is not by itself an account on a bank's
// security platform.
func TestSomeoneWithNoIdentityHereGetsNothing(t *testing.T) {
	pool := rbacTestDB(t)

	_, err := NewResolver(pool).ByEmail(context.Background(), "stranger@elsewhere.example")
	if !errors.Is(err, ErrNoIdentity) {
		t.Errorf("err = %v, want ErrNoIdentity", err)
	}
	if _, err := NewResolver(pool).ByEmail(context.Background(), "  "); !errors.Is(err, ErrNoIdentity) {
		t.Errorf("an empty email gave %v", err)
	}
}

// A directory that hands back a differently-cased address must still resolve
// to the same person.
func TestEmailMatchingIgnoresCase(t *testing.T) {
	pool := rbacTestDB(t)
	email, _ := seedPerson(t, pool, "auditor", "standard")

	upper := ""
	for _, r := range email {
		if r >= 'a' && r <= 'z' {
			upper += string(r - 32)
		} else {
			upper += string(r)
		}
	}
	if _, err := NewResolver(pool).ByEmail(context.Background(), upper); err != nil {
		t.Errorf("%s did not resolve: %v", upper, err)
	}
}

// The cross-tenant scope comes from privilege_level, and says whose data the
// caller may reach — not what they may do, which is what permissions answer.
func TestCrossTenantScopeComesFromPrivilegeLevel(t *testing.T) {
	pool := rbacTestDB(t)
	email, _ := seedPerson(t, pool, "super_admin", "super_admin")

	grant, err := NewResolver(pool).ByEmail(context.Background(), email)
	if err != nil {
		t.Fatalf("ByEmail: %v", err)
	}
	if !grant.IsAdmin {
		t.Error("a super_admin identity was not marked cross-tenant")
	}
	if len(grant.Permissions) == 0 {
		t.Error("super_admin holds no permissions: the matrix is what grants them, not the flag")
	}
}

// Caching bounds how long a revoked role keeps working. It must expire, and a
// deliberate Forget must take effect at once.
func TestGrantsAreCachedButNotForever(t *testing.T) {
	pool := rbacTestDB(t)
	email, _ := seedPerson(t, pool, "auditor", "standard")
	ctx := context.Background()

	r := NewResolver(pool).WithTTL(50 * time.Millisecond)
	before, err := r.ByEmail(ctx, email)
	if err != nil {
		t.Fatalf("ByEmail: %v", err)
	}
	if len(before.Roles) != 1 {
		t.Fatalf("roles = %v", before.Roles)
	}

	if _, err := pool.Exec(ctx,
		`DELETE FROM identity_roles WHERE identity_id = $1`, before.IdentityID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	cached, _ := r.ByEmail(ctx, email)
	if len(cached.Roles) != 1 {
		t.Error("the grant was not cached at all")
	}

	time.Sleep(80 * time.Millisecond)
	after, err := r.ByEmail(ctx, email)
	if err != nil {
		t.Fatalf("ByEmail after expiry: %v", err)
	}
	if len(after.Roles) != 0 {
		t.Errorf("a revoked role survived the cache: %v", after.Roles)
	}

	// And Forget is the way to make a change take effect without waiting.
	r2 := NewResolver(pool)
	if _, err := r2.ByEmail(ctx, email); err != nil {
		t.Fatalf("ByEmail: %v", err)
	}
	r2.Forget(email)
	if _, err := r2.ByEmail(ctx, email); err != nil {
		t.Fatalf("ByEmail after Forget: %v", err)
	}
}

// A disabled account must stop resolving, whatever the directory still says.
func TestADisabledIdentityResolvesToNothing(t *testing.T) {
	pool := rbacTestDB(t)
	email, _ := seedPerson(t, pool, "auditor", "standard")
	ctx := context.Background()

	if _, err := pool.Exec(ctx,
		`UPDATE identities SET status = 'disabled' WHERE lower(email) = lower($1)`, email); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, err := NewResolver(pool).ByEmail(ctx, email); !errors.Is(err, ErrNoIdentity) {
		t.Errorf("a disabled identity resolved: %v", err)
	}
}
