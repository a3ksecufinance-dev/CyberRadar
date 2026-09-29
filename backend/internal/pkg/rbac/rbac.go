// Package rbac resolves what an authenticated caller may do.
//
// It exists because authentication and authorisation come from different
// places. The identity provider says who signed in; this platform's own tables
// say what that person may reach. They are not the same vocabulary — the
// Keycloak realm ships dpo, risk_manager and platform_admin while the platform
// has tenant_admin, threat_hunter and super_admin — and mapping one onto the
// other would mean maintaining both and keeping them in step forever.
//
// So a provider token is trusted for a subject and an email, and nothing else.
// The tenant, the roles and the permissions come from identities,
// identity_roles and role_permissions. A person the provider knows and this
// platform does not gets no access, which is the right answer: an account
// added to the directory is not by itself an account on a bank's security
// platform.
package rbac

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Grant is everything the request context needs about a caller.
type Grant struct {
	IdentityID  uuid.UUID
	TenantID    uuid.UUID
	Email       string
	DisplayName string
	Roles       []string
	Permissions []string
	// IsAdmin is the cross-tenant scope, from privilege_level. It says whose
	// data the caller may reach, not what they may do — permissions answer
	// that. The two were once the same flag and that let one bypass the other.
	IsAdmin bool
}

// ErrNoIdentity means the provider authenticated someone this platform has no
// record of. It is not an authentication failure and must not be reported as
// one: the caller proved who they are, and the answer is that they have no
// account here.
var ErrNoIdentity = fmt.Errorf("rbac: no identity on this platform")

// Resolver reads grants from PostgreSQL and remembers them briefly.
type Resolver struct {
	pool *pgxpool.Pool
	ttl  time.Duration

	mu     sync.RWMutex
	cached map[string]cacheEntry
}

type cacheEntry struct {
	grant   *Grant
	err     error
	expires time.Time
}

// DefaultTTL is how long a resolved grant is reused.
//
// Short, because it bounds how long a revoked role keeps working: taking a
// permission away from someone should take effect in a minute, not at their
// next sign-in. Long enough that a page opening a dozen panels at once does
// not make a dozen identical queries per service.
const DefaultTTL = time.Minute

// NewResolver builds a Resolver over an existing pool.
func NewResolver(pool *pgxpool.Pool) *Resolver {
	return &Resolver{pool: pool, ttl: DefaultTTL, cached: map[string]cacheEntry{}}
}

// WithTTL overrides how long grants are cached. Tests use it; services do not.
func (r *Resolver) WithTTL(ttl time.Duration) *Resolver {
	r.ttl = ttl
	return r
}

// ByEmail resolves the caller an email address belongs to.
//
// The lookup is case-insensitive: a directory that hands back
// Admin@Bank.example for an identity recorded as admin@bank.example would
// otherwise read as a person this platform does not know.
func (r *Resolver) ByEmail(ctx context.Context, email string) (*Grant, error) {
	key := strings.ToLower(strings.TrimSpace(email))
	if key == "" {
		return nil, ErrNoIdentity
	}

	r.mu.RLock()
	entry, found := r.cached[key]
	r.mu.RUnlock()
	if found && time.Now().Before(entry.expires) {
		return entry.grant, entry.err
	}

	grant, err := r.load(ctx, key)

	// A failure to reach the database is not cached: it would turn one bad
	// moment into a minute of refusals for everyone.
	if err == nil || err == ErrNoIdentity {
		r.mu.Lock()
		r.cached[key] = cacheEntry{grant: grant, err: err, expires: time.Now().Add(r.ttl)}
		r.mu.Unlock()
	}
	return grant, err
}

// Forget drops a cached grant, so a role change can be made to take effect at
// once rather than within the TTL.
func (r *Resolver) Forget(email string) {
	r.mu.Lock()
	delete(r.cached, strings.ToLower(strings.TrimSpace(email)))
	r.mu.Unlock()
}

func (r *Resolver) load(ctx context.Context, email string) (*Grant, error) {
	g := &Grant{Email: email}
	var privilege string
	err := r.pool.QueryRow(ctx, `
		SELECT id, tenant_id, COALESCE(display_name, ''), COALESCE(privilege_level, 'standard')
		FROM identities
		WHERE lower(email) = $1 AND status = 'active'`, email,
	).Scan(&g.IdentityID, &g.TenantID, &g.DisplayName, &privilege)
	if err == pgx.ErrNoRows {
		return nil, ErrNoIdentity
	}
	if err != nil {
		return nil, fmt.Errorf("rbac: load identity: %w", err)
	}
	g.IsAdmin = privilege == "super_admin"

	rows, err := r.pool.Query(ctx, `
		SELECT DISTINCT r.name
		FROM identity_roles ir
		JOIN roles r ON r.id = ir.role_id
		WHERE ir.identity_id = $1
		ORDER BY r.name`, g.IdentityID)
	if err != nil {
		return nil, fmt.Errorf("rbac: load roles: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("rbac: scan role: %w", err)
		}
		g.Roles = append(g.Roles, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rbac: load roles: %w", err)
	}

	permRows, err := r.pool.Query(ctx, `
		SELECT DISTINCT p.resource || ':' || p.action
		FROM identity_roles ir
		JOIN role_permissions rp ON rp.role_id = ir.role_id
		JOIN permissions p ON p.id = rp.permission_id
		WHERE ir.identity_id = $1
		ORDER BY 1`, g.IdentityID)
	if err != nil {
		return nil, fmt.Errorf("rbac: load permissions: %w", err)
	}
	defer permRows.Close()
	for permRows.Next() {
		var perm string
		if err := permRows.Scan(&perm); err != nil {
			return nil, fmt.Errorf("rbac: scan permission: %w", err)
		}
		g.Permissions = append(g.Permissions, perm)
	}
	return g, permRows.Err()
}
