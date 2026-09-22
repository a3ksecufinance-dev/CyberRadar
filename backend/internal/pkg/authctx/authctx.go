// Package authctx carries the authenticated caller's identity through a
// request context.
//
// The context key is a private zero-size type, so no other package can write a
// colliding value and every read goes through the accessors below. This is
// deliberate: the previous convention stored claims under untyped string keys
// and read them back with per-service key types and value types, so a mismatch
// compiled cleanly and silently yielded the zero value at runtime — dropping
// tenant isolation on five services without any build or vet error.
package authctx

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

type contextKey struct{}

// Identity is the authenticated caller behind the current request.
type Identity struct {
	TenantID     uuid.UUID
	UserID       uuid.UUID
	Email        string
	Roles        []string
	Permissions  []string
	IsSuperAdmin bool

	// Token is the caller's raw bearer token, kept so a service calling another
	// service on the caller's behalf can forward it and stay within the caller's
	// own authorization scope. Never log it.
	Token string
}

// Parse converts raw JWT claim values into an Identity.
//
// An absent or malformed tenant is an error: tenant_id is the isolation
// boundary, so an unparseable claim must fail the request rather than degrade
// to the zero UUID and resolve to some other tenant's scope.
func Parse(tenantID, userID, email string, roles []string, isSuperAdmin bool) (Identity, error) {
	tid, err := uuid.Parse(tenantID)
	if err != nil {
		return Identity{}, fmt.Errorf("claim tid %q: %w", tenantID, err)
	}

	// A token may legitimately carry no subject (service-to-service tokens),
	// but a present-and-malformed one is a broken token.
	var uid uuid.UUID
	if userID != "" {
		uid, err = uuid.Parse(userID)
		if err != nil {
			return Identity{}, fmt.Errorf("claim uid %q: %w", userID, err)
		}
	}

	return Identity{
		TenantID:     tid,
		UserID:       uid,
		Email:        email,
		Roles:        roles,
		IsSuperAdmin: isSuperAdmin,
	}, nil
}

// With returns a copy of ctx carrying id.
func With(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// From returns the identity carried by ctx, and whether one was present.
func From(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(contextKey{}).(Identity)
	return id, ok
}

// TenantID returns the caller's tenant, or uuid.Nil on an unauthenticated context.
func TenantID(ctx context.Context) uuid.UUID {
	id, _ := From(ctx)
	return id.TenantID
}

// UserID returns the caller's user, or uuid.Nil when the token carries no subject.
func UserID(ctx context.Context) uuid.UUID {
	id, _ := From(ctx)
	return id.UserID
}

// IsSuperAdmin reports whether the caller bypasses tenant scoping.
func IsSuperAdmin(ctx context.Context) bool {
	id, _ := From(ctx)
	return id.IsSuperAdmin
}

// Roles returns the caller's roles, or nil on an unauthenticated context.
func Roles(ctx context.Context) []string {
	id, _ := From(ctx)
	return id.Roles
}

// Token returns the caller's raw bearer token, for forwarding to another
// service on their behalf. Empty on an unauthenticated context.
func Token(ctx context.Context) string {
	id, _ := From(ctx)
	return id.Token
}

// HasPermission reports whether the caller may perform perm, named
// "resource:action". A super-admin holds every permission, which mirrors the
// bypass in policies/rbac.rego.
func HasPermission(ctx context.Context, perm string) bool {
	id, ok := From(ctx)
	if !ok {
		return false
	}
	if id.IsSuperAdmin {
		return true
	}
	for _, p := range id.Permissions {
		if p == perm {
			return true
		}
	}
	return false
}
