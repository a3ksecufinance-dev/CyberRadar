package authctx

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

const (
	validTenant = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	validUser   = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
)

func TestParseRejectsMalformedTenant(t *testing.T) {
	for _, tenant := range []string{"", "not-a-uuid", "12345"} {
		if _, err := Parse(tenant, validUser, "a@b.c", nil, false); err == nil {
			t.Errorf("Parse(%q) = nil error, want error: a malformed tenant must fail the request, not degrade to uuid.Nil", tenant)
		}
	}
}

func TestParseAllowsEmptySubject(t *testing.T) {
	id, err := Parse(validTenant, "", "a@b.c", nil, false)
	if err != nil {
		t.Fatalf("Parse with empty uid: %v, want nil (service tokens carry no subject)", err)
	}
	if id.UserID != uuid.Nil {
		t.Errorf("UserID = %v, want uuid.Nil", id.UserID)
	}
}

func TestParseRejectsMalformedSubject(t *testing.T) {
	if _, err := Parse(validTenant, "not-a-uuid", "a@b.c", nil, false); err == nil {
		t.Error("Parse with malformed uid = nil error, want error")
	}
}

func TestRoundTrip(t *testing.T) {
	want, err := Parse(validTenant, validUser, "a@b.c", []string{"analyst"}, true)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	ctx := With(context.Background(), want)

	if got := TenantID(ctx); got != want.TenantID {
		t.Errorf("TenantID = %v, want %v", got, want.TenantID)
	}
	if got := UserID(ctx); got != want.UserID {
		t.Errorf("UserID = %v, want %v", got, want.UserID)
	}
	if !IsSuperAdmin(ctx) {
		t.Error("IsSuperAdmin = false, want true")
	}
	if got := Roles(ctx); len(got) != 1 || got[0] != "analyst" {
		t.Errorf("Roles = %v, want [analyst]", got)
	}
}

func TestAccessorsOnUnauthenticatedContext(t *testing.T) {
	ctx := context.Background()

	if got := TenantID(ctx); got != uuid.Nil {
		t.Errorf("TenantID = %v, want uuid.Nil", got)
	}
	if IsSuperAdmin(ctx) {
		t.Error("IsSuperAdmin = true on an unauthenticated context, want false (must fail closed)")
	}
	if _, ok := From(ctx); ok {
		t.Error("From reported an identity on an unauthenticated context")
	}
}

// TestStringKeyDoesNotCollide guards the bug this package exists to prevent:
// a value written under an untyped string key must not be readable through the
// typed accessors, and vice versa.
func TestStringKeyDoesNotCollide(t *testing.T) {
	//nolint:staticcheck // deliberately using a string key to prove it cannot collide
	ctx := context.WithValue(context.Background(), "tenant_id", validTenant)

	if got := TenantID(ctx); got != uuid.Nil {
		t.Errorf("TenantID read a string-keyed value (%v); the typed key is not isolated", got)
	}

	id, err := Parse(validTenant, validUser, "a@b.c", nil, false)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	//nolint:staticcheck // reading back through a string key must miss
	if v := With(context.Background(), id).Value("tenant_id"); v != nil {
		t.Errorf(`Value("tenant_id") = %v, want nil`, v)
	}
}
