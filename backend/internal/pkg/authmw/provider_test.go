package authmw

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	"github.com/cyberradar/platform/internal/pkg/oidc"
	"github.com/cyberradar/platform/internal/pkg/rbac"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

type fakeProvider struct {
	claims *oidc.Claims
	err    error
}

func (f fakeProvider) Validate(context.Context, string) (*oidc.Claims, error) {
	return f.claims, f.err
}

type fakeGrants struct {
	grant *rbac.Grant
	err   error
}

func (f fakeGrants) ByEmail(context.Context, string) (*rbac.Grant, error) {
	return f.grant, f.err
}

// seen records the identity the handler was given, so a test can check what
// the middleware put in the context rather than only the status code.
func seen(identity *authctx.Identity) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := authctx.From(r.Context()); ok {
			*identity = id
		}
		w.WriteHeader(http.StatusOK)
	})
}

func callWith(t *testing.T, provider ProviderVerifier, grants GrantResolver) (*httptest.ResponseRecorder, authctx.Identity) {
	t.Helper()
	// A verifier holding a key that signed nothing here, so the platform path
	// refuses and the provider path is the one under test — which is exactly
	// what happens in production with a Keycloak token.
	_, platform := newSignerVerifier(t)

	var got authctx.Identity
	req := httptest.NewRequest(http.MethodGet, "/api/v1/anything", nil)
	req.Header.Set("Authorization", "Bearer not-a-platform-token")
	rec := httptest.NewRecorder()

	RequireJWT(platform, zerolog.Nop(), WithProvider(provider, grants))(seen(&got)).ServeHTTP(rec, req)
	return rec, got
}

// A Keycloak token carries an email and nothing this platform can authorise
// on. The identity the handler sees must be built from the platform's own
// tables: its tenant, its roles, its permissions.
func TestAProviderTokenIsAuthorisedFromThePlatformsOwnTables(t *testing.T) {
	tenantID, identityID := uuid.New(), uuid.New()
	rec, got := callWith(t,
		fakeProvider{claims: &oidc.Claims{
			Subject: "keycloak-subject", Email: "ciso@bank.example",
			// The provider's own roles are deliberately different from the
			// platform's, and must not be what the handler sees.
			Roles: []string{"platform_admin", "dpo"},
		}},
		fakeGrants{grant: &rbac.Grant{
			IdentityID: identityID, TenantID: tenantID, Email: "ciso@bank.example",
			Roles: []string{"ciso"}, Permissions: []string{"siem:read", "assets:read"},
		}})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if got.TenantID != tenantID || got.UserID != identityID {
		t.Errorf("identity = %+v, want the platform's tenant and identity", got)
	}
	if len(got.Roles) != 1 || got.Roles[0] != "ciso" {
		t.Errorf("roles = %v, want the platform's, not the provider's", got.Roles)
	}
	if len(got.Permissions) != 2 {
		t.Errorf("permissions = %v", got.Permissions)
	}
}

// Someone the directory knows and the platform does not has proved who they
// are. Answering 401 would tell an interface to sign them in again, which
// changes nothing and loops.
func TestSomeoneWithNoPlatformIdentityGetsForbiddenNotUnauthorized(t *testing.T) {
	rec, _ := callWith(t,
		fakeProvider{claims: &oidc.Claims{Subject: "s", Email: "stranger@elsewhere.example"}},
		fakeGrants{err: rbac.ErrNoIdentity})

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if body := rec.Body.String(); body == "" || !contains(body, "NO_PLATFORM_IDENTITY") {
		t.Errorf("body = %q, want a reason the interface can act on", body)
	}
}

// A token the provider refuses is not an authorisation question.
func TestAnInvalidProviderTokenIsUnauthorized(t *testing.T) {
	rec, _ := callWith(t,
		fakeProvider{err: errors.New("signature is invalid")},
		fakeGrants{grant: &rbac.Grant{}})

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// With no provider configured the behaviour is what it always was: a token
// this platform did not sign is refused, and nothing reaches for a directory.
func TestWithoutAProviderNothingChanges(t *testing.T) {
	var got authctx.Identity
	req := httptest.NewRequest(http.MethodGet, "/api/v1/anything", nil)
	req.Header.Set("Authorization", "Bearer not-a-platform-token")
	rec := httptest.NewRecorder()

	_, platform := newSignerVerifier(t)
	RequireJWT(platform, zerolog.Nop())(seen(&got)).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// WithProvider needs both halves: a provider with no resolver would
// authenticate people and grant them nothing, which reads as broken.
func TestAProviderWithoutAResolverIsIgnored(t *testing.T) {
	var o Options
	WithProvider(fakeProvider{}, nil)(&o)
	if o.Provider != nil || o.Grants != nil {
		t.Error("a provider was accepted with no way to authorise anyone")
	}
	WithProvider(nil, fakeGrants{})(&o)
	if o.Provider != nil || o.Grants != nil {
		t.Error("a resolver was accepted with no provider")
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
