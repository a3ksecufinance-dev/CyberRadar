package authmw

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	"github.com/cyberradar/platform/internal/pkg/jwt"
	"github.com/rs/zerolog"
)

const (
	testTenant = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	testUser   = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
)

func newSignerVerifier(t *testing.T) (*jwt.Signer, *jwt.Verifier) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	signer, err := jwt.NewSigner(privPEM, 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	verifier, err := jwt.NewVerifier(pubPEM)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return signer, verifier
}

// serve runs one request through the middleware, reporting whether the handler
// was reached and what identity it saw.
func serve(t *testing.T, verifier *jwt.Verifier, authHeader string) (status int, reached bool, seen authctx.Identity) {
	t.Helper()
	handler := RequireJWT(verifier, zerolog.Nop())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		seen, _ = authctx.From(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/things", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code, reached, seen
}

func TestValidTokenReachesHandler(t *testing.T) {
	signer, verifier := newSignerVerifier(t)
	tokens, err := signer.GenerateTokenPair(jwt.Subject{
		TenantID: testTenant, UserID: testUser, Email: "a@b.c",
		Roles: []string{"analyst"}, Permissions: []string{"alerts:read"}, IsAdmin: true,
	})
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}

	status, reached, seen := serve(t, verifier, "Bearer "+tokens.AccessToken)
	if !reached {
		t.Fatalf("handler not reached, status %d", status)
	}
	if got := seen.TenantID.String(); got != testTenant {
		t.Errorf("TenantID = %s, want %s", got, testTenant)
	}
	if !seen.IsSuperAdmin {
		t.Error("IsSuperAdmin = false, want true")
	}
	if seen.Token != tokens.AccessToken {
		t.Error("raw token not carried on the identity; downstream calls cannot forward it")
	}
}

func TestRejectsMissingAndMalformedHeaders(t *testing.T) {
	_, verifier := newSignerVerifier(t)

	for name, header := range map[string]string{
		"absent":        "",
		"no scheme":     "abcdef",
		"wrong scheme":  "Basic abcdef",
		"empty bearer":  "Bearer ",
		"garbage token": "Bearer not.a.jwt",
	} {
		t.Run(name, func(t *testing.T) {
			status, reached, _ := serve(t, verifier, header)
			if reached {
				t.Error("handler reached without a valid token")
			}
			if status != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", status)
			}
		})
	}
}

func TestRejectsTokenFromAnotherIssuerKey(t *testing.T) {
	otherSigner, _ := newSignerVerifier(t)
	_, verifier := newSignerVerifier(t)

	tokens, err := otherSigner.GenerateTokenPair(jwt.Subject{TenantID: testTenant, UserID: testUser, Email: "a@b.c"})
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}

	status, reached, _ := serve(t, verifier, "Bearer "+tokens.AccessToken)
	if reached {
		t.Error("handler reached with a token signed by an unknown key")
	}
	if status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", status)
	}
}

func TestSchemeIsCaseInsensitive(t *testing.T) {
	signer, verifier := newSignerVerifier(t)
	tokens, err := signer.GenerateTokenPair(jwt.Subject{TenantID: testTenant, UserID: testUser, Email: "a@b.c"})
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}

	if _, reached, _ := serve(t, verifier, "bearer "+tokens.AccessToken); !reached {
		t.Error("lowercase bearer scheme rejected")
	}
}

func TestUnauthorizedBodyIsValidJSON(t *testing.T) {
	_, verifier := newSignerVerifier(t)
	handler := RequireJWT(verifier, zerolog.Nop())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/things", nil))

	body, _ := io.ReadAll(rec.Body)
	want := `{"error":{"code":"UNAUTHORIZED","message":"Missing Authorization header"}}`
	if string(body) != want {
		t.Errorf("body = %s, want %s", body, want)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

// ─── Authorization ────────────────────────────────────────────────────────────

// serveAuthorized runs a request through RequireJWT then the given permission
// middleware, reporting the status and whether the handler was reached.
func serveAuthorized(t *testing.T, sub jwt.Subject, mw func(http.Handler) http.Handler, method string) (int, bool) {
	t.Helper()
	signer, verifier := newSignerVerifier(t)
	tokens, err := signer.GenerateTokenPair(sub)
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}

	reached := false
	handler := RequireJWT(verifier, zerolog.Nop())(
		mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true })))

	req := httptest.NewRequest(method, "/api/v1/things", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code, reached
}

func analyst(perms ...string) jwt.Subject {
	return jwt.Subject{TenantID: testTenant, UserID: testUser, Email: "a@b.c",
		Roles: []string{"soc_analyst_l2"}, Permissions: perms}
}

func TestRequirePermissionGrantsAndDenies(t *testing.T) {
	if code, reached := serveAuthorized(t, analyst("alerts:read"),
		RequirePermission("alerts:read"), http.MethodGet); !reached || code != http.StatusOK {
		t.Errorf("holder of alerts:read was denied: status %d", code)
	}

	code, reached := serveAuthorized(t, analyst("alerts:read"),
		RequirePermission("tenants:read"), http.MethodGet)
	if reached {
		t.Error("handler reached without the required permission")
	}
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", code)
	}
}

func TestRequirePermissionDeniesWhenNoneHeld(t *testing.T) {
	if code, reached := serveAuthorized(t, analyst(),
		RequirePermission("alerts:read"), http.MethodGet); reached || code != http.StatusForbidden {
		t.Errorf("caller with no permissions was allowed: status %d", code)
	}
}

func TestSuperAdminBypassesPermissionChecks(t *testing.T) {
	// Mirrors the super-admin rule in policies/rbac.rego.
	sub := jwt.Subject{TenantID: testTenant, UserID: testUser, Email: "a@b.c", IsAdmin: true}
	if code, reached := serveAuthorized(t, sub,
		RequirePermission("tenants:delete"), http.MethodDelete); !reached || code != http.StatusOK {
		t.Errorf("super-admin denied: status %d", code)
	}
}

func TestRequirePermissionByMethodMapsVerbs(t *testing.T) {
	cases := []struct {
		method string
		held   string
		want   int
	}{
		{http.MethodGet, "assets:read", http.StatusOK},
		{http.MethodPost, "assets:write", http.StatusOK},
		{http.MethodPut, "assets:write", http.StatusOK},
		{http.MethodPatch, "assets:write", http.StatusOK},
		{http.MethodDelete, "assets:delete", http.StatusOK},
		// A read grant must not authorize a mutation.
		{http.MethodPost, "assets:read", http.StatusForbidden},
		{http.MethodDelete, "assets:write", http.StatusForbidden},
	}

	for _, c := range cases {
		code, _ := serveAuthorized(t, analyst(c.held), RequirePermissionByMethod("assets"), c.method)
		if code != c.want {
			t.Errorf("%s holding %s: status %d, want %d", c.method, c.held, code, c.want)
		}
	}
}

func TestForbiddenBodyIsValidJSON(t *testing.T) {
	signer, verifier := newSignerVerifier(t)
	tokens, _ := signer.GenerateTokenPair(analyst("alerts:read"))

	handler := RequireJWT(verifier, zerolog.Nop())(
		RequirePermission("tenants:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body, _ := io.ReadAll(rec.Body)
	want := `{"error":{"code":"FORBIDDEN","message":"permission required: tenants:read"}}`
	if string(body) != want {
		t.Errorf("body = %s, want %s", body, want)
	}
}

// ─── Service accounts ─────────────────────────────────────────────────────────

// serveChain runs one request through RequireJWT plus extra middleware.
func serveChain(t *testing.T, verifier *jwt.Verifier, token string, extra ...func(http.Handler) http.Handler) (status int, reached bool) {
	t.Helper()
	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	for i := len(extra) - 1; i >= 0; i-- {
		h = extra[i](h)
	}
	h = RequireJWT(verifier, zerolog.Nop())(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/events/ingest", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, reached
}

func TestServiceTokenIdentifiesItsServiceToHandlers(t *testing.T) {
	signer, verifier := newSignerVerifier(t)
	tokens, err := signer.GenerateServiceToken(jwt.Subject{
		TenantID: testTenant, UserID: testUser, ServiceID: "collector-agent-01",
		Permissions: []string{"events:ingest"},
	}, time.Minute)
	if err != nil {
		t.Fatalf("GenerateServiceToken: %v", err)
	}

	_, reached, seen := serve(t, verifier, "Bearer "+tokens.AccessToken)
	if !reached {
		t.Fatal("handler not reached")
	}
	if seen.ServiceID != "collector-agent-01" {
		t.Errorf("ServiceID = %q, want collector-agent-01", seen.ServiceID)
	}
}

func TestRequireServiceAccountRejectsAPerson(t *testing.T) {
	// The point of the middleware: even a person holding events:ingest — by a
	// role granted in error — must not reach a machine-only route.
	signer, verifier := newSignerVerifier(t)
	tokens, err := signer.GenerateTokenPair(jwt.Subject{
		TenantID: testTenant, UserID: testUser, Email: "analyst@bank.example",
		Permissions: []string{"events:ingest"},
	})
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}

	status, reached := serveChain(t, verifier, tokens.AccessToken,
		RequireServiceAccount(), RequirePermission("events:ingest"))

	if reached {
		t.Error("a person's token reached a service-account-only route")
	}
	if status != http.StatusForbidden {
		t.Errorf("status = %d, want %d", status, http.StatusForbidden)
	}
}

func TestRequireServiceAccountAdmitsAService(t *testing.T) {
	signer, verifier := newSignerVerifier(t)
	tokens, err := signer.GenerateServiceToken(jwt.Subject{
		TenantID: testTenant, UserID: testUser, ServiceID: "collector-agent-01",
		Permissions: []string{"events:ingest"},
	}, time.Minute)
	if err != nil {
		t.Fatalf("GenerateServiceToken: %v", err)
	}

	status, reached := serveChain(t, verifier, tokens.AccessToken,
		RequireServiceAccount(), RequirePermission("events:ingest"))

	if !reached {
		t.Errorf("the service account was turned away with %d", status)
	}
}

func TestAServiceStillNeedsThePermission(t *testing.T) {
	// Being a machine is not authorization. A collector agent must not reach
	// the audit write API just because it holds a service token.
	signer, verifier := newSignerVerifier(t)
	tokens, err := signer.GenerateServiceToken(jwt.Subject{
		TenantID: testTenant, UserID: testUser, ServiceID: "collector-agent-01",
		Permissions: []string{"events:ingest"},
	}, time.Minute)
	if err != nil {
		t.Fatalf("GenerateServiceToken: %v", err)
	}

	status, reached := serveChain(t, verifier, tokens.AccessToken,
		RequireServiceAccount(), RequirePermission("audit:write"))

	if reached {
		t.Error("a service account reached a route it holds no permission for")
	}
	if status != http.StatusForbidden {
		t.Errorf("status = %d, want %d", status, http.StatusForbidden)
	}
}
