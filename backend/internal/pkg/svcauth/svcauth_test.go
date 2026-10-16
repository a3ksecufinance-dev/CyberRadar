package svcauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// identityStub answers the token endpoint and counts how often it was called.
func identityStub(t *testing.T, ttl time.Duration) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/service-token" {
			t.Errorf("identity called at %s, want /api/v1/auth/service-token", r.URL.Path)
		}
		calls++
		w.Header().Set("Content-Type", "application/json")
		//nolint:errcheck // test stub
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"access_token": "token-from-identity",
			"expires_at":   time.Now().Add(ttl),
		}})
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func source(t *testing.T, url string) *TokenSource {
	t.Helper()
	s, err := New(Config{IdentityURL: url, ClientID: "soar", ClientSecret: "s3cret"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestTokenIsFetchedOnFirstUse(t *testing.T) {
	srv, calls := identityStub(t, time.Hour)

	got, err := source(t, srv.URL).Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if got != "token-from-identity" {
		t.Errorf("token = %q", got)
	}
	if *calls != 1 {
		t.Errorf("identity called %d times, want 1", *calls)
	}
}

func TestAValidTokenIsReused(t *testing.T) {
	// One call to identity per service, not one per outgoing request.
	srv, calls := identityStub(t, time.Hour)
	s := source(t, srv.URL)

	for i := 0; i < 5; i++ {
		if _, err := s.Token(context.Background()); err != nil {
			t.Fatalf("Token: %v", err)
		}
	}
	if *calls != 1 {
		t.Errorf("identity called %d times, want 1 — the token is not being cached", *calls)
	}
}

func TestATokenCloseToExpiryIsRenewed(t *testing.T) {
	// Renewing only at expiry means a token can die between the check and the
	// request arriving, which fails the call the token was fetched for.
	srv, calls := identityStub(t, 30*time.Second) // inside the 60s margin
	s := source(t, srv.URL)

	for i := 0; i < 3; i++ {
		if _, err := s.Token(context.Background()); err != nil {
			t.Fatalf("Token: %v", err)
		}
	}
	if *calls != 3 {
		t.Errorf("identity called %d times, want 3 — a nearly expired token was reused", *calls)
	}
}

func TestConcurrentCallersShareOneToken(t *testing.T) {
	srv, calls := identityStub(t, time.Hour)
	s := source(t, srv.URL)

	var wg sync.WaitGroup
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()
			if _, err := s.Token(context.Background()); err != nil {
				t.Errorf("Token: %v", err)
			}
		}()
	}
	wg.Wait()

	if *calls != 1 {
		t.Errorf("identity called %d times for 10 concurrent callers, want 1", *calls)
	}
}

func TestAnUnknownExpiryIsNotTreatedAsUnlimited(t *testing.T) {
	// A response without expires_at must not park a token forever.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		//nolint:errcheck // test stub
		json.NewEncoder(w).Encode(map[string]any{"access_token": "flat-form-token"})
	}))
	defer srv.Close()

	s := source(t, srv.URL)
	if _, err := s.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if s.expiresAt.IsZero() || s.expiresAt.After(time.Now().Add(time.Hour)) {
		t.Errorf("expiresAt = %v, want a short bounded expiry", s.expiresAt)
	}
}

func TestARejectedCredentialIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	if _, err := source(t, srv.URL).Token(context.Background()); err == nil {
		t.Error("a 401 from identity produced no error")
	}
}

func TestIncompleteConfigurationIsRefused(t *testing.T) {
	for name, cfg := range map[string]Config{
		"no url":    {ClientID: "a", ClientSecret: "b"},
		"no id":     {IdentityURL: "http://x", ClientSecret: "b"},
		"no secret": {IdentityURL: "http://x", ClientID: "a"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(cfg); err == nil {
				t.Error("accepted, want an error")
			}
		})
	}
}

func TestAuthorizeSetsTheHeader(t *testing.T) {
	srv, _ := identityStub(t, time.Hour)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/events", nil)

	if err := source(t, srv.URL).Authorize(context.Background(), req); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer token-from-identity" {
		t.Errorf("Authorization = %q", got)
	}
}

// ─── Pool ─────────────────────────────────────────────────────────────────────

// tenantStub records which tenant each token request named.
func tenantStub(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var seen []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			TenantID string `json:"tenant_id"`
		}
		//nolint:errcheck // test stub
		json.NewDecoder(r.Body).Decode(&body)

		mu.Lock()
		seen = append(seen, body.TenantID)
		mu.Unlock()

		//nolint:errcheck // test stub
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"access_token": "token-for-" + body.TenantID,
			"expires_at":   time.Now().Add(time.Hour),
		}})
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func pool(t *testing.T, url string) *Pool {
	t.Helper()
	p, err := NewPool(Config{IdentityURL: url, ClientID: "soar", ClientSecret: "s3cret"})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	return p
}

func TestPoolKeepsTenantsApart(t *testing.T) {
	// The isolation the whole mechanism exists for: a token minted for one
	// customer must never travel on a request about another.
	srv, _ := tenantStub(t)
	p := pool(t, srv.URL)

	for tenant, want := range map[string]string{
		"tenant-a": "token-for-tenant-a",
		"tenant-b": "token-for-tenant-b",
	} {
		src, err := p.For(tenant)
		if err != nil {
			t.Fatalf("For(%s): %v", tenant, err)
		}
		got, err := src.Token(context.Background())
		if err != nil {
			t.Fatalf("Token: %v", err)
		}
		if got != want {
			t.Errorf("token for %s = %q, want %q", tenant, got, want)
		}
	}
}

func TestPoolCachesPerTenant(t *testing.T) {
	srv, seen := tenantStub(t)
	p := pool(t, srv.URL)

	for i := 0; i < 3; i++ {
		for _, tenant := range []string{"tenant-a", "tenant-b"} {
			src, err := p.For(tenant)
			if err != nil {
				t.Fatalf("For: %v", err)
			}
			if _, err := src.Token(context.Background()); err != nil {
				t.Fatalf("Token: %v", err)
			}
		}
	}

	if len(*seen) != 2 {
		t.Errorf("identity called %d times for 2 tenants over 3 rounds, want 2: %v", len(*seen), *seen)
	}
}

func TestPoolAuthorizeNamesTheTenantsToken(t *testing.T) {
	srv, _ := tenantStub(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/netsec/policies", nil)

	if err := pool(t, srv.URL).Authorize(context.Background(), "tenant-b", req); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer token-for-tenant-b" {
		t.Errorf("Authorization = %q", got)
	}
}

func TestPoolRefusesAConfigWithATenant(t *testing.T) {
	// A pool that carried a fixed tenant would hand the same token to every
	// caller, silently defeating the per-tenant split.
	if _, err := NewPool(Config{
		IdentityURL: "http://x", ClientID: "a", ClientSecret: "b", TenantID: "tenant-a",
	}); err == nil {
		t.Error("a Pool was built with a fixed tenant")
	}
}

func TestPoolRefusesAnEmptyTenant(t *testing.T) {
	srv, _ := tenantStub(t)
	if _, err := pool(t, srv.URL).For(""); err == nil {
		t.Error("For(\"\") was accepted; a token with no tenant is never valid")
	}
}

func TestPoolValidatesItsConfigUpFront(t *testing.T) {
	// A missing credential should fail at startup, not on the first playbook.
	if _, err := NewPool(Config{IdentityURL: "http://x", ClientID: "a"}); err == nil {
		t.Error("a Pool was built with no client secret")
	}
}

func TestPoolIsSafeUnderConcurrency(t *testing.T) {
	srv, seen := tenantStub(t)
	p := pool(t, srv.URL)

	var wg sync.WaitGroup
	wg.Add(20)
	for i := 0; i < 20; i++ {
		go func(i int) {
			defer wg.Done()
			tenant := []string{"tenant-a", "tenant-b"}[i%2]
			src, err := p.For(tenant)
			if err != nil {
				t.Errorf("For: %v", err)
				return
			}
			if _, err := src.Token(context.Background()); err != nil {
				t.Errorf("Token: %v", err)
			}
		}(i)
	}
	wg.Wait()

	if len(*seen) != 2 {
		t.Errorf("identity called %d times, want 2", len(*seen))
	}
}
