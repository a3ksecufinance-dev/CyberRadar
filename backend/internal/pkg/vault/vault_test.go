package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeVault serves the KV v2 read API for the given secrets, keyed by the
// path under the mount.
func fakeVault(t *testing.T, mount string, secrets map[string]map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// KV v2 reads are GET /v1/<mount>/data/<path>
		prefix := "/v1/" + mount + "/data/"
		if len(r.URL.Path) <= len(prefix) || r.URL.Path[:len(prefix)] != prefix {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("X-Vault-Token") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		data, ok := secrets[r.URL.Path[len(prefix):]]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[]}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"data": data, "metadata": map[string]any{"version": 1}},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSecretReadsAField(t *testing.T) {
	srv := fakeVault(t, "secret", map[string]map[string]any{
		"crp/identity/db": {"url": "postgres://real", "other": "x"},
	})

	c, err := New(srv.URL, "test-token", "secret")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := c.Secret(context.Background(), "crp/identity/db", "url")
	if err != nil {
		t.Fatalf("Secret: %v", err)
	}
	if got != "postgres://real" {
		t.Errorf("Secret = %q, want postgres://real", got)
	}
}

func TestSecretReportsMissingPathAndField(t *testing.T) {
	srv := fakeVault(t, "secret", map[string]map[string]any{
		"crp/identity/db": {"url": "postgres://real"},
	})
	c, _ := New(srv.URL, "test-token", "secret")

	if _, err := c.Secret(context.Background(), "crp/nope", "url"); err == nil {
		t.Error("reading a missing path returned no error")
	}
	if _, err := c.Secret(context.Background(), "crp/identity/db", "absent"); err == nil {
		t.Error("reading a missing field returned no error")
	}
}

func TestResolverPrefersVault(t *testing.T) {
	srv := fakeVault(t, "secret", map[string]map[string]any{
		"crp/identity/db": {"url": "from-vault"},
	})
	c, _ := New(srv.URL, "test-token", "secret")
	t.Setenv("DATABASE_URL", "from-env")

	value, origin, err := NewResolver(c, "crp/identity").Get(
		context.Background(), "db", "url", "DATABASE_URL")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if value != "from-vault" || origin != FromVault {
		t.Errorf("got (%q, %s), want (from-vault, vault)", value, origin)
	}
}

func TestResolverFallsBackToEnvWhenVaultIsAbsent(t *testing.T) {
	t.Setenv("DATABASE_URL", "from-env")

	// A nil client is the "Vault not configured" case: a developer on a laptop
	// must still be able to start the service.
	value, origin, err := NewResolver(nil, "crp/identity").Get(
		context.Background(), "db", "url", "DATABASE_URL")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if value != "from-env" || origin != FromEnvironment {
		t.Errorf("got (%q, %s), want (from-env, env)", value, origin)
	}
}

func TestResolverReportsAFailedVaultReadEvenWhenItFallsBack(t *testing.T) {
	srv := fakeVault(t, "secret", map[string]map[string]any{})
	c, _ := New(srv.URL, "test-token", "secret")
	t.Setenv("DATABASE_URL", "from-env")

	// Falling back silently would leave a service reading the environment while
	// its operator believes it reads Vault.
	value, origin, err := NewResolver(c, "crp/identity").Get(
		context.Background(), "db", "url", "DATABASE_URL")
	if err == nil {
		t.Error("a failed Vault read was not reported")
	}
	if value != "from-env" || origin != FromEnvironment {
		t.Errorf("got (%q, %s), want the env fallback", value, origin)
	}
}

func TestResolverErrorsWhenNeitherSourceHasTheValue(t *testing.T) {
	t.Setenv("DATABASE_URL", "")

	if _, _, err := NewResolver(nil, "").Get(
		context.Background(), "db", "url", "DATABASE_URL"); err == nil {
		t.Error("a missing value with no Vault returned no error")
	}
}

func TestNewFromEnvTreatsAnAbsentAddressAsNotConfigured(t *testing.T) {
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("VAULT_TOKEN", "")

	c, err := NewFromEnv()
	if err != nil {
		t.Fatalf("NewFromEnv with no address: %v", err)
	}
	if c != nil {
		t.Error("NewFromEnv returned a client without an address")
	}
	if NewResolver(c, "p").Enabled() {
		t.Error("resolver reports Vault enabled without a client")
	}
}

func TestNewFromEnvRejectsAnAddressWithoutAToken(t *testing.T) {
	// Half-configured is a misconfiguration, not "not configured": failing here
	// is what stops a service silently running on the environment fallback.
	t.Setenv("VAULT_ADDR", "http://vault:8200")
	t.Setenv("VAULT_TOKEN", "")

	if _, err := NewFromEnv(); err == nil {
		t.Error("an address with no token was accepted")
	}
}
