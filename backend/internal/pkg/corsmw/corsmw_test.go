package corsmw

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("reached"))
	})
}

func serve(t *testing.T, cfg Config, method, origin string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/api/v1/anything", nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if method == http.MethodOptions {
		req.Header.Set("Access-Control-Request-Method", "GET")
	}
	rec := httptest.NewRecorder()
	Middleware(cfg)(handler()).ServeHTTP(rec, req)
	return rec
}

// The preflight must be answered here and not passed on. A browser sends
// OPTIONS without credentials, so one that reaches the JWT middleware comes
// back 401 and the browser blocks the real request — which is how the whole
// interface came to report "Failed to fetch" with nothing in any log.
func TestPreflightIsAnsweredWithoutReachingTheHandler(t *testing.T) {
	cfg := DefaultConfig([]string{"http://localhost:3000"})
	rec := serve(t, cfg, http.MethodOptions, "http://localhost:3000")

	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", rec.Code)
	}
	if rec.Body.String() != "" {
		t.Errorf("the request reached the handler: %q", rec.Body.String())
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Errorf("allow-origin = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); got == "" {
		t.Error("no allowed headers: the browser will refuse to send Authorization")
	}
}

// An origin nobody allowed gets no header, so the browser blocks it. The
// preflight is still answered rather than passed to the handler: an
// unauthenticated OPTIONS has no business on the auth path.
func TestAnUnknownOriginIsNotAllowed(t *testing.T) {
	cfg := DefaultConfig([]string{"http://localhost:3000"})

	rec := serve(t, cfg, http.MethodGet, "https://evil.example")
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("allow-origin = %q for an origin that is not allowed", got)
	}
	if rec.Body.String() != "reached" {
		t.Error("a same-server call should still be served; the browser is what enforces this")
	}

	pre := serve(t, cfg, http.MethodOptions, "https://evil.example")
	if pre.Code != http.StatusNoContent || pre.Body.String() != "" {
		t.Errorf("preflight from a disallowed origin: %d %q", pre.Code, pre.Body.String())
	}
}

// Credentials mean the origin has to be echoed exactly: "*" is not allowed
// with them, and these services answer to a bearer token.
func TestAllowedOriginIsEchoedNotWildcarded(t *testing.T) {
	cfg := DefaultConfig([]string{"https://radar.bank.example"})
	rec := serve(t, cfg, http.MethodGet, "https://radar.bank.example")

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://radar.bank.example" {
		t.Errorf("allow-origin = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("allow-credentials = %q", got)
	}
}

// A cache that served one origin's response to another would hand a bank's
// data to a page that is not allowed to ask for it.
func TestEveryResponseVariesOnOrigin(t *testing.T) {
	cfg := DefaultConfig([]string{"http://localhost:3000"})
	for _, origin := range []string{"http://localhost:3000", "https://evil.example", ""} {
		rec := serve(t, cfg, http.MethodGet, origin)
		found := false
		for _, v := range rec.Header().Values("Vary") {
			if v == "Origin" {
				found = true
			}
		}
		if !found {
			t.Errorf("origin %q: no Vary: Origin", origin)
		}
	}
}

// With nothing configured the middleware adds nothing, which is right for a
// deployment whose interface and services share one origin.
func TestNoOriginsConfiguredIsANoop(t *testing.T) {
	rec := serve(t, DefaultConfig(nil), http.MethodGet, "http://localhost:3000")
	if rec.Body.String() != "reached" {
		t.Error("the handler was not reached")
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("headers were added with no origins configured")
	}
	// And a preflight is passed through rather than swallowed.
	pre := serve(t, DefaultConfig(nil), http.MethodOptions, "http://localhost:3000")
	if pre.Body.String() != "reached" {
		t.Error("a preflight was answered although CORS is off")
	}
}

func TestOriginsFromEnv(t *testing.T) {
	got := OriginsFromEnv(" http://localhost:3000/ , ,https://radar.bank.example ")
	want := []string{"http://localhost:3000", "https://radar.bank.example"}
	if len(got) != len(want) {
		t.Fatalf("parsed %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("parsed[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if len(OriginsFromEnv("")) != 0 {
		t.Error("an empty variable produced an origin")
	}
}
