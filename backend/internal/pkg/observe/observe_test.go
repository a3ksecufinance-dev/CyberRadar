package observe

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// scrape returns the current /metrics body.
func scrape(t *testing.T) string {
	t.Helper()
	rec := httptest.NewRecorder()
	MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	return string(body)
}

func TestMiddlewareRecordsRequests(t *testing.T) {
	r := chi.NewRouter()
	r.Use(Middleware("test-service"))
	r.Get("/assets/{assetID}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for _, id := range []string{"a1", "a2", "a3"} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/assets/"+id, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
	}

	body := scrape(t)
	// The route label must be the chi pattern, so three different asset IDs
	// collapse into one series rather than three.
	want := `crp_http_requests_total{method="GET",route="/assets/{assetID}",service="test-service",status="200"} 3`
	if !strings.Contains(body, want) {
		t.Errorf("metric not found or not aggregated by route pattern.\nwant line: %s", want)
	}
	for _, id := range []string{"a1", "a2", "a3"} {
		if strings.Contains(body, "/assets/"+id) {
			t.Errorf("raw path %q leaked into a label; cardinality is unbounded", "/assets/"+id)
		}
	}
}

func TestMiddlewareRecordsStatusAndLatency(t *testing.T) {
	r := chi.NewRouter()
	r.Use(Middleware("status-service"))
	r.Get("/boom", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	r.Get("/denied", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	for _, path := range []string{"/boom", "/denied"} {
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
	}

	body := scrape(t)
	for _, want := range []string{
		`route="/boom",service="status-service",status="500"`,
		`route="/denied",service="status-service",status="403"`,
		`crp_http_request_duration_seconds_bucket{method="GET",route="/boom",service="status-service",le="0.2"}`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
}

func TestUnmatchedRouteDoesNotLeakPath(t *testing.T) {
	r := chi.NewRouter()
	r.Use(Middleware("nf-service"))
	r.Get("/known", func(w http.ResponseWriter, r *http.Request) {})

	// A scanner probing random paths must not be able to create a new time
	// series per probe.
	for _, p := range []string{"/../etc/passwd", "/wp-admin", "/%00"} {
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, p, nil))
	}

	body := scrape(t)
	if !strings.Contains(body, `route="unmatched",service="nf-service"`) {
		t.Error("unmatched requests are not recorded under a fixed label")
	}
	for _, p := range []string{"wp-admin", "etc/passwd"} {
		if strings.Contains(body, p) {
			t.Errorf("probe path %q became a metric label", p)
		}
	}
}

func TestHandlerWritingNothingCountsAs200(t *testing.T) {
	r := chi.NewRouter()
	r.Use(Middleware("implicit-service"))
	r.Get("/quiet", func(w http.ResponseWriter, r *http.Request) {})

	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/quiet", nil))

	if !strings.Contains(scrape(t), `route="/quiet",service="implicit-service",status="200"`) {
		t.Error("a handler that never calls WriteHeader was not recorded as 200")
	}
}

func TestInitTracingWithoutEndpointIsANoop(t *testing.T) {
	// A service must still start when no collector is configured.
	shutdown, err := InitTracing(context.Background(), "svc", "test", "")
	if err != nil {
		t.Fatalf("InitTracing with no endpoint: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}

func TestMiddlewareWorksWithoutTracerProvider(t *testing.T) {
	// With tracing disabled the span is a no-op; the request must still serve
	// and still be counted.
	r := chi.NewRouter()
	r.Use(Middleware("notrace-service"))
	r.Get("/ping", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("pong"))
	})

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ping", nil))

	if rec.Body.String() != "pong" {
		t.Errorf("body = %q, want pong", rec.Body.String())
	}
	if !strings.Contains(scrape(t), `service="notrace-service"`) {
		t.Error("request not recorded without a tracer provider")
	}
}

func TestNestedRoutesKeepTheirFullPattern(t *testing.T) {
	// The middleware is mounted on the root router, where chi's RoutePattern()
	// reports only the mount point. Every API call would otherwise collapse
	// into one "/api/v1/*" series, which is useless to an operator.
	r := chi.NewRouter()
	r.Use(Middleware("nested-service"))
	r.Route("/api/v1", func(r chi.Router) {
		r.Route("/tenants", func(r chi.Router) {
			r.Get("/", func(w http.ResponseWriter, r *http.Request) {})
			r.Get("/{tenantID}", func(w http.ResponseWriter, r *http.Request) {})
		})
		r.Get("/assets", func(w http.ResponseWriter, r *http.Request) {})
	})

	for _, p := range []string{"/api/v1/tenants", "/api/v1/tenants/abc", "/api/v1/assets"} {
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, p, nil))
	}

	body := scrape(t)
	for _, want := range []string{
		`route="/api/v1/tenants"`,
		`route="/api/v1/tenants/{tenantID}"`,
		`route="/api/v1/assets"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s — nested patterns are not being joined", want)
		}
	}
	if strings.Contains(body, `route="/api/v1/*"`) {
		t.Error(`route collapsed to "/api/v1/*": the mount wildcard was not resolved`)
	}
}
