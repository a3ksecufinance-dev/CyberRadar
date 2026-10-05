package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	"github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/internal/pkg/testinfra"
	"github.com/cyberradar/platform/services/collector/internal/service"
)

// The ingestion endpoint's gate.
//
// Both routes are machine-only. They were once reachable by any valid token,
// which meant an analyst's token could inject events into the detection
// pipeline — events that would then be correlated, scored and alerted on as if
// a connector had sent them. What is tested here is that the gate is on both
// routes, that it needs a service account and not merely a permission, and that
// the tenant written on the event comes from the token.

const (
	tenantA = "44444444-4444-4444-4444-444444444444"
	tenantB = "55555555-5555-5555-5555-555555555555"
)

type api struct {
	router chi.Router
	topic  string
}

func newAPI(t *testing.T) *api {
	t.Helper()
	f := testinfra.Kafka(t)
	logger := zerolog.New(io.Discard)

	producer := kafka.NewProducer(kafka.ProducerConfig{Brokers: f.Brokers, Topic: f.Topic}, logger)
	t.Cleanup(func() { _ = producer.Close() })
	dlq := kafka.NewProducer(kafka.ProducerConfig{Brokers: f.Brokers, Topic: f.NewTopic("dlq")}, logger)
	t.Cleanup(func() { _ = dlq.Close() })

	r := chi.NewRouter()
	NewCollectorHandler(service.NewCollectorService(producer, dlq, logger)).RegisterRoutes(r)
	return &api{router: r, topic: f.Topic}
}

// caller is who is making the request. The zero value is an authenticated
// person with no permissions — the case both routes must refuse.
type caller struct {
	tenant    string
	serviceID string
	perms     []string
}

var (
	agent = caller{tenant: tenantA, serviceID: "collector-agent", perms: []string{"events:ingest"}}
	// A person holding the ingest permission: refused, because a permission can
	// be granted to a role by mistake and a service account cannot.
	personWithPermission = caller{tenant: tenantA, perms: []string{"events:ingest"}}
	// A service account without the permission: refused the other way round.
	serviceWithoutPermission = caller{tenant: tenantA, serviceID: "other-agent"}
	anonymous                = caller{}
)

func (a *api) do(t *testing.T, c caller, path string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var reader io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		reader = bytes.NewReader([]byte(b))
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(raw)
	}

	req := httptest.NewRequest(http.MethodPost, path, reader)
	if c.tenant != "" {
		id := authctx.Identity{
			TenantID:    uuid.MustParse(c.tenant),
			Permissions: c.perms,
			ServiceID:   c.serviceID,
		}
		req = req.WithContext(authctx.With(req.Context(), id))
	}

	rec := httptest.NewRecorder()
	a.router.ServeHTTP(rec, req)
	return rec
}

func ingestBody(events ...string) map[string]any {
	return map[string]any{
		"connector_id": uuid.NewString(),
		"source":       "pare-feu01",
		"source_type":  "firewall",
		"format":       "json",
		"events":       events,
	}
}

// Both routes need a service account holding events:ingest, and each half of
// that is necessary on its own.
func TestBothRoutesNeedAServiceAccountAndThePermission(t *testing.T) {
	a := newAPI(t)

	heartbeat := map[string]any{
		"connector_id": uuid.NewString(),
		"source":       "agent-01",
		"source_type":  "firewall",
	}

	for _, path := range []string{"/events/ingest", "/events/heartbeat"} {
		body := any(heartbeat)
		if path == "/events/ingest" {
			body = ingestBody(`{"action":"login"}`)
		}

		for _, c := range []struct {
			who  string
			call caller
		}{
			{"an unauthenticated request", anonymous},
			{"a person holding events:ingest", personWithPermission},
			{"a service account without events:ingest", serviceWithoutPermission},
		} {
			rec := a.do(t, c.call, path, body)
			if rec.Code != http.StatusForbidden && rec.Code != http.StatusUnauthorized {
				t.Errorf("POST %s by %s answered %d, want 401 or 403\n%s",
					path, c.who, rec.Code, rec.Body.String())
			}
		}

		if rec := a.do(t, agent, path, body); rec.Code != http.StatusOK {
			t.Errorf("POST %s by a connector answered %d, want 200\n%s",
				path, rec.Code, rec.Body.String())
		}
	}
}

// The response says how many of the batch were published, so a connector can
// tell a partial success from a total one. Partial success is deliberately a
// 200: retrying the whole batch would duplicate the events that did land.
func TestIngestReportsPartialSuccessAsTwoHundred(t *testing.T) {
	a := newAPI(t)

	rec := a.do(t, agent, "/events/ingest", ingestBody(
		`{"action":"login"}`,
		`pas du JSON`,
		`{"action":"logout"}`,
	))
	if rec.Code != http.StatusOK {
		t.Fatalf("answered %d, want 200\n%s", rec.Code, rec.Body.String())
	}

	var env struct {
		Data struct {
			Received  int      `json:"received"`
			Published int      `json:"published"`
			Failed    int      `json:"failed"`
			Errors    []string `json:"errors"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v\n%s", err, rec.Body.String())
	}
	if env.Data.Received != 3 || env.Data.Published != 2 || env.Data.Failed != 1 {
		t.Errorf("the report is %+v, want 3 received / 2 published / 1 failed", env.Data)
	}
	if len(env.Data.Errors) != 1 {
		t.Errorf("the errors are %v, want one", env.Data.Errors)
	}
}

// Each kind of bad request gets the status that says whose mistake it was.
func TestIngestSeparatesBrokenJSONFromInvalidPayloads(t *testing.T) {
	a := newAPI(t)

	rec := a.do(t, agent, "/events/ingest", "{ pas du json")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("broken JSON answered %d, want 400", rec.Code)
	}

	for _, c := range []struct {
		what string
		body map[string]any
	}{
		{"no connector id", map[string]any{
			"source": "x", "source_type": "firewall", "format": "json",
			"events": []string{"{}"},
		}},
		{"a connector id that is not a UUID", map[string]any{
			"connector_id": "agent-01", "source": "x", "source_type": "firewall",
			"format": "json", "events": []string{"{}"},
		}},
		{"a format nobody parses", map[string]any{
			"connector_id": uuid.NewString(), "source": "x", "source_type": "firewall",
			"format": "xml", "events": []string{"{}"},
		}},
		{"an empty batch", map[string]any{
			"connector_id": uuid.NewString(), "source": "x", "source_type": "firewall",
			"format": "json", "events": []string{},
		}},
		{"no source", map[string]any{
			"connector_id": uuid.NewString(), "source_type": "firewall",
			"format": "json", "events": []string{"{}"},
		}},
	} {
		rec := a.do(t, agent, "/events/ingest", c.body)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s answered %d, want 422\n%s", c.what, rec.Code, rec.Body.String())
		}
	}
}

// The batch is capped, so one connector cannot hand the service an unbounded
// slice to normalize in one request.
func TestIngestCapsTheBatch(t *testing.T) {
	a := newAPI(t)

	events := make([]string, 1001)
	for i := range events {
		events[i] = `{"action":"x"}`
	}
	rec := a.do(t, agent, "/events/ingest", ingestBody(events...))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("a batch of 1001 answered %d, want 422", rec.Code)
	}
}

func TestHeartbeatValidatesItsPayload(t *testing.T) {
	a := newAPI(t)

	if rec := a.do(t, agent, "/events/heartbeat", "{ pas du json"); rec.Code != http.StatusBadRequest {
		t.Errorf("broken JSON answered %d, want 400", rec.Code)
	}

	for _, c := range []struct {
		what string
		body map[string]any
	}{
		{"no connector id", map[string]any{"source": "a", "source_type": "firewall"}},
		{"a connector id that is not a UUID", map[string]any{
			"connector_id": "agent-01", "source": "a", "source_type": "firewall"}},
		{"no source type", map[string]any{
			"connector_id": uuid.NewString(), "source": "a"}},
	} {
		rec := a.do(t, agent, "/events/heartbeat", c.body)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s answered %d, want 422\n%s", c.what, rec.Code, rec.Body.String())
		}
	}

	// A queue depth of zero is a legitimate heartbeat, not a missing field.
	rec := a.do(t, agent, "/events/heartbeat", map[string]any{
		"connector_id": uuid.NewString(), "source": "agent-01",
		"source_type": "firewall", "events_queued": 0, "version": "1.0.0",
	})
	if rec.Code != http.StatusOK {
		t.Errorf("a heartbeat with an empty queue answered %d\n%s", rec.Code, rec.Body.String())
	}
}

// The tenant on the event comes from the token. There is no field in the
// payload that could name another one — which is the property that stops a
// compromised agent at one customer writing events into another's timeline.
func TestTheTenantComesFromTheTokenAndNotTheBody(t *testing.T) {
	a := newAPI(t)

	body := ingestBody(`{"action":"login"}`)
	// A payload that tries to name a tenant anyway.
	body["tenant_id"] = tenantB

	rec := a.do(t, agent, "/events/ingest", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("answered %d\n%s", rec.Code, rec.Body.String())
	}

	// mustTenantID is what the handler passes down, and it reads the context.
	req := httptest.NewRequest(http.MethodPost, "/events/ingest", nil)
	req = req.WithContext(authctx.With(req.Context(),
		authctx.Identity{TenantID: uuid.MustParse(tenantA)}))
	if got := mustTenantID(req); got != tenantA {
		t.Errorf("mustTenantID gave %q, want %q", got, tenantA)
	}

	// And on a request with no identity it is empty rather than a zero UUID
	// that would resolve to some tenant's scope.
	bare := httptest.NewRequest(http.MethodPost, "/events/ingest", nil)
	if got := mustTenantID(bare); got != "" {
		t.Errorf("mustTenantID on an unauthenticated request gave %q, want \"\"", got)
	}
}
