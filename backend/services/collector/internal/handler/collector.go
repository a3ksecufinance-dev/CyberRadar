package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	"github.com/cyberradar/platform/internal/pkg/authmw"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/collector/internal/model"
	"github.com/cyberradar/platform/services/collector/internal/repository"
	"github.com/cyberradar/platform/services/collector/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
)

// CollectorHandler exposes the event ingestion API.
type CollectorHandler struct {
	svc      *service.CollectorService
	validate *validator.Validate
}

// NewCollectorHandler creates a CollectorHandler.
func NewCollectorHandler(svc *service.CollectorService) *CollectorHandler {
	return &CollectorHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts collector routes.
//
// Both are machine endpoints: an agent or connector submits events and reports
// liveness, and no person ever calls either. They were reachable by any valid
// token because there was no way to say "a machine" — so an analyst's token
// could inject events into the detection pipeline. Now they need a service
// account holding events:ingest, and the tenant comes from that account's
// token, so an agent at one customer cannot write events for another.
func (h *CollectorHandler) RegisterRoutes(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(authmw.RequireServiceAccount())
		r.Use(authmw.RequirePermission("events:ingest"))

		r.Post("/events/ingest", h.Ingest)
		r.Post("/events/heartbeat", h.Heartbeat)
	})

	// Source health is the exception to the paragraph above: it is the one
	// route here a person calls. "Which of my sources went quiet" is a
	// question for whoever answers for the collection, not for an agent, so
	// it must not sit behind RequireServiceAccount.
	//
	// It is also a read, and must not sit behind events:ingest either — the
	// right to inject events into the detection pipeline is not the right to
	// see which sources are silent, and granting one to obtain the other
	// would hand an analyst the ability to write telemetry.
	r.With(authmw.RequirePermission("connectors:read")).
		Get("/sources/health", h.SourceHealth)
}

// Ingest handles POST /events/ingest
// Accepts a batch of raw events, normalizes and publishes to Kafka.
func (h *CollectorHandler) Ingest(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)

	var req model.IngestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}

	result, err := h.svc.Ingest(r.Context(), tenantID, &req)
	if err != nil {
		response.InternalError(w)
		return
	}

	// Partial success is still 200 — caller can inspect .failed count
	response.OK(w, result)
}

// Heartbeat handles POST /events/heartbeat
// Agents report liveness and queue depth.
func (h *CollectorHandler) Heartbeat(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)

	var req model.ConnectorHeartbeat
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}

	if err := h.svc.Heartbeat(r.Context(), tenantID, &req); err != nil {
		response.InternalError(w)
		return
	}

	response.OK(w, map[string]string{"status": "ok"})
}

// SourceHealth handles GET /sources/health
//
// Which sources are still talking, and how long the quiet ones have been
// quiet. A source that stopped sending is not a gap in a chart: it is traffic
// nobody is looking at, and until this existed the platform held every fact
// needed to say so and never said it.
func (h *CollectorHandler) SourceHealth(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)

	late, err := durationParam(r, "late", defaultLate)
	if err != nil {
		response.BadRequest(w, "INVALID_PARAM", "late must be a duration such as 15m")
		return
	}
	silent, err := durationParam(r, "silent", defaultSilent)
	if err != nil {
		response.BadRequest(w, "INVALID_PARAM", "silent must be a duration such as 1h")
		return
	}

	sources, err := h.svc.SourceHealth(r.Context(), tenantID, late, silent)
	if err != nil {
		response.InternalError(w)
		return
	}
	if sources == nil {
		sources = []repository.SourceHealth{}
	}
	response.OK(w, sources)
}

// The thresholds an operator reads the answer against. Overridable per
// request because a firewall and a quarterly compliance feed are quiet on
// very different scales, and one pair of numbers cannot fit both.
const (
	defaultLate   = 15 * time.Minute
	defaultSilent = time.Hour
)

func durationParam(r *http.Request, name string, def time.Duration) (time.Duration, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def, nil
	}
	return time.ParseDuration(raw)
}

// mustTenantID extracts the tenant_id injected by the JWT middleware.
func mustTenantID(r *http.Request) string {
	if id, ok := authctx.From(r.Context()); ok {
		return id.TenantID.String()
	}
	return ""
}
