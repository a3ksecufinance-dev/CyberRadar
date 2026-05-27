package handler

import (
	"encoding/json"
	"net/http"

	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/collector/internal/model"
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
func (h *CollectorHandler) RegisterRoutes(r chi.Router) {
	r.Post("/events/ingest", h.Ingest)
	r.Post("/events/heartbeat", h.Heartbeat)
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

// mustTenantID extracts the tenant_id injected by the JWT middleware.
func mustTenantID(r *http.Request) string {
	v, _ := r.Context().Value("tenant_id").(string)
	return v
}
