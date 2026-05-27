package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/soar/internal/model"
	"github.com/cyberradar/platform/services/soar/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// SOARHandler exposes the SOAR API.
type SOARHandler struct {
	svc      *service.SOARService
	validate *validator.Validate
}

// NewSOARHandler creates a SOARHandler.
func NewSOARHandler(svc *service.SOARService) *SOARHandler {
	return &SOARHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts all SOAR routes.
func (h *SOARHandler) RegisterRoutes(r chi.Router) {
	// Incidents
	r.Get("/soar/incidents", h.ListIncidents)
	r.Post("/soar/incidents", h.CreateIncident)
	r.Get("/soar/incidents/{incidentID}", h.GetIncident)
	r.Patch("/soar/incidents/{incidentID}", h.UpdateIncident)
	r.Get("/soar/incidents/{incidentID}/timeline", h.GetIncidentTimeline)

	// Playbooks
	r.Get("/soar/playbooks", h.ListPlaybooks)
	r.Post("/soar/playbooks", h.CreatePlaybook)
	r.Get("/soar/playbooks/{playbookID}", h.GetPlaybook)
	r.Post("/soar/playbooks/{playbookID}/enable", h.EnablePlaybook)
	r.Post("/soar/playbooks/{playbookID}/disable", h.DisablePlaybook)
	r.Post("/soar/playbooks/{playbookID}/run", h.RunPlaybook)

	// Executions
	r.Get("/soar/executions", h.ListExecutions)
	r.Get("/soar/executions/{executionID}", h.GetExecution)

	// Stats
	r.Get("/soar/stats", h.Stats)
}

// ─── Incidents ────────────────────────────────────────────────────────────────

func (h *SOARHandler) ListIncidents(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()

	f := model.IncidentFilter{
		TenantID: tenantID,
		Status:   q.Get("status"),
		Severity: q.Get("severity"),
		Source:   q.Get("source"),
		Limit:    queryInt(q.Get("limit"), 50),
		Offset:   queryInt(q.Get("offset"), 0),
	}
	if q.Get("sla_breach") == "true" {
		f.SLABreach = true
	}
	if v := q.Get("assignee_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.Assignee = &id
		}
	}

	incidents, total, err := h.svc.ListIncidents(r.Context(), f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"incidents": incidents, "total": total})
}

func (h *SOARHandler) CreateIncident(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	var req model.CreateIncidentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	inc, err := h.svc.CreateIncident(r.Context(), tenantID, &callerID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, inc)
}

func (h *SOARHandler) GetIncident(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "incidentID")
	if !ok {
		return
	}
	inc, err := h.svc.GetIncident(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, inc)
}

func (h *SOARHandler) UpdateIncident(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	id, ok := parseUUID(w, r, "incidentID")
	if !ok {
		return
	}
	var req model.UpdateIncidentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	inc, err := h.svc.UpdateIncident(r.Context(), tenantID, id, &req, &callerID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, inc)
}

func (h *SOARHandler) GetIncidentTimeline(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "incidentID")
	if !ok {
		return
	}
	events, err := h.svc.GetIncidentTimeline(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"events": events, "total": len(events)})
}

// ─── Playbooks ────────────────────────────────────────────────────────────────

func (h *SOARHandler) ListPlaybooks(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	activeOnly := r.URL.Query().Get("active") != "false"
	playbooks, err := h.svc.ListPlaybooks(r.Context(), tenantID, activeOnly)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"playbooks": playbooks, "total": len(playbooks)})
}

func (h *SOARHandler) CreatePlaybook(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	var req model.CreatePlaybookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	pb, err := h.svc.CreatePlaybook(r.Context(), tenantID, &callerID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, pb)
}

func (h *SOARHandler) GetPlaybook(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "playbookID")
	if !ok {
		return
	}
	pb, err := h.svc.GetPlaybook(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, pb)
}

func (h *SOARHandler) EnablePlaybook(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "playbookID")
	if !ok {
		return
	}
	if err := h.svc.SetPlaybookActive(r.Context(), tenantID, id, true); err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"status": "enabled"})
}

func (h *SOARHandler) DisablePlaybook(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "playbookID")
	if !ok {
		return
	}
	if err := h.svc.SetPlaybookActive(r.Context(), tenantID, id, false); err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"status": "disabled"})
}

func (h *SOARHandler) RunPlaybook(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	id, ok := parseUUID(w, r, "playbookID")
	if !ok {
		return
	}
	var req model.RunPlaybookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.svc.RunPlaybook(r.Context(), tenantID, id, &callerID, &req); err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"status": "running", "playbook_id": id})
}

// ─── Executions ───────────────────────────────────────────────────────────────

func (h *SOARHandler) ListExecutions(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()

	f := model.ExecutionFilter{
		TenantID: tenantID,
		Status:   q.Get("status"),
		Limit:    queryInt(q.Get("limit"), 50),
		Offset:   queryInt(q.Get("offset"), 0),
	}
	if v := q.Get("playbook_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.PlaybookID = &id
		}
	}
	if v := q.Get("incident_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.IncidentID = &id
		}
	}

	execs, total, err := h.svc.ListExecutions(r.Context(), f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"executions": execs, "total": total})
}

func (h *SOARHandler) GetExecution(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "executionID")
	if !ok {
		return
	}
	exec, err := h.svc.GetExecution(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, exec)
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (h *SOARHandler) Stats(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	stats, err := h.svc.GetStats(r.Context(), tenantID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, stats)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func mustTenantID(r *http.Request) uuid.UUID {
	v, _ := r.Context().Value("tenant_id").(string)
	id, _ := uuid.Parse(v)
	return id
}

func mustCallerID(r *http.Request) uuid.UUID {
	v, _ := r.Context().Value("user_id").(string)
	id, _ := uuid.Parse(v)
	return id
}

func parseUUID(w http.ResponseWriter, r *http.Request, param string) (uuid.UUID, bool) {
	raw := chi.URLParam(r, param)
	id, err := uuid.Parse(raw)
	if err != nil {
		response.BadRequest(w, "INVALID_ID", param+" must be a valid UUID")
		return uuid.Nil, false
	}
	return id, true
}

func mapError(w http.ResponseWriter, err error) {
	switch {
	case apierrors.IsKind(err, apierrors.KindNotFound):
		response.NotFound(w, "resource")
	case apierrors.IsKind(err, apierrors.KindForbidden):
		response.Forbidden(w, err.Error())
	case apierrors.IsKind(err, apierrors.KindBadInput):
		response.BadRequest(w, "BAD_INPUT", err.Error())
	default:
		response.InternalError(w)
	}
}

func queryInt(s string, def int) int {
	if s == "" {
		return def
	}
	if n, err := strconv.Atoi(s); err == nil && n >= 0 {
		return n
	}
	return def
}
