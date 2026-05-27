package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/ueba/internal/model"
	"github.com/cyberradar/platform/services/ueba/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// UEBAHandler exposes the UEBA API.
type UEBAHandler struct {
	svc      *service.UEBAService
	validate *validator.Validate
}

// NewUEBAHandler creates a UEBAHandler.
func NewUEBAHandler(svc *service.UEBAService) *UEBAHandler {
	return &UEBAHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts all UEBA routes.
func (h *UEBAHandler) RegisterRoutes(r chi.Router) {
	// Entity profiles
	r.Get("/ueba/profiles", h.ListProfiles)
	r.Get("/ueba/profiles/{entityID}", h.GetProfile)

	// Anomalies
	r.Get("/ueba/anomalies", h.ListAnomalies)
	r.Get("/ueba/anomalies/stats", h.Stats)
	r.Put("/ueba/anomalies/{anomalyID}", h.UpdateAnomaly)

	// Behavioral timeline
	r.Get("/ueba/entities/{entityID}/timeline", h.Timeline)

	// Peer groups
	r.Get("/ueba/peer-groups", h.ListPeerGroups)
	r.Post("/ueba/peer-groups", h.CreatePeerGroup)
}

// ─── Profiles ─────────────────────────────────────────────────────────────────

func (h *UEBAHandler) ListProfiles(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()

	f := model.ProfileFilter{
		TenantID:   tenantID,
		EntityType: q.Get("entity_type"),
		Limit:      queryInt(q.Get("limit"), 50),
		Offset:     queryInt(q.Get("offset"), 0),
	}
	if v := q.Get("min_risk"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			f.MinRisk = n
		}
	}
	if v := q.Get("baseline_ready"); v == "true" {
		t := true
		f.BaselineReady = &t
	}

	profiles, total, err := h.svc.ListProfiles(r.Context(), f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"profiles": profiles, "total": total})
}

func (h *UEBAHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	entityID, ok := parseUUID(w, r, "entityID")
	if !ok {
		return
	}
	p, err := h.svc.GetProfile(r.Context(), tenantID, entityID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, p)
}

// ─── Anomalies ────────────────────────────────────────────────────────────────

func (h *UEBAHandler) ListAnomalies(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()

	f := model.AnomalyFilter{
		TenantID:    tenantID,
		Status:      q.Get("status"),
		Severity:    q.Get("severity"),
		AnomalyType: q.Get("type"),
		Limit:       queryInt(q.Get("limit"), 50),
		Offset:      queryInt(q.Get("offset"), 0),
	}
	if v := q.Get("entity_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.EntityID = &id
		}
	}
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.From = &t
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.To = &t
		}
	}

	anomalies, total, err := h.svc.ListAnomalies(r.Context(), f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"anomalies": anomalies, "total": total})
}

func (h *UEBAHandler) Stats(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	stats, err := h.svc.GetStats(r.Context(), tenantID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, stats)
}

func (h *UEBAHandler) UpdateAnomaly(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "anomalyID")
	if !ok {
		return
	}
	var req model.UpdateAnomalyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	a, err := h.svc.UpdateAnomaly(r.Context(), tenantID, id, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, a)
}

// ─── Timeline ─────────────────────────────────────────────────────────────────

func (h *UEBAHandler) Timeline(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	entityID, ok := parseUUID(w, r, "entityID")
	if !ok {
		return
	}
	q := r.URL.Query()
	days := queryInt(q.Get("days"), 7)
	limit := queryInt(q.Get("limit"), 100)

	events, err := h.svc.GetTimeline(r.Context(), tenantID, entityID, days, limit)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"events": events, "total": len(events)})
}

// ─── Peer Groups ──────────────────────────────────────────────────────────────

func (h *UEBAHandler) ListPeerGroups(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	groups, err := h.svc.ListPeerGroups(r.Context(), tenantID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"peer_groups": groups, "total": len(groups)})
}

func (h *UEBAHandler) CreatePeerGroup(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.CreatePeerGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	pg, err := h.svc.CreatePeerGroup(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, pg)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func mustTenantID(r *http.Request) uuid.UUID {
	v, _ := r.Context().Value("tenant_id").(string)
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
		response.Forbidden(w, "access denied")
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
