package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/attackpath/internal/model"
	"github.com/cyberradar/platform/services/attackpath/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// AttackPathHandler exposes the Attack Path Analysis API.
type AttackPathHandler struct {
	svc      *service.AttackPathService
	validate *validator.Validate
}

// NewAttackPathHandler creates an AttackPathHandler.
func NewAttackPathHandler(svc *service.AttackPathService) *AttackPathHandler {
	return &AttackPathHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts all attack path routes.
func (h *AttackPathHandler) RegisterRoutes(r chi.Router) {
	// Graph nodes
	r.Get("/attack/nodes", h.ListNodes)
	r.Post("/attack/nodes", h.UpsertNode)
	r.Get("/attack/nodes/{nodeID}", h.GetNode)
	r.Put("/attack/nodes/{nodeID}/compromise", h.MarkCompromised)

	// Graph edges
	r.Get("/attack/edges", h.ListEdges)
	r.Post("/attack/edges", h.UpsertEdge)

	// Scenarios
	r.Get("/attack/scenarios", h.ListScenarios)
	r.Post("/attack/scenarios", h.CreateScenario)
	r.Get("/attack/scenarios/{scenarioID}", h.GetScenario)
	r.Post("/attack/scenarios/{scenarioID}/run", h.RunScenario)

	// Attack paths
	r.Get("/attack/paths", h.ListPaths)
	r.Get("/attack/paths/graph", h.ListPathsWithGraph)

	// Choke points / remediation priority
	r.Get("/attack/choke-points", h.ChokePoints)

	// Stats
	r.Get("/attack/stats", h.Stats)
}

// ─── Nodes ────────────────────────────────────────────────────────────────────

func (h *AttackPathHandler) ListNodes(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()
	f := model.NodeFilter{
		TenantID:    tenantID,
		NodeType:    q.Get("type"),
		NetworkZone: q.Get("zone"),
		Limit:       queryInt(q.Get("limit"), 50),
		Offset:      queryInt(q.Get("offset"), 0),
	}
	if v := q.Get("internet_facing"); v == "true" {
		t := true
		f.IsInternetFacing = &t
	}
	if v := q.Get("critical_system"); v == "true" {
		t := true
		f.IsCriticalSystem = &t
	}
	if v := q.Get("compromised"); v == "true" {
		t := true
		f.IsCompromised = &t
	}
	if v := q.Get("min_risk"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			f.MinRisk = n
		}
	}
	nodes, total, err := h.svc.ListNodes(r.Context(), f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"nodes": nodes, "total": total})
}

func (h *AttackPathHandler) UpsertNode(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.CreateNodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	n, err := h.svc.UpsertNode(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, n)
}

func (h *AttackPathHandler) GetNode(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "nodeID")
	if !ok {
		return
	}
	n, err := h.svc.GetNode(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, n)
}

func (h *AttackPathHandler) MarkCompromised(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "nodeID")
	if !ok {
		return
	}
	var body struct {
		Compromised bool `json:"compromised"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.svc.MarkCompromised(r.Context(), tenantID, id, body.Compromised); err != nil {
		mapError(w, err)
		return
	}
	response.NoContent(w)
}

// ─── Edges ────────────────────────────────────────────────────────────────────

func (h *AttackPathHandler) ListEdges(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()
	var sourceID *uuid.UUID
	if v := q.Get("source_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			sourceID = &id
		}
	}
	activeOnly := q.Get("active") != "false"
	edges, err := h.svc.ListEdges(r.Context(), tenantID, sourceID, activeOnly)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"edges": edges, "total": len(edges)})
}

func (h *AttackPathHandler) UpsertEdge(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.CreateEdgeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	e, err := h.svc.UpsertEdge(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, e)
}

// ─── Scenarios ────────────────────────────────────────────────────────────────

func (h *AttackPathHandler) ListScenarios(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	scenarios, err := h.svc.ListScenarios(r.Context(), tenantID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"scenarios": scenarios, "total": len(scenarios)})
}

func (h *AttackPathHandler) CreateScenario(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	var req model.CreateScenarioRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	sc, err := h.svc.CreateScenario(r.Context(), tenantID, &callerID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, sc)
}

func (h *AttackPathHandler) GetScenario(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "scenarioID")
	if !ok {
		return
	}
	sc, err := h.svc.GetScenario(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, sc)
}

func (h *AttackPathHandler) RunScenario(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "scenarioID")
	if !ok {
		return
	}
	if err := h.svc.RunScenario(r.Context(), tenantID, id); err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"status": "running", "scenario_id": id})
}

// ─── Paths ────────────────────────────────────────────────────────────────────

func (h *AttackPathHandler) ListPaths(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()
	f := model.PathFilter{
		TenantID: tenantID,
		PathType: q.Get("type"),
		Limit:    queryInt(q.Get("limit"), 50),
		Offset:   queryInt(q.Get("offset"), 0),
	}
	if v := q.Get("scenario_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.ScenarioID = &id
		}
	}
	if v := q.Get("target_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.TargetID = &id
		}
	}
	if v := q.Get("min_score"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			f.MinScore = n
		}
	}
	paths, total, err := h.svc.ListPaths(r.Context(), f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"paths": paths, "total": total})
}

func (h *AttackPathHandler) ListPathsWithGraph(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()
	f := model.PathFilter{
		TenantID: tenantID,
		PathType: q.Get("type"),
		Limit:    queryInt(q.Get("limit"), 20),
		Offset:   queryInt(q.Get("offset"), 0),
	}
	if v := q.Get("scenario_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.ScenarioID = &id
		}
	}
	paths, total, err := h.svc.GetPathWithGraph(r.Context(), tenantID, f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"paths": paths, "total": total})
}

// ─── Choke Points ─────────────────────────────────────────────────────────────

func (h *AttackPathHandler) ChokePoints(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()
	limit := queryInt(q.Get("limit"), 10)
	var scenarioID *uuid.UUID
	if v := q.Get("scenario_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			scenarioID = &id
		}
	}
	cps, err := h.svc.GetChokePoints(r.Context(), tenantID, scenarioID, limit)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"choke_points": cps, "total": len(cps)})
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (h *AttackPathHandler) Stats(w http.ResponseWriter, r *http.Request) {
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
	return authctx.TenantID(r.Context())
}

func mustCallerID(r *http.Request) uuid.UUID {
	return authctx.UserID(r.Context())
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
		response.NotFound(w, "resource not found")
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
