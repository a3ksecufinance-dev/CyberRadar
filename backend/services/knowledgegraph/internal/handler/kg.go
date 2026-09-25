package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/knowledgegraph/internal/model"
	"github.com/cyberradar/platform/services/knowledgegraph/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// KGHandler exposes the Knowledge Graph API.
type KGHandler struct {
	svc      *service.KGService
	validate *validator.Validate
}

// NewKGHandler creates a KGHandler.
func NewKGHandler(svc *service.KGService) *KGHandler {
	return &KGHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts all knowledge graph routes.
func (h *KGHandler) RegisterRoutes(r chi.Router) {
	// Entities
	r.Get("/kg/entities", h.ListEntities)
	r.Post("/kg/entities", h.UpsertEntity)
	r.Get("/kg/entities/{entityID}", h.GetEntity)
	r.Patch("/kg/entities/{entityID}", h.UpdateEntity)

	// Relationships
	r.Post("/kg/relationships", h.UpsertRelationship)
	r.Get("/kg/relationships/{relID}", h.GetRelationship)
	r.Delete("/kg/relationships/{relID}", h.DeleteRelationship)
	r.Get("/kg/entities/{entityID}/relationships", h.ListRelationships)

	// Graph traversal
	r.Get("/kg/entities/{entityID}/neighbors", h.Neighbors)
	r.Get("/kg/subgraph", h.Subgraph)

	// Observations / timeline
	r.Post("/kg/observations", h.CreateObservation)
	r.Get("/kg/entities/{entityID}/timeline", h.Timeline)

	// Enrichment
	r.Get("/kg/enrich", h.Enrich)

	// Stats
	r.Get("/kg/stats", h.Stats)
}

// ─── Entities ─────────────────────────────────────────────────────────────────

func (h *KGHandler) ListEntities(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()

	f := model.EntityFilter{
		TenantID:   tenantID,
		EntityType: q.Get("type"),
		Search:     q.Get("search"),
		Limit:      queryInt(q.Get("limit"), 50),
		Offset:     queryInt(q.Get("offset"), 0),
	}
	if v := q.Get("min_risk"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			f.MinRisk = n
		}
	}
	if v := q.Get("tags"); v != "" {
		f.Tags = strings.Split(v, ",")
	}

	entities, total, err := h.svc.ListEntities(r.Context(), f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"entities": entities, "total": total})
}

func (h *KGHandler) UpsertEntity(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.UpsertEntityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	e, err := h.svc.UpsertEntity(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, e)
}

func (h *KGHandler) GetEntity(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "entityID")
	if !ok {
		return
	}
	e, err := h.svc.GetEntity(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, e)
}

func (h *KGHandler) UpdateEntity(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "entityID")
	if !ok {
		return
	}
	var req model.UpdateEntityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	e, err := h.svc.UpdateEntity(r.Context(), tenantID, id, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, e)
}

// ─── Relationships ─────────────────────────────────────────────────────────────

func (h *KGHandler) UpsertRelationship(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.UpsertRelationshipRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	rel, err := h.svc.UpsertRelationship(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, rel)
}

func (h *KGHandler) GetRelationship(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "relID")
	if !ok {
		return
	}
	rel, err := h.svc.GetRelationship(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, rel)
}

func (h *KGHandler) DeleteRelationship(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "relID")
	if !ok {
		return
	}
	if err := h.svc.DeleteRelationship(r.Context(), tenantID, id); err != nil {
		mapError(w, err)
		return
	}
	response.NoContent(w)
}

func (h *KGHandler) ListRelationships(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	entityID, ok := parseUUID(w, r, "entityID")
	if !ok {
		return
	}
	direction := r.URL.Query().Get("direction")
	if direction == "" {
		direction = "both"
	}
	rels, err := h.svc.ListRelationships(r.Context(), tenantID, entityID, direction)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"relationships": rels, "total": len(rels)})
}

// ─── Graph traversal ──────────────────────────────────────────────────────────

func (h *KGHandler) Neighbors(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	entityID, ok := parseUUID(w, r, "entityID")
	if !ok {
		return
	}
	q := r.URL.Query()
	query := model.NeighborQuery{
		TenantID:  tenantID,
		EntityID:  entityID,
		MaxHops:   queryInt(q.Get("hops"), 2),
		Direction: q.Get("direction"),
	}
	if query.Direction == "" {
		query.Direction = "both"
	}
	if v := q.Get("rel_types"); v != "" {
		query.RelTypes = strings.Split(v, ",")
	}

	neighbors, err := h.svc.Neighbors(r.Context(), query)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"neighbors": neighbors, "total": len(neighbors)})
}

func (h *KGHandler) Subgraph(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	rawIDs := r.URL.Query().Get("ids")
	if rawIDs == "" {
		response.BadRequest(w, "MISSING_PARAM", "ids query parameter is required")
		return
	}
	parts := strings.Split(rawIDs, ",")
	ids := make([]uuid.UUID, 0, len(parts))
	for _, p := range parts {
		id, err := uuid.Parse(strings.TrimSpace(p))
		if err == nil {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		response.BadRequest(w, "INVALID_IDS", "No valid UUIDs provided")
		return
	}

	sg, err := h.svc.Subgraph(r.Context(), tenantID, ids)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, sg)
}

// ─── Observations ─────────────────────────────────────────────────────────────

func (h *KGHandler) CreateObservation(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.CreateObservationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	obs, err := h.svc.CreateObservation(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, obs)
}

func (h *KGHandler) Timeline(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	entityID, ok := parseUUID(w, r, "entityID")
	if !ok {
		return
	}
	q := r.URL.Query()
	f := model.ObservationFilter{
		TenantID:      tenantID,
		EntityID:      entityID,
		SourceService: q.Get("source"),
		Severity:      q.Get("severity"),
		Limit:         queryInt(q.Get("limit"), 50),
		Offset:        queryInt(q.Get("offset"), 0),
	}
	obs, total, err := h.svc.ListObservations(r.Context(), f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"observations": obs, "total": total})
}

// ─── Enrichment ───────────────────────────────────────────────────────────────

func (h *KGHandler) Enrich(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()
	entityType := q.Get("type")
	name := q.Get("name")
	if entityType == "" || name == "" {
		response.BadRequest(w, "MISSING_PARAM", "type and name query parameters are required")
		return
	}
	enriched, err := h.svc.Enrich(r.Context(), tenantID, entityType, name)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, enriched)
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (h *KGHandler) Stats(w http.ResponseWriter, r *http.Request) {
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
