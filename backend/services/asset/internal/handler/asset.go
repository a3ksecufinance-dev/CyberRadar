package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/asset/internal/model"
	"github.com/cyberradar/platform/services/asset/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// AssetHandler exposes the asset inventory API.
type AssetHandler struct {
	svc      *service.AssetService
	validate *validator.Validate
}

// NewAssetHandler creates an AssetHandler.
func NewAssetHandler(svc *service.AssetService) *AssetHandler {
	return &AssetHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts all asset routes.
func (h *AssetHandler) RegisterRoutes(r chi.Router) {
	r.Get("/assets", h.List)
	r.Post("/assets", h.Create)
	r.Get("/assets/stats", h.Stats)
	r.Get("/assets/discovery", h.ListDiscovery)

	r.Route("/assets/{assetID}", func(r chi.Router) {
		r.Get("/", h.GetByID)
		r.Put("/", h.Update)
		r.Delete("/", h.Delete)
		r.Get("/risk", h.RiskBreakdown)
		r.Get("/relationships", h.GetRelationships)
		r.Post("/relationships", h.AddRelationship)
	})
}

// List handles GET /assets
func (h *AssetHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()

	var cbsConnected, pciScope *bool
	if v := q.Get("cbs_connected"); v != "" {
		b := v == "true"
		cbsConnected = &b
	}
	if v := q.Get("pci_scope"); v != "" {
		b := v == "true"
		pciScope = &b
	}

	f := model.AssetFilter{
		TenantID:        tenantID,
		AssetType:       q.Get("type"),
		Status:          q.Get("status"),
		Environment:     q.Get("environment"),
		BusinessService: q.Get("business_service"),
		Tag:             q.Get("tag"),
		Search:          q.Get("q"),
		IsCBSConnected:  cbsConnected,
		IsPCIScope:      pciScope,
		Limit:           queryInt(q.Get("limit"), 50),
		Offset:          queryInt(q.Get("offset"), 0),
	}

	if v := q.Get("criticality"); v != "" {
		if c, err := strconv.Atoi(v); err == nil {
			f.Criticality = c
		}
	}

	result, err := h.svc.List(r.Context(), f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, result)
}

// Create handles POST /assets
func (h *AssetHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)

	var req model.CreateAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}

	a, err := h.svc.Create(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, a)
}

// GetByID handles GET /assets/{assetID}
func (h *AssetHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	tenantID, assetID, ok := mustIDs(w, r)
	if !ok {
		return
	}
	a, err := h.svc.GetByID(r.Context(), tenantID, assetID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, a)
}

// Update handles PUT /assets/{assetID}
func (h *AssetHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID, assetID, ok := mustIDs(w, r)
	if !ok {
		return
	}

	var req model.UpdateAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}

	a, err := h.svc.Update(r.Context(), tenantID, assetID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, a)
}

// Delete handles DELETE /assets/{assetID}
func (h *AssetHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID, assetID, ok := mustIDs(w, r)
	if !ok {
		return
	}
	if err := h.svc.Delete(r.Context(), tenantID, assetID); err != nil {
		mapError(w, err)
		return
	}
	response.NoContent(w)
}

// RiskBreakdown handles GET /assets/{assetID}/risk
func (h *AssetHandler) RiskBreakdown(w http.ResponseWriter, r *http.Request) {
	tenantID, assetID, ok := mustIDs(w, r)
	if !ok {
		return
	}
	rb, err := h.svc.RiskBreakdown(r.Context(), tenantID, assetID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, rb)
}

// Stats handles GET /assets/stats
func (h *AssetHandler) Stats(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	stats, err := h.svc.Stats(r.Context(), tenantID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, stats)
}

// ListDiscovery handles GET /assets/discovery
func (h *AssetHandler) ListDiscovery(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	candidates, err := h.svc.ListDiscoveryCandidates(r.Context(), tenantID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"candidates": candidates, "total": len(candidates)})
}

// GetRelationships handles GET /assets/{assetID}/relationships
func (h *AssetHandler) GetRelationships(w http.ResponseWriter, r *http.Request) {
	tenantID, assetID, ok := mustIDs(w, r)
	if !ok {
		return
	}
	rels, err := h.svc.GetRelationships(r.Context(), tenantID, assetID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"relationships": rels, "total": len(rels)})
}

// AddRelationship handles POST /assets/{assetID}/relationships
func (h *AssetHandler) AddRelationship(w http.ResponseWriter, r *http.Request) {
	tenantID, assetID, ok := mustIDs(w, r)
	if !ok {
		return
	}

	var req model.CreateRelationshipRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}

	rel, err := h.svc.AddRelationship(r.Context(), tenantID, assetID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, rel)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func mustTenantID(r *http.Request) uuid.UUID {
	return authctx.TenantID(r.Context())
}

func mustIDs(w http.ResponseWriter, r *http.Request) (uuid.UUID, uuid.UUID, bool) {
	tenantID := mustTenantID(r)
	rawID := chi.URLParam(r, "assetID")
	assetID, err := uuid.Parse(rawID)
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "assetID must be a valid UUID")
		return uuid.Nil, uuid.Nil, false
	}
	return tenantID, assetID, true
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
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return def
	}
	return n
}
