package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/tenant/internal/model"
	"github.com/cyberradar/platform/services/tenant/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// TenantHandler exposes tenant management endpoints.
type TenantHandler struct {
	svc      *service.TenantService
	validate *validator.Validate
}

// NewTenantHandler creates a TenantHandler.
func NewTenantHandler(svc *service.TenantService) *TenantHandler {
	return &TenantHandler{
		svc:      svc,
		validate: validator.New(),
	}
}

// RegisterRoutes mounts all tenant routes on the provided router.
// All routes require a valid JWT (enforced by the auth middleware upstream).
func (h *TenantHandler) RegisterRoutes(r chi.Router) {
	r.Route("/tenants", func(r chi.Router) {
		r.Get("/", h.List)
		r.Post("/", h.Create)
		r.Route("/{tenantID}", func(r chi.Router) {
			r.Get("/", h.GetByID)
			r.Put("/", h.Update)
			r.Delete("/", h.Delete)
			r.Get("/stats", h.Stats)
		})
	})
}

// Create handles POST /tenants
func (h *TenantHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req model.CreateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}

	requesterTenantID := mustTenantID(r)
	isSuperAdmin := mustIsSuperAdmin(r)

	// Only super admins can create tenants
	if !isSuperAdmin {
		response.Forbidden(w, "Only platform super admins can create tenants")
		return
	}

	tenant, err := h.svc.Create(r.Context(), &req)
	if err := mapError(w, err); err != nil {
		return
	}

	_ = requesterTenantID
	response.Created(w, tenant)
}

// GetByID handles GET /tenants/{tenantID}
func (h *TenantHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	targetID, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "Invalid tenant ID format")
		return
	}

	requesterTenantID := mustTenantID(r)
	isSuperAdmin := mustIsSuperAdmin(r)

	tenant, svcErr := h.svc.GetByID(r.Context(), requesterTenantID, targetID, isSuperAdmin)
	if mapError(w, svcErr) != nil {
		return
	}

	response.OK(w, tenant)
}

// List handles GET /tenants
func (h *TenantHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := &model.ListTenantsFilter{
		Status: q.Get("status"),
		Plan:   q.Get("plan"),
		Page:   queryInt(q.Get("page"), 1),
		Limit:  queryInt(q.Get("limit"), 50),
	}

	requesterTenantID := mustTenantID(r)
	isSuperAdmin := mustIsSuperAdmin(r)

	list, svcErr := h.svc.List(r.Context(), requesterTenantID, isSuperAdmin, f)
	if mapError(w, svcErr) != nil {
		return
	}

	response.OKWithMeta(w, list.Tenants, &response.Meta{
		Page:     list.Page,
		Limit:    list.Limit,
		Total:    list.Total,
		TenantID: requesterTenantID.String(),
	})
}

// Update handles PUT /tenants/{tenantID}
func (h *TenantHandler) Update(w http.ResponseWriter, r *http.Request) {
	targetID, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "Invalid tenant ID format")
		return
	}

	var req model.UpdateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}

	requesterTenantID := mustTenantID(r)
	isSuperAdmin := mustIsSuperAdmin(r)

	tenant, svcErr := h.svc.Update(r.Context(), requesterTenantID, targetID, isSuperAdmin, &req)
	if mapError(w, svcErr) != nil {
		return
	}

	response.OK(w, tenant)
}

// Delete handles DELETE /tenants/{tenantID}
func (h *TenantHandler) Delete(w http.ResponseWriter, r *http.Request) {
	targetID, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "Invalid tenant ID format")
		return
	}

	requesterTenantID := mustTenantID(r)
	isSuperAdmin := mustIsSuperAdmin(r)

	if svcErr := h.svc.Delete(r.Context(), requesterTenantID, targetID, isSuperAdmin); mapError(w, svcErr) != nil {
		return
	}

	response.NoContent(w)
}

// Stats handles GET /tenants/{tenantID}/stats
func (h *TenantHandler) Stats(w http.ResponseWriter, r *http.Request) {
	// TODO: implement stats aggregation (asset count, user count, alert count)
	response.OK(w, map[string]any{"message": "stats endpoint — implementation in progress"})
}

// ─── Context helpers ─────────────────────────────────────────────────────────

// mustTenantID extracts the tenant_id from context (set by JWT middleware).
// It panics if not found — the auth middleware must always set this.
func mustTenantID(r *http.Request) uuid.UUID {
	return authctx.TenantID(r.Context())
}

func mustIsSuperAdmin(r *http.Request) bool {
	return authctx.IsSuperAdmin(r.Context())
}

// ─── Error mapping ────────────────────────────────────────────────────────────

// mapError converts domain errors to HTTP responses.
// Returns non-nil if an error was handled (so caller can return immediately).
func mapError(w http.ResponseWriter, err error) error {
	if err == nil {
		return nil
	}
	switch {
	case apierrors.IsKind(err, apierrors.KindNotFound):
		response.NotFound(w, apierrors.Message(err))
	case apierrors.IsKind(err, apierrors.KindConflict):
		response.Conflict(w, apierrors.Message(err))
	case apierrors.IsKind(err, apierrors.KindForbidden):
		response.Forbidden(w, apierrors.Message(err))
	case apierrors.IsKind(err, apierrors.KindBadInput):
		response.BadRequest(w, "BAD_INPUT", err.Error())
	default:
		response.InternalError(w)
	}
	return err
}

// ─── Query helpers ────────────────────────────────────────────────────────────

func queryInt(s string, def int) int {
	if s == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil || n <= 0 {
		return def
	}
	return n
}
