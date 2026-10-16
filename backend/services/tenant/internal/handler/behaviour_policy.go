package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	"github.com/cyberradar/platform/internal/pkg/authmw"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/tenant/internal/model"
	"github.com/cyberradar/platform/services/tenant/internal/service"
)

// BehaviourPolicyHandler exposes what a tenant considers anomalous behaviour.
type BehaviourPolicyHandler struct {
	svc      *service.BehaviourPolicyService
	validate *validator.Validate
}

// NewBehaviourPolicyHandler creates a BehaviourPolicyHandler.
func NewBehaviourPolicyHandler(svc *service.BehaviourPolicyService) *BehaviourPolicyHandler {
	return &BehaviourPolicyHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts the behaviour policy routes.
//
// Gated on ueba:* — deciding what counts as anomalous is a detection authority,
// not an administrative one. The tenant comes from the token, never the path.
func (h *BehaviourPolicyHandler) RegisterRoutes(r chi.Router) {
	r.Route("/behaviour-policies", func(r chi.Router) {
		r.With(authmw.RequirePermission("ueba:read")).Get("/presets", h.Presets)
		r.With(authmw.RequirePermission("ueba:read")).Get("/active", h.Active)
		r.With(authmw.RequirePermission("ueba:read")).Get("/history", h.History)
		r.With(authmw.RequirePermission("ueba:write")).Put("/active", h.Set)
	})
}

// Presets handles GET /behaviour-policies/presets.
func (h *BehaviourPolicyHandler) Presets(w http.ResponseWriter, r *http.Request) {
	presets, err := h.svc.Presets(r.Context())
	if err != nil {
		mapError(w, err) //nolint:errcheck // the response is already written
		return
	}
	response.OKWithMeta(w, presets, &response.Meta{Total: int64(len(presets))})
}

// activeBehaviourResponse says which policy is in force and whether the tenant
// chose it.
type activeBehaviourResponse struct {
	Policy *model.BehaviourPolicy `json:"policy"`
	Chosen bool                   `json:"chosen"`
}

// Active handles GET /behaviour-policies/active.
func (h *BehaviourPolicyHandler) Active(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	policy, chosen, err := h.svc.Effective(r.Context(), tenantID)
	if err != nil {
		mapError(w, err) //nolint:errcheck // the response is already written
		return
	}
	response.OK(w, activeBehaviourResponse{Policy: policy, Chosen: chosen})
}

// History handles GET /behaviour-policies/history.
func (h *BehaviourPolicyHandler) History(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	history, err := h.svc.History(r.Context(), tenantID)
	if err != nil {
		mapError(w, err) //nolint:errcheck // the response is already written
		return
	}
	response.OKWithMeta(w, history, &response.Meta{Total: int64(len(history))})
}

// Set handles PUT /behaviour-policies/active.
func (h *BehaviourPolicyHandler) Set(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)

	var req model.SetBehaviourPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}

	var callerID *uuid.UUID
	if id, ok := authctx.From(r.Context()); ok && id.UserID != uuid.Nil {
		caller := id.UserID
		callerID = &caller
	}

	saved, err := h.svc.Set(r.Context(), tenantID, callerID, &req)
	if err != nil {
		mapError(w, err) //nolint:errcheck // the response is already written
		return
	}
	response.OK(w, saved)
}
