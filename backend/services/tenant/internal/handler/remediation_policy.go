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

// RemediationPolicyHandler exposes the deadlines a tenant is held to.
type RemediationPolicyHandler struct {
	svc      *service.RemediationPolicyService
	validate *validator.Validate
}

// NewRemediationPolicyHandler creates a RemediationPolicyHandler.
func NewRemediationPolicyHandler(svc *service.RemediationPolicyService) *RemediationPolicyHandler {
	return &RemediationPolicyHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts the remediation policy routes.
//
// Gated on vulnerabilities:* rather than tenants:*: committing to fix a critical in a day
// is a vulnerability-management authority, and creating a tenant is an
// administrative one. The tenant comes from the token, never from the path.
func (h *RemediationPolicyHandler) RegisterRoutes(r chi.Router) {
	r.Route("/remediation-policies", func(r chi.Router) {
		r.With(authmw.RequirePermission("vulnerabilities:read")).Get("/presets", h.Presets)
		r.With(authmw.RequirePermission("vulnerabilities:read")).Get("/active", h.Active)
		r.With(authmw.RequirePermission("vulnerabilities:read")).Get("/history", h.History)
		r.With(authmw.RequirePermission("vulnerabilities:write")).Put("/active", h.Set)
	})
}

// Presets handles GET /remediation-policies/presets.
func (h *RemediationPolicyHandler) Presets(w http.ResponseWriter, r *http.Request) {
	presets, err := h.svc.Presets(r.Context())
	if err != nil {
		mapError(w, err) //nolint:errcheck // the response is already written
		return
	}
	response.OKWithMeta(w, presets, &response.Meta{Total: int64(len(presets))})
}

// activePolicyResponse says which policy is in force and whether the tenant
// chose it. A deadline is a commitment; presenting ours as theirs is how a
// vendor ends up defending someone else's SLA.
type activePolicyResponse struct {
	Policy *model.RemediationPolicy `json:"policy"`
	Chosen bool                     `json:"chosen"`
}

// Active handles GET /remediation-policies/active.
func (h *RemediationPolicyHandler) Active(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	policy, chosen, err := h.svc.Effective(r.Context(), tenantID)
	if err != nil {
		mapError(w, err) //nolint:errcheck // the response is already written
		return
	}
	response.OK(w, activePolicyResponse{Policy: policy, Chosen: chosen})
}

// History handles GET /remediation-policies/history.
func (h *RemediationPolicyHandler) History(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	history, err := h.svc.History(r.Context(), tenantID)
	if err != nil {
		mapError(w, err) //nolint:errcheck // the response is already written
		return
	}
	response.OKWithMeta(w, history, &response.Meta{Total: int64(len(history))})
}

// Set handles PUT /remediation-policies/active — a new version of the deadlines.
func (h *RemediationPolicyHandler) Set(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)

	var req model.SetRemediationPolicyRequest
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
