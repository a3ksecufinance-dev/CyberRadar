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

// RiskProfileHandler exposes the tenant's risk appetite.
type RiskProfileHandler struct {
	svc      *service.RiskProfileService
	validate *validator.Validate
}

// NewRiskProfileHandler creates a RiskProfileHandler.
func NewRiskProfileHandler(svc *service.RiskProfileService) *RiskProfileHandler {
	return &RiskProfileHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts the risk profile routes.
//
// They are gated on risk:* rather than tenants:*, because setting a risk
// appetite is a risk-management authority and creating a tenant is an
// administrative one. In the seeded matrix that means the CISO can change this
// and a tenant administrator cannot, which is the right way round.
//
// The tenant comes from the token, never from the path: there is no identifier
// to mismatch, and no route that could be pointed at another customer.
func (h *RiskProfileHandler) RegisterRoutes(r chi.Router) {
	r.Route("/risk-profiles", func(r chi.Router) {
		r.With(authmw.RequirePermission("risk:read")).Get("/presets", h.Presets)
		r.With(authmw.RequirePermission("risk:read")).Get("/active", h.Active)
		r.With(authmw.RequirePermission("risk:read")).Get("/history", h.History)
		r.With(authmw.RequirePermission("risk:write")).Put("/active", h.Set)
	})
}

// Presets handles GET /risk-profiles/presets — the standard profiles.
func (h *RiskProfileHandler) Presets(w http.ResponseWriter, r *http.Request) {
	presets, err := h.svc.Presets(r.Context())
	if err != nil {
		mapError(w, err) //nolint:errcheck // the response is already written
		return
	}
	response.OKWithMeta(w, presets, &response.Meta{Total: int64(len(presets))})
}

// activeResponse says which profile is in force and whether the tenant chose it.
type activeResponse struct {
	Profile *model.RiskProfile `json:"profile"`
	// Chosen is false when the tenant has made no decision and is being scored
	// under the platform's standard values. Presenting a default as a choice
	// the customer made is how a vendor ends up defending someone else's risk
	// appetite in an audit.
	Chosen bool `json:"chosen"`
}

// Active handles GET /risk-profiles/active.
func (h *RiskProfileHandler) Active(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	profile, chosen, err := h.svc.Effective(r.Context(), tenantID)
	if err != nil {
		mapError(w, err) //nolint:errcheck // the response is already written
		return
	}
	response.OK(w, activeResponse{Profile: profile, Chosen: chosen})
}

// History handles GET /risk-profiles/history.
func (h *RiskProfileHandler) History(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	history, err := h.svc.History(r.Context(), tenantID)
	if err != nil {
		mapError(w, err) //nolint:errcheck // the response is already written
		return
	}
	response.OKWithMeta(w, history, &response.Meta{Total: int64(len(history))})
}

// Set handles PUT /risk-profiles/active — a new version of the risk appetite.
func (h *RiskProfileHandler) Set(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)

	var req model.SetRiskProfileRequest
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
