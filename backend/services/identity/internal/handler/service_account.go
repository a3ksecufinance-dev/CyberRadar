package handler

import (
	"encoding/json"
	"net/http"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	"github.com/cyberradar/platform/internal/pkg/authmw"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/identity/internal/model"
	"github.com/cyberradar/platform/services/identity/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// ServiceAccountHandler exposes machine authentication and credential
// management.
type ServiceAccountHandler struct {
	svc      *service.ServiceAccountService
	validate *validator.Validate
}

// NewServiceAccountHandler creates a ServiceAccountHandler.
func NewServiceAccountHandler(svc *service.ServiceAccountService) *ServiceAccountHandler {
	return &ServiceAccountHandler{svc: svc, validate: validator.New()}
}

// RegisterPublicRoutes mounts the token endpoint, which is reached with a
// client credential rather than a token and so cannot sit behind RequireJWT.
func (h *ServiceAccountHandler) RegisterPublicRoutes(r chi.Router) {
	r.Post("/auth/service-token", h.IssueToken)
}

// RegisterProtectedRoutes mounts credential management. Creating a machine
// credential is an administrative act, gated by api_keys:* like any other
// credential a tenant issues.
func (h *ServiceAccountHandler) RegisterProtectedRoutes(r chi.Router) {
	r.Route("/service-accounts", func(r chi.Router) {
		r.With(authmw.RequirePermission("api_keys:read")).Get("/", h.List)
		r.With(authmw.RequirePermission("api_keys:write")).Post("/", h.Create)
		r.With(authmw.RequirePermission("api_keys:delete")).Delete("/{id}", h.Revoke)
	})
}

// IssueToken handles POST /auth/service-token — the client-credentials grant.
func (h *ServiceAccountHandler) IssueToken(w http.ResponseWriter, r *http.Request) {
	var req model.ServiceTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}

	resp, svcErr := h.svc.IssueToken(r.Context(), &req)
	if mapError(w, svcErr) != nil {
		return
	}

	// A token must never be cached by an intermediary.
	w.Header().Set("Cache-Control", "no-store")
	response.OK(w, resp)
}

// Create handles POST /service-accounts. The secret it returns is shown once.
func (h *ServiceAccountHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req model.CreateServiceAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}

	// A platform-scoped account can mint a token for any tenant, so only a
	// super admin may create one. Without this a tenant administrator could
	// grant themselves a credential that reaches every other customer.
	if req.Scope == model.ScopePlatform && !isSuperAdmin(r) {
		response.Forbidden(w, "only a super admin may create a platform-scoped service account")
		return
	}

	resp, svcErr := h.svc.Create(r.Context(), mustTenantID(r), mustUserID(r), &req)
	if mapError(w, svcErr) != nil {
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	response.Created(w, resp)
}

// List handles GET /service-accounts.
func (h *ServiceAccountHandler) List(w http.ResponseWriter, r *http.Request) {
	accounts, svcErr := h.svc.List(r.Context(), mustTenantID(r))
	if mapError(w, svcErr) != nil {
		return
	}
	response.OK(w, accounts)
}

// Revoke handles DELETE /service-accounts/{id}.
func (h *ServiceAccountHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "Invalid service account ID")
		return
	}
	if svcErr := h.svc.Revoke(r.Context(), mustTenantID(r), id); mapError(w, svcErr) != nil {
		return
	}
	response.NoContent(w)
}

func isSuperAdmin(r *http.Request) bool {
	return authctx.IsSuperAdmin(r.Context())
}
