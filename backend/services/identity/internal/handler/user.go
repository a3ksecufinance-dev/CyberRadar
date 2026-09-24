package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/identity/internal/model"
	"github.com/cyberradar/platform/services/identity/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// UserHandler exposes user management endpoints.
type UserHandler struct {
	userSvc  *service.UserService
	validate *validator.Validate
}

// NewUserHandler creates a UserHandler.
func NewUserHandler(userSvc *service.UserService) *UserHandler {
	return &UserHandler{
		userSvc:  userSvc,
		validate: validator.New(),
	}
}

// RegisterRoutes mounts user routes. All require JWT auth.
func (h *UserHandler) RegisterRoutes(r chi.Router) {
	r.Route("/users", func(r chi.Router) {
		r.Get("/", h.List)
		r.Post("/", h.Create)
		r.Route("/{userID}", func(r chi.Router) {
			r.Get("/", h.GetByID)
			r.Put("/", h.Update)
			r.Delete("/", h.Disable)
			r.Get("/risk", h.RiskScore)
		})
	})

	// Privileged identities
	r.Get("/identities/orphans", h.ListOrphans)
	r.Get("/identities/dormant", h.ListDormant)
	r.Get("/identities/privileged", h.ListPrivileged)
}

// Create handles POST /users
func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)

	var req model.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}

	user, svcErr := h.userSvc.Create(r.Context(), tenantID, &req)
	if mapErrorU(w, svcErr) != nil {
		return
	}

	response.Created(w, user)
}

// GetByID handles GET /users/{userID}
func (h *UserHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "Invalid user ID")
		return
	}

	user, svcErr := h.userSvc.GetByID(r.Context(), tenantID, userID)
	if mapErrorU(w, svcErr) != nil {
		return
	}

	response.OK(w, user)
}

// List handles GET /users
func (h *UserHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()

	f := &model.ListUsersFilter{
		TenantID:     tenantID,
		Status:       q.Get("status"),
		IdentityType: q.Get("type"),
		Search:       q.Get("q"),
		Page:         queryInt(q.Get("page"), 1),
		Limit:        queryInt(q.Get("limit"), 50),
	}

	list, svcErr := h.userSvc.List(r.Context(), f)
	if mapErrorU(w, svcErr) != nil {
		return
	}

	response.OKWithMeta(w, list.Users, &response.Meta{
		Page:     list.Page,
		Limit:    list.Limit,
		Total:    list.Total,
		TenantID: tenantID.String(),
	})
}

// Update handles PUT /users/{userID}
func (h *UserHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "Invalid user ID")
		return
	}

	var req model.UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}

	user, svcErr := h.userSvc.Update(r.Context(), tenantID, userID, &req)
	if mapErrorU(w, svcErr) != nil {
		return
	}

	response.OK(w, user)
}

// Disable handles DELETE /users/{userID}
func (h *UserHandler) Disable(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "Invalid user ID")
		return
	}

	if svcErr := h.userSvc.Disable(r.Context(), tenantID, userID); mapErrorU(w, svcErr) != nil {
		return
	}
	response.NoContent(w)
}

// RiskScore handles GET /users/{userID}/risk
func (h *UserHandler) RiskScore(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "Invalid user ID")
		return
	}

	user, svcErr := h.userSvc.GetByID(r.Context(), tenantID, userID)
	if mapErrorU(w, svcErr) != nil {
		return
	}

	response.OK(w, map[string]any{
		"user_id":        user.ID,
		"risk_score":     user.RiskScore,
		"behavior_score": user.BehaviorScore,
		"status":         user.Status,
		"mfa_enabled":    user.MFAEnabled,
	})
}

// ListOrphans handles GET /identities/orphans
func (h *UserHandler) ListOrphans(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	list, svcErr := h.userSvc.List(r.Context(), &model.ListUsersFilter{
		TenantID: tenantID,
		Status:   "orphan",
		Page:     1,
		Limit:    100,
	})
	if mapErrorU(w, svcErr) != nil {
		return
	}
	response.OK(w, list.Users)
}

// ListDormant handles GET /identities/dormant
func (h *UserHandler) ListDormant(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	list, svcErr := h.userSvc.List(r.Context(), &model.ListUsersFilter{
		TenantID: tenantID,
		Status:   "dormant",
		Page:     1,
		Limit:    100,
	})
	if mapErrorU(w, svcErr) != nil {
		return
	}
	response.OK(w, list.Users)
}

// ListPrivileged handles GET /identities/privileged
func (h *UserHandler) ListPrivileged(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	list, svcErr := h.userSvc.List(r.Context(), &model.ListUsersFilter{
		TenantID:       tenantID,
		PrivilegeLevel: "admin",
		Page:           1,
		Limit:          100,
	})
	if mapErrorU(w, svcErr) != nil {
		return
	}
	response.OK(w, list.Users)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func mapErrorU(w http.ResponseWriter, err error) error {
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
	case apierrors.IsKind(err, apierrors.KindUnauth):
		response.Unauthorized(w, apierrors.Message(err))
	case apierrors.IsKind(err, apierrors.KindBadInput):
		response.BadRequest(w, "BAD_INPUT", err.Error())
	default:
		response.InternalError(w)
	}
	return err
}

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
