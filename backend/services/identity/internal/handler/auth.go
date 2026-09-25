package handler

import (
	"encoding/json"
	"net/http"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/identity/internal/model"
	"github.com/cyberradar/platform/services/identity/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// AuthHandler exposes authentication endpoints.
type AuthHandler struct {
	userSvc  *service.UserService
	validate *validator.Validate
}

// NewAuthHandler creates an AuthHandler.
func NewAuthHandler(userSvc *service.UserService) *AuthHandler {
	return &AuthHandler{
		userSvc:  userSvc,
		validate: validator.New(),
	}
}

// RegisterRoutes mounts auth routes.
func (h *AuthHandler) RegisterRoutes(r chi.Router) {
	h.RegisterPublicRoutes(r)
	h.RegisterProtectedRoutes(r)
}

// RegisterPublicRoutes mounts routes that do not require JWT.
func (h *AuthHandler) RegisterPublicRoutes(r chi.Router) {
	r.Post("/auth/login", h.Login)
	r.Post("/auth/refresh", h.Refresh)
}

// RegisterProtectedRoutes mounts routes that require a valid JWT (applied by main.go middleware).
func (h *AuthHandler) RegisterProtectedRoutes(r chi.Router) {
	r.Post("/auth/logout", h.Logout)
	r.Get("/auth/me", h.Me)
	r.Post("/users/{userID}/mfa/enroll", h.EnrollMFA)
	r.Post("/users/{userID}/mfa/verify", h.VerifyMFA)
	r.Post("/users/{userID}/disable", h.DisableUser)
}

// Login handles POST /auth/login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}

	// Tenant ID must come from the subdomain or a header — here we use X-Tenant-ID for dev.
	// In production this is resolved from the JWT issuer or the hostname.
	tenantID, err := resolveTenantID(r)
	if err != nil {
		response.BadRequest(w, "MISSING_TENANT", "X-Tenant-ID header is required")
		return
	}

	resp, svcErr := h.userSvc.Login(r.Context(), tenantID, &req)
	if mapError(w, svcErr) != nil {
		return
	}

	response.OK(w, resp)
}

// Refresh handles POST /auth/refresh
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req model.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}

	resp, svcErr := h.userSvc.Refresh(r.Context(), req.RefreshToken)
	if mapError(w, svcErr) != nil {
		return
	}

	response.OK(w, resp)
}

// Logout handles POST /auth/logout (revokes refresh token)
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var req model.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Logout is idempotent — ignore body errors
		response.NoContent(w)
		return
	}
	_ = h.userSvc.RevokeToken(r.Context(), req.RefreshToken)
	response.NoContent(w)
}

// Me handles GET /auth/me — returns the authenticated user's profile.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	userID := mustUserID(r)

	user, svcErr := h.userSvc.GetByID(r.Context(), tenantID, userID)
	if mapError(w, svcErr) != nil {
		return
	}

	response.OK(w, user)
}

// EnrollMFA handles POST /users/{userID}/mfa/enroll
func (h *AuthHandler) EnrollMFA(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "Invalid user ID")
		return
	}

	resp, svcErr := h.userSvc.EnrollMFA(r.Context(), tenantID, userID)
	if mapError(w, svcErr) != nil {
		return
	}

	response.OK(w, resp)
}

// VerifyMFA handles POST /users/{userID}/mfa/verify
func (h *AuthHandler) VerifyMFA(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "Invalid user ID")
		return
	}

	var req model.MFAVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}

	if svcErr := h.userSvc.VerifyMFAEnrolment(r.Context(), tenantID, userID, req.Code); mapError(w, svcErr) != nil {
		return
	}

	response.OK(w, map[string]string{"message": "MFA successfully enabled"})
}

// DisableUser handles POST /users/{userID}/disable
func (h *AuthHandler) DisableUser(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "Invalid user ID")
		return
	}

	if svcErr := h.userSvc.Disable(r.Context(), tenantID, userID); mapError(w, svcErr) != nil {
		return
	}

	response.NoContent(w)
}

// ─── Context helpers ─────────────────────────────────────────────────────────

func mustTenantID(r *http.Request) uuid.UUID {
	return authctx.TenantID(r.Context())
}

func mustUserID(r *http.Request) uuid.UUID {
	return authctx.UserID(r.Context())
}

func resolveTenantID(r *http.Request) (uuid.UUID, error) {
	raw := r.Header.Get("X-Tenant-ID")
	if raw == "" {
		return uuid.Nil, apierrors.BadInput("X-Tenant-ID header required")
	}
	return uuid.Parse(raw)
}

func requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := authctx.From(r.Context()); !ok {
			response.Unauthorized(w, "Authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ─── Error mapping ────────────────────────────────────────────────────────────

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
	case apierrors.IsKind(err, apierrors.KindUnauth):
		response.Unauthorized(w, apierrors.Message(err))
	case apierrors.IsKind(err, apierrors.KindBadInput):
		response.BadRequest(w, "BAD_INPUT", err.Error())
	default:
		response.InternalError(w)
	}
	return err
}
