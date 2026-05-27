package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/pam/internal/model"
	"github.com/cyberradar/platform/services/pam/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// PAMHandler exposes all PAM API endpoints.
type PAMHandler struct {
	svc      *service.PAMService
	validate *validator.Validate
}

// NewPAMHandler creates a PAMHandler.
func NewPAMHandler(svc *service.PAMService) *PAMHandler {
	return &PAMHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts all PAM routes.
func (h *PAMHandler) RegisterRoutes(r chi.Router) {
	// Privileged accounts (admin only)
	r.Get("/pam/accounts", h.ListAccounts)
	r.Post("/pam/accounts", h.CreateAccount)
	r.Get("/pam/accounts/{accountID}", h.GetAccount)

	// JIT Access Requests
	r.Get("/pam/requests", h.ListRequests)
	r.Post("/pam/requests", h.CreateRequest)
	r.Get("/pam/requests/{requestID}", h.GetRequest)
	r.Post("/pam/requests/{requestID}/approve", h.ResolveRequest)

	// Privileged Sessions
	r.Get("/pam/sessions", h.ListSessions)
	r.Post("/pam/sessions", h.OpenSession)
	r.Get("/pam/sessions/{sessionID}", h.GetSession)
	r.Delete("/pam/sessions/{sessionID}", h.TerminateSession)
	r.Get("/pam/sessions/{sessionID}/events", h.ListSessionEvents)
	r.Post("/pam/sessions/{sessionID}/events", h.RecordEvent)

	// Identity Risk
	r.Get("/pam/identities/high-risk", h.ListHighRisk)
	r.Get("/pam/identities/{identityID}/risk", h.GetRisk)
	r.Get("/pam/identities/{identityID}/risk/breakdown", h.GetRiskBreakdown)
}

// ─── Privileged Accounts ──────────────────────────────────────────────────────

func (h *PAMHandler) ListAccounts(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	accounts, err := h.svc.ListAccounts(r.Context(), tenantID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"accounts": accounts, "total": len(accounts)})
}

func (h *PAMHandler) CreateAccount(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.CreateAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	a, err := h.svc.CreateAccount(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, a)
}

func (h *PAMHandler) GetAccount(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "accountID")
	if !ok {
		return
	}
	a, err := h.svc.GetAccount(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, a)
}

// ─── Access Requests ──────────────────────────────────────────────────────────

func (h *PAMHandler) ListRequests(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	f := model.AccessRequestFilter{
		TenantID: tenantID,
		Status:   r.URL.Query().Get("status"),
		Limit:    queryInt(r.URL.Query().Get("limit"), 50),
		Offset:   queryInt(r.URL.Query().Get("offset"), 0),
	}
	requests, total, err := h.svc.ListRequests(r.Context(), f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"requests": requests, "total": total})
}

func (h *PAMHandler) CreateRequest(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)

	var req model.CreateRequestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}

	ar, err := h.svc.CreateRequest(r.Context(), tenantID, callerID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, ar)
}

func (h *PAMHandler) GetRequest(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "requestID")
	if !ok {
		return
	}
	ar, err := h.svc.GetRequest(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, ar)
}

func (h *PAMHandler) ResolveRequest(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	approverID := mustCallerID(r)
	id, ok := parseUUID(w, r, "requestID")
	if !ok {
		return
	}

	var req model.ApproveRequestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}

	if err := h.svc.ResolveRequest(r.Context(), tenantID, id, approverID, &req); err != nil {
		mapError(w, err)
		return
	}

	msg := "access request rejected"
	if req.Approved {
		msg = "access request approved"
	}
	response.OK(w, map[string]string{"message": msg})
}

// ─── Sessions ─────────────────────────────────────────────────────────────────

func (h *PAMHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	f := model.SessionFilter{
		TenantID: tenantID,
		Status:   r.URL.Query().Get("status"),
		Limit:    queryInt(r.URL.Query().Get("limit"), 50),
		Offset:   queryInt(r.URL.Query().Get("offset"), 0),
	}
	sessions, total, err := h.svc.ListSessions(r.Context(), f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"sessions": sessions, "total": total})
}

func (h *PAMHandler) OpenSession(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)

	var req model.OpenSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}

	sess, err := h.svc.OpenSession(r.Context(), tenantID, callerID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, sess)
}

func (h *PAMHandler) GetSession(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "sessionID")
	if !ok {
		return
	}
	sess, err := h.svc.GetSession(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, sess)
}

func (h *PAMHandler) TerminateSession(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	id, ok := parseUUID(w, r, "sessionID")
	if !ok {
		return
	}
	if err := h.svc.TerminateSession(r.Context(), tenantID, id, callerID); err != nil {
		mapError(w, err)
		return
	}
	response.NoContent(w)
}

func (h *PAMHandler) RecordEvent(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	sessionID, ok := parseUUID(w, r, "sessionID")
	if !ok {
		return
	}

	var req model.RecordEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}

	e, err := h.svc.RecordEvent(r.Context(), tenantID, sessionID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, e)
}

func (h *PAMHandler) ListSessionEvents(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	sessionID, ok := parseUUID(w, r, "sessionID")
	if !ok {
		return
	}
	events, err := h.svc.ListSessionEvents(r.Context(), tenantID, sessionID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"events": events, "total": len(events)})
}

// ─── Identity Risk ────────────────────────────────────────────────────────────

func (h *PAMHandler) GetRisk(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	identityID, ok := parseUUID(w, r, "identityID")
	if !ok {
		return
	}
	p, err := h.svc.GetIdentityRisk(r.Context(), tenantID, identityID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, p)
}

func (h *PAMHandler) GetRiskBreakdown(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	identityID, ok := parseUUID(w, r, "identityID")
	if !ok {
		return
	}
	rb, err := h.svc.GetRiskBreakdown(r.Context(), tenantID, identityID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, rb)
}

func (h *PAMHandler) ListHighRisk(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	threshold := 6.0
	if v := r.URL.Query().Get("threshold"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			threshold = f
		}
	}
	profiles, err := h.svc.ListHighRiskIdentities(r.Context(), tenantID, threshold)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"profiles": profiles, "total": len(profiles)})
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func mustTenantID(r *http.Request) uuid.UUID {
	v, _ := r.Context().Value("tenant_id").(string)
	id, _ := uuid.Parse(v)
	return id
}

func mustCallerID(r *http.Request) uuid.UUID {
	v, _ := r.Context().Value("user_id").(string)
	id, _ := uuid.Parse(v)
	return id
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
