package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/copilot/internal/model"
	"github.com/cyberradar/platform/services/copilot/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// CopilotHandler exposes the AI Copilot API.
type CopilotHandler struct {
	svc      *service.CopilotService
	validate *validator.Validate
}

// NewCopilotHandler creates a CopilotHandler.
func NewCopilotHandler(svc *service.CopilotService) *CopilotHandler {
	return &CopilotHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts all copilot routes.
func (h *CopilotHandler) RegisterRoutes(r chi.Router) {
	// Sessions
	r.Get("/copilot/sessions", h.ListSessions)
	r.Post("/copilot/sessions", h.CreateSession)
	r.Get("/copilot/sessions/{sessionID}", h.GetSession)
	r.Post("/copilot/sessions/{sessionID}/close", h.CloseSession)
	r.Get("/copilot/sessions/{sessionID}/history", h.GetHistory)

	// Chat (main interaction)
	r.Post("/copilot/sessions/{sessionID}/chat", h.Chat)

	// Async hunt jobs
	r.Get("/copilot/hunt-jobs", h.ListHuntJobs)
	r.Post("/copilot/hunt-jobs", h.CreateHuntJob)
	r.Get("/copilot/hunt-jobs/{jobID}", h.GetHuntJob)

	// Stats
	r.Get("/copilot/stats", h.Stats)
}

// ─── Sessions ─────────────────────────────────────────────────────────────────

func (h *CopilotHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	userID := mustCallerID(r)
	q := r.URL.Query()

	f := model.SessionFilter{
		TenantID: tenantID,
		UserID:   userID,
		Limit:    queryInt(q.Get("limit"), 20),
		Offset:   queryInt(q.Get("offset"), 0),
	}
	if v := q.Get("active"); v != "" {
		active := v == "true"
		f.Active = &active
	}

	sessions, total, err := h.svc.ListSessions(r.Context(), f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"sessions": sessions, "total": total})
}

func (h *CopilotHandler) CreateSession(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	userID := mustCallerID(r)
	var req model.CreateSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req = model.CreateSessionRequest{} // empty body is fine
	}
	session, err := h.svc.CreateSession(r.Context(), tenantID, userID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, session)
}

func (h *CopilotHandler) GetSession(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "sessionID")
	if !ok {
		return
	}
	session, err := h.svc.GetSession(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, session)
}

func (h *CopilotHandler) CloseSession(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "sessionID")
	if !ok {
		return
	}
	if err := h.svc.CloseSession(r.Context(), tenantID, id); err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"status": "closed"})
}

func (h *CopilotHandler) GetHistory(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "sessionID")
	if !ok {
		return
	}
	limit := queryInt(r.URL.Query().Get("limit"), 50)
	msgs, err := h.svc.GetHistory(r.Context(), tenantID, id, limit)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"messages": msgs, "total": len(msgs)})
}

// ─── Chat ─────────────────────────────────────────────────────────────────────

func (h *CopilotHandler) Chat(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	userID := mustCallerID(r)
	sessionID, ok := parseUUID(w, r, "sessionID")
	if !ok {
		return
	}
	var req model.SendMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	msg, err := h.svc.Chat(r.Context(), tenantID, userID, sessionID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, msg)
}

// ─── Hunt Jobs ────────────────────────────────────────────────────────────────

func (h *CopilotHandler) ListHuntJobs(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	userID := mustCallerID(r)
	q := r.URL.Query()
	limit := queryInt(q.Get("limit"), 20)
	offset := queryInt(q.Get("offset"), 0)

	jobs, total, err := h.svc.ListHuntJobs(r.Context(), tenantID, userID, limit, offset)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"jobs": jobs, "total": total})
}

func (h *CopilotHandler) CreateHuntJob(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	userID := mustCallerID(r)
	var req model.CreateHuntJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	job, err := h.svc.CreateHuntJob(r.Context(), tenantID, userID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, job)
}

func (h *CopilotHandler) GetHuntJob(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "jobID")
	if !ok {
		return
	}
	job, err := h.svc.GetHuntJob(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, job)
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (h *CopilotHandler) Stats(w http.ResponseWriter, r *http.Request) {
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

func mustCallerID(r *http.Request) uuid.UUID {
	return authctx.UserID(r.Context())
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
