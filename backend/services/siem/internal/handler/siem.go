package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	"github.com/cyberradar/platform/internal/pkg/authmw"
	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/siem/internal/model"
	"github.com/cyberradar/platform/services/siem/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// SIEMHandler exposes the SIEM API.
type SIEMHandler struct {
	svc      *service.SIEMService
	validate *validator.Validate
}

// NewSIEMHandler creates a SIEMHandler.
func NewSIEMHandler(svc *service.SIEMService) *SIEMHandler {
	return &SIEMHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts all SIEM routes.
//
// The three groups carry different permissions: authoring a detection rule is
// not the same authority as triaging an alert, and a case is an incident.
func (h *SIEMHandler) RegisterRoutes(r chi.Router) {
	r.Route("/siem/rules", func(r chi.Router) {
		r.Use(authmw.RequirePermissionByMethod("rules"))
		r.Get("/", h.ListRules)
		r.Post("/", h.CreateRule)
		r.Get("/{ruleID}", h.GetRule)
		r.Put("/{ruleID}", h.UpdateRule)
		r.Delete("/{ruleID}", h.DeleteRule)
	})

	r.Route("/siem/alerts", func(r chi.Router) {
		r.Use(authmw.RequirePermissionByMethod("alerts"))
		r.Get("/", h.ListAlerts)
		r.Get("/stats", h.AlertStats)
		r.Put("/{alertID}", h.UpdateAlert)
		r.Post("/{alertID}/case", h.PromoteToCase)
	})

	r.Route("/siem/cases", func(r chi.Router) {
		r.Use(authmw.RequirePermissionByMethod("incidents"))
		r.Get("/", h.ListCases)
		r.Post("/", h.CreateCase)
		r.Get("/{caseID}", h.GetCase)
		r.Put("/{caseID}", h.UpdateCase)
		r.Get("/{caseID}/comments", h.ListComments)
		r.Post("/{caseID}/comments", h.AddComment)
		r.Post("/{caseID}/observables", h.AddObservable)
	})
}

// ─── Rules ────────────────────────────────────────────────────────────────────

func (h *SIEMHandler) ListRules(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	enabledOnly := r.URL.Query().Get("enabled") == "true"
	rules, err := h.svc.ListRules(r.Context(), tenantID, enabledOnly)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"rules": rules, "total": len(rules)})
}

func (h *SIEMHandler) CreateRule(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)

	var req model.CreateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}

	rule, err := h.svc.CreateRule(r.Context(), tenantID, &callerID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, rule)
}

func (h *SIEMHandler) GetRule(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "ruleID")
	if !ok {
		return
	}
	rule, err := h.svc.GetRule(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, rule)
}

func (h *SIEMHandler) UpdateRule(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "ruleID")
	if !ok {
		return
	}
	var req model.UpdateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	rule, err := h.svc.UpdateRule(r.Context(), tenantID, id, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, rule)
}

func (h *SIEMHandler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "ruleID")
	if !ok {
		return
	}
	if err := h.svc.DeleteRule(r.Context(), tenantID, id); err != nil {
		mapError(w, err)
		return
	}
	response.NoContent(w)
}

// ─── Alerts ───────────────────────────────────────────────────────────────────

func (h *SIEMHandler) ListAlerts(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()

	f := model.AlertFilter{
		TenantID:   tenantID,
		Severity:   q.Get("severity"),
		Status:     q.Get("status"),
		RuleID:     q.Get("rule_id"),
		EntityType: q.Get("entity_type"),
		Limit:      queryInt(q.Get("limit"), 50),
		Offset:     queryInt(q.Get("offset"), 0),
	}
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.From = &t
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.To = &t
		}
	}

	alerts, total, err := h.svc.ListAlerts(r.Context(), f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"alerts": alerts, "total": total})
}

func (h *SIEMHandler) AlertStats(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	stats, err := h.svc.GetAlertStats(r.Context(), tenantID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, stats)
}

func (h *SIEMHandler) UpdateAlert(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "alertID")
	if !ok {
		return
	}
	var req model.UpdateAlertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	meta, err := h.svc.UpdateAlert(r.Context(), tenantID, id, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, meta)
}

func (h *SIEMHandler) PromoteToCase(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	alertID, ok := parseUUID(w, r, "alertID")
	if !ok {
		return
	}
	var req model.CreateCaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	c, err := h.svc.PromoteToCase(r.Context(), tenantID, alertID, &callerID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, c)
}

// ─── Cases ────────────────────────────────────────────────────────────────────

func (h *SIEMHandler) ListCases(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()
	f := model.CaseFilter{
		TenantID: tenantID,
		Status:   q.Get("status"),
		Severity: q.Get("severity"),
		Limit:    queryInt(q.Get("limit"), 50),
		Offset:   queryInt(q.Get("offset"), 0),
	}
	cases, total, err := h.svc.ListCases(r.Context(), f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"cases": cases, "total": total})
}

func (h *SIEMHandler) CreateCase(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	var req model.CreateCaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	c, err := h.svc.CreateCase(r.Context(), tenantID, &callerID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, c)
}

func (h *SIEMHandler) GetCase(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "caseID")
	if !ok {
		return
	}
	c, err := h.svc.GetCase(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, c)
}

func (h *SIEMHandler) UpdateCase(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "caseID")
	if !ok {
		return
	}
	var req model.UpdateCaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	c, err := h.svc.UpdateCase(r.Context(), tenantID, id, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, c)
}

func (h *SIEMHandler) ListComments(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "caseID")
	if !ok {
		return
	}
	comments, err := h.svc.ListComments(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"comments": comments, "total": len(comments)})
}

func (h *SIEMHandler) AddComment(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	id, ok := parseUUID(w, r, "caseID")
	if !ok {
		return
	}
	var req model.AddCommentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	comment, err := h.svc.AddComment(r.Context(), tenantID, id, &callerID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, comment)
}

func (h *SIEMHandler) AddObservable(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	id, ok := parseUUID(w, r, "caseID")
	if !ok {
		return
	}
	var req model.AddObservableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	obs, err := h.svc.AddObservable(r.Context(), tenantID, id, &callerID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, obs)
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
		response.NotFound(w, "resource")
	case apierrors.IsKind(err, apierrors.KindForbidden):
		response.Forbidden(w, err.Error())
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
