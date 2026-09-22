package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/cspm/internal/model"
	"github.com/cyberradar/platform/services/cspm/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// CSPMHandler exposes the Cloud Security Posture Management API.
type CSPMHandler struct {
	svc      *service.CSPMService
	validate *validator.Validate
}

// NewCSPMHandler creates a CSPMHandler.
func NewCSPMHandler(svc *service.CSPMService) *CSPMHandler {
	return &CSPMHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts all CSPM routes under the provided router.
func (h *CSPMHandler) RegisterRoutes(r chi.Router) {
	// Cloud accounts
	r.Post("/cspm/accounts", h.RegisterAccount)
	r.Get("/cspm/accounts", h.ListAccounts)
	r.Get("/cspm/accounts/{accountID}", h.GetAccount)
	r.Patch("/cspm/accounts/{accountID}", h.UpdateAccount)

	// Security rules
	r.Post("/cspm/rules", h.CreateRule)
	r.Get("/cspm/rules", h.ListRules)
	r.Post("/cspm/rules/seed", h.SeedRules)

	// Resources
	r.Post("/cspm/resources", h.UpsertResource)
	r.Get("/cspm/resources", h.ListResources)
	r.Get("/cspm/resources/{resourceID}", h.GetResource)

	// Findings
	r.Post("/cspm/findings", h.ReportFinding)
	r.Get("/cspm/findings", h.ListFindings)
	r.Patch("/cspm/findings/{findingID}", h.UpdateFinding)

	// Scans
	r.Post("/cspm/scans", h.TriggerScan)
	r.Get("/cspm/scans", h.ListScans)
	r.Get("/cspm/scans/{scanID}", h.GetScan)

	// Stats
	r.Get("/cspm/stats", h.GetStats)
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func tenantFromCtx(r *http.Request) (uuid.UUID, error) {
	id := authctx.TenantID(r.Context())
	if id == uuid.Nil {
		return uuid.Nil, apierrors.Forbidden("no tenant in context")
	}
	return id, nil
}

func userFromCtx(r *http.Request) uuid.UUID {
	return authctx.UserID(r.Context())
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	de, ok := err.(*apierrors.DomainError)
	if !ok {
		response.InternalError(w)
		return
	}
	switch de.Kind {
	case apierrors.KindNotFound:
		response.NotFound(w, de.Message)
	case apierrors.KindForbidden:
		response.Forbidden(w, de.Message)
	case apierrors.KindUnauth:
		response.Unauthorized(w, de.Message)
	case apierrors.KindBadInput, apierrors.KindConflict:
		response.BadRequest(w, string(de.Kind), de.Message)
	default:
		response.InternalError(w)
	}
}

func parseUUID(r *http.Request, param string) (uuid.UUID, error) {
	return uuid.Parse(chi.URLParam(r, param))
}

func queryInt(r *http.Request, key, def string) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		v = def
	}
	n, _ := strconv.Atoi(v)
	return n
}

// ─── Accounts ─────────────────────────────────────────────────────────────────

func (h *CSPMHandler) RegisterAccount(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	var req model.RegisterAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	if err := h.validate.Struct(req); err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, err.Error()))
		return
	}
	a, err := h.svc.RegisterAccount(r.Context(), tenantID, &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

func (h *CSPMHandler) ListAccounts(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	accounts, err := h.svc.ListAccounts(r.Context(), tenantID, r.URL.Query().Get("provider"), r.URL.Query().Get("environment"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": accounts, "total": len(accounts)})
}

func (h *CSPMHandler) GetAccount(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	accountID, err := parseUUID(r, "accountID")
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, "invalid account id"))
		return
	}
	a, err := h.svc.GetAccount(r.Context(), tenantID, accountID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (h *CSPMHandler) UpdateAccount(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	accountID, err := parseUUID(r, "accountID")
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, "invalid account id"))
		return
	}
	var req model.UpdateAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	a, err := h.svc.UpdateAccount(r.Context(), tenantID, accountID, &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

// ─── Rules ────────────────────────────────────────────────────────────────────

func (h *CSPMHandler) CreateRule(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	var req model.CreateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	if err := h.validate.Struct(req); err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, err.Error()))
		return
	}
	rule, err := h.svc.CreateRule(r.Context(), tenantID, &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func (h *CSPMHandler) ListRules(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	page     := queryInt(r, "page", "1")
	pageSize := queryInt(r, "page_size", "100")
	rules, total, err := h.svc.ListRules(r.Context(), tenantID,
		r.URL.Query().Get("provider"), r.URL.Query().Get("framework"),
		r.URL.Query().Get("severity"), page, pageSize)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules, "total": total, "page": page, "page_size": pageSize})
}

func (h *CSPMHandler) SeedRules(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	provider := r.URL.Query().Get("provider")
	if provider == "" {
		writeError(w, apierrors.New(apierrors.KindBadInput, "provider query param required"))
		return
	}
	count, err := h.svc.SeedRules(r.Context(), tenantID, provider)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules_seeded": count, "provider": provider})
}

// ─── Resources ────────────────────────────────────────────────────────────────

func (h *CSPMHandler) UpsertResource(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	var req model.UpsertResourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	if err := h.validate.Struct(req); err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, err.Error()))
		return
	}
	res, err := h.svc.UpsertResource(r.Context(), tenantID, &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *CSPMHandler) ListResources(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	f := model.ListResourcesFilter{
		ResourceType: r.URL.Query().Get("resource_type"),
		Service:      r.URL.Query().Get("service"),
		Page:         queryInt(r, "page", "1"),
		PageSize:     queryInt(r, "page_size", "50"),
	}
	if v := r.URL.Query().Get("account_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.AccountID = &id
		}
	}
	if v := r.URL.Query().Get("is_public"); v == "true" {
		b := true; f.IsPublic = &b
	}
	if v := r.URL.Query().Get("min_risk_score"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.MinRiskScore = &n
		}
	}
	if f.Page < 1 { f.Page = 1 }
	if f.PageSize < 1 || f.PageSize > 200 { f.PageSize = 50 }
	resources, total, err := h.svc.ListResources(r.Context(), tenantID, f)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"resources": resources, "total": total, "page": f.Page, "page_size": f.PageSize})
}

func (h *CSPMHandler) GetResource(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	resourceID, err := parseUUID(r, "resourceID")
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, "invalid resource id"))
		return
	}
	res, err := h.svc.GetResource(r.Context(), tenantID, resourceID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// ─── Findings ─────────────────────────────────────────────────────────────────

func (h *CSPMHandler) ReportFinding(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	var req model.ReportFindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	if err := h.validate.Struct(req); err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, err.Error()))
		return
	}
	finding, err := h.svc.ReportFinding(r.Context(), tenantID, &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, finding)
}

func (h *CSPMHandler) ListFindings(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	f := model.ListFindingsFilter{
		Severity: r.URL.Query().Get("severity"),
		Status:   r.URL.Query().Get("status"),
		Provider: r.URL.Query().Get("provider"),
		Page:     queryInt(r, "page", "1"),
		PageSize: queryInt(r, "page_size", "50"),
	}
	if v := r.URL.Query().Get("account_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.AccountID = &id
		}
	}
	if v := r.URL.Query().Get("resource_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.ResourceID = &id
		}
	}
	if f.Page < 1 { f.Page = 1 }
	if f.PageSize < 1 || f.PageSize > 200 { f.PageSize = 50 }
	findings, total, err := h.svc.ListFindings(r.Context(), tenantID, f)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": findings, "total": total, "page": f.Page, "page_size": f.PageSize})
}

func (h *CSPMHandler) UpdateFinding(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	findingID, err := parseUUID(r, "findingID")
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, "invalid finding id"))
		return
	}
	var req model.UpdateFindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	if err := h.validate.Struct(req); err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, err.Error()))
		return
	}
	finding, err := h.svc.UpdateFinding(r.Context(), tenantID, findingID, userFromCtx(r), &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, finding)
}

// ─── Scans ────────────────────────────────────────────────────────────────────

func (h *CSPMHandler) TriggerScan(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	var req model.TriggerScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	if err := h.validate.Struct(req); err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, err.Error()))
		return
	}
	scan, err := h.svc.TriggerScan(r.Context(), tenantID, &req, userFromCtx(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, scan)
}

func (h *CSPMHandler) ListScans(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	accountIDStr := r.URL.Query().Get("account_id")
	accountID, err := uuid.Parse(accountIDStr)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, "account_id query param required"))
		return
	}
	page     := queryInt(r, "page", "1")
	pageSize := queryInt(r, "page_size", "20")
	scans, total, err := h.svc.ListScans(r.Context(), tenantID, accountID, page, pageSize)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scans": scans, "total": total, "page": page, "page_size": pageSize})
}

func (h *CSPMHandler) GetScan(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	scanID, err := parseUUID(r, "scanID")
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, "invalid scan id"))
		return
	}
	scan, err := h.svc.GetScan(r.Context(), tenantID, scanID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, scan)
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (h *CSPMHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	stats, err := h.svc.Stats(r.Context(), tenantID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}
