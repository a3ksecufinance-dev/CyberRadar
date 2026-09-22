package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/iga/internal/model"
	"github.com/cyberradar/platform/services/iga/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// IGAHandler exposes the Identity Governance & Administration API.
type IGAHandler struct {
	svc      *service.IGAService
	validate *validator.Validate
}

// NewIGAHandler creates an IGAHandler.
func NewIGAHandler(svc *service.IGAService) *IGAHandler {
	return &IGAHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts all IGA routes under the provided router.
func (h *IGAHandler) RegisterRoutes(r chi.Router) {
	// Roles
	r.Post("/iga/roles", h.CreateRole)
	r.Get("/iga/roles", h.ListRoles)
	r.Get("/iga/roles/{roleID}", h.GetRole)
	r.Patch("/iga/roles/{roleID}", h.UpdateRole)

	// Role assignments
	r.Post("/iga/assignments", h.AssignRole)
	r.Get("/iga/assignments", h.ListAssignments)
	r.Get("/iga/assignments/{assignmentID}", h.GetAssignment)
	r.Patch("/iga/assignments/{assignmentID}", h.UpdateAssignment)

	// Access review campaigns
	r.Post("/iga/campaigns", h.CreateCampaign)
	r.Get("/iga/campaigns", h.ListCampaigns)
	r.Get("/iga/campaigns/{campaignID}", h.GetCampaign)
	r.Post("/iga/campaigns/{campaignID}/launch", h.LaunchCampaign)

	// Review items
	r.Get("/iga/reviews", h.ListReviewItems)
	r.Post("/iga/reviews/{itemID}/decision", h.SubmitDecision)

	// SoD policies
	r.Post("/iga/sod/policies", h.CreateSoDPolicy)
	r.Get("/iga/sod/policies", h.ListSoDPolicies)
	r.Post("/iga/sod/scan", h.RunSoDScan)

	// SoD violations
	r.Get("/iga/sod/violations", h.ListSoDViolations)
	r.Patch("/iga/sod/violations/{violationID}", h.UpdateViolation)

	// Stats
	r.Get("/iga/stats", h.GetStats)
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

// ─── Roles ────────────────────────────────────────────────────────────────────

func (h *IGAHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	var req model.CreateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	if err := h.validate.Struct(req); err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, err.Error()))
		return
	}
	role, err := h.svc.CreateRole(r.Context(), tenantID, &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, role)
}

func (h *IGAHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	activeOnly := r.URL.Query().Get("active_only") != "false"
	page     := queryInt(r, "page", "1")
	pageSize := queryInt(r, "page_size", "50")
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 50
	}
	roles, total, err := h.svc.ListRoles(r.Context(), tenantID,
		r.URL.Query().Get("role_type"), r.URL.Query().Get("risk_level"),
		activeOnly, page, pageSize)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles, "total": total, "page": page, "page_size": pageSize})
}

func (h *IGAHandler) GetRole(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	roleID, err := parseUUID(r, "roleID")
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, "invalid role id"))
		return
	}
	role, err := h.svc.GetRole(r.Context(), tenantID, roleID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, role)
}

func (h *IGAHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	roleID, err := parseUUID(r, "roleID")
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, "invalid role id"))
		return
	}
	var req model.UpdateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	role, err := h.svc.UpdateRole(r.Context(), tenantID, roleID, &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, role)
}

// ─── Assignments ──────────────────────────────────────────────────────────────

func (h *IGAHandler) AssignRole(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	var req model.AssignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	if err := h.validate.Struct(req); err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, err.Error()))
		return
	}
	assignment, err := h.svc.AssignRole(r.Context(), tenantID, &req, userFromCtx(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, assignment)
}

func (h *IGAHandler) ListAssignments(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	f := model.ListAssignmentsFilter{
		Status:   r.URL.Query().Get("status"),
		Page:     queryInt(r, "page", "1"),
		PageSize: queryInt(r, "page_size", "50"),
	}
	if v := r.URL.Query().Get("identity_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.IdentityID = &id
		}
	}
	if v := r.URL.Query().Get("role_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.RoleID = &id
		}
	}
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize < 1 || f.PageSize > 200 {
		f.PageSize = 50
	}
	assignments, total, err := h.svc.ListAssignments(r.Context(), tenantID, f)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"assignments": assignments, "total": total, "page": f.Page, "page_size": f.PageSize})
}

func (h *IGAHandler) GetAssignment(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	assignmentID, err := parseUUID(r, "assignmentID")
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, "invalid assignment id"))
		return
	}
	assignment, err := h.svc.GetAssignment(r.Context(), tenantID, assignmentID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, assignment)
}

func (h *IGAHandler) UpdateAssignment(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	assignmentID, err := parseUUID(r, "assignmentID")
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, "invalid assignment id"))
		return
	}
	var req model.UpdateAssignmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	assignment, err := h.svc.UpdateAssignment(r.Context(), tenantID, assignmentID, &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, assignment)
}

// ─── Campaigns ────────────────────────────────────────────────────────────────

func (h *IGAHandler) CreateCampaign(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	var req model.CreateCampaignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	if err := h.validate.Struct(req); err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, err.Error()))
		return
	}
	c, err := h.svc.CreateCampaign(r.Context(), tenantID, &req, userFromCtx(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (h *IGAHandler) ListCampaigns(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	page     := queryInt(r, "page", "1")
	pageSize := queryInt(r, "page_size", "20")
	campaigns, total, err := h.svc.ListCampaigns(r.Context(), tenantID, r.URL.Query().Get("status"), page, pageSize)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"campaigns": campaigns, "total": total, "page": page, "page_size": pageSize})
}

func (h *IGAHandler) GetCampaign(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	campaignID, err := parseUUID(r, "campaignID")
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, "invalid campaign id"))
		return
	}
	c, err := h.svc.GetCampaign(r.Context(), tenantID, campaignID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (h *IGAHandler) LaunchCampaign(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	campaignID, err := parseUUID(r, "campaignID")
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, "invalid campaign id"))
		return
	}
	c, err := h.svc.LaunchCampaign(r.Context(), tenantID, campaignID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// ─── Review Items ─────────────────────────────────────────────────────────────

func (h *IGAHandler) ListReviewItems(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	f := model.ListReviewItemsFilter{
		Decision: r.URL.Query().Get("decision"),
		Page:     queryInt(r, "page", "1"),
		PageSize: queryInt(r, "page_size", "50"),
	}
	if v := r.URL.Query().Get("campaign_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.CampaignID = &id
		}
	}
	if v := r.URL.Query().Get("identity_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.IdentityID = &id
		}
	}
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize < 1 || f.PageSize > 200 {
		f.PageSize = 50
	}
	items, total, err := h.svc.ListReviewItems(r.Context(), tenantID, f)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "page": f.Page, "page_size": f.PageSize})
}

func (h *IGAHandler) SubmitDecision(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	itemID, err := parseUUID(r, "itemID")
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, "invalid item id"))
		return
	}
	var req model.ReviewDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	if err := h.validate.Struct(req); err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, err.Error()))
		return
	}
	item, err := h.svc.SubmitDecision(r.Context(), tenantID, itemID, userFromCtx(r), &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

// ─── SoD ──────────────────────────────────────────────────────────────────────

func (h *IGAHandler) CreateSoDPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	var req model.CreateSoDPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	if err := h.validate.Struct(req); err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, err.Error()))
		return
	}
	policy, err := h.svc.CreateSoDPolicy(r.Context(), tenantID, &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, policy)
}

func (h *IGAHandler) ListSoDPolicies(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	policies, err := h.svc.ListSoDPolicies(r.Context(), tenantID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": policies, "total": len(policies)})
}

func (h *IGAHandler) RunSoDScan(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	count, err := h.svc.RunSoDScan(r.Context(), tenantID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"violations_detected": count})
}

func (h *IGAHandler) ListSoDViolations(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	page     := queryInt(r, "page", "1")
	pageSize := queryInt(r, "page_size", "50")
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 50
	}
	violations, total, err := h.svc.ListSoDViolations(r.Context(), tenantID,
		r.URL.Query().Get("status"), r.URL.Query().Get("severity"), page, pageSize)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"violations": violations, "total": total, "page": page, "page_size": pageSize})
}

func (h *IGAHandler) UpdateViolation(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	violationID, err := parseUUID(r, "violationID")
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, "invalid violation id"))
		return
	}
	var req model.UpdateViolationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	if err := h.validate.Struct(req); err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, err.Error()))
		return
	}
	v, err := h.svc.UpdateViolation(r.Context(), tenantID, violationID, userFromCtx(r), &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (h *IGAHandler) GetStats(w http.ResponseWriter, r *http.Request) {
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
