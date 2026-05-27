package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/compliance/internal/model"
	"github.com/cyberradar/platform/services/compliance/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// ComplianceHandler exposes the Compliance API.
type ComplianceHandler struct {
	svc      *service.ComplianceService
	validate *validator.Validate
}

// NewComplianceHandler creates a ComplianceHandler.
func NewComplianceHandler(svc *service.ComplianceService) *ComplianceHandler {
	return &ComplianceHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts all compliance routes under the provided router.
func (h *ComplianceHandler) RegisterRoutes(r chi.Router) {
	// Frameworks
	r.Get("/compliance/frameworks", h.ListFrameworks)
	r.Post("/compliance/frameworks", h.CreateFramework)
	r.Get("/compliance/frameworks/{frameworkID}", h.GetFramework)
	r.Post("/compliance/frameworks/{frameworkID}/activate", h.ActivateFramework)
	r.Post("/compliance/frameworks/{frameworkID}/deactivate", h.DeactivateFramework)
	r.Get("/compliance/frameworks/{frameworkID}/score", h.FrameworkScore)

	// Controls
	r.Get("/compliance/controls", h.ListControls)
	r.Post("/compliance/controls", h.CreateControl)
	r.Get("/compliance/controls/{controlID}", h.GetControl)

	// Assessments
	r.Get("/compliance/assessments", h.ListAssessments)
	r.Post("/compliance/assessments", h.UpsertAssessment)
	r.Get("/compliance/assessments/{assessmentID}", h.GetAssessment)
	r.Patch("/compliance/assessments/{assessmentID}", h.UpdateAssessment)
	r.Post("/compliance/assessments/bulk", h.BulkUpsertAssessments)
	r.Post("/compliance/assessments/auto", h.AutoAssess)

	// Evidence
	r.Get("/compliance/evidence", h.ListEvidence)
	r.Post("/compliance/evidence", h.CreateEvidence)

	// Risks
	r.Get("/compliance/risks", h.ListRisks)
	r.Post("/compliance/risks", h.CreateRisk)
	r.Get("/compliance/risks/{riskID}", h.GetRisk)
	r.Patch("/compliance/risks/{riskID}", h.UpdateRisk)

	// Dashboard
	r.Get("/compliance/stats", h.Stats)
}

// ─── Frameworks ───────────────────────────────────────────────────────────────

func (h *ComplianceHandler) ListFrameworks(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)

	var activeOnly *bool
	if v := r.URL.Query().Get("active"); v != "" {
		b := v == "true"
		activeOnly = &b
	}

	frameworks, err := h.svc.ListFrameworks(r.Context(), tenantID, activeOnly)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"frameworks": frameworks, "total": len(frameworks)})
}

func (h *ComplianceHandler) CreateFramework(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.CreateFrameworkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	fw, err := h.svc.CreateFramework(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, fw)
}

func (h *ComplianceHandler) GetFramework(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "frameworkID")
	if !ok {
		return
	}
	fw, err := h.svc.GetFramework(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	// Enrich with score
	score, _ := h.svc.ComputeFrameworkScore(r.Context(), tenantID, id)
	response.OK(w, map[string]any{"framework": fw, "score": score})
}

func (h *ComplianceHandler) ActivateFramework(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "frameworkID")
	if !ok {
		return
	}
	if err := h.svc.SetFrameworkActive(r.Context(), tenantID, id, true); err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"status": "activated"})
}

func (h *ComplianceHandler) DeactivateFramework(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "frameworkID")
	if !ok {
		return
	}
	if err := h.svc.SetFrameworkActive(r.Context(), tenantID, id, false); err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"status": "deactivated"})
}

func (h *ComplianceHandler) FrameworkScore(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "frameworkID")
	if !ok {
		return
	}
	score, err := h.svc.ComputeFrameworkScore(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, score)
}

// ─── Controls ─────────────────────────────────────────────────────────────────

func (h *ComplianceHandler) ListControls(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()

	f := model.ControlFilter{
		TenantID: tenantID,
		Domain:   q.Get("domain"),
		Priority: q.Get("priority"),
		Limit:    queryInt(q.Get("limit"), 100),
		Offset:   queryInt(q.Get("offset"), 0),
	}
	if v := q.Get("framework_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.FrameworkID = &id
		}
	}
	if v := q.Get("is_automated"); v != "" {
		b := v == "true"
		f.IsAutomated = &b
	}

	controls, total, err := h.svc.ListControls(r.Context(), f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"controls": controls, "total": total})
}

func (h *ComplianceHandler) CreateControl(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.CreateControlRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	c, err := h.svc.CreateControl(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, c)
}

func (h *ComplianceHandler) GetControl(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "controlID")
	if !ok {
		return
	}
	c, err := h.svc.GetControl(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, c)
}

// ─── Assessments ──────────────────────────────────────────────────────────────

func (h *ComplianceHandler) ListAssessments(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()

	f := model.AssessmentFilter{
		TenantID: tenantID,
		Status:   q.Get("status"),
		Limit:    queryInt(q.Get("limit"), 100),
		Offset:   queryInt(q.Get("offset"), 0),
	}
	if v := q.Get("framework_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.FrameworkID = &id
		}
	}

	assessments, total, err := h.svc.ListAssessments(r.Context(), f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"assessments": assessments, "total": total})
}

func (h *ComplianceHandler) UpsertAssessment(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	var req model.CreateAssessmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	a, err := h.svc.UpsertAssessment(r.Context(), tenantID, &callerID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, a)
}

func (h *ComplianceHandler) GetAssessment(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "assessmentID")
	if !ok {
		return
	}
	a, err := h.svc.GetAssessment(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, a)
}

func (h *ComplianceHandler) UpdateAssessment(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	id, ok := parseUUID(w, r, "assessmentID")
	if !ok {
		return
	}
	var req model.UpdateAssessmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	a, err := h.svc.UpdateAssessment(r.Context(), tenantID, id, &req, &callerID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, a)
}

func (h *ComplianceHandler) BulkUpsertAssessments(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	var req model.BulkAssessmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	count, err := h.svc.BulkUpsertAssessments(r.Context(), tenantID, &callerID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"upserted": count})
}

func (h *ComplianceHandler) AutoAssess(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	suggestions, err := h.svc.AutoAssessFromPlatform(r.Context(), tenantID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"suggestions": suggestions, "total": len(suggestions)})
}

// ─── Evidence ─────────────────────────────────────────────────────────────────

func (h *ComplianceHandler) ListEvidence(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	assessmentIDStr := r.URL.Query().Get("assessment_id")
	if assessmentIDStr == "" {
		response.BadRequest(w, "MISSING_PARAM", "assessment_id is required")
		return
	}
	assessmentID, err := uuid.Parse(assessmentIDStr)
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "assessment_id must be a valid UUID")
		return
	}
	evs, err := h.svc.ListEvidence(r.Context(), tenantID, assessmentID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"evidence": evs, "total": len(evs)})
}

func (h *ComplianceHandler) CreateEvidence(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	var req model.CreateEvidenceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	ev, err := h.svc.CreateEvidence(r.Context(), tenantID, &callerID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, ev)
}

// ─── Risks ────────────────────────────────────────────────────────────────────

func (h *ComplianceHandler) ListRisks(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()

	f := model.RiskFilter{
		TenantID: tenantID,
		Status:   q.Get("status"),
		Category: q.Get("category"),
		MinScore: queryInt(q.Get("min_score"), 0),
		Limit:    queryInt(q.Get("limit"), 50),
		Offset:   queryInt(q.Get("offset"), 0),
	}
	if v := q.Get("owner_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.OwnerID = &id
		}
	}

	risks, total, err := h.svc.ListRisks(r.Context(), f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"risks": risks, "total": total})
}

func (h *ComplianceHandler) CreateRisk(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	var req model.CreateRiskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	risk, err := h.svc.CreateRisk(r.Context(), tenantID, &callerID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, risk)
}

func (h *ComplianceHandler) GetRisk(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "riskID")
	if !ok {
		return
	}
	risk, err := h.svc.GetRisk(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, risk)
}

func (h *ComplianceHandler) UpdateRisk(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "riskID")
	if !ok {
		return
	}
	var req model.UpdateRiskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	risk, err := h.svc.UpdateRisk(r.Context(), tenantID, id, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, risk)
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (h *ComplianceHandler) Stats(w http.ResponseWriter, r *http.Request) {
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
	if n, err := strconv.Atoi(s); err == nil && n >= 0 {
		return n
	}
	return def
}
