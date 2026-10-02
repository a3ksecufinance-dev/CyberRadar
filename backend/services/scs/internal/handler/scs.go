package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	"github.com/cyberradar/platform/internal/pkg/httperr"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/scs/internal/model"
	"github.com/cyberradar/platform/services/scs/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

type SCSHandler struct {
	svc    *service.SCSService
	logger zerolog.Logger
}

func NewSCSHandler(svc *service.SCSService, logger zerolog.Logger) *SCSHandler {
	return &SCSHandler{svc: svc, logger: logger}
}

func (h *SCSHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Vendors
	r.Post("/vendors", h.CreateVendor)
	r.Get("/vendors", h.ListVendors)
	r.Get("/vendors/{vendorID}", h.GetVendor)
	r.Patch("/vendors/{vendorID}", h.UpdateVendor)

	// Components (SBOM entries)
	r.Post("/components", h.CreateComponent)
	r.Get("/components", h.ListComponents)
	r.Get("/components/{componentID}", h.GetComponent)
	r.Patch("/components/{componentID}", h.UpdateComponent)

	// SBOMs
	r.Post("/sboms", h.CreateSBOM)
	r.Get("/sboms", h.ListSBOMs)
	r.Get("/sboms/{sbomID}", h.GetSBOM)

	// Assessments
	r.Post("/assessments", h.CreateAssessment)
	r.Get("/assessments", h.ListAssessments)
	r.Patch("/assessments/{assessmentID}", h.UpdateAssessment)

	// Alerts
	r.Post("/alerts", h.CreateAlert)
	r.Get("/alerts", h.ListAlerts)
	r.Patch("/alerts/{alertID}", h.UpdateAlert)

	// Policies
	r.Post("/policies", h.CreatePolicy)
	r.Get("/policies", h.ListPolicies)
	r.Patch("/policies/{policyID}", h.UpdatePolicy)

	// Stats
	r.Get("/stats", h.GetStats)

	return r
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func tenantFromCtx(r *http.Request) (uuid.UUID, bool) {
	id := authctx.TenantID(r.Context())
	return id, id != uuid.Nil
}

func userFromCtx(r *http.Request) *uuid.UUID {
	if id := authctx.UserID(r.Context()); id != uuid.Nil {
		return &id
	}
	return nil
}

func parseUUID(r *http.Request, param string) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, param))
	return id, err == nil
}

func parseBoolQuery(r *http.Request, key string) *bool {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return nil
	}
	return &v
}

// ─── Vendors ──────────────────────────────────────────────────────────────────

func (h *SCSHandler) CreateVendor(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	var req model.CreateVendorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	if req.Name == "" || req.VendorType == "" {
		response.BadRequest(w, "VALIDATION_ERROR", "name and vendor_type are required")
		return
	}
	v, err := h.svc.CreateVendor(r.Context(), tenantID, &req, userFromCtx(r))
	if err != nil {
		h.logger.Error().Err(err).Msg("CreateVendor")
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	response.Created(w, v)
}

func (h *SCSHandler) ListVendors(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	tier, _ := strconv.Atoi(q.Get("risk_tier"))
	f := model.ListVendorsFilter{
		Status:    q.Get("status"),
		RiskTier:  tier,
		RiskLevel: q.Get("risk_level"),
		Limit:     limit,
		Offset:    offset,
	}
	vendors, total, err := h.svc.ListVendors(r.Context(), tenantID, f)
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	if vendors == nil {
		vendors = []model.SCSVendor{}
	}
	response.OKWithMeta(w, vendors, &response.Meta{Total: int64(total)})
}

func (h *SCSHandler) GetVendor(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	id, ok := parseUUID(r, "vendorID")
	if !ok {
		response.BadRequest(w, "INVALID_ID", "invalid id")
		return
	}
	v, err := h.svc.GetVendor(r.Context(), tenantID, id)
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	if v == nil {
		response.NotFound(w, "not found")
		return
	}
	response.OK(w, v)
}

func (h *SCSHandler) UpdateVendor(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	id, ok := parseUUID(r, "vendorID")
	if !ok {
		response.BadRequest(w, "INVALID_ID", "invalid id")
		return
	}
	var req model.UpdateVendorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	v, err := h.svc.UpdateVendor(r.Context(), tenantID, id, &req)
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	response.OK(w, v)
}

// ─── Components ───────────────────────────────────────────────────────────────

func (h *SCSHandler) CreateComponent(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	var req model.CreateComponentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	if req.Name == "" || req.Version == "" || req.ComponentType == "" {
		response.BadRequest(w, "VALIDATION_ERROR", "name, version and component_type are required")
		return
	}
	c, err := h.svc.CreateComponent(r.Context(), tenantID, &req)
	if err != nil {
		h.logger.Error().Err(err).Msg("CreateComponent")
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	response.Created(w, c)
}

func (h *SCSHandler) ListComponents(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	f := model.ListComponentsFilter{
		Ecosystem:    q.Get("ecosystem"),
		HasVulns:     parseBoolQuery(r, "has_vulns"),
		IsEOL:        parseBoolQuery(r, "is_eol"),
		IsDeprecated: parseBoolQuery(r, "is_deprecated"),
		Limit:        limit,
		Offset:       offset,
	}
	comps, total, err := h.svc.ListComponents(r.Context(), tenantID, f)
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	if comps == nil {
		comps = []model.SCSComponent{}
	}
	response.OKWithMeta(w, comps, &response.Meta{Total: int64(total)})
}

func (h *SCSHandler) GetComponent(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	id, ok := parseUUID(r, "componentID")
	if !ok {
		response.BadRequest(w, "INVALID_ID", "invalid id")
		return
	}
	c, err := h.svc.GetComponent(r.Context(), tenantID, id)
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	if c == nil {
		response.NotFound(w, "not found")
		return
	}
	response.OK(w, c)
}

func (h *SCSHandler) UpdateComponent(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	id, ok := parseUUID(r, "componentID")
	if !ok {
		response.BadRequest(w, "INVALID_ID", "invalid id")
		return
	}
	var req model.UpdateComponentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	c, err := h.svc.UpdateComponent(r.Context(), tenantID, id, &req)
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	response.OK(w, c)
}

// ─── SBOMs ────────────────────────────────────────────────────────────────────

func (h *SCSHandler) CreateSBOM(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	var req model.CreateSBOMRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	if req.Name == "" {
		response.BadRequest(w, "VALIDATION_ERROR", "name is required")
		return
	}
	sbom, err := h.svc.CreateSBOM(r.Context(), tenantID, &req, userFromCtx(r))
	if err != nil {
		h.logger.Error().Err(err).Msg("CreateSBOM")
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	response.Created(w, sbom)
}

func (h *SCSHandler) ListSBOMs(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	sboms, total, err := h.svc.ListSBOMs(r.Context(), tenantID, limit, offset)
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	if sboms == nil {
		sboms = []model.SCSSBOM{}
	}
	response.OKWithMeta(w, sboms, &response.Meta{Total: int64(total)})
}

func (h *SCSHandler) GetSBOM(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	id, ok := parseUUID(r, "sbomID")
	if !ok {
		response.BadRequest(w, "INVALID_ID", "invalid id")
		return
	}
	sbom, err := h.svc.GetSBOM(r.Context(), tenantID, id)
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	if sbom == nil {
		response.NotFound(w, "not found")
		return
	}
	response.OK(w, sbom)
}

// ─── Assessments ──────────────────────────────────────────────────────────────

func (h *SCSHandler) CreateAssessment(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	var req model.CreateAssessmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	if req.VendorID == uuid.Nil {
		response.BadRequest(w, "VALIDATION_ERROR", "vendor_id is required")
		return
	}
	a, err := h.svc.CreateAssessment(r.Context(), tenantID, &req, userFromCtx(r))
	if err != nil {
		h.logger.Error().Err(err).Msg("CreateAssessment")
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	response.Created(w, a)
}

func (h *SCSHandler) ListAssessments(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	q := r.URL.Query()
	var vendorID uuid.UUID
	if raw := q.Get("vendor_id"); raw != "" {
		vendorID, _ = uuid.Parse(raw)
	}
	assessments, err := h.svc.ListAssessments(r.Context(), tenantID, vendorID, q.Get("status"))
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	if assessments == nil {
		assessments = []model.SCSAssessment{}
	}
	response.OKWithMeta(w, assessments, &response.Meta{Total: int64(len(assessments))})
}

func (h *SCSHandler) UpdateAssessment(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	id, ok := parseUUID(r, "assessmentID")
	if !ok {
		response.BadRequest(w, "INVALID_ID", "invalid id")
		return
	}
	var req model.UpdateAssessmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	a, err := h.svc.UpdateAssessment(r.Context(), tenantID, id, &req)
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	response.OK(w, a)
}

// ─── Alerts ───────────────────────────────────────────────────────────────────

func (h *SCSHandler) CreateAlert(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	var req model.CreateAlertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	if req.Title == "" || req.AlertType == "" || req.Severity == "" {
		response.BadRequest(w, "VALIDATION_ERROR", "title, alert_type and severity are required")
		return
	}
	a, err := h.svc.CreateAlert(r.Context(), tenantID, &req)
	if err != nil {
		h.logger.Error().Err(err).Msg("CreateAlert")
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	response.Created(w, a)
}

func (h *SCSHandler) ListAlerts(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	f := model.ListAlertsFilter{
		Status:    q.Get("status"),
		Severity:  q.Get("severity"),
		AlertType: q.Get("alert_type"),
		Limit:     limit,
		Offset:    offset,
	}
	alerts, total, err := h.svc.ListAlerts(r.Context(), tenantID, f)
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	if alerts == nil {
		alerts = []model.SCSAlert{}
	}
	response.OKWithMeta(w, alerts, &response.Meta{Total: int64(total)})
}

func (h *SCSHandler) UpdateAlert(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	id, ok := parseUUID(r, "alertID")
	if !ok {
		response.BadRequest(w, "INVALID_ID", "invalid id")
		return
	}
	var req model.UpdateAlertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	a, err := h.svc.UpdateAlert(r.Context(), tenantID, id, &req)
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	response.OK(w, a)
}

// ─── Policies ─────────────────────────────────────────────────────────────────

func (h *SCSHandler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	var req model.CreatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	if req.Name == "" || req.PolicyType == "" {
		response.BadRequest(w, "VALIDATION_ERROR", "name and policy_type are required")
		return
	}
	p, err := h.svc.CreatePolicy(r.Context(), tenantID, &req, userFromCtx(r))
	if err != nil {
		h.logger.Error().Err(err).Msg("CreatePolicy")
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	response.Created(w, p)
}

func (h *SCSHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	policies, err := h.svc.ListPolicies(r.Context(), tenantID, r.URL.Query().Get("policy_type"))
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	if policies == nil {
		policies = []model.SCSPolicy{}
	}
	response.OKWithMeta(w, policies, &response.Meta{Total: int64(len(policies))})
}

func (h *SCSHandler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	id, ok := parseUUID(r, "policyID")
	if !ok {
		response.BadRequest(w, "INVALID_ID", "invalid id")
		return
	}
	var req model.UpdatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	p, err := h.svc.UpdatePolicy(r.Context(), tenantID, id, &req)
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	response.OK(w, p)
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (h *SCSHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		response.Unauthorized(w, "missing tenant")
		return
	}
	stats, err := h.svc.GetStats(r.Context(), tenantID)
	if err != nil {
		httperr.WriteLogged(w, err, h.logger)
		return
	}
	response.OK(w, stats)
}
