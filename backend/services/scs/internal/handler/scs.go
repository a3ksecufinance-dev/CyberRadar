package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/cyberradar/platform/internal/pkg/authctx"
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
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
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	var req model.CreateVendorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Name == "" || req.VendorType == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and vendor_type are required"})
		return
	}
	v, err := h.svc.CreateVendor(r.Context(), tenantID, &req, userFromCtx(r))
	if err != nil {
		h.logger.Error().Err(err).Msg("CreateVendor")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

func (h *SCSHandler) ListVendors(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if vendors == nil {
		vendors = []model.SCSVendor{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"vendors": vendors, "total": total})
}

func (h *SCSHandler) GetVendor(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	id, ok := parseUUID(r, "vendorID")
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	v, err := h.svc.GetVendor(r.Context(), tenantID, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if v == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (h *SCSHandler) UpdateVendor(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	id, ok := parseUUID(r, "vendorID")
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var req model.UpdateVendorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	v, err := h.svc.UpdateVendor(r.Context(), tenantID, id, &req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// ─── Components ───────────────────────────────────────────────────────────────

func (h *SCSHandler) CreateComponent(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	var req model.CreateComponentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Name == "" || req.Version == "" || req.ComponentType == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name, version and component_type are required"})
		return
	}
	c, err := h.svc.CreateComponent(r.Context(), tenantID, &req)
	if err != nil {
		h.logger.Error().Err(err).Msg("CreateComponent")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (h *SCSHandler) ListComponents(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if comps == nil {
		comps = []model.SCSComponent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"components": comps, "total": total})
}

func (h *SCSHandler) GetComponent(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	id, ok := parseUUID(r, "componentID")
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	c, err := h.svc.GetComponent(r.Context(), tenantID, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if c == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (h *SCSHandler) UpdateComponent(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	id, ok := parseUUID(r, "componentID")
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var req model.UpdateComponentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	c, err := h.svc.UpdateComponent(r.Context(), tenantID, id, &req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// ─── SBOMs ────────────────────────────────────────────────────────────────────

func (h *SCSHandler) CreateSBOM(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	var req model.CreateSBOMRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	sbom, err := h.svc.CreateSBOM(r.Context(), tenantID, &req, userFromCtx(r))
	if err != nil {
		h.logger.Error().Err(err).Msg("CreateSBOM")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, sbom)
}

func (h *SCSHandler) ListSBOMs(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	sboms, total, err := h.svc.ListSBOMs(r.Context(), tenantID, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if sboms == nil {
		sboms = []model.SCSSBOM{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sboms": sboms, "total": total})
}

func (h *SCSHandler) GetSBOM(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	id, ok := parseUUID(r, "sbomID")
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	sbom, err := h.svc.GetSBOM(r.Context(), tenantID, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if sbom == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, sbom)
}

// ─── Assessments ──────────────────────────────────────────────────────────────

func (h *SCSHandler) CreateAssessment(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	var req model.CreateAssessmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.VendorID == uuid.Nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "vendor_id is required"})
		return
	}
	a, err := h.svc.CreateAssessment(r.Context(), tenantID, &req, userFromCtx(r))
	if err != nil {
		h.logger.Error().Err(err).Msg("CreateAssessment")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

func (h *SCSHandler) ListAssessments(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	q := r.URL.Query()
	var vendorID uuid.UUID
	if raw := q.Get("vendor_id"); raw != "" {
		vendorID, _ = uuid.Parse(raw)
	}
	assessments, err := h.svc.ListAssessments(r.Context(), tenantID, vendorID, q.Get("status"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if assessments == nil {
		assessments = []model.SCSAssessment{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"assessments": assessments, "total": len(assessments)})
}

func (h *SCSHandler) UpdateAssessment(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	id, ok := parseUUID(r, "assessmentID")
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var req model.UpdateAssessmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	a, err := h.svc.UpdateAssessment(r.Context(), tenantID, id, &req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, a)
}

// ─── Alerts ───────────────────────────────────────────────────────────────────

func (h *SCSHandler) CreateAlert(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	var req model.CreateAlertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Title == "" || req.AlertType == "" || req.Severity == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "title, alert_type and severity are required"})
		return
	}
	a, err := h.svc.CreateAlert(r.Context(), tenantID, &req)
	if err != nil {
		h.logger.Error().Err(err).Msg("CreateAlert")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

func (h *SCSHandler) ListAlerts(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if alerts == nil {
		alerts = []model.SCSAlert{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": alerts, "total": total})
}

func (h *SCSHandler) UpdateAlert(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	id, ok := parseUUID(r, "alertID")
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var req model.UpdateAlertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	a, err := h.svc.UpdateAlert(r.Context(), tenantID, id, &req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, a)
}

// ─── Policies ─────────────────────────────────────────────────────────────────

func (h *SCSHandler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	var req model.CreatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Name == "" || req.PolicyType == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and policy_type are required"})
		return
	}
	p, err := h.svc.CreatePolicy(r.Context(), tenantID, &req, userFromCtx(r))
	if err != nil {
		h.logger.Error().Err(err).Msg("CreatePolicy")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (h *SCSHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	policies, err := h.svc.ListPolicies(r.Context(), tenantID, r.URL.Query().Get("policy_type"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if policies == nil {
		policies = []model.SCSPolicy{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": policies, "total": len(policies)})
}

func (h *SCSHandler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	id, ok := parseUUID(r, "policyID")
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var req model.UpdatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	p, err := h.svc.UpdatePolicy(r.Context(), tenantID, id, &req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (h *SCSHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	stats, err := h.svc.GetStats(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, stats)
}
