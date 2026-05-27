package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/cyberradar/platform/services/dspm/internal/model"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

type Service interface {
	// Data Stores
	CreateDataStore(ctx context.Context, tenantID uuid.UUID, req model.CreateDataStoreRequest, createdBy *uuid.UUID) (*model.DSPMDataStore, error)
	GetDataStore(ctx context.Context, tenantID, storeID uuid.UUID) (*model.DSPMDataStore, error)
	ListDataStores(ctx context.Context, tenantID uuid.UUID, f model.ListDataStoresFilter) ([]model.DSPMDataStore, int, error)
	UpdateDataStore(ctx context.Context, tenantID, storeID uuid.UUID, req model.UpdateDataStoreRequest) (*model.DSPMDataStore, error)
	DeleteDataStore(ctx context.Context, tenantID, storeID uuid.UUID) error

	// Scan Jobs
	CreateScanJob(ctx context.Context, tenantID uuid.UUID, req model.CreateScanJobRequest) (*model.DSPMScanJob, error)
	GetScanJob(ctx context.Context, tenantID, jobID uuid.UUID) (*model.DSPMScanJob, error)
	ListScanJobs(ctx context.Context, tenantID, storeID uuid.UUID) ([]model.DSPMScanJob, error)
	UpdateScanJob(ctx context.Context, tenantID, jobID uuid.UUID, req model.UpdateScanJobRequest) (*model.DSPMScanJob, error)

	// Findings
	CreateFinding(ctx context.Context, tenantID uuid.UUID, req model.CreateFindingRequest) (*model.DSPMFinding, error)
	GetFinding(ctx context.Context, tenantID, findingID uuid.UUID) (*model.DSPMFinding, error)
	ListFindings(ctx context.Context, tenantID uuid.UUID, f model.ListFindingsFilter) ([]model.DSPMFinding, int, error)
	UpdateFinding(ctx context.Context, tenantID, findingID uuid.UUID, req model.UpdateFindingRequest) (*model.DSPMFinding, error)

	// Policies
	CreatePolicy(ctx context.Context, tenantID uuid.UUID, req model.CreatePolicyRequest, createdBy *uuid.UUID) (*model.DSPMPolicy, error)
	GetPolicy(ctx context.Context, tenantID, policyID uuid.UUID) (*model.DSPMPolicy, error)
	ListPolicies(ctx context.Context, tenantID uuid.UUID) ([]model.DSPMPolicy, error)
	UpdatePolicy(ctx context.Context, tenantID, policyID uuid.UUID, req model.UpdatePolicyRequest) (*model.DSPMPolicy, error)
	DeletePolicy(ctx context.Context, tenantID, policyID uuid.UUID) error

	// Remediation
	CreateRemediationItem(ctx context.Context, tenantID uuid.UUID, req model.CreateRemediationRequest) (*model.DSPMRemediationItem, error)
	GetRemediationItem(ctx context.Context, tenantID, itemID uuid.UUID) (*model.DSPMRemediationItem, error)
	ListRemediationItems(ctx context.Context, tenantID, findingID uuid.UUID) ([]model.DSPMRemediationItem, error)
	UpdateRemediationItem(ctx context.Context, tenantID, itemID uuid.UUID, req model.UpdateRemediationRequest) (*model.DSPMRemediationItem, error)

	// Stats
	GetStats(ctx context.Context, tenantID uuid.UUID) (*model.DSPMStats, error)
}

type DSPMHandler struct {
	svc    Service
	logger zerolog.Logger
}

func NewDSPMHandler(svc Service, logger zerolog.Logger) *DSPMHandler {
	return &DSPMHandler{svc: svc, logger: logger}
}

func (h *DSPMHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Data Stores
	r.Get("/data-stores", h.ListDataStores)
	r.Post("/data-stores", h.CreateDataStore)
	r.Get("/data-stores/{storeID}", h.GetDataStore)
	r.Patch("/data-stores/{storeID}", h.UpdateDataStore)
	r.Delete("/data-stores/{storeID}", h.DeleteDataStore)

	// Scans (nested under data-stores, and top-level by ID)
	r.Post("/data-stores/{storeID}/scans", h.CreateScanJob)
	r.Get("/data-stores/{storeID}/scans", h.ListScanJobs)
	r.Get("/scans/{jobID}", h.GetScanJob)
	r.Patch("/scans/{jobID}", h.UpdateScanJob)

	// Findings
	r.Get("/findings", h.ListFindings)
	r.Post("/findings", h.CreateFinding)
	r.Get("/findings/{findingID}", h.GetFinding)
	r.Patch("/findings/{findingID}", h.UpdateFinding)

	// Policies
	r.Get("/policies", h.ListPolicies)
	r.Post("/policies", h.CreatePolicy)
	r.Get("/policies/{policyID}", h.GetPolicy)
	r.Patch("/policies/{policyID}", h.UpdatePolicy)
	r.Delete("/policies/{policyID}", h.DeletePolicy)

	// Remediation
	r.Post("/remediation", h.CreateRemediationItem)
	r.Get("/remediation/{findingID}", h.ListRemediationItems)
	r.Get("/remediation/item/{itemID}", h.GetRemediationItem)
	r.Patch("/remediation/item/{itemID}", h.UpdateRemediationItem)

	// Stats
	r.Get("/stats", h.GetStats)

	return r
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func tenantFromCtx(r *http.Request) (uuid.UUID, bool) {
	raw, ok := r.Context().Value("tenant_id").(string)
	if !ok || raw == "" {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(raw)
	return id, err == nil
}

func userFromCtx(r *http.Request) *uuid.UUID {
	raw, ok := r.Context().Value("user_id").(string)
	if !ok || raw == "" {
		return nil
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return nil
	}
	return &id
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// ─── Data Stores ──────────────────────────────────────────────────────────────

func (h *DSPMHandler) CreateDataStore(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	var req model.CreateDataStoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	ds, err := h.svc.CreateDataStore(r.Context(), tenantID, req, userFromCtx(r))
	if err != nil {
		h.logger.Error().Err(err).Msg("CreateDataStore")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, ds)
}

func (h *DSPMHandler) GetDataStore(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	storeID, err := uuid.Parse(chi.URLParam(r, "storeID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid store id")
		return
	}
	ds, err := h.svc.GetDataStore(r.Context(), tenantID, storeID)
	if err != nil {
		h.logger.Error().Err(err).Msg("GetDataStore")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ds == nil {
		writeError(w, http.StatusNotFound, "data store not found")
		return
	}
	writeJSON(w, http.StatusOK, ds)
}

func (h *DSPMHandler) ListDataStores(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	offset, _ := strconv.Atoi(q.Get("offset"))

	var isEncrypted *bool
	if v := q.Get("is_encrypted"); v != "" {
		b, _ := strconv.ParseBool(v)
		isEncrypted = &b
	}

	f := model.ListDataStoresFilter{
		StoreType:        q.Get("store_type"),
		SensitivityLevel: q.Get("sensitivity_level"),
		RiskLevel:        q.Get("risk_level"),
		IsEncrypted:      isEncrypted,
		Department:       q.Get("department"),
		Limit:            limit,
		Offset:           offset,
	}

	stores, total, err := h.svc.ListDataStores(r.Context(), tenantID, f)
	if err != nil {
		h.logger.Error().Err(err).Msg("ListDataStores")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": stores, "total": total})
}

func (h *DSPMHandler) UpdateDataStore(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	storeID, err := uuid.Parse(chi.URLParam(r, "storeID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid store id")
		return
	}
	var req model.UpdateDataStoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	ds, err := h.svc.UpdateDataStore(r.Context(), tenantID, storeID, req)
	if err != nil {
		h.logger.Error().Err(err).Msg("UpdateDataStore")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ds == nil {
		writeError(w, http.StatusNotFound, "data store not found")
		return
	}
	writeJSON(w, http.StatusOK, ds)
}

func (h *DSPMHandler) DeleteDataStore(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	storeID, err := uuid.Parse(chi.URLParam(r, "storeID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid store id")
		return
	}
	if err := h.svc.DeleteDataStore(r.Context(), tenantID, storeID); err != nil {
		h.logger.Error().Err(err).Msg("DeleteDataStore")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─── Scan Jobs ────────────────────────────────────────────────────────────────

func (h *DSPMHandler) CreateScanJob(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	storeID, err := uuid.Parse(chi.URLParam(r, "storeID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid store id")
		return
	}
	var req model.CreateScanJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	req.DataStoreID = storeID
	job, err := h.svc.CreateScanJob(r.Context(), tenantID, req)
	if err != nil {
		h.logger.Error().Err(err).Msg("CreateScanJob")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, job)
}

func (h *DSPMHandler) ListScanJobs(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	storeID, err := uuid.Parse(chi.URLParam(r, "storeID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid store id")
		return
	}
	jobs, err := h.svc.ListScanJobs(r.Context(), tenantID, storeID)
	if err != nil {
		h.logger.Error().Err(err).Msg("ListScanJobs")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": jobs})
}

func (h *DSPMHandler) GetScanJob(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	jobID, err := uuid.Parse(chi.URLParam(r, "jobID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid job id")
		return
	}
	job, err := h.svc.GetScanJob(r.Context(), tenantID, jobID)
	if err != nil {
		h.logger.Error().Err(err).Msg("GetScanJob")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if job == nil {
		writeError(w, http.StatusNotFound, "scan job not found")
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (h *DSPMHandler) UpdateScanJob(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	jobID, err := uuid.Parse(chi.URLParam(r, "jobID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid job id")
		return
	}
	var req model.UpdateScanJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	job, err := h.svc.UpdateScanJob(r.Context(), tenantID, jobID, req)
	if err != nil {
		h.logger.Error().Err(err).Msg("UpdateScanJob")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if job == nil {
		writeError(w, http.StatusNotFound, "scan job not found")
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// ─── Findings ─────────────────────────────────────────────────────────────────

func (h *DSPMHandler) CreateFinding(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	var req model.CreateFindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	f, err := h.svc.CreateFinding(r.Context(), tenantID, req)
	if err != nil {
		h.logger.Error().Err(err).Msg("CreateFinding")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, f)
}

func (h *DSPMHandler) GetFinding(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	findingID, err := uuid.Parse(chi.URLParam(r, "findingID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid finding id")
		return
	}
	f, err := h.svc.GetFinding(r.Context(), tenantID, findingID)
	if err != nil {
		h.logger.Error().Err(err).Msg("GetFinding")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if f == nil {
		writeError(w, http.StatusNotFound, "finding not found")
		return
	}
	writeJSON(w, http.StatusOK, f)
}

func (h *DSPMHandler) ListFindings(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	offset, _ := strconv.Atoi(q.Get("offset"))

	filter := model.ListFindingsFilter{
		FindingType: q.Get("finding_type"),
		Severity:    q.Get("severity"),
		Status:      q.Get("status"),
		Limit:       limit,
		Offset:      offset,
	}
	if v := q.Get("data_store_id"); v != "" {
		id, err := uuid.Parse(v)
		if err == nil {
			filter.DataStoreID = &id
		}
	}

	findings, total, err := h.svc.ListFindings(r.Context(), tenantID, filter)
	if err != nil {
		h.logger.Error().Err(err).Msg("ListFindings")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": findings, "total": total})
}

func (h *DSPMHandler) UpdateFinding(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	findingID, err := uuid.Parse(chi.URLParam(r, "findingID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid finding id")
		return
	}
	var req model.UpdateFindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	f, err := h.svc.UpdateFinding(r.Context(), tenantID, findingID, req)
	if err != nil {
		h.logger.Error().Err(err).Msg("UpdateFinding")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if f == nil {
		writeError(w, http.StatusNotFound, "finding not found")
		return
	}
	writeJSON(w, http.StatusOK, f)
}

// ─── Policies ─────────────────────────────────────────────────────────────────

func (h *DSPMHandler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	var req model.CreatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	p, err := h.svc.CreatePolicy(r.Context(), tenantID, req, userFromCtx(r))
	if err != nil {
		h.logger.Error().Err(err).Msg("CreatePolicy")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (h *DSPMHandler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	policyID, err := uuid.Parse(chi.URLParam(r, "policyID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	p, err := h.svc.GetPolicy(r.Context(), tenantID, policyID)
	if err != nil {
		h.logger.Error().Err(err).Msg("GetPolicy")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if p == nil {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (h *DSPMHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	policies, err := h.svc.ListPolicies(r.Context(), tenantID)
	if err != nil {
		h.logger.Error().Err(err).Msg("ListPolicies")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": policies})
}

func (h *DSPMHandler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	policyID, err := uuid.Parse(chi.URLParam(r, "policyID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	var req model.UpdatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	p, err := h.svc.UpdatePolicy(r.Context(), tenantID, policyID, req)
	if err != nil {
		h.logger.Error().Err(err).Msg("UpdatePolicy")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if p == nil {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (h *DSPMHandler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	policyID, err := uuid.Parse(chi.URLParam(r, "policyID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	if err := h.svc.DeletePolicy(r.Context(), tenantID, policyID); err != nil {
		h.logger.Error().Err(err).Msg("DeletePolicy")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─── Remediation ──────────────────────────────────────────────────────────────

func (h *DSPMHandler) CreateRemediationItem(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	var req model.CreateRemediationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	item, err := h.svc.CreateRemediationItem(r.Context(), tenantID, req)
	if err != nil {
		h.logger.Error().Err(err).Msg("CreateRemediationItem")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (h *DSPMHandler) ListRemediationItems(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	findingID, err := uuid.Parse(chi.URLParam(r, "findingID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid finding id")
		return
	}
	items, err := h.svc.ListRemediationItems(r.Context(), tenantID, findingID)
	if err != nil {
		h.logger.Error().Err(err).Msg("ListRemediationItems")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": items})
}

func (h *DSPMHandler) GetRemediationItem(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	itemID, err := uuid.Parse(chi.URLParam(r, "itemID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid item id")
		return
	}
	item, err := h.svc.GetRemediationItem(r.Context(), tenantID, itemID)
	if err != nil {
		h.logger.Error().Err(err).Msg("GetRemediationItem")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if item == nil {
		writeError(w, http.StatusNotFound, "remediation item not found")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (h *DSPMHandler) UpdateRemediationItem(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	itemID, err := uuid.Parse(chi.URLParam(r, "itemID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid item id")
		return
	}
	var req model.UpdateRemediationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	item, err := h.svc.UpdateRemediationItem(r.Context(), tenantID, itemID, req)
	if err != nil {
		h.logger.Error().Err(err).Msg("UpdateRemediationItem")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if item == nil {
		writeError(w, http.StatusNotFound, "remediation item not found")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (h *DSPMHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	stats, err := h.svc.GetStats(r.Context(), tenantID)
	if err != nil {
		h.logger.Error().Err(err).Msg("GetStats")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}
