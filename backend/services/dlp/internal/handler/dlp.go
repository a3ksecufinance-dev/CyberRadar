package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/dlp/internal/model"
	"github.com/cyberradar/platform/services/dlp/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// DLPHandler exposes the Data Security & DLP API.
type DLPHandler struct {
	svc      *service.DLPService
	validate *validator.Validate
}

// NewDLPHandler creates a DLPHandler.
func NewDLPHandler(svc *service.DLPService) *DLPHandler {
	return &DLPHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts all DLP routes under the provided router.
func (h *DLPHandler) RegisterRoutes(r chi.Router) {
	// Labels
	r.Post("/dlp/labels", h.CreateLabel)
	r.Get("/dlp/labels", h.ListLabels)
	r.Get("/dlp/labels/{labelID}", h.GetLabel)
	r.Patch("/dlp/labels/{labelID}", h.UpdateLabel)

	// Data assets
	r.Post("/dlp/assets", h.CreateAsset)
	r.Get("/dlp/assets", h.ListAssets)
	r.Get("/dlp/assets/{assetID}", h.GetAsset)
	r.Patch("/dlp/assets/{assetID}", h.UpdateAsset)

	// Policies
	r.Post("/dlp/policies", h.CreatePolicy)
	r.Get("/dlp/policies", h.ListPolicies)
	r.Get("/dlp/policies/{policyID}", h.GetPolicy)
	r.Patch("/dlp/policies/{policyID}", h.UpdatePolicy)

	// Violations
	r.Post("/dlp/violations", h.ReportViolation)
	r.Get("/dlp/violations", h.ListViolations)
	r.Patch("/dlp/violations/{violationID}", h.UpdateViolation)

	// Scans
	r.Post("/dlp/scans", h.TriggerScan)
	r.Get("/dlp/scans", h.ListScans)

	// Stats
	r.Get("/dlp/stats", h.GetStats)
}

// ─── Labels ───────────────────────────────────────────────────────────────────

func (h *DLPHandler) CreateLabel(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	var req model.CreateLabelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.BadRequest(w, "VALIDATION_ERROR", err.Error())
		return
	}
	l, err := h.svc.CreateLabel(r.Context(), tenantID, &req, callerID)
	if err != nil { mapError(w, err); return }
	response.JSON(w, http.StatusCreated, l)
}

func (h *DLPHandler) ListLabels(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	activeOnly := r.URL.Query().Get("active") != "false"
	labels, total, err := h.svc.ListLabels(r.Context(), tenantID, activeOnly,
		queryInt(r, "page", 1), queryInt(r, "page_size", 50))
	if err != nil { mapError(w, err); return }
	response.JSON(w, http.StatusOK, map[string]any{"data": labels, "total": total})
}

func (h *DLPHandler) GetLabel(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	labelID, err := parseUUID(chi.URLParam(r, "labelID"))
	if err != nil { response.BadRequest(w, "INVALID_UUID", "invalid label id"); return }
	l, err := h.svc.GetLabel(r.Context(), tenantID, labelID)
	if err != nil { mapError(w, err); return }
	response.JSON(w, http.StatusOK, l)
}

func (h *DLPHandler) UpdateLabel(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	labelID, err := parseUUID(chi.URLParam(r, "labelID"))
	if err != nil { response.BadRequest(w, "INVALID_UUID", "invalid label id"); return }
	var req model.UpdateLabelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error()); return
	}
	l, err := h.svc.UpdateLabel(r.Context(), tenantID, labelID, &req)
	if err != nil { mapError(w, err); return }
	response.JSON(w, http.StatusOK, l)
}

// ─── Data Assets ──────────────────────────────────────────────────────────────

func (h *DLPHandler) CreateAsset(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.CreateAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error()); return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.BadRequest(w, "VALIDATION_ERROR", err.Error()); return
	}
	a, err := h.svc.CreateAsset(r.Context(), tenantID, &req)
	if err != nil { mapError(w, err); return }
	response.JSON(w, http.StatusCreated, a)
}

func (h *DLPHandler) ListAssets(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	f := model.ListAssetsFilter{
		AssetType:  queryString(r, "asset_type"),
		ScanStatus: queryString(r, "scan_status"),
		Page:       queryInt(r, "page", 1),
		PageSize:   queryInt(r, "page_size", 20),
	}
	if v := r.URL.Query().Get("min_risk"); v != "" {
		if n, err := strconv.Atoi(v); err == nil { f.MinRisk = &n }
	}
	assets, total, err := h.svc.ListAssets(r.Context(), tenantID, f)
	if err != nil { mapError(w, err); return }
	response.JSON(w, http.StatusOK, map[string]any{"data": assets, "total": total})
}

func (h *DLPHandler) GetAsset(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	assetID, err := parseUUID(chi.URLParam(r, "assetID"))
	if err != nil { response.BadRequest(w, "INVALID_UUID", "invalid asset id"); return }
	a, err := h.svc.GetAsset(r.Context(), tenantID, assetID)
	if err != nil { mapError(w, err); return }
	response.JSON(w, http.StatusOK, a)
}

func (h *DLPHandler) UpdateAsset(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	assetID, err := parseUUID(chi.URLParam(r, "assetID"))
	if err != nil { response.BadRequest(w, "INVALID_UUID", "invalid asset id"); return }
	var req model.UpdateAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error()); return
	}
	a, err := h.svc.UpdateAsset(r.Context(), tenantID, assetID, &req)
	if err != nil { mapError(w, err); return }
	response.JSON(w, http.StatusOK, a)
}

// ─── Policies ─────────────────────────────────────────────────────────────────

func (h *DLPHandler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	var req model.CreatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error()); return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.BadRequest(w, "VALIDATION_ERROR", err.Error()); return
	}
	p, err := h.svc.CreatePolicy(r.Context(), tenantID, &req, callerID)
	if err != nil { mapError(w, err); return }
	response.JSON(w, http.StatusCreated, p)
}

func (h *DLPHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	activeOnly := r.URL.Query().Get("active") != "false"
	policies, total, err := h.svc.ListPolicies(r.Context(), tenantID,
		queryString(r, "policy_type"), activeOnly,
		queryInt(r, "page", 1), queryInt(r, "page_size", 20))
	if err != nil { mapError(w, err); return }
	response.JSON(w, http.StatusOK, map[string]any{"data": policies, "total": total})
}

func (h *DLPHandler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	policyID, err := parseUUID(chi.URLParam(r, "policyID"))
	if err != nil { response.BadRequest(w, "INVALID_UUID", "invalid policy id"); return }
	p, err := h.svc.GetPolicy(r.Context(), tenantID, policyID)
	if err != nil { mapError(w, err); return }
	response.JSON(w, http.StatusOK, p)
}

func (h *DLPHandler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	policyID, err := parseUUID(chi.URLParam(r, "policyID"))
	if err != nil { response.BadRequest(w, "INVALID_UUID", "invalid policy id"); return }
	var req model.UpdatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error()); return
	}
	p, err := h.svc.UpdatePolicy(r.Context(), tenantID, policyID, &req)
	if err != nil { mapError(w, err); return }
	response.JSON(w, http.StatusOK, p)
}

// ─── Violations ───────────────────────────────────────────────────────────────

func (h *DLPHandler) ReportViolation(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.ReportViolationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error()); return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.BadRequest(w, "VALIDATION_ERROR", err.Error()); return
	}
	v, err := h.svc.ReportViolation(r.Context(), tenantID, &req)
	if err != nil { mapError(w, err); return }
	response.JSON(w, http.StatusCreated, v)
}

func (h *DLPHandler) ListViolations(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	f := model.ListViolationsFilter{
		Severity: queryString(r, "severity"),
		Status:   queryString(r, "status"),
		Channel:  queryString(r, "channel"),
		Page:     queryInt(r, "page", 1),
		PageSize: queryInt(r, "page_size", 20),
	}
	if v := r.URL.Query().Get("policy_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil { f.PolicyID = &id }
	}
	if v := r.URL.Query().Get("asset_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil { f.AssetID = &id }
	}
	viols, total, err := h.svc.ListViolations(r.Context(), tenantID, f)
	if err != nil { mapError(w, err); return }
	response.JSON(w, http.StatusOK, map[string]any{"data": viols, "total": total})
}

func (h *DLPHandler) UpdateViolation(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	violID, err := parseUUID(chi.URLParam(r, "violationID"))
	if err != nil { response.BadRequest(w, "INVALID_UUID", "invalid violation id"); return }
	var req model.UpdateViolationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error()); return
	}
	v, err := h.svc.UpdateViolation(r.Context(), tenantID, violID, &req)
	if err != nil { mapError(w, err); return }
	response.JSON(w, http.StatusOK, v)
}

// ─── Scans ────────────────────────────────────────────────────────────────────

func (h *DLPHandler) TriggerScan(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	var req model.TriggerScanRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	scan, err := h.svc.TriggerScan(r.Context(), tenantID, req.AssetID, callerID)
	if err != nil { mapError(w, err); return }
	response.JSON(w, http.StatusAccepted, scan)
}

func (h *DLPHandler) ListScans(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var assetID *uuid.UUID
	if v := r.URL.Query().Get("asset_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil { assetID = &id }
	}
	scans, total, err := h.svc.ListScans(r.Context(), tenantID, assetID,
		queryInt(r, "page", 1), queryInt(r, "page_size", 20))
	if err != nil { mapError(w, err); return }
	response.JSON(w, http.StatusOK, map[string]any{"data": scans, "total": total})
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (h *DLPHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	stats, err := h.svc.Stats(r.Context(), tenantID)
	if err != nil { mapError(w, err); return }
	response.JSON(w, http.StatusOK, stats)
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

func parseUUID(s string) (uuid.UUID, error) { return uuid.Parse(s) }

func queryString(r *http.Request, key string) string { return r.URL.Query().Get(key) }

func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil { return n }
	}
	return def
}

func mapError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	de, ok := err.(*apierrors.DomainError)
	if !ok {
		response.InternalError(w)
		return
	}
	switch de.Kind {
	case apierrors.KindNotFound:
		response.NotFound(w, de.Message)
	case apierrors.KindConflict:
		response.Conflict(w, de.Message)
	case apierrors.KindBadInput:
		response.BadRequest(w, "VALIDATION_ERROR", de.Message)
	case apierrors.KindUnauth:
		response.Unauthorized(w, de.Message)
	case apierrors.KindForbidden:
		response.Forbidden(w, de.Message)
	default:
		response.InternalError(w)
	}
}
