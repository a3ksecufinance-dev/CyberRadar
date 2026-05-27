package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/easm/internal/model"
	"github.com/cyberradar/platform/services/easm/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// EASMHandler exposes the EASM API.
type EASMHandler struct {
	svc      *service.EASMService
	validate *validator.Validate
}

// NewEASMHandler creates an EASMHandler.
func NewEASMHandler(svc *service.EASMService) *EASMHandler {
	return &EASMHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts all EASM routes under the provided router.
func (h *EASMHandler) RegisterRoutes(r chi.Router) {
	// Assets
	r.Post("/easm/assets", h.CreateAsset)
	r.Get("/easm/assets", h.ListAssets)
	r.Get("/easm/assets/{assetID}", h.GetAsset)
	r.Put("/easm/assets/{assetID}", h.UpdateAsset)
	r.Delete("/easm/assets/{assetID}", h.DeleteAsset)

	// Exposures
	r.Post("/easm/exposures", h.CreateExposure)
	r.Get("/easm/exposures", h.ListExposures)
	r.Get("/easm/exposures/{exposureID}", h.GetExposure)
	r.Post("/easm/exposures/{exposureID}/remediate", h.RemediateExposure)

	// Leaks
	r.Post("/easm/leaks", h.CreateLeak)
	r.Get("/easm/leaks", h.ListLeaks)
	r.Post("/easm/leaks/{leakID}/acknowledge", h.AcknowledgeLeak)

	// Brand alerts
	r.Post("/easm/brand-alerts", h.CreateBrandAlert)
	r.Get("/easm/brand-alerts", h.ListBrandAlerts)
	r.Get("/easm/brand-alerts/{alertID}", h.GetBrandAlert)
	r.Put("/easm/brand-alerts/{alertID}/status", h.UpdateBrandAlertStatus)

	// Scans
	r.Post("/easm/scans", h.CreateScan)
	r.Get("/easm/scans", h.ListScans)
	r.Get("/easm/scans/{scanID}", h.GetScan)

	// Risk & stats
	r.Get("/easm/risk-score", h.GetRiskScore)
	r.Get("/easm/stats", h.GetStats)
}

// ─── Assets ───────────────────────────────────────────────────────────────────

func (h *EASMHandler) CreateAsset(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.CreateAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.BadRequest(w, "VALIDATION_ERROR", err.Error())
		return
	}
	a, err := h.svc.CreateAsset(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusCreated, a)
}

func (h *EASMHandler) ListAssets(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	f := model.ListAssetsFilter{
		AssetType: queryString(r, "asset_type"),
		Status:    queryString(r, "status"),
		Page:      queryInt(r, "page", 1),
		PageSize:  queryInt(r, "page_size", 20),
	}
	if v := r.URL.Query().Get("min_risk_score"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.MinRiskScore = &n
		}
	}
	assets, total, err := h.svc.ListAssets(r.Context(), tenantID, f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, map[string]any{"data": assets, "total": total})
}

func (h *EASMHandler) GetAsset(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	assetID, err := parseUUID(chi.URLParam(r, "assetID"))
	if err != nil {
		response.BadRequest(w, "INVALID_UUID", "invalid asset id")
		return
	}
	a, err := h.svc.GetAsset(r.Context(), tenantID, assetID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, a)
}

func (h *EASMHandler) UpdateAsset(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	assetID, err := parseUUID(chi.URLParam(r, "assetID"))
	if err != nil {
		response.BadRequest(w, "INVALID_UUID", "invalid asset id")
		return
	}
	var req model.UpdateAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	a, err := h.svc.UpdateAsset(r.Context(), tenantID, assetID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, a)
}

func (h *EASMHandler) DeleteAsset(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	assetID, err := parseUUID(chi.URLParam(r, "assetID"))
	if err != nil {
		response.BadRequest(w, "INVALID_UUID", "invalid asset id")
		return
	}
	if err := h.svc.DeleteAsset(r.Context(), tenantID, assetID); err != nil {
		mapError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─── Exposures ────────────────────────────────────────────────────────────────

func (h *EASMHandler) CreateExposure(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.CreateExposureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.BadRequest(w, "VALIDATION_ERROR", err.Error())
		return
	}
	e, err := h.svc.CreateExposure(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusCreated, e)
}

func (h *EASMHandler) ListExposures(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var assetID *uuid.UUID
	if v := r.URL.Query().Get("asset_id"); v != "" {
		id, err := uuid.Parse(v)
		if err == nil {
			assetID = &id
		}
	}
	var remediated *bool
	if v := r.URL.Query().Get("remediated"); v != "" {
		b := v == "true"
		remediated = &b
	}
	exposures, total, err := h.svc.ListExposures(r.Context(), tenantID, assetID,
		queryString(r, "severity"), remediated,
		queryInt(r, "page", 1), queryInt(r, "page_size", 20))
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, map[string]any{"data": exposures, "total": total})
}

func (h *EASMHandler) GetExposure(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	exposureID, err := parseUUID(chi.URLParam(r, "exposureID"))
	if err != nil {
		response.BadRequest(w, "INVALID_UUID", "invalid exposure id")
		return
	}
	exposures, _, err := h.svc.ListExposures(r.Context(), tenantID, nil, "", nil, 1, 1000)
	if err != nil {
		mapError(w, err)
		return
	}
	for _, e := range exposures {
		if e.ID == exposureID {
			response.JSON(w, http.StatusOK, e)
			return
		}
	}
	response.NotFound(w, "exposure not found")
}

func (h *EASMHandler) RemediateExposure(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	exposureID, err := parseUUID(chi.URLParam(r, "exposureID"))
	if err != nil {
		response.BadRequest(w, "INVALID_UUID", "invalid exposure id")
		return
	}
	e, err := h.svc.RemediateExposure(r.Context(), tenantID, exposureID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, e)
}

// ─── Leaks ────────────────────────────────────────────────────────────────────

func (h *EASMHandler) CreateLeak(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.CreateLeakRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.BadRequest(w, "VALIDATION_ERROR", err.Error())
		return
	}
	l, err := h.svc.CreateLeak(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusCreated, l)
}

func (h *EASMHandler) ListLeaks(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var acknowledged *bool
	if v := r.URL.Query().Get("acknowledged"); v != "" {
		b := v == "true"
		acknowledged = &b
	}
	leaks, total, err := h.svc.ListLeaks(r.Context(), tenantID, acknowledged,
		queryString(r, "severity"),
		queryInt(r, "page", 1), queryInt(r, "page_size", 20))
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, map[string]any{"data": leaks, "total": total})
}

func (h *EASMHandler) AcknowledgeLeak(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	leakID, err := parseUUID(chi.URLParam(r, "leakID"))
	if err != nil {
		response.BadRequest(w, "INVALID_UUID", "invalid leak id")
		return
	}
	l, err := h.svc.AcknowledgeLeak(r.Context(), tenantID, leakID, callerID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, l)
}

// ─── Brand alerts ─────────────────────────────────────────────────────────────

func (h *EASMHandler) CreateBrandAlert(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.CreateBrandAlertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.BadRequest(w, "VALIDATION_ERROR", err.Error())
		return
	}
	a, err := h.svc.CreateBrandAlert(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusCreated, a)
}

func (h *EASMHandler) ListBrandAlerts(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	alerts, total, err := h.svc.ListBrandAlerts(r.Context(), tenantID,
		queryString(r, "alert_type"), queryString(r, "status"),
		queryInt(r, "page", 1), queryInt(r, "page_size", 20))
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, map[string]any{"data": alerts, "total": total})
}

func (h *EASMHandler) GetBrandAlert(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	alertID, err := parseUUID(chi.URLParam(r, "alertID"))
	if err != nil {
		response.BadRequest(w, "INVALID_UUID", "invalid alert id")
		return
	}
	alerts, _, err := h.svc.ListBrandAlerts(r.Context(), tenantID, "", "", 1, 1000)
	if err != nil {
		mapError(w, err)
		return
	}
	for _, a := range alerts {
		if a.ID == alertID {
			response.JSON(w, http.StatusOK, a)
			return
		}
	}
	response.NotFound(w, "brand alert not found")
}

func (h *EASMHandler) UpdateBrandAlertStatus(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	alertID, err := parseUUID(chi.URLParam(r, "alertID"))
	if err != nil {
		response.BadRequest(w, "INVALID_UUID", "invalid alert id")
		return
	}
	var body struct {
		Status string `json:"status" validate:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	if err := h.validate.Struct(&body); err != nil {
		response.BadRequest(w, "VALIDATION_ERROR", err.Error())
		return
	}
	a, err := h.svc.UpdateBrandAlert(r.Context(), tenantID, alertID, body.Status)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, a)
}

// ─── Scans ────────────────────────────────────────────────────────────────────

func (h *EASMHandler) CreateScan(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	var req model.CreateScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", err.Error())
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.BadRequest(w, "VALIDATION_ERROR", err.Error())
		return
	}
	sc, err := h.svc.CreateScan(r.Context(), tenantID, &req, callerID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusAccepted, sc)
}

func (h *EASMHandler) ListScans(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	scans, total, err := h.svc.ListScans(r.Context(), tenantID.String(),
		queryInt(r, "page", 1), queryInt(r, "page_size", 20))
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, map[string]any{"data": scans, "total": total})
}

func (h *EASMHandler) GetScan(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	scanID, err := parseUUID(chi.URLParam(r, "scanID"))
	if err != nil {
		response.BadRequest(w, "INVALID_UUID", "invalid scan id")
		return
	}
	sc, err := h.svc.GetScan(r.Context(), tenantID, scanID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, sc)
}

// ─── Risk & stats ─────────────────────────────────────────────────────────────

func (h *EASMHandler) GetRiskScore(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	score, err := h.svc.ExternalRiskScore(r.Context(), tenantID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, score)
}

func (h *EASMHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	stats, err := h.svc.Stats(r.Context(), tenantID)
	if err != nil {
		mapError(w, err)
		return
	}
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

func parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

func queryString(r *http.Request, key string) string {
	return r.URL.Query().Get(key)
}

func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
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
