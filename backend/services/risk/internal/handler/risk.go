package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/risk/internal/model"
	"github.com/cyberradar/platform/services/risk/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// RiskHandler exposes the Cyber Risk Quantification API.
type RiskHandler struct {
	svc      *service.RiskService
	validate *validator.Validate
}

// NewRiskHandler creates a RiskHandler.
func NewRiskHandler(svc *service.RiskService) *RiskHandler {
	return &RiskHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts all risk routes under the provided router.
func (h *RiskHandler) RegisterRoutes(r chi.Router) {
	// Risk assets
	r.Post("/risk/assets", h.CreateAsset)
	r.Get("/risk/assets", h.ListAssets)
	r.Get("/risk/assets/{assetID}", h.GetAsset)
	r.Patch("/risk/assets/{assetID}", h.UpdateAsset)

	// Risk scenarios
	r.Post("/risk/scenarios", h.CreateScenario)
	r.Get("/risk/scenarios", h.ListScenarios)
	r.Get("/risk/scenarios/{scenarioID}", h.GetScenario)
	r.Patch("/risk/scenarios/{scenarioID}", h.UpdateScenario)

	// Risk treatments
	r.Post("/risk/treatments", h.CreateTreatment)
	r.Get("/risk/treatments", h.ListTreatments)
	r.Get("/risk/treatments/{treatmentID}", h.GetTreatment)
	r.Patch("/risk/treatments/{treatmentID}", h.UpdateTreatment)

	// Risk assessments
	r.Post("/risk/assessments", h.CreateAssessment)
	r.Get("/risk/assessments", h.ListAssessments)
	r.Get("/risk/assessments/{assessmentID}", h.GetAssessment)

	// KRIs
	r.Post("/risk/kris", h.CreateKRI)
	r.Get("/risk/kris", h.ListKRIs)
	r.Get("/risk/kris/{kriID}", h.GetKRI)
	r.Post("/risk/kris/{kriID}/value", h.UpdateKRIValue)
	r.Get("/risk/kris/{kriID}/history", h.GetKRIHistory)

	// Stats
	r.Get("/risk/stats", h.GetStats)
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

// ─── Assets ───────────────────────────────────────────────────────────────────

func (h *RiskHandler) CreateAsset(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	var req model.CreateRiskAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	if err := h.validate.Struct(req); err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, err.Error()))
		return
	}
	asset, err := h.svc.CreateAsset(r.Context(), tenantID, &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, asset)
}

func (h *RiskHandler) ListAssets(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	f := model.ListAssetsFilter{
		AssetType:    r.URL.Query().Get("asset_type"),
		Criticality:  r.URL.Query().Get("criticality"),
		BusinessUnit: r.URL.Query().Get("business_unit"),
		Page:         queryInt(r, "page", "1"),
		PageSize:     queryInt(r, "page_size", "50"),
	}
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize < 1 || f.PageSize > 200 {
		f.PageSize = 50
	}
	assets, total, err := h.svc.ListAssets(r.Context(), tenantID, f)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"assets": assets, "total": total, "page": f.Page, "page_size": f.PageSize})
}

func (h *RiskHandler) GetAsset(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	assetID, err := parseUUID(r, "assetID")
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, "invalid asset id"))
		return
	}
	asset, err := h.svc.GetAsset(r.Context(), tenantID, assetID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, asset)
}

func (h *RiskHandler) UpdateAsset(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	assetID, err := parseUUID(r, "assetID")
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, "invalid asset id"))
		return
	}
	var req model.UpdateRiskAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	asset, err := h.svc.UpdateAsset(r.Context(), tenantID, assetID, &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, asset)
}

// ─── Scenarios ────────────────────────────────────────────────────────────────

func (h *RiskHandler) CreateScenario(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	var req model.CreateScenarioRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	if err := h.validate.Struct(req); err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, err.Error()))
		return
	}
	sc, err := h.svc.CreateScenario(r.Context(), tenantID, &req, userFromCtx(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, sc)
}

func (h *RiskHandler) ListScenarios(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	f := model.ListScenariosFilter{
		ScenarioType: r.URL.Query().Get("scenario_type"),
		RiskLevel:    r.URL.Query().Get("risk_level"),
		Status:       r.URL.Query().Get("status"),
		Framework:    r.URL.Query().Get("framework"),
		Page:         queryInt(r, "page", "1"),
		PageSize:     queryInt(r, "page_size", "50"),
	}
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize < 1 || f.PageSize > 200 {
		f.PageSize = 50
	}
	scenarios, total, err := h.svc.ListScenarios(r.Context(), tenantID, f)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scenarios": scenarios, "total": total, "page": f.Page, "page_size": f.PageSize})
}

func (h *RiskHandler) GetScenario(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	scenarioID, err := parseUUID(r, "scenarioID")
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, "invalid scenario id"))
		return
	}
	sc, err := h.svc.GetScenario(r.Context(), tenantID, scenarioID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sc)
}

func (h *RiskHandler) UpdateScenario(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	scenarioID, err := parseUUID(r, "scenarioID")
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, "invalid scenario id"))
		return
	}
	var req model.UpdateScenarioRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	sc, err := h.svc.UpdateScenario(r.Context(), tenantID, scenarioID, &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sc)
}

// ─── Treatments ───────────────────────────────────────────────────────────────

func (h *RiskHandler) CreateTreatment(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	var req model.CreateTreatmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	if err := h.validate.Struct(req); err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, err.Error()))
		return
	}
	t, err := h.svc.CreateTreatment(r.Context(), tenantID, &req, userFromCtx(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (h *RiskHandler) ListTreatments(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	var scenarioID *uuid.UUID
	if v := r.URL.Query().Get("scenario_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			scenarioID = &id
		}
	}
	status := r.URL.Query().Get("status")
	page := queryInt(r, "page", "1")
	pageSize := queryInt(r, "page_size", "50")
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 50
	}
	treatments, total, err := h.svc.ListTreatments(r.Context(), tenantID, scenarioID, status, page, pageSize)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"treatments": treatments, "total": total, "page": page, "page_size": pageSize})
}

func (h *RiskHandler) GetTreatment(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	treatmentID, err := parseUUID(r, "treatmentID")
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, "invalid treatment id"))
		return
	}
	t, err := h.svc.GetTreatment(r.Context(), tenantID, treatmentID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (h *RiskHandler) UpdateTreatment(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	treatmentID, err := parseUUID(r, "treatmentID")
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, "invalid treatment id"))
		return
	}
	var req model.UpdateTreatmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	t, err := h.svc.UpdateTreatment(r.Context(), tenantID, treatmentID, &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// ─── Assessments ──────────────────────────────────────────────────────────────

func (h *RiskHandler) CreateAssessment(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	var req model.CreateAssessmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	if err := h.validate.Struct(req); err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, err.Error()))
		return
	}
	a, err := h.svc.CreateAssessment(r.Context(), tenantID, &req, userFromCtx(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

func (h *RiskHandler) ListAssessments(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	status := r.URL.Query().Get("status")
	page := queryInt(r, "page", "1")
	pageSize := queryInt(r, "page_size", "20")
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	assessments, total, err := h.svc.ListAssessments(r.Context(), tenantID, status, page, pageSize)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"assessments": assessments, "total": total, "page": page, "page_size": pageSize})
}

func (h *RiskHandler) GetAssessment(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	assessmentID, err := parseUUID(r, "assessmentID")
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, "invalid assessment id"))
		return
	}
	a, err := h.svc.GetAssessment(r.Context(), tenantID, assessmentID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

// ─── KRIs ─────────────────────────────────────────────────────────────────────

func (h *RiskHandler) CreateKRI(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	var req model.CreateKRIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	if err := h.validate.Struct(req); err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, err.Error()))
		return
	}
	k, err := h.svc.CreateKRI(r.Context(), tenantID, &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, k)
}

func (h *RiskHandler) ListKRIs(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	category := r.URL.Query().Get("category")
	status := r.URL.Query().Get("status")
	kris, err := h.svc.ListKRIs(r.Context(), tenantID, category, status)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"kris": kris, "total": len(kris)})
}

func (h *RiskHandler) GetKRI(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	kriID, err := parseUUID(r, "kriID")
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, "invalid kri id"))
		return
	}
	k, err := h.svc.GetKRI(r.Context(), tenantID, kriID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, k)
}

func (h *RiskHandler) UpdateKRIValue(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	kriID, err := parseUUID(r, "kriID")
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, "invalid kri id"))
		return
	}
	var req model.UpdateKRIValueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	k, err := h.svc.UpdateKRIValue(r.Context(), tenantID, kriID, req.Value)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, k)
}

func (h *RiskHandler) GetKRIHistory(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	kriID, err := parseUUID(r, "kriID")
	if err != nil {
		writeError(w, apierrors.New(apierrors.KindBadInput, "invalid kri id"))
		return
	}
	limit := queryInt(r, "limit", "90")
	history, err := h.svc.GetKRIHistory(r.Context(), tenantID, kriID, limit)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"history": history, "total": len(history)})
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (h *RiskHandler) GetStats(w http.ResponseWriter, r *http.Request) {
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
