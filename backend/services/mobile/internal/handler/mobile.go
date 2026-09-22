package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	"github.com/cyberradar/platform/services/mobile/internal/model"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

type Service interface {
	// Devices
	CreateDevice(ctx context.Context, tenantID uuid.UUID, req model.CreateDeviceRequest) (*model.MobDevice, error)
	GetDevice(ctx context.Context, tenantID, deviceID uuid.UUID) (*model.MobDevice, error)
	ListDevices(ctx context.Context, tenantID uuid.UUID, f model.ListDevicesFilter) ([]model.MobDevice, int, error)
	UpdateDevice(ctx context.Context, tenantID, deviceID uuid.UUID, req model.UpdateDeviceRequest) (*model.MobDevice, error)
	DeleteDevice(ctx context.Context, tenantID, deviceID uuid.UUID) error

	// Apps
	CreateApp(ctx context.Context, tenantID uuid.UUID, req model.CreateAppRequest) (*model.MobApp, error)
	GetApp(ctx context.Context, tenantID, appID uuid.UUID) (*model.MobApp, error)
	ListApps(ctx context.Context, tenantID uuid.UUID, f model.ListAppsFilter) ([]model.MobApp, int, error)
	UpdateApp(ctx context.Context, tenantID, appID uuid.UUID, req model.UpdateAppRequest) (*model.MobApp, error)
	InstallApp(ctx context.Context, tenantID, deviceID, appID uuid.UUID) error
	ListDeviceApps(ctx context.Context, tenantID, deviceID uuid.UUID) ([]model.MobApp, error)

	// Policies
	CreatePolicy(ctx context.Context, tenantID uuid.UUID, req model.CreatePolicyRequest, createdBy *uuid.UUID) (*model.MobPolicy, error)
	GetPolicy(ctx context.Context, tenantID, policyID uuid.UUID) (*model.MobPolicy, error)
	ListPolicies(ctx context.Context, tenantID uuid.UUID) ([]model.MobPolicy, error)
	UpdatePolicy(ctx context.Context, tenantID, policyID uuid.UUID, req model.UpdatePolicyRequest) (*model.MobPolicy, error)
	DeletePolicy(ctx context.Context, tenantID, policyID uuid.UUID) error

	// Threats
	CreateThreat(ctx context.Context, tenantID uuid.UUID, req model.CreateThreatRequest) (*model.MobThreat, error)
	GetThreat(ctx context.Context, tenantID, threatID uuid.UUID) (*model.MobThreat, error)
	ListThreats(ctx context.Context, tenantID uuid.UUID, f model.ListThreatsFilter) ([]model.MobThreat, int, error)
	UpdateThreat(ctx context.Context, tenantID, threatID uuid.UUID, req model.UpdateThreatRequest) (*model.MobThreat, error)

	// Compliance
	RunComplianceCheck(ctx context.Context, tenantID uuid.UUID, req model.RunComplianceRequest) (*model.MobComplianceCheck, error)
	ListComplianceChecks(ctx context.Context, tenantID, deviceID uuid.UUID, limit int) ([]model.MobComplianceCheck, error)

	// Remote Actions
	CreateRemoteAction(ctx context.Context, tenantID uuid.UUID, req model.CreateRemoteActionRequest) (*model.MobRemoteAction, error)
	GetRemoteAction(ctx context.Context, tenantID, actionID uuid.UUID) (*model.MobRemoteAction, error)
	ListRemoteActions(ctx context.Context, tenantID, deviceID uuid.UUID) ([]model.MobRemoteAction, error)
	UpdateRemoteAction(ctx context.Context, tenantID, actionID uuid.UUID, req model.UpdateRemoteActionRequest) (*model.MobRemoteAction, error)

	// Stats
	GetStats(ctx context.Context, tenantID uuid.UUID) (*model.MobStats, error)
}

type Handler struct {
	svc Service
	log zerolog.Logger
}

func New(svc Service, log zerolog.Logger) *Handler {
	return &Handler{svc: svc, log: log}
}

func (h *Handler) Routes() http.Handler {
	r := chi.NewRouter()

	// Devices
	r.Get("/devices", h.ListDevices)
	r.Post("/devices", h.CreateDevice)
	r.Get("/devices/{deviceID}", h.GetDevice)
	r.Patch("/devices/{deviceID}", h.UpdateDevice)
	r.Delete("/devices/{deviceID}", h.DeleteDevice)
	r.Get("/devices/{deviceID}/apps", h.ListDeviceApps)
	r.Post("/devices/{deviceID}/apps/{appID}", h.InstallApp)

	// Apps
	r.Get("/apps", h.ListApps)
	r.Post("/apps", h.CreateApp)
	r.Get("/apps/{appID}", h.GetApp)
	r.Patch("/apps/{appID}", h.UpdateApp)

	// Policies
	r.Get("/policies", h.ListPolicies)
	r.Post("/policies", h.CreatePolicy)
	r.Get("/policies/{policyID}", h.GetPolicy)
	r.Patch("/policies/{policyID}", h.UpdatePolicy)
	r.Delete("/policies/{policyID}", h.DeletePolicy)

	// Threats
	r.Get("/threats", h.ListThreats)
	r.Post("/threats", h.CreateThreat)
	r.Get("/threats/{threatID}", h.GetThreat)
	r.Patch("/threats/{threatID}", h.UpdateThreat)

	// Compliance
	r.Post("/compliance/check", h.RunComplianceCheck)
	r.Get("/compliance/{deviceID}", h.ListComplianceChecks)

	// Remote Actions
	r.Post("/actions", h.CreateRemoteAction)
	r.Get("/actions/{deviceID}", h.ListRemoteActions)
	r.Get("/actions/detail/{actionID}", h.GetRemoteAction)
	r.Patch("/actions/{actionID}", h.UpdateRemoteAction)

	// Stats
	r.Get("/stats", h.GetStats)

	return r
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func tenantFromCtx(r *http.Request) uuid.UUID {
	return authctx.TenantID(r.Context())
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

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

// ─── Devices ──────────────────────────────────────────────────────────────────

func (h *Handler) CreateDevice(w http.ResponseWriter, r *http.Request) {
	var req model.CreateDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	device, err := h.svc.CreateDevice(r.Context(), tenantFromCtx(r), req)
	if err != nil {
		h.log.Error().Err(err).Msg("CreateDevice")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, device)
}

func (h *Handler) GetDevice(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "deviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}
	device, err := h.svc.GetDevice(r.Context(), tenantFromCtx(r), id)
	if err != nil {
		h.log.Error().Err(err).Msg("GetDevice")
		writeError(w, http.StatusNotFound, "device not found")
		return
	}
	writeJSON(w, http.StatusOK, device)
}

func (h *Handler) ListDevices(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	offset, _ := strconv.Atoi(q.Get("offset"))

	var isCompliant *bool
	if v := q.Get("is_compliant"); v != "" {
		b, _ := strconv.ParseBool(v)
		isCompliant = &b
	}

	f := model.ListDevicesFilter{
		Platform:         q.Get("platform"),
		EnrollmentStatus: q.Get("enrollment_status"),
		Ownership:        q.Get("ownership"),
		RiskLevel:        q.Get("risk_level"),
		IsCompliant:      isCompliant,
		Department:       q.Get("department"),
		Limit:            limit,
		Offset:           offset,
	}
	devices, total, err := h.svc.ListDevices(r.Context(), tenantFromCtx(r), f)
	if err != nil {
		h.log.Error().Err(err).Msg("ListDevices")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": devices, "total": total})
}

func (h *Handler) UpdateDevice(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "deviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}
	var req model.UpdateDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	device, err := h.svc.UpdateDevice(r.Context(), tenantFromCtx(r), id, req)
	if err != nil {
		h.log.Error().Err(err).Msg("UpdateDevice")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, device)
}

func (h *Handler) DeleteDevice(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "deviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}
	if err := h.svc.DeleteDevice(r.Context(), tenantFromCtx(r), id); err != nil {
		h.log.Error().Err(err).Msg("DeleteDevice")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ListDeviceApps(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "deviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}
	apps, err := h.svc.ListDeviceApps(r.Context(), tenantFromCtx(r), id)
	if err != nil {
		h.log.Error().Err(err).Msg("ListDeviceApps")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": apps})
}

func (h *Handler) InstallApp(w http.ResponseWriter, r *http.Request) {
	deviceID, err := parseUUID(chi.URLParam(r, "deviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}
	appID, err := parseUUID(chi.URLParam(r, "appID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid app id")
		return
	}
	if err := h.svc.InstallApp(r.Context(), tenantFromCtx(r), deviceID, appID); err != nil {
		h.log.Error().Err(err).Msg("InstallApp")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "installed"})
}

// ─── Apps ─────────────────────────────────────────────────────────────────────

func (h *Handler) CreateApp(w http.ResponseWriter, r *http.Request) {
	var req model.CreateAppRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	app, err := h.svc.CreateApp(r.Context(), tenantFromCtx(r), req)
	if err != nil {
		h.log.Error().Err(err).Msg("CreateApp")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, app)
}

func (h *Handler) GetApp(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "appID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid app id")
		return
	}
	app, err := h.svc.GetApp(r.Context(), tenantFromCtx(r), id)
	if err != nil {
		h.log.Error().Err(err).Msg("GetApp")
		writeError(w, http.StatusNotFound, "app not found")
		return
	}
	writeJSON(w, http.StatusOK, app)
}

func (h *Handler) ListApps(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	offset, _ := strconv.Atoi(q.Get("offset"))

	var isApproved, isBlocklisted, hasVulns *bool
	if v := q.Get("is_approved"); v != "" {
		b, _ := strconv.ParseBool(v)
		isApproved = &b
	}
	if v := q.Get("is_blocklisted"); v != "" {
		b, _ := strconv.ParseBool(v)
		isBlocklisted = &b
	}
	if v := q.Get("has_vulns"); v != "" {
		b, _ := strconv.ParseBool(v)
		hasVulns = &b
	}

	f := model.ListAppsFilter{
		Platform:      q.Get("platform"),
		IsApproved:    isApproved,
		IsBlocklisted: isBlocklisted,
		HasVulns:      hasVulns,
		Limit:         limit,
		Offset:        offset,
	}
	apps, total, err := h.svc.ListApps(r.Context(), tenantFromCtx(r), f)
	if err != nil {
		h.log.Error().Err(err).Msg("ListApps")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": apps, "total": total})
}

func (h *Handler) UpdateApp(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "appID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid app id")
		return
	}
	var req model.UpdateAppRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	app, err := h.svc.UpdateApp(r.Context(), tenantFromCtx(r), id, req)
	if err != nil {
		h.log.Error().Err(err).Msg("UpdateApp")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, app)
}

// ─── Policies ─────────────────────────────────────────────────────────────────

func (h *Handler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	var req model.CreatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	policy, err := h.svc.CreatePolicy(r.Context(), tenantFromCtx(r), req, userFromCtx(r))
	if err != nil {
		h.log.Error().Err(err).Msg("CreatePolicy")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, policy)
}

func (h *Handler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "policyID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	policy, err := h.svc.GetPolicy(r.Context(), tenantFromCtx(r), id)
	if err != nil {
		h.log.Error().Err(err).Msg("GetPolicy")
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (h *Handler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := h.svc.ListPolicies(r.Context(), tenantFromCtx(r))
	if err != nil {
		h.log.Error().Err(err).Msg("ListPolicies")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": policies})
}

func (h *Handler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "policyID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	var req model.UpdatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	policy, err := h.svc.UpdatePolicy(r.Context(), tenantFromCtx(r), id, req)
	if err != nil {
		h.log.Error().Err(err).Msg("UpdatePolicy")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (h *Handler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "policyID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	if err := h.svc.DeletePolicy(r.Context(), tenantFromCtx(r), id); err != nil {
		h.log.Error().Err(err).Msg("DeletePolicy")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─── Threats ──────────────────────────────────────────────────────────────────

func (h *Handler) CreateThreat(w http.ResponseWriter, r *http.Request) {
	var req model.CreateThreatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	threat, err := h.svc.CreateThreat(r.Context(), tenantFromCtx(r), req)
	if err != nil {
		h.log.Error().Err(err).Msg("CreateThreat")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, threat)
}

func (h *Handler) GetThreat(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "threatID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid threat id")
		return
	}
	threat, err := h.svc.GetThreat(r.Context(), tenantFromCtx(r), id)
	if err != nil {
		h.log.Error().Err(err).Msg("GetThreat")
		writeError(w, http.StatusNotFound, "threat not found")
		return
	}
	writeJSON(w, http.StatusOK, threat)
}

func (h *Handler) ListThreats(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	offset, _ := strconv.Atoi(q.Get("offset"))

	f := model.ListThreatsFilter{
		ThreatType: q.Get("threat_type"),
		Severity:   q.Get("severity"),
		Status:     q.Get("status"),
		Limit:      limit,
		Offset:     offset,
	}
	if v := q.Get("device_id"); v != "" {
		id, err := parseUUID(v)
		if err == nil {
			f.DeviceID = &id
		}
	}

	threats, total, err := h.svc.ListThreats(r.Context(), tenantFromCtx(r), f)
	if err != nil {
		h.log.Error().Err(err).Msg("ListThreats")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": threats, "total": total})
}

func (h *Handler) UpdateThreat(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "threatID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid threat id")
		return
	}
	var req model.UpdateThreatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	threat, err := h.svc.UpdateThreat(r.Context(), tenantFromCtx(r), id, req)
	if err != nil {
		h.log.Error().Err(err).Msg("UpdateThreat")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, threat)
}

// ─── Compliance ───────────────────────────────────────────────────────────────

func (h *Handler) RunComplianceCheck(w http.ResponseWriter, r *http.Request) {
	var req model.RunComplianceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	check, err := h.svc.RunComplianceCheck(r.Context(), tenantFromCtx(r), req)
	if err != nil {
		h.log.Error().Err(err).Msg("RunComplianceCheck")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, check)
}

func (h *Handler) ListComplianceChecks(w http.ResponseWriter, r *http.Request) {
	deviceID, err := parseUUID(chi.URLParam(r, "deviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20
	}
	checks, err := h.svc.ListComplianceChecks(r.Context(), tenantFromCtx(r), deviceID, limit)
	if err != nil {
		h.log.Error().Err(err).Msg("ListComplianceChecks")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": checks})
}

// ─── Remote Actions ───────────────────────────────────────────────────────────

func (h *Handler) CreateRemoteAction(w http.ResponseWriter, r *http.Request) {
	var req model.CreateRemoteActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if userID := userFromCtx(r); userID != nil && req.RequestedByID == nil {
		req.RequestedByID = userID
	}
	action, err := h.svc.CreateRemoteAction(r.Context(), tenantFromCtx(r), req)
	if err != nil {
		h.log.Error().Err(err).Msg("CreateRemoteAction")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, action)
}

func (h *Handler) GetRemoteAction(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "actionID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid action id")
		return
	}
	action, err := h.svc.GetRemoteAction(r.Context(), tenantFromCtx(r), id)
	if err != nil {
		h.log.Error().Err(err).Msg("GetRemoteAction")
		writeError(w, http.StatusNotFound, "action not found")
		return
	}
	writeJSON(w, http.StatusOK, action)
}

func (h *Handler) ListRemoteActions(w http.ResponseWriter, r *http.Request) {
	deviceID, err := parseUUID(chi.URLParam(r, "deviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}
	actions, err := h.svc.ListRemoteActions(r.Context(), tenantFromCtx(r), deviceID)
	if err != nil {
		h.log.Error().Err(err).Msg("ListRemoteActions")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": actions})
}

func (h *Handler) UpdateRemoteAction(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "actionID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid action id")
		return
	}
	var req model.UpdateRemoteActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	action, err := h.svc.UpdateRemoteAction(r.Context(), tenantFromCtx(r), id, req)
	if err != nil {
		h.log.Error().Err(err).Msg("UpdateRemoteAction")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, action)
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (h *Handler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.svc.GetStats(r.Context(), tenantFromCtx(r))
	if err != nil {
		h.log.Error().Err(err).Msg("GetStats")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}
