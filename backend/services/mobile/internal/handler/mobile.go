package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	"github.com/cyberradar/platform/internal/pkg/httperr"
	"github.com/cyberradar/platform/internal/pkg/response"
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

func parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

// ─── Devices ──────────────────────────────────────────────────────────────────

func (h *Handler) CreateDevice(w http.ResponseWriter, r *http.Request) {
	var req model.CreateDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_VALUE", "invalid body")
		return
	}
	device, err := h.svc.CreateDevice(r.Context(), tenantFromCtx(r), req)
	if err != nil {
		h.log.Error().Err(err).Msg("CreateDevice")
		httperr.WriteLogged(w, err, h.log)
		return
	}
	response.Created(w, device)
}

func (h *Handler) GetDevice(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "deviceID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "invalid device id")
		return
	}
	device, err := h.svc.GetDevice(r.Context(), tenantFromCtx(r), id)
	if err != nil {
		h.log.Error().Err(err).Msg("GetDevice")
		response.NotFound(w, "device not found")
		return
	}
	response.OK(w, device)
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
		httperr.WriteLogged(w, err, h.log)
		return
	}
	response.OKWithMeta(w, devices, &response.Meta{Total: int64(total)})
}

func (h *Handler) UpdateDevice(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "deviceID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "invalid device id")
		return
	}
	var req model.UpdateDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_VALUE", "invalid body")
		return
	}
	device, err := h.svc.UpdateDevice(r.Context(), tenantFromCtx(r), id, req)
	if err != nil {
		h.log.Error().Err(err).Msg("UpdateDevice")
		httperr.WriteLogged(w, err, h.log)
		return
	}
	response.OK(w, device)
}

func (h *Handler) DeleteDevice(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "deviceID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "invalid device id")
		return
	}
	if err := h.svc.DeleteDevice(r.Context(), tenantFromCtx(r), id); err != nil {
		h.log.Error().Err(err).Msg("DeleteDevice")
		httperr.WriteLogged(w, err, h.log)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ListDeviceApps(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "deviceID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "invalid device id")
		return
	}
	apps, err := h.svc.ListDeviceApps(r.Context(), tenantFromCtx(r), id)
	if err != nil {
		h.log.Error().Err(err).Msg("ListDeviceApps")
		httperr.WriteLogged(w, err, h.log)
		return
	}
	response.OKWithMeta(w, apps, &response.Meta{Total: int64(len(apps))})
}

func (h *Handler) InstallApp(w http.ResponseWriter, r *http.Request) {
	deviceID, err := parseUUID(chi.URLParam(r, "deviceID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "invalid device id")
		return
	}
	appID, err := parseUUID(chi.URLParam(r, "appID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "invalid app id")
		return
	}
	if err := h.svc.InstallApp(r.Context(), tenantFromCtx(r), deviceID, appID); err != nil {
		h.log.Error().Err(err).Msg("InstallApp")
		httperr.WriteLogged(w, err, h.log)
		return
	}
	response.OK(w, map[string]string{"status": "installed"})
}

// ─── Apps ─────────────────────────────────────────────────────────────────────

func (h *Handler) CreateApp(w http.ResponseWriter, r *http.Request) {
	var req model.CreateAppRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_VALUE", "invalid body")
		return
	}
	app, err := h.svc.CreateApp(r.Context(), tenantFromCtx(r), req)
	if err != nil {
		h.log.Error().Err(err).Msg("CreateApp")
		httperr.WriteLogged(w, err, h.log)
		return
	}
	response.Created(w, app)
}

func (h *Handler) GetApp(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "appID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "invalid app id")
		return
	}
	app, err := h.svc.GetApp(r.Context(), tenantFromCtx(r), id)
	if err != nil {
		h.log.Error().Err(err).Msg("GetApp")
		response.NotFound(w, "app not found")
		return
	}
	response.OK(w, app)
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
		httperr.WriteLogged(w, err, h.log)
		return
	}
	response.OKWithMeta(w, apps, &response.Meta{Total: int64(total)})
}

func (h *Handler) UpdateApp(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "appID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "invalid app id")
		return
	}
	var req model.UpdateAppRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_VALUE", "invalid body")
		return
	}
	app, err := h.svc.UpdateApp(r.Context(), tenantFromCtx(r), id, req)
	if err != nil {
		h.log.Error().Err(err).Msg("UpdateApp")
		httperr.WriteLogged(w, err, h.log)
		return
	}
	response.OK(w, app)
}

// ─── Policies ─────────────────────────────────────────────────────────────────

func (h *Handler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	var req model.CreatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_VALUE", "invalid body")
		return
	}
	policy, err := h.svc.CreatePolicy(r.Context(), tenantFromCtx(r), req, userFromCtx(r))
	if err != nil {
		h.log.Error().Err(err).Msg("CreatePolicy")
		httperr.WriteLogged(w, err, h.log)
		return
	}
	response.Created(w, policy)
}

func (h *Handler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "policyID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "invalid policy id")
		return
	}
	policy, err := h.svc.GetPolicy(r.Context(), tenantFromCtx(r), id)
	if err != nil {
		h.log.Error().Err(err).Msg("GetPolicy")
		response.NotFound(w, "policy not found")
		return
	}
	response.OK(w, policy)
}

func (h *Handler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := h.svc.ListPolicies(r.Context(), tenantFromCtx(r))
	if err != nil {
		h.log.Error().Err(err).Msg("ListPolicies")
		httperr.WriteLogged(w, err, h.log)
		return
	}
	response.OKWithMeta(w, policies, &response.Meta{Total: int64(len(policies))})
}

func (h *Handler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "policyID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "invalid policy id")
		return
	}
	var req model.UpdatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_VALUE", "invalid body")
		return
	}
	policy, err := h.svc.UpdatePolicy(r.Context(), tenantFromCtx(r), id, req)
	if err != nil {
		h.log.Error().Err(err).Msg("UpdatePolicy")
		httperr.WriteLogged(w, err, h.log)
		return
	}
	response.OK(w, policy)
}

func (h *Handler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "policyID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "invalid policy id")
		return
	}
	if err := h.svc.DeletePolicy(r.Context(), tenantFromCtx(r), id); err != nil {
		h.log.Error().Err(err).Msg("DeletePolicy")
		httperr.WriteLogged(w, err, h.log)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─── Threats ──────────────────────────────────────────────────────────────────

func (h *Handler) CreateThreat(w http.ResponseWriter, r *http.Request) {
	var req model.CreateThreatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_VALUE", "invalid body")
		return
	}
	threat, err := h.svc.CreateThreat(r.Context(), tenantFromCtx(r), req)
	if err != nil {
		h.log.Error().Err(err).Msg("CreateThreat")
		httperr.WriteLogged(w, err, h.log)
		return
	}
	response.Created(w, threat)
}

func (h *Handler) GetThreat(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "threatID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "invalid threat id")
		return
	}
	threat, err := h.svc.GetThreat(r.Context(), tenantFromCtx(r), id)
	if err != nil {
		h.log.Error().Err(err).Msg("GetThreat")
		response.NotFound(w, "threat not found")
		return
	}
	response.OK(w, threat)
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
		httperr.WriteLogged(w, err, h.log)
		return
	}
	response.OKWithMeta(w, threats, &response.Meta{Total: int64(total)})
}

func (h *Handler) UpdateThreat(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "threatID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "invalid threat id")
		return
	}
	var req model.UpdateThreatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_VALUE", "invalid body")
		return
	}
	threat, err := h.svc.UpdateThreat(r.Context(), tenantFromCtx(r), id, req)
	if err != nil {
		h.log.Error().Err(err).Msg("UpdateThreat")
		httperr.WriteLogged(w, err, h.log)
		return
	}
	response.OK(w, threat)
}

// ─── Compliance ───────────────────────────────────────────────────────────────

func (h *Handler) RunComplianceCheck(w http.ResponseWriter, r *http.Request) {
	var req model.RunComplianceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_VALUE", "invalid body")
		return
	}
	check, err := h.svc.RunComplianceCheck(r.Context(), tenantFromCtx(r), req)
	if err != nil {
		h.log.Error().Err(err).Msg("RunComplianceCheck")
		httperr.WriteLogged(w, err, h.log)
		return
	}
	response.OK(w, check)
}

func (h *Handler) ListComplianceChecks(w http.ResponseWriter, r *http.Request) {
	deviceID, err := parseUUID(chi.URLParam(r, "deviceID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "invalid device id")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20
	}
	checks, err := h.svc.ListComplianceChecks(r.Context(), tenantFromCtx(r), deviceID, limit)
	if err != nil {
		h.log.Error().Err(err).Msg("ListComplianceChecks")
		httperr.WriteLogged(w, err, h.log)
		return
	}
	response.OKWithMeta(w, checks, &response.Meta{Total: int64(len(checks))})
}

// ─── Remote Actions ───────────────────────────────────────────────────────────

func (h *Handler) CreateRemoteAction(w http.ResponseWriter, r *http.Request) {
	var req model.CreateRemoteActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_VALUE", "invalid body")
		return
	}
	if userID := userFromCtx(r); userID != nil && req.RequestedByID == nil {
		req.RequestedByID = userID
	}
	action, err := h.svc.CreateRemoteAction(r.Context(), tenantFromCtx(r), req)
	if err != nil {
		h.log.Error().Err(err).Msg("CreateRemoteAction")
		httperr.WriteLogged(w, err, h.log)
		return
	}
	response.Created(w, action)
}

func (h *Handler) GetRemoteAction(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "actionID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "invalid action id")
		return
	}
	action, err := h.svc.GetRemoteAction(r.Context(), tenantFromCtx(r), id)
	if err != nil {
		h.log.Error().Err(err).Msg("GetRemoteAction")
		response.NotFound(w, "action not found")
		return
	}
	response.OK(w, action)
}

func (h *Handler) ListRemoteActions(w http.ResponseWriter, r *http.Request) {
	deviceID, err := parseUUID(chi.URLParam(r, "deviceID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "invalid device id")
		return
	}
	actions, err := h.svc.ListRemoteActions(r.Context(), tenantFromCtx(r), deviceID)
	if err != nil {
		h.log.Error().Err(err).Msg("ListRemoteActions")
		httperr.WriteLogged(w, err, h.log)
		return
	}
	response.OKWithMeta(w, actions, &response.Meta{Total: int64(len(actions))})
}

func (h *Handler) UpdateRemoteAction(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "actionID"))
	if err != nil {
		response.BadRequest(w, "INVALID_ID", "invalid action id")
		return
	}
	var req model.UpdateRemoteActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_VALUE", "invalid body")
		return
	}
	action, err := h.svc.UpdateRemoteAction(r.Context(), tenantFromCtx(r), id, req)
	if err != nil {
		h.log.Error().Err(err).Msg("UpdateRemoteAction")
		httperr.WriteLogged(w, err, h.log)
		return
	}
	response.OK(w, action)
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (h *Handler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.svc.GetStats(r.Context(), tenantFromCtx(r))
	if err != nil {
		h.log.Error().Err(err).Msg("GetStats")
		httperr.WriteLogged(w, err, h.log)
		return
	}
	response.OK(w, stats)
}
