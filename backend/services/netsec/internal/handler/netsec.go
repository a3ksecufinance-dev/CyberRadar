package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/httperr"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/netsec/internal/model"
	"github.com/cyberradar/platform/services/netsec/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// NetSecHandler exposes the Network Security & Microsegmentation API.
type NetSecHandler struct {
	svc      *service.NetSecService
	validate *validator.Validate
}

// NewNetSecHandler creates a NetSecHandler.
func NewNetSecHandler(svc *service.NetSecService) *NetSecHandler {
	return &NetSecHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts all netsec routes under the provided router.
func (h *NetSecHandler) RegisterRoutes(r chi.Router) {
	// Zones
	r.Post("/netsec/zones", h.CreateZone)
	r.Get("/netsec/zones", h.ListZones)
	r.Get("/netsec/zones/{zoneID}", h.GetZone)
	r.Patch("/netsec/zones/{zoneID}", h.UpdateZone)

	// Policies
	r.Post("/netsec/policies", h.CreatePolicy)
	r.Get("/netsec/policies", h.ListPolicies)
	r.Get("/netsec/policies/{policyID}", h.GetPolicy)
	r.Patch("/netsec/policies/{policyID}", h.UpdatePolicy)

	// Flows
	r.Post("/netsec/flows", h.IngestFlow)
	r.Get("/netsec/flows", h.ListFlows)

	// Anomalies
	r.Post("/netsec/anomalies", h.CreateAnomaly)
	r.Get("/netsec/anomalies", h.ListAnomalies)
	r.Patch("/netsec/anomalies/{anomalyID}", h.UpdateAnomalyStatus)

	// Devices
	r.Post("/netsec/devices", h.RegisterDevice)
	r.Get("/netsec/devices", h.ListDevices)
	r.Patch("/netsec/devices/{deviceID}", h.UpdateDevice)

	// Topology & Stats
	r.Get("/netsec/topology", h.GetTopology)
	r.Get("/netsec/stats", h.GetStats)
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

// ─── Zones ────────────────────────────────────────────────────────────────────

func (h *NetSecHandler) CreateZone(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	var req model.CreateZoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperr.Write(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	if err := h.validate.Struct(req); err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindBadInput, err.Error()))
		return
	}
	zone, err := h.svc.CreateZone(r.Context(), tenantID, &req)
	if err != nil {
		httperr.Write(w, err)
		return
	}
	response.Created(w, zone)
}

func (h *NetSecHandler) ListZones(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	activeOnly := r.URL.Query().Get("active_only") != "false"
	zones, err := h.svc.ListZones(r.Context(), tenantID, activeOnly)
	if err != nil {
		httperr.Write(w, err)
		return
	}
	response.OKWithMeta(w, zones, &response.Meta{Total: int64(len(zones))})
}

func (h *NetSecHandler) GetZone(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	zoneID, err := parseUUID(r, "zoneID")
	if err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindBadInput, "invalid zone id"))
		return
	}
	zone, err := h.svc.GetZone(r.Context(), tenantID, zoneID)
	if err != nil {
		httperr.Write(w, err)
		return
	}
	response.OK(w, zone)
}

func (h *NetSecHandler) UpdateZone(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	zoneID, err := parseUUID(r, "zoneID")
	if err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindBadInput, "invalid zone id"))
		return
	}
	var req model.UpdateZoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperr.Write(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	zone, err := h.svc.UpdateZone(r.Context(), tenantID, zoneID, &req)
	if err != nil {
		httperr.Write(w, err)
		return
	}
	response.OK(w, zone)
}

// ─── Policies ─────────────────────────────────────────────────────────────────

func (h *NetSecHandler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	var req model.CreatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperr.Write(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	if err := h.validate.Struct(req); err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindBadInput, err.Error()))
		return
	}
	createdBy := userFromCtx(r)
	policy, err := h.svc.CreatePolicy(r.Context(), tenantID, &req, createdBy)
	if err != nil {
		httperr.Write(w, err)
		return
	}
	response.Created(w, policy)
}

func (h *NetSecHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	var srcZoneID, dstZoneID *uuid.UUID
	if v := r.URL.Query().Get("src_zone_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			srcZoneID = &id
		}
	}
	if v := r.URL.Query().Get("dst_zone_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			dstZoneID = &id
		}
	}
	activeOnly := r.URL.Query().Get("active_only") != "false"
	page := queryInt(r, "page", "1")
	pageSize := queryInt(r, "page_size", "50")
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 50
	}
	policies, total, err := h.svc.ListPolicies(r.Context(), tenantID, srcZoneID, dstZoneID, activeOnly, page, pageSize)
	if err != nil {
		httperr.Write(w, err)
		return
	}
	response.OKWithMeta(w, policies, &response.Meta{Total: int64(total), Page: page, Limit: pageSize})
}

func (h *NetSecHandler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	policyID, err := parseUUID(r, "policyID")
	if err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindBadInput, "invalid policy id"))
		return
	}
	policy, err := h.svc.GetPolicy(r.Context(), tenantID, policyID)
	if err != nil {
		httperr.Write(w, err)
		return
	}
	response.OK(w, policy)
}

func (h *NetSecHandler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	policyID, err := parseUUID(r, "policyID")
	if err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindBadInput, "invalid policy id"))
		return
	}
	var req model.UpdatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperr.Write(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	policy, err := h.svc.UpdatePolicy(r.Context(), tenantID, policyID, &req)
	if err != nil {
		httperr.Write(w, err)
		return
	}
	response.OK(w, policy)
}

// ─── Flows ────────────────────────────────────────────────────────────────────

func (h *NetSecHandler) IngestFlow(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	var req model.IngestFlowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperr.Write(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	if err := h.validate.Struct(req); err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindBadInput, err.Error()))
		return
	}
	flow, err := h.svc.IngestFlow(r.Context(), tenantID, &req)
	if err != nil {
		httperr.Write(w, err)
		return
	}
	response.Accepted(w, flow)
}

func (h *NetSecHandler) ListFlows(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	f := model.ListFlowsFilter{
		SrcIP:    r.URL.Query().Get("src_ip"),
		DstIP:    r.URL.Query().Get("dst_ip"),
		Action:   r.URL.Query().Get("action"),
		Page:     queryInt(r, "page", "1"),
		PageSize: queryInt(r, "page_size", "50"),
	}
	if v := r.URL.Query().Get("src_zone_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.SrcZoneID = &id
		}
	}
	if v := r.URL.Query().Get("dst_zone_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.DstZoneID = &id
		}
	}
	if v := r.URL.Query().Get("min_score"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.MinScore = &n
		}
	}
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize < 1 || f.PageSize > 200 {
		f.PageSize = 50
	}
	flows, total, err := h.svc.ListFlows(r.Context(), tenantID, f)
	if err != nil {
		httperr.Write(w, err)
		return
	}
	response.OKWithMeta(w, flows, &response.Meta{Total: int64(total), Page: f.Page, Limit: f.PageSize})
}

// ─── Anomalies ────────────────────────────────────────────────────────────────

func (h *NetSecHandler) CreateAnomaly(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	var req model.CreateAnomalyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperr.Write(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	if err := h.validate.Struct(req); err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindBadInput, err.Error()))
		return
	}
	anomaly, err := h.svc.CreateAnomaly(r.Context(), tenantID, &req)
	if err != nil {
		httperr.Write(w, err)
		return
	}
	response.Created(w, anomaly)
}

func (h *NetSecHandler) ListAnomalies(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	f := model.ListAnomaliesFilter{
		AnomalyType: r.URL.Query().Get("anomaly_type"),
		Severity:    r.URL.Query().Get("severity"),
		Status:      r.URL.Query().Get("status"),
		Page:        queryInt(r, "page", "1"),
		PageSize:    queryInt(r, "page_size", "50"),
	}
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize < 1 || f.PageSize > 200 {
		f.PageSize = 50
	}
	anomalies, total, err := h.svc.ListAnomalies(r.Context(), tenantID, f)
	if err != nil {
		httperr.Write(w, err)
		return
	}
	response.OKWithMeta(w, anomalies, &response.Meta{Total: int64(total), Page: f.Page, Limit: f.PageSize})
}

func (h *NetSecHandler) UpdateAnomalyStatus(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	anomalyID, err := parseUUID(r, "anomalyID")
	if err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindBadInput, "invalid anomaly id"))
		return
	}
	var req model.UpdateAnomalyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperr.Write(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	if err := h.validate.Struct(req); err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindBadInput, err.Error()))
		return
	}
	anomaly, err := h.svc.UpdateAnomaly(r.Context(), tenantID, anomalyID, req.Status)
	if err != nil {
		httperr.Write(w, err)
		return
	}
	response.OK(w, anomaly)
}

// ─── Devices ──────────────────────────────────────────────────────────────────

func (h *NetSecHandler) RegisterDevice(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	var req model.RegisterDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperr.Write(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	if err := h.validate.Struct(req); err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindBadInput, err.Error()))
		return
	}
	device, err := h.svc.RegisterDevice(r.Context(), tenantID, &req)
	if err != nil {
		httperr.Write(w, err)
		return
	}
	response.Created(w, device)
}

func (h *NetSecHandler) ListDevices(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	deviceType := r.URL.Query().Get("device_type")
	var zoneID *uuid.UUID
	if v := r.URL.Query().Get("zone_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			zoneID = &id
		}
	}
	page := queryInt(r, "page", "1")
	pageSize := queryInt(r, "page_size", "50")
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 50
	}
	devices, total, err := h.svc.ListDevices(r.Context(), tenantID, deviceType, zoneID, page, pageSize)
	if err != nil {
		httperr.Write(w, err)
		return
	}
	response.OKWithMeta(w, devices, &response.Meta{Total: int64(total), Page: page, Limit: pageSize})
}

func (h *NetSecHandler) UpdateDevice(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	deviceID, err := parseUUID(r, "deviceID")
	if err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindBadInput, "invalid device id"))
		return
	}
	var req model.UpdateDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperr.Write(w, apierrors.Wrap(apierrors.KindBadInput, "invalid request body", err))
		return
	}
	device, err := h.svc.UpdateDevice(r.Context(), tenantID, deviceID, &req)
	if err != nil {
		httperr.Write(w, err)
		return
	}
	response.OK(w, device)
}

// ─── Topology & Stats ─────────────────────────────────────────────────────────

func (h *NetSecHandler) GetTopology(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	topo, err := h.svc.GetTopology(r.Context(), tenantID)
	if err != nil {
		httperr.Write(w, err)
		return
	}
	response.OK(w, topo)
}

func (h *NetSecHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	tenantID, err := tenantFromCtx(r)
	if err != nil {
		httperr.Write(w, apierrors.New(apierrors.KindUnauth, "invalid tenant"))
		return
	}
	stats, err := h.svc.Stats(r.Context(), tenantID)
	if err != nil {
		httperr.Write(w, err)
		return
	}
	response.OK(w, stats)
}
