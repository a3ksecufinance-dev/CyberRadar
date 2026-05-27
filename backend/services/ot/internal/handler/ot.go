package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/cyberradar/platform/services/ot/internal/model"
	"github.com/cyberradar/platform/services/ot/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

type OTHandler struct {
	svc    *service.OTService
	logger zerolog.Logger
}

func NewOTHandler(svc *service.OTService, logger zerolog.Logger) *OTHandler {
	return &OTHandler{svc: svc, logger: logger}
}

func (h *OTHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Assets
	r.Post("/assets", h.CreateAsset)
	r.Get("/assets", h.ListAssets)
	r.Get("/assets/{assetID}", h.GetAsset)
	r.Patch("/assets/{assetID}", h.UpdateAsset)

	// Zones
	r.Post("/zones", h.CreateZone)
	r.Get("/zones", h.ListZones)
	r.Patch("/zones/{zoneID}", h.UpdateZone)

	// Communications / network flows
	r.Post("/communications", h.CreateCommunication)
	r.Get("/communications", h.ListCommunications)

	// Vulnerabilities
	r.Post("/vulnerabilities", h.CreateVulnerability)
	r.Get("/vulnerabilities", h.ListVulnerabilities)
	r.Patch("/vulnerabilities/{vulnID}", h.UpdateVulnerability)

	// Events / alerts
	r.Post("/events", h.CreateEvent)
	r.Get("/events", h.ListEvents)
	r.Patch("/events/{eventID}", h.UpdateEvent)

	// Policies
	r.Post("/policies", h.CreatePolicy)
	r.Get("/policies", h.ListPolicies)
	r.Patch("/policies/{policyID}", h.UpdatePolicy)

	// Patch management
	r.Post("/patches", h.CreatePatch)
	r.Get("/patches", h.ListPatches)
	r.Patch("/patches/{patchID}", h.UpdatePatch)

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

func parseUUID(r *http.Request, param string) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, param))
	return id, err == nil
}

// ─── Assets ───────────────────────────────────────────────────────────────────

func (h *OTHandler) CreateAsset(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	var req model.CreateAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Name == "" || req.AssetType == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and asset_type are required"})
		return
	}
	a, err := h.svc.CreateAsset(r.Context(), tenantID, &req, userFromCtx(r))
	if err != nil {
		h.logger.Error().Err(err).Msg("CreateAsset")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

func (h *OTHandler) ListAssets(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	purdue, _ := strconv.Atoi(q.Get("purdue_level"))
	f := model.ListAssetsFilter{
		Site:        q.Get("site"),
		AssetType:   q.Get("asset_type"),
		RiskLevel:   q.Get("risk_level"),
		PurdueLevel: purdue,
		Limit:       limit,
		Offset:      offset,
	}
	assets, total, err := h.svc.ListAssets(r.Context(), tenantID, f)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if assets == nil {
		assets = []model.OTAsset{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"assets": assets, "total": total})
}

func (h *OTHandler) GetAsset(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	id, ok := parseUUID(r, "assetID")
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	a, err := h.svc.GetAsset(r.Context(), tenantID, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if a == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (h *OTHandler) UpdateAsset(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	id, ok := parseUUID(r, "assetID")
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var req model.UpdateAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	a, err := h.svc.UpdateAsset(r.Context(), tenantID, id, &req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, a)
}

// ─── Zones ────────────────────────────────────────────────────────────────────

func (h *OTHandler) CreateZone(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	var req model.CreateZoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Name == "" || req.ZoneType == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and zone_type are required"})
		return
	}
	z, err := h.svc.CreateZone(r.Context(), tenantID, &req, userFromCtx(r))
	if err != nil {
		h.logger.Error().Err(err).Msg("CreateZone")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, z)
}

func (h *OTHandler) ListZones(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	zones, err := h.svc.ListZones(r.Context(), tenantID, r.URL.Query().Get("site"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if zones == nil {
		zones = []model.OTZone{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"zones": zones, "total": len(zones)})
}

func (h *OTHandler) UpdateZone(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	id, ok := parseUUID(r, "zoneID")
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var req model.UpdateZoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	z, err := h.svc.UpdateZone(r.Context(), tenantID, id, &req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, z)
}

// ─── Communications ───────────────────────────────────────────────────────────

func (h *OTHandler) CreateCommunication(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	var req model.CreateCommunicationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	c, err := h.svc.CreateCommunication(r.Context(), tenantID, &req)
	if err != nil {
		h.logger.Error().Err(err).Msg("CreateCommunication")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (h *OTHandler) ListCommunications(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	anomalousOnly := r.URL.Query().Get("anomalous") == "true"
	comms, err := h.svc.ListCommunications(r.Context(), tenantID, anomalousOnly)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if comms == nil {
		comms = []model.OTCommunication{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"communications": comms, "total": len(comms)})
}

// ─── Vulnerabilities ──────────────────────────────────────────────────────────

func (h *OTHandler) CreateVulnerability(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	var req model.CreateVulnerabilityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Title == "" || req.Severity == "" || req.AssetID == uuid.Nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "asset_id, title and severity are required"})
		return
	}
	v, err := h.svc.CreateVulnerability(r.Context(), tenantID, &req)
	if err != nil {
		h.logger.Error().Err(err).Msg("CreateVulnerability")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

func (h *OTHandler) ListVulnerabilities(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	f := model.ListVulnsFilter{
		Severity: q.Get("severity"),
		Status:   q.Get("status"),
		Limit:    limit,
		Offset:   offset,
	}
	if raw := q.Get("asset_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err == nil {
			f.AssetID = &id
		}
	}
	vulns, total, err := h.svc.ListVulnerabilities(r.Context(), tenantID, f)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if vulns == nil {
		vulns = []model.OTVulnerability{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"vulnerabilities": vulns, "total": total})
}

func (h *OTHandler) UpdateVulnerability(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	id, ok := parseUUID(r, "vulnID")
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var req model.UpdateVulnerabilityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	v, err := h.svc.UpdateVulnerability(r.Context(), tenantID, id, &req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// ─── Events ───────────────────────────────────────────────────────────────────

func (h *OTHandler) CreateEvent(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	var req model.CreateEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Title == "" || req.EventType == "" || req.Severity == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "title, event_type and severity are required"})
		return
	}
	e, err := h.svc.CreateEvent(r.Context(), tenantID, &req)
	if err != nil {
		h.logger.Error().Err(err).Msg("CreateEvent")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, e)
}

func (h *OTHandler) ListEvents(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	f := model.ListEventsFilter{
		EventType: q.Get("event_type"),
		Severity:  q.Get("severity"),
		Status:    q.Get("status"),
		Limit:     limit,
		Offset:    offset,
	}
	if raw := q.Get("asset_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err == nil {
			f.AssetID = &id
		}
	}
	events, total, err := h.svc.ListEvents(r.Context(), tenantID, f)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if events == nil {
		events = []model.OTEvent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "total": total})
}

func (h *OTHandler) UpdateEvent(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	id, ok := parseUUID(r, "eventID")
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var req model.UpdateEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	e, err := h.svc.UpdateEvent(r.Context(), tenantID, id, &req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, e)
}

// ─── Policies ─────────────────────────────────────────────────────────────────

func (h *OTHandler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
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

func (h *OTHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
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
		policies = []model.OTPolicy{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": policies, "total": len(policies)})
}

func (h *OTHandler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
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

// ─── Patches ──────────────────────────────────────────────────────────────────

func (h *OTHandler) CreatePatch(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	var req model.CreatePatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Title == "" || req.AssetID == uuid.Nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "asset_id and title are required"})
		return
	}
	p, err := h.svc.CreatePatch(r.Context(), tenantID, &req, userFromCtx(r))
	if err != nil {
		h.logger.Error().Err(err).Msg("CreatePatch")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (h *OTHandler) ListPatches(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	q := r.URL.Query()
	var assetID *uuid.UUID
	if raw := q.Get("asset_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err == nil {
			assetID = &id
		}
	}
	patches, err := h.svc.ListPatches(r.Context(), tenantID, assetID, q.Get("status"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if patches == nil {
		patches = []model.OTPatch{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"patches": patches, "total": len(patches)})
}

func (h *OTHandler) UpdatePatch(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromCtx(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing tenant"})
		return
	}
	id, ok := parseUUID(r, "patchID")
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var req model.UpdatePatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	p, err := h.svc.UpdatePatch(r.Context(), tenantID, id, &req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (h *OTHandler) GetStats(w http.ResponseWriter, r *http.Request) {
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
