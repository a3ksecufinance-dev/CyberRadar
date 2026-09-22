package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/vuln/internal/model"
	"github.com/cyberradar/platform/services/vuln/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// VulnHandler exposes the Vulnerability & Exposure Management API.
type VulnHandler struct {
	svc      *service.VulnService
	validate *validator.Validate
}

// NewVulnHandler creates a VulnHandler.
func NewVulnHandler(svc *service.VulnService) *VulnHandler {
	return &VulnHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts all Vuln routes.
func (h *VulnHandler) RegisterRoutes(r chi.Router) {
	// Vulnerabilities (CVE library)
	r.Get("/vuln/vulnerabilities", h.ListVulns)
	r.Post("/vuln/vulnerabilities", h.CreateVuln)
	r.Get("/vuln/vulnerabilities/{vulnID}", h.GetVuln)

	// Findings (asset ↔ vulnerability links)
	r.Get("/vuln/findings", h.ListFindings)
	r.Post("/vuln/findings", h.CreateFinding)
	r.Post("/vuln/findings/bulk", h.BulkCreateFindings)
	r.Put("/vuln/findings/{findingID}", h.UpdateFinding)

	// Asset exposure
	r.Get("/vuln/assets/{assetID}/exposure", h.AssetExposure)

	// Scan jobs
	r.Get("/vuln/scans", h.ListScans)
	r.Post("/vuln/scans", h.CreateScan)

	// Remediation tickets
	r.Get("/vuln/tickets", h.ListTickets)
	r.Post("/vuln/tickets", h.CreateTicket)
	r.Put("/vuln/tickets/{ticketID}", h.UpdateTicket)

	// Dashboard stats
	r.Get("/vuln/stats", h.Stats)
}

// ─── Vulnerabilities ──────────────────────────────────────────────────────────

func (h *VulnHandler) ListVulns(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()
	f := model.VulnFilter{
		TenantID: tenantID,
		Severity: q.Get("severity"),
		Search:   q.Get("q"),
		Limit:    queryInt(q.Get("limit"), 50),
		Offset:   queryInt(q.Get("offset"), 0),
	}
	if v := q.Get("exploited"); v == "true" {
		t := true
		f.IsExploited = &t
	}
	vulns, total, err := h.svc.ListVulns(r.Context(), f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"vulnerabilities": vulns, "total": total})
}

func (h *VulnHandler) CreateVuln(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.CreateVulnRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	v, err := h.svc.CreateVuln(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, v)
}

func (h *VulnHandler) GetVuln(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "vulnID")
	if !ok {
		return
	}
	v, err := h.svc.GetVuln(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, v)
}

// ─── Findings ─────────────────────────────────────────────────────────────────

func (h *VulnHandler) ListFindings(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()
	f := model.FindingFilter{
		TenantID: tenantID,
		Status:   q.Get("status"),
		Severity: q.Get("severity"),
		Limit:    queryInt(q.Get("limit"), 50),
		Offset:   queryInt(q.Get("offset"), 0),
	}
	if v := q.Get("asset_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.AssetID = &id
		}
	}
	if v := q.Get("vuln_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.VulnID = &id
		}
	}
	if v := q.Get("scan_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.ScanID = &id
		}
	}
	findings, total, err := h.svc.ListFindings(r.Context(), f)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"findings": findings, "total": total})
}

func (h *VulnHandler) CreateFinding(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.CreateFindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	av, err := h.svc.CreateFinding(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, av)
}

func (h *VulnHandler) BulkCreateFindings(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	var req model.BulkCreateFindingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	count, err := h.svc.BulkCreateFindings(r.Context(), tenantID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, map[string]any{"created": count, "total": len(req.Findings)})
}

func (h *VulnHandler) UpdateFinding(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "findingID")
	if !ok {
		return
	}
	var req model.UpdateFindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	av, err := h.svc.UpdateFinding(r.Context(), tenantID, id, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, av)
}

func (h *VulnHandler) AssetExposure(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	assetID, ok := parseUUID(w, r, "assetID")
	if !ok {
		return
	}
	es, err := h.svc.GetAssetExposure(r.Context(), tenantID, assetID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, es)
}

// ─── Scan Jobs ────────────────────────────────────────────────────────────────

func (h *VulnHandler) ListScans(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	status := r.URL.Query().Get("status")
	limit := queryInt(r.URL.Query().Get("limit"), 20)
	jobs, err := h.svc.ListScanJobs(r.Context(), tenantID, status, limit)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"scans": jobs, "total": len(jobs)})
}

func (h *VulnHandler) CreateScan(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	var req model.CreateScanJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	job, err := h.svc.CreateScanJob(r.Context(), tenantID, &callerID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, job)
}

// ─── Remediation Tickets ──────────────────────────────────────────────────────

func (h *VulnHandler) ListTickets(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()
	status := q.Get("status")
	limit := queryInt(q.Get("limit"), 50)
	offset := queryInt(q.Get("offset"), 0)
	tickets, total, err := h.svc.ListTickets(r.Context(), tenantID, status, limit, offset)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"tickets": tickets, "total": total})
}

func (h *VulnHandler) CreateTicket(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	var req model.CreateTicketRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	t, err := h.svc.CreateTicket(r.Context(), tenantID, &callerID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, t)
}

func (h *VulnHandler) UpdateTicket(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "ticketID")
	if !ok {
		return
	}
	var req model.UpdateTicketRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	t, err := h.svc.UpdateTicket(r.Context(), tenantID, id, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, t)
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (h *VulnHandler) Stats(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	stats, err := h.svc.GetStats(r.Context(), tenantID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, stats)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func mustTenantID(r *http.Request) uuid.UUID {
	return authctx.TenantID(r.Context())
}

func mustCallerID(r *http.Request) uuid.UUID {
	return authctx.UserID(r.Context())
}

func parseUUID(w http.ResponseWriter, r *http.Request, param string) (uuid.UUID, bool) {
	raw := chi.URLParam(r, param)
	id, err := uuid.Parse(raw)
	if err != nil {
		response.BadRequest(w, "INVALID_ID", param+" must be a valid UUID")
		return uuid.Nil, false
	}
	return id, true
}

func mapError(w http.ResponseWriter, err error) {
	switch {
	case apierrors.IsKind(err, apierrors.KindNotFound):
		response.NotFound(w, "resource")
	case apierrors.IsKind(err, apierrors.KindForbidden):
		response.Forbidden(w, "access denied")
	case apierrors.IsKind(err, apierrors.KindBadInput):
		response.BadRequest(w, "BAD_INPUT", err.Error())
	default:
		response.InternalError(w)
	}
}

func queryInt(s string, def int) int {
	if s == "" {
		return def
	}
	if n, err := strconv.Atoi(s); err == nil && n >= 0 {
		return n
	}
	return def
}
