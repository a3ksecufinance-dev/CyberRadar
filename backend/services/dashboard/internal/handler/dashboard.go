package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/internal/pkg/response"
	"github.com/cyberradar/platform/services/dashboard/internal/model"
	"github.com/cyberradar/platform/services/dashboard/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// DashboardHandler exposes the Dashboard API.
type DashboardHandler struct {
	svc      *service.DashboardService
	validate *validator.Validate
}

// NewDashboardHandler creates a DashboardHandler.
func NewDashboardHandler(svc *service.DashboardService) *DashboardHandler {
	return &DashboardHandler{svc: svc, validate: validator.New()}
}

// RegisterRoutes mounts all dashboard routes.
func (h *DashboardHandler) RegisterRoutes(r chi.Router) {
	// Platform overview
	r.Get("/dashboard/overview", h.Overview)

	// Dashboards
	r.Get("/dashboard/dashboards", h.ListDashboards)
	r.Post("/dashboard/dashboards", h.CreateDashboard)
	r.Get("/dashboard/dashboards/{dashID}", h.GetDashboard)
	r.Patch("/dashboard/dashboards/{dashID}", h.UpdateDashboard)
	r.Delete("/dashboard/dashboards/{dashID}", h.DeleteDashboard)

	// Widgets
	r.Post("/dashboard/dashboards/{dashID}/widgets", h.AddWidget)
	r.Patch("/dashboard/widgets/{widgetID}", h.UpdateWidget)
	r.Delete("/dashboard/widgets/{widgetID}", h.DeleteWidget)

	// KPI / time series
	r.Get("/dashboard/kpi/timeseries", h.TimeSeries)
	r.Get("/dashboard/kpi/snapshot", h.DomainSnapshot)
	r.Get("/dashboard/kpi/risk-timeline", h.RiskTimeline)

	// Reports
	r.Get("/dashboard/reports", h.ListReports)
	r.Post("/dashboard/reports", h.CreateReport)
	r.Get("/dashboard/reports/{reportID}", h.GetReport)
	r.Post("/dashboard/reports/{reportID}/run", h.RunReport)
	r.Delete("/dashboard/reports/{reportID}", h.DeleteReport)
}

// ─── Platform Overview ────────────────────────────────────────────────────────

func (h *DashboardHandler) Overview(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	overview, err := h.svc.PlatformOverview(r.Context(), tenantID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, overview)
}

// ─── Dashboards ───────────────────────────────────────────────────────────────

func (h *DashboardHandler) ListDashboards(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	dashboards, err := h.svc.ListDashboards(r.Context(), tenantID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"dashboards": dashboards, "total": len(dashboards)})
}

func (h *DashboardHandler) CreateDashboard(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	var req model.CreateDashboardRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	d, err := h.svc.CreateDashboard(r.Context(), tenantID, &callerID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, d)
}

func (h *DashboardHandler) GetDashboard(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "dashID")
	if !ok {
		return
	}
	d, err := h.svc.GetDashboard(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, d)
}

func (h *DashboardHandler) UpdateDashboard(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "dashID")
	if !ok {
		return
	}
	var req model.UpdateDashboardRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	d, err := h.svc.UpdateDashboard(r.Context(), tenantID, id, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, d)
}

func (h *DashboardHandler) DeleteDashboard(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "dashID")
	if !ok {
		return
	}
	if err := h.svc.DeleteDashboard(r.Context(), tenantID, id); err != nil {
		mapError(w, err)
		return
	}
	response.NoContent(w)
}

// ─── Widgets ──────────────────────────────────────────────────────────────────

func (h *DashboardHandler) AddWidget(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	dashID, ok := parseUUID(w, r, "dashID")
	if !ok {
		return
	}
	var req model.CreateWidgetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	widget, err := h.svc.AddWidget(r.Context(), tenantID, dashID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, widget)
}

func (h *DashboardHandler) UpdateWidget(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "widgetID")
	if !ok {
		return
	}
	var req model.UpdateWidgetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	widget, err := h.svc.UpdateWidget(r.Context(), tenantID, id, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, widget)
}

func (h *DashboardHandler) DeleteWidget(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "widgetID")
	if !ok {
		return
	}
	if err := h.svc.DeleteWidget(r.Context(), tenantID, id); err != nil {
		mapError(w, err)
		return
	}
	response.NoContent(w)
}

// ─── KPI / Time Series ────────────────────────────────────────────────────────

func (h *DashboardHandler) TimeSeries(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()

	domain := q.Get("domain")
	metricKey := q.Get("metric_key")
	if domain == "" || metricKey == "" {
		response.BadRequest(w, "MISSING_PARAM", "domain and metric_key are required")
		return
	}

	req := model.KPIQueryRequest{
		TenantID:  tenantID,
		Domain:    domain,
		MetricKey: metricKey,
		Interval:  q.Get("interval"),
	}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err == nil {
			req.Since = t
		}
	}
	if v := q.Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err == nil {
			req.Until = t
		}
	}

	points, err := h.svc.QueryTimeSeries(r.Context(), req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{
		"domain":     domain,
		"metric_key": metricKey,
		"interval":   req.Interval,
		"points":     points,
		"total":      len(points),
	})
}

func (h *DashboardHandler) DomainSnapshot(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		response.BadRequest(w, "MISSING_PARAM", "domain is required")
		return
	}
	snap, err := h.svc.DomainSnapshot(r.Context(), tenantID, domain)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"domain": domain, "metrics": snap})
}

func (h *DashboardHandler) RiskTimeline(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	q := r.URL.Query()

	entityType := q.Get("entity_type")
	entityID := q.Get("entity_id")
	if entityType == "" || entityID == "" {
		response.BadRequest(w, "MISSING_PARAM", "entity_type and entity_id are required")
		return
	}

	since := time.Now().UTC().Add(-7 * 24 * time.Hour)
	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			since = t
		}
	}

	points, err := h.svc.RiskTimeline(r.Context(), tenantID, entityType, entityID, since)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"points": points, "total": len(points)})
}

// ─── Reports ──────────────────────────────────────────────────────────────────

func (h *DashboardHandler) ListReports(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	reports, err := h.svc.ListReports(r.Context(), tenantID)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, map[string]any{"reports": reports, "total": len(reports)})
}

func (h *DashboardHandler) CreateReport(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	callerID := mustCallerID(r)
	var req model.CreateReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "INVALID_JSON", "Invalid request body")
		return
	}
	if err := h.validate.Struct(&req); err != nil {
		response.UnprocessableEntity(w, err.Error())
		return
	}
	rpt, err := h.svc.CreateReport(r.Context(), tenantID, &callerID, &req)
	if err != nil {
		mapError(w, err)
		return
	}
	response.Created(w, rpt)
}

func (h *DashboardHandler) GetReport(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "reportID")
	if !ok {
		return
	}
	rpt, err := h.svc.GetReport(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, rpt)
}

func (h *DashboardHandler) RunReport(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "reportID")
	if !ok {
		return
	}
	rpt, err := h.svc.RunReport(r.Context(), tenantID, id)
	if err != nil {
		mapError(w, err)
		return
	}
	response.OK(w, rpt)
}

func (h *DashboardHandler) DeleteReport(w http.ResponseWriter, r *http.Request) {
	tenantID := mustTenantID(r)
	id, ok := parseUUID(w, r, "reportID")
	if !ok {
		return
	}
	if err := h.svc.DeleteReport(r.Context(), tenantID, id); err != nil {
		mapError(w, err)
		return
	}
	response.NoContent(w)
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
		response.NotFound(w, "resource not found")
	case apierrors.IsKind(err, apierrors.KindForbidden):
		response.Forbidden(w, "access denied")
	case apierrors.IsKind(err, apierrors.KindBadInput):
		response.BadRequest(w, "BAD_INPUT", err.Error())
	default:
		response.InternalError(w)
	}
}
