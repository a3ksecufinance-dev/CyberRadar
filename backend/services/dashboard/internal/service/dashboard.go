package service

import (
	"context"
	"math"
	"time"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
	"github.com/cyberradar/platform/services/dashboard/internal/model"
	"github.com/cyberradar/platform/services/dashboard/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// DashboardService orchestrates dashboard, widget, and report operations.
type DashboardService struct {
	repo   *repository.DashboardRepository
	kpi    *repository.KPIRepository
	logger zerolog.Logger
}

// NewDashboardService creates a DashboardService.
func NewDashboardService(repo *repository.DashboardRepository, kpi *repository.KPIRepository, logger zerolog.Logger) *DashboardService {
	return &DashboardService{repo: repo, kpi: kpi, logger: logger}
}

// ─── Dashboards ───────────────────────────────────────────────────────────────

func (s *DashboardService) CreateDashboard(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreateDashboardRequest) (*model.Dashboard, error) {
	d, err := s.repo.CreateDashboard(ctx, tenantID, callerID, req)
	if err != nil {
		return nil, apierrors.Internal("create dashboard", err)
	}
	return d, nil
}

func (s *DashboardService) GetDashboard(ctx context.Context, tenantID, dashID uuid.UUID) (*model.Dashboard, error) {
	d, err := s.repo.GetDashboard(ctx, tenantID, dashID)
	if err != nil {
		return nil, apierrors.Internal("get dashboard", err)
	}
	if d == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "dashboard not found")
	}
	return d, nil
}

func (s *DashboardService) UpdateDashboard(ctx context.Context, tenantID, dashID uuid.UUID, req *model.UpdateDashboardRequest) (*model.Dashboard, error) {
	d, err := s.repo.UpdateDashboard(ctx, tenantID, dashID, req)
	if err != nil {
		return nil, apierrors.Internal("update dashboard", err)
	}
	return d, nil
}

func (s *DashboardService) DeleteDashboard(ctx context.Context, tenantID, dashID uuid.UUID) error {
	if err := s.repo.DeleteDashboard(ctx, tenantID, dashID); err != nil {
		return apierrors.Internal("delete dashboard", err)
	}
	return nil
}

func (s *DashboardService) ListDashboards(ctx context.Context, tenantID uuid.UUID) ([]*model.Dashboard, error) {
	dashboards, err := s.repo.ListDashboards(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("list dashboards", err)
	}
	return dashboards, nil
}

// ─── Widgets ──────────────────────────────────────────────────────────────────

func (s *DashboardService) AddWidget(ctx context.Context, tenantID, dashID uuid.UUID, req *model.CreateWidgetRequest) (*model.Widget, error) {
	// Confirm dashboard exists and belongs to tenant
	if _, err := s.GetDashboard(ctx, tenantID, dashID); err != nil {
		return nil, err
	}
	w, err := s.repo.AddWidget(ctx, tenantID, dashID, req)
	if err != nil {
		return nil, apierrors.Internal("add widget", err)
	}
	return w, nil
}

func (s *DashboardService) UpdateWidget(ctx context.Context, tenantID, widgetID uuid.UUID, req *model.UpdateWidgetRequest) (*model.Widget, error) {
	w, err := s.repo.UpdateWidget(ctx, tenantID, widgetID, req)
	if err != nil {
		return nil, apierrors.Internal("update widget", err)
	}
	return w, nil
}

func (s *DashboardService) DeleteWidget(ctx context.Context, tenantID, widgetID uuid.UUID) error {
	if err := s.repo.DeleteWidget(ctx, tenantID, widgetID); err != nil {
		return apierrors.Internal("delete widget", err)
	}
	return nil
}

// ─── KPI & time series ────────────────────────────────────────────────────────

func (s *DashboardService) QueryTimeSeries(ctx context.Context, req model.KPIQueryRequest) ([]model.KPIPoint, error) {
	if req.Since.IsZero() {
		req.Since = time.Now().UTC().Add(-24 * time.Hour)
	}
	if req.Until.IsZero() {
		req.Until = time.Now().UTC()
	}
	if req.Interval == "" {
		req.Interval = "1h"
	}
	points, err := s.kpi.QueryTimeSeries(ctx, req)
	if err != nil {
		return nil, apierrors.Internal("query time series", err)
	}
	return points, nil
}

func (s *DashboardService) DomainSnapshot(ctx context.Context, tenantID uuid.UUID, domain string) (map[string]float64, error) {
	snap, err := s.kpi.LatestSnapshots(ctx, tenantID, domain)
	if err != nil {
		return nil, apierrors.Internal("domain snapshot", err)
	}
	return snap, nil
}

func (s *DashboardService) RiskTimeline(ctx context.Context, tenantID uuid.UUID, entityType, entityID string, since time.Time) ([]model.KPIPoint, error) {
	points, err := s.kpi.RiskTimeline(ctx, tenantID, entityType, entityID, since)
	if err != nil {
		return nil, apierrors.Internal("risk timeline", err)
	}
	return points, nil
}

// PlatformOverview aggregates KPIs across all domains into a single executive view.
// It reads from ClickHouse snapshots for the latest metric values.
func (s *DashboardService) PlatformOverview(ctx context.Context, tenantID uuid.UUID) (*model.PlatformOverview, error) {
	domains := []string{
		model.SourceSIEM, model.SourceUEBA, model.SourceTI,
		model.SourceVuln, model.SourceAttackPath, model.SourceSOAR, model.SourceKG,
	}

	// Fetch all domain snapshots concurrently (serial for simplicity; add goroutines if needed)
	allMetrics := make(map[string]map[string]float64)
	for _, d := range domains {
		snap, err := s.kpi.LatestSnapshots(ctx, tenantID, d)
		if err != nil {
			s.logger.Warn().Err(err).Str("domain", d).Msg("overview_snapshot_error")
			snap = map[string]float64{}
		}
		allMetrics[d] = snap
	}

	siem := allMetrics[model.SourceSIEM]
	ueba := allMetrics[model.SourceUEBA]
	ti := allMetrics[model.SourceTI]
	vuln := allMetrics[model.SourceVuln]
	ap := allMetrics[model.SourceAttackPath]
	soar := allMetrics[model.SourceSOAR]
	kg := allMetrics[model.SourceKG]

	// Compute composite risk score: weighted average across domains
	scores := []float64{
		metricOrDefault(siem, "risk_score", 0),
		metricOrDefault(ueba, "risk_score", 0),
		metricOrDefault(ti, "risk_score", 0),
		metricOrDefault(vuln, "risk_score", 0),
		metricOrDefault(ap, "risk_score", 0),
	}
	overallRisk := weightedRisk(scores)

	return &model.PlatformOverview{
		OpenAlerts:       int(metricOrDefault(siem, "open_alerts", 0)),
		CriticalAlerts:   int(metricOrDefault(siem, "critical_alerts", 0)),
		ActiveAnomalies:  int(metricOrDefault(ueba, "active_anomalies", 0)),
		HighRiskEntities: int(metricOrDefault(ueba, "high_risk_entities", 0)),
		ActiveIOCs:       int(metricOrDefault(ti, "active_iocs", 0)),
		IOCHitsToday:     int(metricOrDefault(ti, "ioc_hits_today", 0)),
		CriticalVulns:    int(metricOrDefault(vuln, "critical_vulns", 0)),
		SLABreachedVulns: int(metricOrDefault(vuln, "sla_breached", 0)),
		AttackPaths:      int(metricOrDefault(ap, "total_paths", 0)),
		ChokePoints:      int(metricOrDefault(ap, "choke_points", 0)),
		OpenIncidents:    int(metricOrDefault(soar, "open_incidents", 0)),
		SLABreachedInc:   int(metricOrDefault(soar, "sla_breached", 0)),
		TotalEntities:    int(metricOrDefault(kg, "total_entities", 0)),
		OverallRiskScore: overallRisk,
		GeneratedAt:      time.Now().UTC(),
	}, nil
}

// ─── Reports ──────────────────────────────────────────────────────────────────

func (s *DashboardService) CreateReport(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreateReportRequest) (*model.Report, error) {
	rpt, err := s.repo.CreateReport(ctx, tenantID, callerID, req)
	if err != nil {
		return nil, apierrors.Internal("create report", err)
	}
	return rpt, nil
}

func (s *DashboardService) GetReport(ctx context.Context, tenantID, reportID uuid.UUID) (*model.Report, error) {
	rpt, err := s.repo.GetReport(ctx, tenantID, reportID)
	if err != nil {
		return nil, apierrors.Internal("get report", err)
	}
	if rpt == nil {
		return nil, apierrors.New(apierrors.KindNotFound, "report not found")
	}
	return rpt, nil
}

func (s *DashboardService) ListReports(ctx context.Context, tenantID uuid.UUID) ([]*model.Report, error) {
	reports, err := s.repo.ListReports(ctx, tenantID)
	if err != nil {
		return nil, apierrors.Internal("list reports", err)
	}
	return reports, nil
}

func (s *DashboardService) DeleteReport(ctx context.Context, tenantID, reportID uuid.UUID) error {
	if err := s.repo.DeleteReport(ctx, tenantID, reportID); err != nil {
		return apierrors.Internal("delete report", err)
	}
	return nil
}

// RunReport generates a report snapshot synchronously and persists it.
func (s *DashboardService) RunReport(ctx context.Context, tenantID, reportID uuid.UUID) (*model.Report, error) {
	rpt, err := s.GetReport(ctx, tenantID, reportID)
	if err != nil {
		return nil, err
	}

	// Mark running
	_ = s.repo.SaveReportPayload(ctx, tenantID, reportID, nil, "running")

	// Build payload based on type
	payload, err := s.buildReportPayload(ctx, tenantID, rpt.ReportType)
	if err != nil {
		_ = s.repo.SaveReportPayload(ctx, tenantID, reportID, map[string]any{"error": err.Error()}, "failed")
		return nil, apierrors.Internal("build report", err)
	}

	if err := s.repo.SaveReportPayload(ctx, tenantID, reportID, payload, "completed"); err != nil {
		return nil, apierrors.Internal("save report payload", err)
	}

	rpt.LastPayload = payload
	rpt.Status = "completed"
	now := time.Now().UTC()
	rpt.LastRunAt = &now
	return rpt, nil
}

func (s *DashboardService) buildReportPayload(ctx context.Context, tenantID uuid.UUID, reportType string) (map[string]any, error) {
	overview, err := s.PlatformOverview(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	payload := map[string]any{
		"report_type":  reportType,
		"generated_at": time.Now().UTC(),
		"overview":     overview,
	}

	switch reportType {
	case model.ReportExecutiveSummary:
		payload["summary"] = map[string]any{
			"open_incidents":   overview.OpenIncidents,
			"critical_alerts":  overview.CriticalAlerts,
			"critical_vulns":   overview.CriticalVulns,
			"overall_risk":     overview.OverallRiskScore,
			"active_anomalies": overview.ActiveAnomalies,
		}
	case model.ReportVulnPosture:
		payload["vuln"] = map[string]any{
			"critical":     overview.CriticalVulns,
			"sla_breached": overview.SLABreachedVulns,
		}
	case model.ReportIncidentSummary:
		payload["incidents"] = map[string]any{
			"open":         overview.OpenIncidents,
			"sla_breached": overview.SLABreachedInc,
		}
	case model.ReportThreatIntelligence:
		payload["ti"] = map[string]any{
			"active_iocs":  overview.ActiveIOCs,
			"hits_today":   overview.IOCHitsToday,
			"attack_paths": overview.AttackPaths,
		}
	}
	return payload, nil
}

// IngestKPISnapshot is called by the Kafka consumer to store domain KPI events.
func (s *DashboardService) IngestKPISnapshot(ctx context.Context, snap model.KPISnapshot) {
	if err := s.kpi.InsertSnapshot(ctx, snap); err != nil {
		s.logger.Warn().Err(err).Str("domain", snap.Domain).Str("metric", snap.MetricKey).Msg("kpi_insert_error")
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func metricOrDefault(m map[string]float64, key string, def float64) float64 {
	if v, ok := m[key]; ok {
		return v
	}
	return def
}

// weightedRisk computes the composite risk as the max score
// boosted logarithmically by the number of elevated domains.
func weightedRisk(scores []float64) float64 {
	if len(scores) == 0 {
		return 0
	}
	maxScore := 0.0
	elevated := 0
	for _, s := range scores {
		if s > maxScore {
			maxScore = s
		}
		if s >= 5.0 {
			elevated++
		}
	}
	boost := math.Log1p(float64(elevated)) * 0.5
	return math.Min(10.0, maxScore+boost)
}
