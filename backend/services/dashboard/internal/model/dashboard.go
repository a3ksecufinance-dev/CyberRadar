package model

import (
	"time"

	"github.com/google/uuid"
)

// ── Widget types ──────────────────────────────────────────────────────────────
const (
	WidgetMetricCard  = "metric_card"
	WidgetTimeSeries  = "time_series"
	WidgetBarChart    = "bar_chart"
	WidgetPieChart    = "pie_chart"
	WidgetHeatmap     = "heatmap"
	WidgetTable       = "table"
	WidgetAlertFeed   = "alert_feed"
	WidgetRiskGauge   = "risk_gauge"
	WidgetTopologyMap = "topology_map"
	WidgetText        = "text"
)

// ── Data sources ──────────────────────────────────────────────────────────────
const (
	SourceSIEM       = "siem"
	SourceUEBA       = "ueba"
	SourceTI         = "ti"
	SourceVuln       = "vuln"
	SourceAttackPath = "attackpath"
	SourceSOAR       = "soar"
	SourceAsset      = "asset"
	SourceKG         = "kg"
	SourcePlatform   = "platform"
)

// ── Report types ──────────────────────────────────────────────────────────────
const (
	ReportExecutiveSummary   = "executive_summary"
	ReportIncidentSummary    = "incident_summary"
	ReportVulnPosture        = "vulnerability_posture"
	ReportThreatIntelligence = "threat_intelligence"
	ReportCompliance         = "compliance"
	ReportCustom             = "custom"
)

// ─── Core models ──────────────────────────────────────────────────────────────

// Dashboard is a collection of widgets arranged on a grid.
type Dashboard struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Layout      string     `json:"layout"`
	Columns     int        `json:"columns"`
	IsDefault   bool       `json:"is_default"`
	IsPublic    bool       `json:"is_public"`
	Tags        []string   `json:"tags"`
	Widgets     []Widget   `json:"widgets,omitempty"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Widget is a single visualization unit on a dashboard.
type Widget struct {
	ID          uuid.UUID      `json:"id"`
	DashboardID uuid.UUID      `json:"dashboard_id"`
	TenantID    uuid.UUID      `json:"tenant_id"`
	WidgetType  string         `json:"widget_type"`
	Title       string         `json:"title"`
	PosX        int            `json:"pos_x"`
	PosY        int            `json:"pos_y"`
	Width       int            `json:"width"`
	Height      int            `json:"height"`
	DataSource  string         `json:"data_source"`
	MetricKey   string         `json:"metric_key"`
	Config      map[string]any `json:"config,omitempty"`
	RefreshSec  int            `json:"refresh_sec"`
	// Populated at query time
	Data      any       `json:"data,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Report is a scheduled or on-demand report definition.
type Report struct {
	ID          uuid.UUID      `json:"id"`
	TenantID    uuid.UUID      `json:"tenant_id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	ReportType  string         `json:"report_type"`
	Schedule    string         `json:"schedule,omitempty"`
	LastPayload map[string]any `json:"last_payload,omitempty"`
	LastRunAt   *time.Time     `json:"last_run_at,omitempty"`
	NextRunAt   *time.Time     `json:"next_run_at,omitempty"`
	Status      string         `json:"status"`
	Format      string         `json:"format"`
	Recipients  []string       `json:"recipients"`
	CreatedBy   *uuid.UUID     `json:"created_by,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// KPISnapshot is a single domain metric reading stored in ClickHouse.
type KPISnapshot struct {
	TenantID    uuid.UUID         `json:"tenant_id"`
	Domain      string            `json:"domain"`
	MetricKey   string            `json:"metric_key"`
	MetricValue float64           `json:"metric_value"`
	Labels      map[string]string `json:"labels,omitempty"`
	SnappedAt   time.Time         `json:"snapped_at"`
}

// KPIPoint is one data point in a time series response.
type KPIPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// PlatformOverview is the cross-domain executive summary returned by /dashboard/overview.
type PlatformOverview struct {
	// SIEM
	OpenAlerts     int `json:"open_alerts"`
	CriticalAlerts int `json:"critical_alerts"`
	// UEBA
	ActiveAnomalies  int `json:"active_anomalies"`
	HighRiskEntities int `json:"high_risk_entities"`
	// TI
	ActiveIOCs   int `json:"active_iocs"`
	IOCHitsToday int `json:"ioc_hits_today"`
	// Vuln
	CriticalVulns    int `json:"critical_vulns"`
	SLABreachedVulns int `json:"sla_breached_vulns"`
	// Attack Path
	AttackPaths int `json:"attack_paths"`
	ChokePoints int `json:"choke_points"`
	// SOAR
	OpenIncidents  int `json:"open_incidents"`
	SLABreachedInc int `json:"sla_breached_incidents"`
	// KG
	TotalEntities int `json:"total_entities"`
	// Platform risk
	OverallRiskScore float64   `json:"overall_risk_score"`
	GeneratedAt      time.Time `json:"generated_at"`
}

// ── Request / filter models ───────────────────────────────────────────────────

type CreateDashboardRequest struct {
	Name        string   `json:"name"    validate:"required,min=2,max=200"`
	Description string   `json:"description"`
	Layout      string   `json:"layout"  validate:"omitempty,oneof=grid freeform"`
	Columns     int      `json:"columns" validate:"omitempty,min=1,max=24"`
	IsDefault   bool     `json:"is_default"`
	IsPublic    bool     `json:"is_public"`
	Tags        []string `json:"tags"`
}

type UpdateDashboardRequest struct {
	Name        *string  `json:"name"`
	Description *string  `json:"description"`
	IsDefault   *bool    `json:"is_default"`
	IsPublic    *bool    `json:"is_public"`
	Tags        []string `json:"tags"`
}

type CreateWidgetRequest struct {
	WidgetType string         `json:"widget_type" validate:"required,oneof=metric_card time_series bar_chart pie_chart heatmap table alert_feed risk_gauge topology_map text"`
	Title      string         `json:"title"       validate:"required,min=1,max=200"`
	PosX       int            `json:"pos_x"       validate:"min=0"`
	PosY       int            `json:"pos_y"       validate:"min=0"`
	Width      int            `json:"width"       validate:"min=1,max=24"`
	Height     int            `json:"height"      validate:"min=1,max=20"`
	DataSource string         `json:"data_source" validate:"required,oneof=siem ueba ti vuln attackpath soar asset kg platform"`
	MetricKey  string         `json:"metric_key"  validate:"required,min=1"`
	Config     map[string]any `json:"config"`
	RefreshSec int            `json:"refresh_sec" validate:"omitempty,min=0"`
}

type UpdateWidgetRequest struct {
	Title      *string        `json:"title"`
	PosX       *int           `json:"pos_x"`
	PosY       *int           `json:"pos_y"`
	Width      *int           `json:"width"  validate:"omitempty,min=1,max=24"`
	Height     *int           `json:"height" validate:"omitempty,min=1,max=20"`
	Config     map[string]any `json:"config"`
	RefreshSec *int           `json:"refresh_sec"`
}

type CreateReportRequest struct {
	Name        string   `json:"name"        validate:"required,min=2,max=200"`
	Description string   `json:"description"`
	ReportType  string   `json:"report_type" validate:"required,oneof=executive_summary incident_summary vulnerability_posture threat_intelligence compliance custom"`
	Schedule    string   `json:"schedule"` // cron expression, empty = on-demand
	Format      string   `json:"format"      validate:"omitempty,oneof=json pdf"`
	Recipients  []string `json:"recipients"`
}

type KPIQueryRequest struct {
	TenantID  uuid.UUID
	Domain    string
	MetricKey string
	Since     time.Time
	Until     time.Time
	Interval  string // 1m, 5m, 1h, 1d
}
