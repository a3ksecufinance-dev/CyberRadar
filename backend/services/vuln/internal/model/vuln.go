package model

import (
	"time"

	"github.com/google/uuid"
)

// CVSS severity levels
const (
	SeverityCritical = "CRITICAL" // CVSS 9.0-10.0
	SeverityHigh     = "HIGH"     // CVSS 7.0-8.9
	SeverityMedium   = "MEDIUM"   // CVSS 4.0-6.9
	SeverityLow      = "LOW"      // CVSS 0.1-3.9
	SeverityInfo     = "INFO"     // CVSS 0.0
)

// Finding / ticket statuses
const (
	StatusOpen          = "open"
	StatusInRemediation = "in_remediation"
	StatusResolved      = "resolved"
	StatusAcceptedRisk  = "accepted_risk"
	StatusFalsePositive = "false_positive"
	StatusWontFix       = "wont_fix"
)

// Scan types
const (
	ScanTypeNetwork   = "network"
	ScanTypeWeb       = "web"
	ScanTypeContainer = "container"
	ScanTypeConfig    = "config"
	ScanTypeCloud     = "cloud"
)

// SLA days by severity (banking-grade: tighter than industry defaults)
var SLADays = map[string]int{
	SeverityCritical: 3,
	SeverityHigh:     7,
	SeverityMedium:   30,
	SeverityLow:      90,
}

// Vulnerability is a CVE or internal finding definition.
type Vulnerability struct {
	ID               uuid.UUID  `json:"id"`
	TenantID         uuid.UUID  `json:"tenant_id"`
	CVEID            string     `json:"cve_id,omitempty"`
	Title            string     `json:"title"`
	Description      string     `json:"description,omitempty"`
	CVSSScore        float64    `json:"cvss_score"`
	CVSSVector       string     `json:"cvss_vector,omitempty"`
	CVSSSeverity     string     `json:"cvss_severity"`
	IsExploited      bool       `json:"is_exploited"`
	ExploitAvailable bool       `json:"exploit_available"`
	EPSSScore        float64    `json:"epss_score"`
	CWEID            string     `json:"cwe_id,omitempty"`
	CWEName          string     `json:"cwe_name,omitempty"`
	MitreTechnique   string     `json:"mitre_technique,omitempty"`
	AffectedProducts []string   `json:"affected_products"`
	PatchAvailable   bool       `json:"patch_available"`
	PatchURL         string     `json:"patch_url,omitempty"`
	PublishedAt      *time.Time `json:"published_at,omitempty"`
	ModifiedAt       *time.Time `json:"modified_at,omitempty"`
	NVDURL           string     `json:"nvd_url,omitempty"`
	References       []string   `json:"references"`
	Tags             []string   `json:"tags"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// AssetVulnerability links a vulnerability finding to an asset.
type AssetVulnerability struct {
	ID                  uuid.UUID      `json:"id"`
	TenantID            uuid.UUID      `json:"tenant_id"`
	AssetID             uuid.UUID      `json:"asset_id"`
	VulnID              uuid.UUID      `json:"vuln_id"`
	ScanJobID           *uuid.UUID     `json:"scan_job_id,omitempty"`
	Status              string         `json:"status"`
	ExposureScore       float64        `json:"exposure_score"`
	Port                *int           `json:"port,omitempty"`
	Protocol            string         `json:"protocol,omitempty"`
	ServiceName         string         `json:"service_name,omitempty"`
	FirstSeenAt         time.Time      `json:"first_seen_at"`
	LastSeenAt          time.Time      `json:"last_seen_at"`
	ResolvedAt          *time.Time     `json:"resolved_at,omitempty"`
	SLADueAt            *time.Time     `json:"sla_due_at,omitempty"`
	RemediationTicketID *uuid.UUID     `json:"remediation_ticket_id,omitempty"`
	AssigneeID          *uuid.UUID     `json:"assignee_id,omitempty"`
	Notes               string         `json:"notes,omitempty"`
	Evidence            map[string]any `json:"evidence,omitempty"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           time.Time      `json:"updated_at"`
	// Joined fields (populated in list views)
	Vulnerability *Vulnerability `json:"vulnerability,omitempty"`
}

// ScanJob represents a vulnerability scan execution.
type ScanJob struct {
	ID               uuid.UUID      `json:"id"`
	TenantID         uuid.UUID      `json:"tenant_id"`
	Name             string         `json:"name"`
	ScanType         string         `json:"scan_type"`
	Targets          map[string]any `json:"targets"`
	Status           string         `json:"status"`
	TriggeredBy      *uuid.UUID     `json:"triggered_by,omitempty"`
	ScheduledAt      *time.Time     `json:"scheduled_at,omitempty"`
	StartedAt        *time.Time     `json:"started_at,omitempty"`
	CompletedAt      *time.Time     `json:"completed_at,omitempty"`
	TotalAssets      int            `json:"total_assets"`
	ScannedAssets    int            `json:"scanned_assets"`
	TotalFindings    int            `json:"total_findings"`
	NewFindings      int            `json:"new_findings"`
	ResolvedFindings int            `json:"resolved_findings"`
	CriticalCount    int            `json:"critical_count"`
	HighCount        int            `json:"high_count"`
	MediumCount      int            `json:"medium_count"`
	LowCount         int            `json:"low_count"`
	ErrorMessage     string         `json:"error_message,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

// RemediationTicket groups related findings for tracking.
type RemediationTicket struct {
	ID             uuid.UUID  `json:"id"`
	TenantID       uuid.UUID  `json:"tenant_id"`
	Title          string     `json:"title"`
	Description    string     `json:"description,omitempty"`
	Status         string     `json:"status"`
	Priority       int        `json:"priority"`
	AssigneeID     *uuid.UUID `json:"assignee_id,omitempty"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	FindingCount   int        `json:"finding_count"`
	AffectedAssets int        `json:"affected_asset_count"`
	SLADueAt       *time.Time `json:"sla_due_at,omitempty"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	ExternalID     string     `json:"external_id,omitempty"`
	ExternalURL    string     `json:"external_url,omitempty"`
	Tags           []string   `json:"tags"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// ExposureScore is a per-asset aggregated vulnerability posture.
type ExposureScore struct {
	AssetID       uuid.UUID `json:"asset_id"`
	TotalFindings int       `json:"total_findings"`
	OpenFindings  int       `json:"open_findings"`
	CriticalCount int       `json:"critical_count"`
	HighCount     int       `json:"high_count"`
	MediumCount   int       `json:"medium_count"`
	LowCount      int       `json:"low_count"`
	AvgCVSS       float64   `json:"avg_cvss"`
	MaxCVSS       float64   `json:"max_cvss"`
	ExposureScore float64   `json:"exposure_score"` // 0-10
	SLABreached   int       `json:"sla_breached"`
	HasKEV        bool      `json:"has_kev"` // Known Exploited Vulnerability
}

// VulnStats is the dashboard summary.
type VulnStats struct {
	TotalVulns          int              `json:"total_vulns"`
	TotalFindings       int              `json:"total_findings"`
	OpenFindings        int              `json:"open_findings"`
	SLABreached         int              `json:"sla_breached"`
	KEVFindings         int              `json:"kev_findings"` // known exploited in wild
	AvgCVSS             float64          `json:"avg_cvss"`
	BySeverity          map[string]int   `json:"by_severity"`
	ByStatus            map[string]int   `json:"by_status"`
	TopVulnerableAssets []*ExposureScore `json:"top_vulnerable_assets"`
	RecentScans         []*ScanJob       `json:"recent_scans"`
}

// ─── Request / filter models ──────────────────────────────────────────────────

type VulnFilter struct {
	TenantID    uuid.UUID
	Severity    string
	IsExploited *bool
	Search      string
	Limit       int
	Offset      int
}

type FindingFilter struct {
	TenantID uuid.UUID
	AssetID  *uuid.UUID
	VulnID   *uuid.UUID
	Status   string
	Severity string
	ScanID   *uuid.UUID
	Limit    int
	Offset   int
}

type CreateVulnRequest struct {
	CVEID            string     `json:"cve_id"`
	Title            string     `json:"title"           validate:"required,min=3"`
	Description      string     `json:"description"`
	CVSSScore        float64    `json:"cvss_score"      validate:"min=0,max=10"`
	CVSSVector       string     `json:"cvss_vector"`
	IsExploited      bool       `json:"is_exploited"`
	ExploitAvailable bool       `json:"exploit_available"`
	EPSSScore        float64    `json:"epss_score"      validate:"min=0,max=1"`
	CWEID            string     `json:"cwe_id"`
	CWEName          string     `json:"cwe_name"`
	MitreTechnique   string     `json:"mitre_technique"`
	AffectedProducts []string   `json:"affected_products"`
	PatchAvailable   bool       `json:"patch_available"`
	PatchURL         string     `json:"patch_url"`
	PublishedAt      *time.Time `json:"published_at"`
	Tags             []string   `json:"tags"`
}

type CreateFindingRequest struct {
	AssetID     uuid.UUID      `json:"asset_id"  validate:"required"`
	VulnID      uuid.UUID      `json:"vuln_id"   validate:"required"`
	ScanJobID   *uuid.UUID     `json:"scan_job_id"`
	Port        *int           `json:"port"`
	Protocol    string         `json:"protocol"`
	ServiceName string         `json:"service_name"`
	Evidence    map[string]any `json:"evidence"`
}

type UpdateFindingRequest struct {
	Status              *string    `json:"status"    validate:"omitempty,oneof=open in_remediation resolved accepted_risk false_positive"`
	AssigneeID          *uuid.UUID `json:"assignee_id"`
	RemediationTicketID *uuid.UUID `json:"remediation_ticket_id"`
	Notes               *string    `json:"notes"`
}

type CreateScanJobRequest struct {
	Name        string         `json:"name"       validate:"required,min=2"`
	ScanType    string         `json:"scan_type"  validate:"required,oneof=network web container config cloud"`
	Targets     map[string]any `json:"targets"`
	ScheduledAt *time.Time     `json:"scheduled_at"`
}

type CreateTicketRequest struct {
	Title       string     `json:"title"    validate:"required,min=3"`
	Description string     `json:"description"`
	Priority    int        `json:"priority" validate:"min=1,max=4"`
	AssigneeID  *uuid.UUID `json:"assignee_id"`
	SLADueAt    *time.Time `json:"sla_due_at"`
	ExternalID  string     `json:"external_id"`
	ExternalURL string     `json:"external_url"`
	Tags        []string   `json:"tags"`
}

type UpdateTicketRequest struct {
	Status      *string    `json:"status"   validate:"omitempty,oneof=open in_progress resolved wont_fix accepted_risk"`
	AssigneeID  *uuid.UUID `json:"assignee_id"`
	Priority    *int       `json:"priority" validate:"omitempty,min=1,max=4"`
	SLADueAt    *time.Time `json:"sla_due_at"`
	ExternalID  *string    `json:"external_id"`
	ExternalURL *string    `json:"external_url"`
}

type BulkCreateFindingsRequest struct {
	ScanJobID *uuid.UUID             `json:"scan_job_id"`
	Findings  []CreateFindingRequest `json:"findings" validate:"required,min=1,max=5000"`
}
