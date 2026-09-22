package model

import (
	"time"

	"github.com/google/uuid"
)

// ─── Vendors ──────────────────────────────────────────────────────────────────

type SCSVendor struct {
	ID               uuid.UUID  `json:"id"`
	TenantID         uuid.UUID  `json:"tenant_id"`
	Name             string     `json:"name"`
	Website          string     `json:"website,omitempty"`
	VendorType       string     `json:"vendor_type"`
	RiskTier         int        `json:"risk_tier"`
	RiskScore        int        `json:"risk_score"`
	RiskLevel        string     `json:"risk_level"`
	ContactName      string     `json:"contact_name,omitempty"`
	ContactEmail     string     `json:"contact_email,omitempty"`
	ContactPhone     string     `json:"contact_phone,omitempty"`
	HasSOC2          bool       `json:"has_soc2"`
	HasISO27001      bool       `json:"has_iso27001"`
	HasPCIDSS        bool       `json:"has_pci_dss"`
	LastAssessmentAt *time.Time `json:"last_assessment_at,omitempty"`
	NextAssessmentAt *time.Time `json:"next_assessment_at,omitempty"`
	Status           string     `json:"status"`
	Tags             []string   `json:"tags"`
	Notes            string     `json:"notes,omitempty"`
	CreatedBy        *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	// Computed
	ComponentCount  int `json:"component_count,omitempty"`
	AssessmentCount int `json:"assessment_count,omitempty"`
	OpenAlertCount  int `json:"open_alert_count,omitempty"`
}

type CreateVendorRequest struct {
	Name             string     `json:"name"`
	Website          string     `json:"website"`
	VendorType       string     `json:"vendor_type"`
	RiskTier         int        `json:"risk_tier"`
	ContactName      string     `json:"contact_name"`
	ContactEmail     string     `json:"contact_email"`
	ContactPhone     string     `json:"contact_phone"`
	HasSOC2          bool       `json:"has_soc2"`
	HasISO27001      bool       `json:"has_iso27001"`
	HasPCIDSS        bool       `json:"has_pci_dss"`
	NextAssessmentAt *time.Time `json:"next_assessment_at"`
	Tags             []string   `json:"tags"`
	Notes            string     `json:"notes"`
}

type UpdateVendorRequest struct {
	Name             *string    `json:"name"`
	Website          *string    `json:"website"`
	RiskTier         *int       `json:"risk_tier"`
	Status           *string    `json:"status"`
	ContactName      *string    `json:"contact_name"`
	ContactEmail     *string    `json:"contact_email"`
	HasSOC2          *bool      `json:"has_soc2"`
	HasISO27001      *bool      `json:"has_iso27001"`
	HasPCIDSS        *bool      `json:"has_pci_dss"`
	NextAssessmentAt *time.Time `json:"next_assessment_at"`
	Notes            *string    `json:"notes"`
	Tags             []string   `json:"tags"`
}

type ListVendorsFilter struct {
	Status    string
	RiskTier  int
	RiskLevel string
	Limit     int
	Offset    int
}

// ─── Components ───────────────────────────────────────────────────────────────

type SCSComponent struct {
	ID                uuid.UUID  `json:"id"`
	TenantID          uuid.UUID  `json:"tenant_id"`
	VendorID          *uuid.UUID `json:"vendor_id,omitempty"`
	Name              string     `json:"name"`
	Version           string     `json:"version"`
	ComponentType     string     `json:"component_type"`
	Ecosystem         string     `json:"ecosystem,omitempty"`
	PURL              string     `json:"purl,omitempty"`
	License           string     `json:"license,omitempty"`
	IsDeprecated      bool       `json:"is_deprecated"`
	IsEndOfLife       bool       `json:"is_end_of_life"`
	HasKnownVulns     bool       `json:"has_known_vulns"`
	VulnCount         int        `json:"vuln_count"`
	CriticalVulnCount int        `json:"critical_vuln_count"`
	RiskScore         int        `json:"risk_score"`
	SourceRepo        string     `json:"source_repo,omitempty"`
	SourceHash        string     `json:"source_hash,omitempty"`
	UsedIn            []string   `json:"used_in"`
	IsDirect          bool       `json:"is_direct"`
	Tags              []string   `json:"tags"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type CreateComponentRequest struct {
	VendorID      *uuid.UUID `json:"vendor_id"`
	Name          string     `json:"name"`
	Version       string     `json:"version"`
	ComponentType string     `json:"component_type"`
	Ecosystem     string     `json:"ecosystem"`
	PURL          string     `json:"purl"`
	License       string     `json:"license"`
	SourceRepo    string     `json:"source_repo"`
	SourceHash    string     `json:"source_hash"`
	UsedIn        []string   `json:"used_in"`
	IsDirect      bool       `json:"is_direct"`
	Tags          []string   `json:"tags"`
}

type UpdateComponentRequest struct {
	IsDeprecated      *bool    `json:"is_deprecated"`
	IsEndOfLife       *bool    `json:"is_end_of_life"`
	HasKnownVulns     *bool    `json:"has_known_vulns"`
	VulnCount         *int     `json:"vuln_count"`
	CriticalVulnCount *int     `json:"critical_vuln_count"`
	License           *string  `json:"license"`
	UsedIn            []string `json:"used_in"`
	Tags              []string `json:"tags"`
}

type ListComponentsFilter struct {
	Ecosystem    string
	HasVulns     *bool
	IsEOL        *bool
	IsDeprecated *bool
	Limit        int
	Offset       int
}

// ─── SBOMs ────────────────────────────────────────────────────────────────────

type SCSSBOM struct {
	ID                   uuid.UUID      `json:"id"`
	TenantID             uuid.UUID      `json:"tenant_id"`
	Name                 string         `json:"name"`
	Version              string         `json:"version,omitempty"`
	SBOMFormat           string         `json:"sbom_format"`
	TotalComponents      int            `json:"total_components"`
	DirectComponents     int            `json:"direct_components"`
	TransitiveComponents int            `json:"transitive_components"`
	CriticalVulns        int            `json:"critical_vulns"`
	HighVulns            int            `json:"high_vulns"`
	MediumVulns          int            `json:"medium_vulns"`
	LowVulns             int            `json:"low_vulns"`
	DeprecatedCount      int            `json:"deprecated_count"`
	EOLCount             int            `json:"eol_count"`
	RiskScore            int            `json:"risk_score"`
	RawData              map[string]any `json:"raw_data,omitempty"`
	Source               string         `json:"source,omitempty"`
	SourceRef            string         `json:"source_ref,omitempty"`
	GeneratedAt          time.Time      `json:"generated_at"`
	CreatedBy            *uuid.UUID     `json:"created_by,omitempty"`
	CreatedAt            time.Time      `json:"created_at"`
}

type CreateSBOMRequest struct {
	Name       string                   `json:"name"`
	Version    string                   `json:"version"`
	SBOMFormat string                   `json:"sbom_format"`
	Source     string                   `json:"source"`
	SourceRef  string                   `json:"source_ref"`
	RawData    map[string]any           `json:"raw_data"`
	Components []CreateComponentRequest `json:"components"`
}

// ─── Assessments ──────────────────────────────────────────────────────────────

type SCSAssessment struct {
	ID               uuid.UUID      `json:"id"`
	TenantID         uuid.UUID      `json:"tenant_id"`
	VendorID         uuid.UUID      `json:"vendor_id"`
	AssessmentType   string         `json:"assessment_type"`
	Status           string         `json:"status"`
	Score            *int           `json:"score,omitempty"`
	MaxScore         int            `json:"max_score"`
	RiskRating       string         `json:"risk_rating,omitempty"`
	FindingsCount    int            `json:"findings_count"`
	CriticalFindings int            `json:"critical_findings"`
	PlannedAt        *time.Time     `json:"planned_at,omitempty"`
	StartedAt        *time.Time     `json:"started_at,omitempty"`
	CompletedAt      *time.Time     `json:"completed_at,omitempty"`
	DueAt            *time.Time     `json:"due_at,omitempty"`
	NextDueAt        *time.Time     `json:"next_due_at,omitempty"`
	Assessor         string         `json:"assessor,omitempty"`
	AssessorID       *uuid.UUID     `json:"assessor_id,omitempty"`
	Questionnaire    map[string]any `json:"questionnaire,omitempty"`
	Findings         []any          `json:"findings"`
	Recommendations  string         `json:"recommendations,omitempty"`
	Notes            string         `json:"notes,omitempty"`
	CreatedBy        *uuid.UUID     `json:"created_by,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

type CreateAssessmentRequest struct {
	VendorID       uuid.UUID  `json:"vendor_id"`
	AssessmentType string     `json:"assessment_type"`
	Assessor       string     `json:"assessor"`
	AssessorID     *uuid.UUID `json:"assessor_id"`
	DueAt          *time.Time `json:"due_at"`
	PlannedAt      *time.Time `json:"planned_at"`
	Notes          string     `json:"notes"`
}

type UpdateAssessmentRequest struct {
	Status          *string        `json:"status"`
	Score           *int           `json:"score"`
	RiskRating      *string        `json:"risk_rating"`
	Questionnaire   map[string]any `json:"questionnaire"`
	Findings        []any          `json:"findings"`
	Recommendations *string        `json:"recommendations"`
	Notes           *string        `json:"notes"`
	NextDueAt       *time.Time     `json:"next_due_at"`
}

// ─── Alerts ───────────────────────────────────────────────────────────────────

type SCSAlert struct {
	ID                 uuid.UUID  `json:"id"`
	TenantID           uuid.UUID  `json:"tenant_id"`
	VendorID           *uuid.UUID `json:"vendor_id,omitempty"`
	ComponentID        *uuid.UUID `json:"component_id,omitempty"`
	AlertType          string     `json:"alert_type"`
	Severity           string     `json:"severity"`
	Status             string     `json:"status"`
	Title              string     `json:"title"`
	Description        string     `json:"description,omitempty"`
	AffectedComponents []string   `json:"affected_components"`
	AffectedSystems    []string   `json:"affected_systems"`
	CVEIDs             []string   `json:"cve_ids"`
	AdvisoryURL        string     `json:"advisory_url,omitempty"`
	Remediation        string     `json:"remediation,omitempty"`
	ResolvedBy         string     `json:"resolved_by,omitempty"`
	ResolvedAt         *time.Time `json:"resolved_at,omitempty"`
	Source             string     `json:"source,omitempty"`
	SourceRef          string     `json:"source_ref,omitempty"`
	DetectedAt         time.Time  `json:"detected_at"`
	Tags               []string   `json:"tags"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

type CreateAlertRequest struct {
	VendorID           *uuid.UUID `json:"vendor_id"`
	ComponentID        *uuid.UUID `json:"component_id"`
	AlertType          string     `json:"alert_type"`
	Severity           string     `json:"severity"`
	Title              string     `json:"title"`
	Description        string     `json:"description"`
	AffectedComponents []string   `json:"affected_components"`
	AffectedSystems    []string   `json:"affected_systems"`
	CVEIDs             []string   `json:"cve_ids"`
	AdvisoryURL        string     `json:"advisory_url"`
	Remediation        string     `json:"remediation"`
	Source             string     `json:"source"`
	SourceRef          string     `json:"source_ref"`
	Tags               []string   `json:"tags"`
}

type UpdateAlertRequest struct {
	Status      *string `json:"status"`
	Remediation *string `json:"remediation"`
	ResolvedBy  *string `json:"resolved_by"`
}

type ListAlertsFilter struct {
	Status    string
	Severity  string
	AlertType string
	Limit     int
	Offset    int
}

// ─── Policies ─────────────────────────────────────────────────────────────────

type SCSPolicy struct {
	ID          uuid.UUID      `json:"id"`
	TenantID    uuid.UUID      `json:"tenant_id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	PolicyType  string         `json:"policy_type"`
	Rule        map[string]any `json:"rule"`
	Action      string         `json:"action"`
	IsActive    bool           `json:"is_active"`
	CreatedBy   *uuid.UUID     `json:"created_by,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

type CreatePolicyRequest struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	PolicyType  string         `json:"policy_type"`
	Rule        map[string]any `json:"rule"`
	Action      string         `json:"action"`
}

type UpdatePolicyRequest struct {
	Name        *string        `json:"name"`
	Description *string        `json:"description"`
	Rule        map[string]any `json:"rule"`
	Action      *string        `json:"action"`
	IsActive    *bool          `json:"is_active"`
}

// ─── Stats ────────────────────────────────────────────────────────────────────

type SCSStats struct {
	TotalVendors         int            `json:"total_vendors"`
	HighRiskVendors      int            `json:"high_risk_vendors"`
	TotalComponents      int            `json:"total_components"`
	VulnerableComponents int            `json:"vulnerable_components"`
	EOLComponents        int            `json:"eol_components"`
	TotalSBOMs           int            `json:"total_sboms"`
	OpenAlerts           int            `json:"open_alerts"`
	CriticalAlerts       int            `json:"critical_alerts"`
	PendingAssessments   int            `json:"pending_assessments"`
	OverdueAssessments   int            `json:"overdue_assessments"`
	AlertsBySeverity     map[string]int `json:"alerts_by_severity"`
	AlertsByType         map[string]int `json:"alerts_by_type"`
	VendorsByTier        map[string]int `json:"vendors_by_tier"`
	TopRiskyVendors      []SCSVendor    `json:"top_risky_vendors"`
	RecentAlerts         []SCSAlert     `json:"recent_alerts"`
}
