package model

import (
	"time"

	"github.com/google/uuid"
)

// ─── Providers ────────────────────────────────────────────────────────────────

const (
	ProviderAWS     = "aws"
	ProviderAzure   = "azure"
	ProviderGCP     = "gcp"
	ProviderOCI     = "oci"
	ProviderAlibaba = "alibaba"
	ProviderMulti   = "multi"
)

// ─── Frameworks ───────────────────────────────────────────────────────────────

const (
	FrameworkCIS      = "cis"
	FrameworkNIST     = "nist"
	FrameworkPCIDSS   = "pci_dss"
	FrameworkHIPAA    = "hipaa"
	FrameworkSOX      = "sox"
	FrameworkISO27001 = "iso27001"
	FrameworkGDPR     = "gdpr"
	FrameworkDORA     = "dora"
	FrameworkCustom   = "custom"
)

// ─── Severities ───────────────────────────────────────────────────────────────

const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// ─── Core structs ─────────────────────────────────────────────────────────────

type CSPMAccount struct {
	ID            uuid.UUID      `json:"id"`
	TenantID      uuid.UUID      `json:"tenant_id"`
	Name          string         `json:"name"`
	Description   string         `json:"description,omitempty"`
	Provider      string         `json:"provider"`
	AccountID     string         `json:"account_id"`
	Region        string         `json:"region,omitempty"`
	Environment   string         `json:"environment"`
	Status        string         `json:"status"`
	PostureScore  int            `json:"posture_score"`
	CriticalCount int            `json:"critical_count"`
	HighCount     int            `json:"high_count"`
	MediumCount   int            `json:"medium_count"`
	LowCount      int            `json:"low_count"`
	ResourceCount int            `json:"resource_count"`
	LastScannedAt *time.Time     `json:"last_scanned_at,omitempty"`
	Metadata      map[string]any `json:"metadata"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

type CSPMRule struct {
	ID               uuid.UUID `json:"id"`
	TenantID         uuid.UUID `json:"tenant_id"`
	RuleID           string    `json:"rule_id"`
	Title            string    `json:"title"`
	Description      string    `json:"description,omitempty"`
	Rationale        string    `json:"rationale,omitempty"`
	Remediation      string    `json:"remediation,omitempty"`
	Provider         string    `json:"provider"`
	ResourceType     string    `json:"resource_type"`
	Framework        string    `json:"framework"`
	FrameworkSection string    `json:"framework_section,omitempty"`
	Severity         string    `json:"severity"`
	IsActive         bool      `json:"is_active"`
	CreatedAt        time.Time `json:"created_at"`
}

type CSPMResource struct {
	ID            uuid.UUID      `json:"id"`
	TenantID      uuid.UUID      `json:"tenant_id"`
	AccountID     uuid.UUID      `json:"account_id"`
	ResourceUID   string         `json:"resource_uid"`
	Name          string         `json:"name,omitempty"`
	ResourceType  string         `json:"resource_type"`
	Service       string         `json:"service"`
	Region        string         `json:"region,omitempty"`
	Tags          map[string]any `json:"tags"`
	Configuration map[string]any `json:"configuration,omitempty"`
	RiskScore     int            `json:"risk_score"`
	FindingCount  int            `json:"finding_count"`
	IsPublic      bool           `json:"is_public"`
	LastSeenAt    time.Time      `json:"last_seen_at"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

type CSPMFinding struct {
	ID                uuid.UUID      `json:"id"`
	TenantID          uuid.UUID      `json:"tenant_id"`
	AccountID         uuid.UUID      `json:"account_id"`
	ResourceID        *uuid.UUID     `json:"resource_id,omitempty"`
	RuleID            uuid.UUID      `json:"rule_id"`
	RuleRef           string         `json:"rule_ref"`
	Title             string         `json:"title"`
	Severity          string         `json:"severity"`
	Status            string         `json:"status"`
	ResourceUID       string         `json:"resource_uid,omitempty"`
	ResourceType      string         `json:"resource_type,omitempty"`
	Region            string         `json:"region,omitempty"`
	Evidence          map[string]any `json:"evidence"`
	Remediation       string         `json:"remediation,omitempty"`
	FirstSeenAt       time.Time      `json:"first_seen_at"`
	LastSeenAt        time.Time      `json:"last_seen_at"`
	ResolvedAt        *time.Time     `json:"resolved_at,omitempty"`
	SuppressedBy      *uuid.UUID     `json:"suppressed_by,omitempty"`
	SuppressionReason string         `json:"suppression_reason,omitempty"`
	ScanID            *uuid.UUID     `json:"scan_id,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
}

type CSPMScan struct {
	ID               uuid.UUID  `json:"id"`
	TenantID         uuid.UUID  `json:"tenant_id"`
	AccountID        uuid.UUID  `json:"account_id"`
	Status           string     `json:"status"`
	ScanType         string     `json:"scan_type"`
	ResourcesScanned int        `json:"resources_scanned"`
	RulesEvaluated   int        `json:"rules_evaluated"`
	FindingsNew      int        `json:"findings_new"`
	FindingsResolved int        `json:"findings_resolved"`
	PostureScore     *int       `json:"posture_score,omitempty"`
	ErrorMessage     string     `json:"error_message,omitempty"`
	StartedAt        *time.Time `json:"started_at,omitempty"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
	TriggeredBy      *uuid.UUID `json:"triggered_by,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

// ─── Stats ────────────────────────────────────────────────────────────────────

type CSPMStats struct {
	TotalAccounts       int                   `json:"total_accounts"`
	TotalResources      int                   `json:"total_resources"`
	PublicResources     int                   `json:"public_resources"`
	OpenFindings        int                   `json:"open_findings"`
	AvgPostureScore     float64               `json:"avg_posture_score"`
	FindingsBySeverity  map[string]int        `json:"findings_by_severity"`
	FindingsByProvider  map[string]int        `json:"findings_by_provider"`
	FindingsByFramework map[string]int        `json:"findings_by_framework"`
	AccountPostures     []*AccountPosture     `json:"account_postures"`
	TopViolatedRules    []*RuleViolationStats `json:"top_violated_rules"`
}

type AccountPosture struct {
	AccountID    uuid.UUID `json:"account_id"`
	AccountName  string    `json:"account_name"`
	Provider     string    `json:"provider"`
	PostureScore int       `json:"posture_score"`
	OpenFindings int       `json:"open_findings"`
}

type RuleViolationStats struct {
	RuleID         uuid.UUID `json:"rule_id"`
	RuleRef        string    `json:"rule_ref"`
	Title          string    `json:"title"`
	Severity       string    `json:"severity"`
	ViolationCount int       `json:"violation_count"`
}

// ─── Request models ───────────────────────────────────────────────────────────

type RegisterAccountRequest struct {
	Name        string         `json:"name"       validate:"required"`
	Description string         `json:"description"`
	Provider    string         `json:"provider"   validate:"required"`
	AccountID   string         `json:"account_id" validate:"required"`
	Region      string         `json:"region"`
	Environment string         `json:"environment"`
	Metadata    map[string]any `json:"metadata"`
}

type UpdateAccountRequest struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Region      string         `json:"region"`
	Environment string         `json:"environment"`
	Status      string         `json:"status"`
	Metadata    map[string]any `json:"metadata"`
}

type CreateRuleRequest struct {
	RuleID           string `json:"rule_id"       validate:"required"`
	Title            string `json:"title"         validate:"required"`
	Description      string `json:"description"`
	Rationale        string `json:"rationale"`
	Remediation      string `json:"remediation"`
	Provider         string `json:"provider"      validate:"required"`
	ResourceType     string `json:"resource_type" validate:"required"`
	Framework        string `json:"framework"     validate:"required"`
	FrameworkSection string `json:"framework_section"`
	Severity         string `json:"severity"      validate:"required"`
}

type UpsertResourceRequest struct {
	AccountID     uuid.UUID      `json:"account_id"    validate:"required"`
	ResourceUID   string         `json:"resource_uid"  validate:"required"`
	Name          string         `json:"name"`
	ResourceType  string         `json:"resource_type" validate:"required"`
	Service       string         `json:"service"       validate:"required"`
	Region        string         `json:"region"`
	Tags          map[string]any `json:"tags"`
	Configuration map[string]any `json:"configuration"`
	IsPublic      bool           `json:"is_public"`
}

type ReportFindingRequest struct {
	AccountID    uuid.UUID      `json:"account_id"    validate:"required"`
	ResourceUID  string         `json:"resource_uid"`
	ResourceType string         `json:"resource_type"`
	RuleID       uuid.UUID      `json:"rule_id"       validate:"required"`
	Region       string         `json:"region"`
	Evidence     map[string]any `json:"evidence"`
	ScanID       *uuid.UUID     `json:"scan_id"`
}

type UpdateFindingRequest struct {
	Status            string `json:"status"             validate:"required"`
	SuppressionReason string `json:"suppression_reason"`
}

type TriggerScanRequest struct {
	AccountID uuid.UUID `json:"account_id" validate:"required"`
	ScanType  string    `json:"scan_type"`
}

type ListFindingsFilter struct {
	AccountID  *uuid.UUID
	ResourceID *uuid.UUID
	Severity   string
	Status     string
	Framework  string
	Provider   string
	Page       int
	PageSize   int
}

type ListResourcesFilter struct {
	AccountID    *uuid.UUID
	ResourceType string
	Service      string
	IsPublic     *bool
	MinRiskScore *int
	Page         int
	PageSize     int
}
