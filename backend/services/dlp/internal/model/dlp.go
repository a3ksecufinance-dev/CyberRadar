package model

import (
	"time"

	"github.com/google/uuid"
)

// ─── Sensitivity levels ───────────────────────────────────────────────────────

const (
	SensitivityPublic       = "PUBLIC"
	SensitivityInternal     = "INTERNAL"
	SensitivityConfidential = "CONFIDENTIAL"
	SensitivityRestricted   = "RESTRICTED"
	SensitivityTopSecret    = "TOP_SECRET"
)

// ─── Asset types ──────────────────────────────────────────────────────────────

const (
	AssetTypeDatabase      = "database"
	AssetTypeFileShare     = "file_share"
	AssetTypeObjectStorage = "object_storage"
	AssetTypeAPIEndpoint   = "api_endpoint"
	AssetTypeEmail         = "email"
	AssetTypeMessaging     = "messaging"
	AssetTypeEndpoint      = "endpoint"
	AssetTypeCloudStorage  = "cloud_storage"
)

// ─── Policy types ─────────────────────────────────────────────────────────────

const (
	PolicyTypeExfiltration   = "exfiltration"
	PolicyTypeSharing        = "sharing"
	PolicyTypeRetention      = "retention"
	PolicyTypeAccess         = "access"
	PolicyTypeEncryption     = "encryption"
	PolicyTypeClassification = "classification"
)

// ─── Policy actions ───────────────────────────────────────────────────────────

const (
	ActionBlock      = "block"
	ActionAlert      = "alert"
	ActionLog        = "log"
	ActionQuarantine = "quarantine"
	ActionEncrypt    = "encrypt"
	ActionRedact     = "redact"
)

// ─── Severities ───────────────────────────────────────────────────────────────

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// ─── Violation statuses ───────────────────────────────────────────────────────

const (
	ViolationStatusOpen          = "open"
	ViolationStatusInvestigating = "investigating"
	ViolationStatusFalsePositive = "false_positive"
	ViolationStatusResolved      = "resolved"
)

// ─── Data categories ──────────────────────────────────────────────────────────

const (
	DataCategoryPII         = "pii"
	DataCategoryPCI         = "pci"
	DataCategoryPHI         = "phi"
	DataCategoryBanking     = "banking"
	DataCategorySWIFT       = "swift"
	DataCategoryCredentials = "credentials"
	DataCategoryIP          = "ip" // intellectual property
)

// ─── Core structs ─────────────────────────────────────────────────────────────

type DLPLabel struct {
	ID            uuid.UUID  `json:"id"`
	TenantID      uuid.UUID  `json:"tenant_id"`
	Name          string     `json:"name"`
	Description   string     `json:"description,omitempty"`
	Sensitivity   string     `json:"sensitivity"`
	Color         string     `json:"color"`
	RegexPatterns []string   `json:"regex_patterns"`
	Keywords      []string   `json:"keywords"`
	IsActive      bool       `json:"is_active"`
	CreatedBy     *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type DLPDataAsset struct {
	ID             uuid.UUID      `json:"id"`
	TenantID       uuid.UUID      `json:"tenant_id"`
	Name           string         `json:"name"`
	AssetType      string         `json:"asset_type"`
	Location       string         `json:"location"`
	LabelID        *uuid.UUID     `json:"label_id,omitempty"`
	LabelName      string         `json:"label_name,omitempty"`
	DataCategories []string       `json:"data_categories"`
	RecordCount    int64          `json:"record_count"`
	SizeBytes      int64          `json:"size_bytes"`
	LastScannedAt  *time.Time     `json:"last_scanned_at,omitempty"`
	ScanStatus     string         `json:"scan_status"`
	RiskScore      int            `json:"risk_score"`
	Owner          string         `json:"owner,omitempty"`
	Metadata       map[string]any `json:"metadata"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

type DLPPolicy struct {
	ID                uuid.UUID      `json:"id"`
	TenantID          uuid.UUID      `json:"tenant_id"`
	Name              string         `json:"name"`
	Description       string         `json:"description,omitempty"`
	PolicyType        string         `json:"policy_type"`
	SensitivityLevels []string       `json:"sensitivity_levels"`
	DataCategories    []string       `json:"data_categories"`
	Action            string         `json:"action"`
	Channels          []string       `json:"channels"`
	Conditions        map[string]any `json:"conditions"`
	IsActive          bool           `json:"is_active"`
	ViolationCount    int64          `json:"violation_count"`
	CreatedBy         *uuid.UUID     `json:"created_by,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}

type DLPViolation struct {
	ID             uuid.UUID  `json:"id"`
	TenantID       uuid.UUID  `json:"tenant_id"`
	PolicyID       *uuid.UUID `json:"policy_id,omitempty"`
	PolicyName     string     `json:"policy_name,omitempty"`
	AssetID        *uuid.UUID `json:"asset_id,omitempty"`
	LabelID        *uuid.UUID `json:"label_id,omitempty"`
	ViolationType  string     `json:"violation_type"`
	Channel        string     `json:"channel,omitempty"`
	Severity       string     `json:"severity"`
	UserIDSrc      string     `json:"user_id_src,omitempty"`
	Endpoint       string     `json:"endpoint,omitempty"`
	Destination    string     `json:"destination,omitempty"`
	DataSnippet    string     `json:"data_snippet,omitempty"`
	MatchCount     int        `json:"match_count"`
	ActionTaken    string     `json:"action_taken"`
	Status         string     `json:"status"`
	InvestigatedBy *uuid.UUID `json:"investigated_by,omitempty"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	DetectedAt     time.Time  `json:"detected_at"`
	CreatedAt      time.Time  `json:"created_at"`
}

type DLPScan struct {
	ID              uuid.UUID  `json:"id"`
	TenantID        uuid.UUID  `json:"tenant_id"`
	AssetID         *uuid.UUID `json:"asset_id,omitempty"`
	Status          string     `json:"status"`
	ItemsScanned    int64      `json:"items_scanned"`
	ViolationsFound int        `json:"violations_found"`
	LabelsDetected  []string   `json:"labels_detected"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	ErrorText       string     `json:"error_text,omitempty"`
	CreatedBy       *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

type DLPStats struct {
	TotalAssets          int                `json:"total_assets"`
	AssetsAtRisk         int                `json:"assets_at_risk"`
	TotalPolicies        int                `json:"total_policies"`
	ActivePolicies       int                `json:"active_policies"`
	OpenViolations       int                `json:"open_violations"`
	TotalViolations      int                `json:"total_violations"`
	ViolationsBySeverity map[string]int     `json:"violations_by_severity"`
	ViolationsByType     map[string]int     `json:"violations_by_type"`
	AssetsByCategory     map[string]int     `json:"assets_by_category"`
	TopPolicies          []*PolicyViolStats `json:"top_policies"`
}

type PolicyViolStats struct {
	PolicyID   uuid.UUID `json:"policy_id"`
	PolicyName string    `json:"policy_name"`
	Count      int64     `json:"violation_count"`
}

// ─── Request models ───────────────────────────────────────────────────────────

type CreateLabelRequest struct {
	Name          string   `json:"name"        validate:"required"`
	Description   string   `json:"description"`
	Sensitivity   string   `json:"sensitivity" validate:"required"`
	Color         string   `json:"color"`
	RegexPatterns []string `json:"regex_patterns"`
	Keywords      []string `json:"keywords"`
}

type UpdateLabelRequest struct {
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	Sensitivity   string   `json:"sensitivity"`
	Color         string   `json:"color"`
	RegexPatterns []string `json:"regex_patterns"`
	Keywords      []string `json:"keywords"`
	IsActive      *bool    `json:"is_active"`
}

type CreateAssetRequest struct {
	Name           string         `json:"name"       validate:"required"`
	AssetType      string         `json:"asset_type" validate:"required"`
	Location       string         `json:"location"   validate:"required"`
	LabelID        *uuid.UUID     `json:"label_id"`
	DataCategories []string       `json:"data_categories"`
	RecordCount    int64          `json:"record_count"`
	SizeBytes      int64          `json:"size_bytes"`
	Owner          string         `json:"owner"`
	Metadata       map[string]any `json:"metadata"`
}

type UpdateAssetRequest struct {
	LabelID        *uuid.UUID     `json:"label_id"`
	DataCategories []string       `json:"data_categories"`
	RecordCount    int64          `json:"record_count"`
	SizeBytes      int64          `json:"size_bytes"`
	Owner          string         `json:"owner"`
	RiskScore      *int           `json:"risk_score"`
	Metadata       map[string]any `json:"metadata"`
}

type CreatePolicyRequest struct {
	Name              string         `json:"name"        validate:"required"`
	Description       string         `json:"description"`
	PolicyType        string         `json:"policy_type" validate:"required"`
	SensitivityLevels []string       `json:"sensitivity_levels"`
	DataCategories    []string       `json:"data_categories"`
	Action            string         `json:"action"      validate:"required"`
	Channels          []string       `json:"channels"`
	Conditions        map[string]any `json:"conditions"`
}

type UpdatePolicyRequest struct {
	Name              string         `json:"name"`
	Description       string         `json:"description"`
	SensitivityLevels []string       `json:"sensitivity_levels"`
	DataCategories    []string       `json:"data_categories"`
	Action            string         `json:"action"`
	Channels          []string       `json:"channels"`
	Conditions        map[string]any `json:"conditions"`
	IsActive          *bool          `json:"is_active"`
}

type ReportViolationRequest struct {
	PolicyID      *uuid.UUID `json:"policy_id"`
	AssetID       *uuid.UUID `json:"asset_id"`
	LabelID       *uuid.UUID `json:"label_id"`
	ViolationType string     `json:"violation_type" validate:"required"`
	Channel       string     `json:"channel"`
	Severity      string     `json:"severity"       validate:"required"`
	UserIDSrc     string     `json:"user_id_src"`
	Endpoint      string     `json:"endpoint"`
	Destination   string     `json:"destination"`
	DataSnippet   string     `json:"data_snippet"`
	MatchCount    int        `json:"match_count"`
	ActionTaken   string     `json:"action_taken"   validate:"required"`
}

type UpdateViolationRequest struct {
	Status         string     `json:"status"`
	InvestigatedBy *uuid.UUID `json:"investigated_by"`
}

type TriggerScanRequest struct {
	AssetID *uuid.UUID `json:"asset_id"` // nil = scan all assets
}

type ListViolationsFilter struct {
	PolicyID *uuid.UUID
	AssetID  *uuid.UUID
	Severity string
	Status   string
	Channel  string
	Page     int
	PageSize int
}

type ListAssetsFilter struct {
	AssetType  string
	ScanStatus string
	MinRisk    *int
	Page       int
	PageSize   int
}
