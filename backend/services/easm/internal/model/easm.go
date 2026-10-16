package model

import (
	"time"

	"github.com/google/uuid"
)

// ─── Asset types ──────────────────────────────────────────────────────────────

const (
	AssetTypeDomain      = "domain"
	AssetTypeSubdomain   = "subdomain"
	AssetTypeIP          = "ip"
	AssetTypeCIDR        = "cidr"
	AssetTypeASN         = "asn"
	AssetTypeCertificate = "certificate"
	AssetTypeURL         = "url"
)

// ─── Exposure types ───────────────────────────────────────────────────────────

const (
	ExposureTypeOpenPort       = "open_port"
	ExposureTypeExpiredTLS     = "expired_tls"
	ExposureTypeWeakCipher     = "weak_cipher"
	ExposureTypeHTTPRedirect   = "http_redirect"
	ExposureTypeDanglingDNS    = "dangling_dns"
	ExposureTypeAdminInterface = "admin_interface"
	ExposureTypeAPIEndpoint    = "api_endpoint"
	ExposureTypeSensitivePath  = "sensitive_path"
)

// ─── Severities ───────────────────────────────────────────────────────────────

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// ─── Scan types ───────────────────────────────────────────────────────────────

const (
	ScanTypeSubdomainEnum = "subdomain_enum"
	ScanTypePortScan      = "port_scan"
	ScanTypeTLSAudit      = "tls_audit"
	ScanTypeLeakSearch    = "leak_search"
	ScanTypeBrandMonitor  = "brand_monitor"
)

// ─── Brand alert types ────────────────────────────────────────────────────────

const (
	AlertTypePhishingDomain = "phishing_domain"
	AlertTypeTyposquatting  = "typosquatting"
	AlertTypeImpersonation  = "impersonation"
	AlertTypeFakeApp        = "fake_app"
	AlertTypeSocialMedia    = "social_media"
	AlertTypeDarkWebMention = "dark_web_mention"
	AlertTypePasteMention   = "paste_mention"
)

// ─── Brand alert statuses ─────────────────────────────────────────────────────

const (
	AlertStatusNew               = "new"
	AlertStatusInvestigating     = "investigating"
	AlertStatusConfirmed         = "confirmed"
	AlertStatusFalsePositive     = "false_positive"
	AlertStatusTakedownRequested = "takedown_requested"
	AlertStatusResolved          = "resolved"
)

// ─── Core structs ─────────────────────────────────────────────────────────────

type EASMAsset struct {
	ID            uuid.UUID      `json:"id"`
	TenantID      uuid.UUID      `json:"tenant_id"`
	AssetType     string         `json:"asset_type"`
	Value         string         `json:"value"`
	Source        string         `json:"source"`
	Status        string         `json:"status"`
	RiskScore     int            `json:"risk_score"`
	Tags          []string       `json:"tags"`
	FirstSeenAt   time.Time      `json:"first_seen_at"`
	LastSeenAt    time.Time      `json:"last_seen_at"`
	Metadata      map[string]any `json:"metadata"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	ExposureCount int            `json:"exposure_count,omitempty"`
}

type EASMExposure struct {
	ID              uuid.UUID  `json:"id"`
	TenantID        uuid.UUID  `json:"tenant_id"`
	AssetID         uuid.UUID  `json:"asset_id"`
	ExposureType    string     `json:"exposure_type"`
	Port            *int       `json:"port,omitempty"`
	Protocol        string     `json:"protocol,omitempty"`
	Title           string     `json:"title"`
	Description     string     `json:"description,omitempty"`
	Severity        string     `json:"severity"`
	IsRemediated    bool       `json:"is_remediated"`
	FirstDetectedAt time.Time  `json:"first_detected_at"`
	LastSeenAt      time.Time  `json:"last_seen_at"`
	RemediatedAt    *time.Time `json:"remediated_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	AssetValue      string     `json:"asset_value,omitempty"`
}

type EASMLeak struct {
	ID             uuid.UUID  `json:"id"`
	TenantID       uuid.UUID  `json:"tenant_id"`
	Source         string     `json:"source"`
	BreachDate     *time.Time `json:"breach_date,omitempty"`
	DataTypes      []string   `json:"data_types"`
	AffectedCount  *int       `json:"affected_count,omitempty"`
	SampleData     string     `json:"sample_data,omitempty"`
	Severity       string     `json:"severity"`
	IsAcknowledged bool       `json:"is_acknowledged"`
	AcknowledgedBy *uuid.UUID `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

type EASMBrandAlert struct {
	ID              uuid.UUID  `json:"id"`
	TenantID        uuid.UUID  `json:"tenant_id"`
	AlertType       string     `json:"alert_type"`
	Value           string     `json:"value"`
	SimilarityScore *float64   `json:"similarity_score,omitempty"`
	Status          string     `json:"status"`
	DetectedAt      time.Time  `json:"detected_at"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

type EASMScan struct {
	ID             uuid.UUID  `json:"id"`
	TenantID       uuid.UUID  `json:"tenant_id"`
	ScanType       string     `json:"scan_type"`
	Status         string     `json:"status"`
	Targets        []string   `json:"targets"`
	AssetsFound    int        `json:"assets_found"`
	ExposuresFound int        `json:"exposures_found"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
	ErrorText      string     `json:"error_text,omitempty"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

type ExternalRiskScore struct {
	TenantID          uuid.UUID `json:"tenant_id"`
	OverallScore      int       `json:"overall_score"`
	AssetScore        int       `json:"asset_score"`
	ExposureScore     int       `json:"exposure_score"`
	LeakScore         int       `json:"leak_score"`
	BrandScore        int       `json:"brand_score"`
	CriticalExposures int       `json:"critical_exposures"`
	HighExposures     int       `json:"high_exposures"`
	ActiveLeaks       int       `json:"active_leaks"`
	ActiveAlerts      int       `json:"active_alerts"`
	ComputedAt        time.Time `json:"computed_at"`
}

type EASMStats struct {
	TotalAssets         int               `json:"total_assets"`
	ActiveAssets        int               `json:"active_assets"`
	TotalExposures      int               `json:"total_exposures"`
	RemediatedExposures int               `json:"remediated_exposures"`
	OpenLeaks           int               `json:"open_leaks"`
	OpenAlerts          int               `json:"open_alerts"`
	RiskScore           ExternalRiskScore `json:"risk_score"`
	ScansByStatus       map[string]int    `json:"scans_by_status"`
	ExposuresBySeverity map[string]int    `json:"exposures_by_severity"`
}

// ─── Request / filter models ──────────────────────────────────────────────────

type CreateAssetRequest struct {
	AssetType string         `json:"asset_type" validate:"required"`
	Value     string         `json:"value"      validate:"required"`
	Source    string         `json:"source"`
	Tags      []string       `json:"tags"`
	Metadata  map[string]any `json:"metadata"`
}

type UpdateAssetRequest struct {
	Status    string         `json:"status"`
	RiskScore *int           `json:"risk_score"`
	Tags      []string       `json:"tags"`
	Metadata  map[string]any `json:"metadata"`
}

type ListAssetsFilter struct {
	AssetType    string
	Status       string
	MinRiskScore *int
	Page         int
	PageSize     int
}

type CreateExposureRequest struct {
	AssetID      uuid.UUID `json:"asset_id"      validate:"required"`
	ExposureType string    `json:"exposure_type" validate:"required"`
	Port         *int      `json:"port"`
	Protocol     string    `json:"protocol"`
	Title        string    `json:"title"         validate:"required"`
	Description  string    `json:"description"`
	Severity     string    `json:"severity"      validate:"required"`
}

type CreateLeakRequest struct {
	Source        string     `json:"source"    validate:"required"`
	BreachDate    *time.Time `json:"breach_date"`
	DataTypes     []string   `json:"data_types"`
	AffectedCount *int       `json:"affected_count"`
	SampleData    string     `json:"sample_data"`
	Severity      string     `json:"severity"  validate:"required"`
}

type CreateBrandAlertRequest struct {
	AlertType       string   `json:"alert_type" validate:"required"`
	Value           string   `json:"value"      validate:"required"`
	SimilarityScore *float64 `json:"similarity_score"`
}

type CreateScanRequest struct {
	ScanType string   `json:"scan_type" validate:"required"`
	Targets  []string `json:"targets"   validate:"required,min=1"`
}
