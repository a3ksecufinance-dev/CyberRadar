package model

import (
	"time"

	"github.com/google/uuid"
)

// ─── Data Stores ──────────────────────────────────────────────────────────────

type DSPMDataStore struct {
	ID                 uuid.UUID  `json:"id"`
	TenantID           uuid.UUID  `json:"tenant_id"`
	Name               string     `json:"name"`
	StoreType          string     `json:"store_type"`
	CloudProvider      string     `json:"cloud_provider,omitempty"`
	Region             string     `json:"region,omitempty"`
	Endpoint           string     `json:"endpoint,omitempty"`
	SensitivityLevel   string     `json:"sensitivity_level"`
	DataCategories     []string   `json:"data_categories"`
	IsEncrypted        bool       `json:"is_encrypted"`
	IsAccessControlled bool       `json:"is_access_controlled"`
	IsMonitored        bool       `json:"is_monitored"`
	IsBackupEnabled    bool       `json:"is_backup_enabled"`
	Owner              string     `json:"owner,omitempty"`
	OwnerID            *uuid.UUID `json:"owner_id,omitempty"`
	Department         string     `json:"department,omitempty"`
	RiskScore          int        `json:"risk_score"`
	RiskLevel          string     `json:"risk_level"`
	LastScannedAt      *time.Time `json:"last_scanned_at,omitempty"`
	ScanStatus         string     `json:"scan_status"`
	Tags               []string   `json:"tags"`
	Notes              string     `json:"notes,omitempty"`
	CreatedBy          *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	// Computed
	FindingCount     int `json:"finding_count,omitempty"`
	OpenFindingCount int `json:"open_finding_count,omitempty"`
}

type CreateDataStoreRequest struct {
	Name               string     `json:"name"`
	StoreType          string     `json:"store_type"`
	CloudProvider      string     `json:"cloud_provider"`
	Region             string     `json:"region"`
	Endpoint           string     `json:"endpoint"`
	SensitivityLevel   string     `json:"sensitivity_level"`
	DataCategories     []string   `json:"data_categories"`
	IsEncrypted        bool       `json:"is_encrypted"`
	IsAccessControlled bool       `json:"is_access_controlled"`
	IsMonitored        bool       `json:"is_monitored"`
	IsBackupEnabled    bool       `json:"is_backup_enabled"`
	Owner              string     `json:"owner"`
	OwnerID            *uuid.UUID `json:"owner_id"`
	Department         string     `json:"department"`
	Tags               []string   `json:"tags"`
}

type UpdateDataStoreRequest struct {
	Name               *string    `json:"name"`
	StoreType          *string    `json:"store_type"`
	CloudProvider      *string    `json:"cloud_provider"`
	Region             *string    `json:"region"`
	Endpoint           *string    `json:"endpoint"`
	SensitivityLevel   *string    `json:"sensitivity_level"`
	DataCategories     []string   `json:"data_categories"`
	IsEncrypted        *bool      `json:"is_encrypted"`
	IsAccessControlled *bool      `json:"is_access_controlled"`
	IsMonitored        *bool      `json:"is_monitored"`
	IsBackupEnabled    *bool      `json:"is_backup_enabled"`
	Owner              *string    `json:"owner"`
	OwnerID            *uuid.UUID `json:"owner_id"`
	Department         *string    `json:"department"`
	ScanStatus         *string    `json:"scan_status"`
	Tags               []string   `json:"tags"`
	Notes              *string    `json:"notes"`
}

type ListDataStoresFilter struct {
	StoreType        string
	SensitivityLevel string
	RiskLevel        string
	IsEncrypted      *bool
	Department       string
	Limit            int
	Offset           int
}

// ─── Scan Jobs ────────────────────────────────────────────────────────────────

type DSPMScanJob struct {
	ID                     uuid.UUID  `json:"id"`
	TenantID               uuid.UUID  `json:"tenant_id"`
	DataStoreID            uuid.UUID  `json:"data_store_id"`
	ScanType               string     `json:"scan_type"`
	Status                 string     `json:"status"`
	FindingsCount          int        `json:"findings_count"`
	SensitiveFindingsCount int        `json:"sensitive_findings_count"`
	ScannedObjects         int        `json:"scanned_objects"`
	ErrorMessage           string     `json:"error_message,omitempty"`
	TriggeredBy            string     `json:"triggered_by,omitempty"`
	StartedAt              *time.Time `json:"started_at,omitempty"`
	CompletedAt            *time.Time `json:"completed_at,omitempty"`
	DurationSeconds        int        `json:"duration_seconds,omitempty"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

type CreateScanJobRequest struct {
	DataStoreID uuid.UUID `json:"data_store_id"`
	ScanType    string    `json:"scan_type"`
	TriggeredBy string    `json:"triggered_by"`
}

type UpdateScanJobRequest struct {
	Status                 *string `json:"status"`
	FindingsCount          *int    `json:"findings_count"`
	SensitiveFindingsCount *int    `json:"sensitive_findings_count"`
	ScannedObjects         *int    `json:"scanned_objects"`
	ErrorMessage           *string `json:"error_message"`
}

// ─── Findings ─────────────────────────────────────────────────────────────────

type DSPMFinding struct {
	ID                   uuid.UUID  `json:"id"`
	TenantID             uuid.UUID  `json:"tenant_id"`
	DataStoreID          uuid.UUID  `json:"data_store_id"`
	ScanJobID            *uuid.UUID `json:"scan_job_id,omitempty"`
	FindingType          string     `json:"finding_type"`
	Severity             string     `json:"severity"`
	Status               string     `json:"status"`
	LocationPath         string     `json:"location_path,omitempty"`
	LocationField        string     `json:"location_field,omitempty"`
	RecordCount          int64      `json:"record_count"`
	IsPublicAccessible   bool       `json:"is_public_accessible"`
	IsEncrypted          bool       `json:"is_encrypted"`
	Title                string     `json:"title"`
	Description          string     `json:"description,omitempty"`
	Evidence             string     `json:"evidence,omitempty"`
	Remediation          string     `json:"remediation,omitempty"`
	ComplianceViolations []string   `json:"compliance_violations"`
	ResolvedBy           string     `json:"resolved_by,omitempty"`
	ResolvedAt           *time.Time `json:"resolved_at,omitempty"`
	Tags                 []string   `json:"tags"`
	DetectedAt           time.Time  `json:"detected_at"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
	// Computed
	RemediationCount int `json:"remediation_count,omitempty"`
}

type CreateFindingRequest struct {
	DataStoreID          uuid.UUID  `json:"data_store_id"`
	ScanJobID            *uuid.UUID `json:"scan_job_id"`
	FindingType          string     `json:"finding_type"`
	Severity             string     `json:"severity"`
	LocationPath         string     `json:"location_path"`
	LocationField        string     `json:"location_field"`
	RecordCount          int64      `json:"record_count"`
	IsPublicAccessible   bool       `json:"is_public_accessible"`
	IsEncrypted          bool       `json:"is_encrypted"`
	Title                string     `json:"title"`
	Description          string     `json:"description"`
	Evidence             string     `json:"evidence"`
	Remediation          string     `json:"remediation"`
	ComplianceViolations []string   `json:"compliance_violations"`
	Tags                 []string   `json:"tags"`
}

type UpdateFindingRequest struct {
	Status      *string `json:"status"`
	Remediation *string `json:"remediation"`
	ResolvedBy  *string `json:"resolved_by"`
}

type ListFindingsFilter struct {
	DataStoreID *uuid.UUID
	FindingType string
	Severity    string
	Status      string
	Limit       int
	Offset      int
}

// ─── Policies ─────────────────────────────────────────────────────────────────

type DSPMPolicy struct {
	ID                   uuid.UUID      `json:"id"`
	TenantID             uuid.UUID      `json:"tenant_id"`
	Name                 string         `json:"name"`
	Description          string         `json:"description,omitempty"`
	PolicyType           string         `json:"policy_type"`
	Rules                map[string]any `json:"rules"`
	Action               string         `json:"action"`
	IsActive             bool           `json:"is_active"`
	AppliesToCategories  []string       `json:"applies_to_categories"`
	AppliesToTypes       []string       `json:"applies_to_types"`
	ComplianceFrameworks []string       `json:"compliance_frameworks"`
	ViolationCount       int            `json:"violation_count"`
	CreatedBy            *uuid.UUID     `json:"created_by,omitempty"`
	CreatedAt            time.Time      `json:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at"`
}

type CreatePolicyRequest struct {
	Name                 string         `json:"name"`
	Description          string         `json:"description"`
	PolicyType           string         `json:"policy_type"`
	Rules                map[string]any `json:"rules"`
	Action               string         `json:"action"`
	AppliesToCategories  []string       `json:"applies_to_categories"`
	AppliesToTypes       []string       `json:"applies_to_types"`
	ComplianceFrameworks []string       `json:"compliance_frameworks"`
}

type UpdatePolicyRequest struct {
	Name        *string        `json:"name"`
	Description *string        `json:"description"`
	Rules       map[string]any `json:"rules"`
	Action      *string        `json:"action"`
	IsActive    *bool          `json:"is_active"`
}

// ─── Remediation Items ────────────────────────────────────────────────────────

type DSPMRemediationItem struct {
	ID           uuid.UUID  `json:"id"`
	TenantID     uuid.UUID  `json:"tenant_id"`
	FindingID    uuid.UUID  `json:"finding_id"`
	Status       string     `json:"status"`
	Priority     string     `json:"priority"`
	AssigneeID   *uuid.UUID `json:"assignee_id,omitempty"`
	AssigneeName string     `json:"assignee_name,omitempty"`
	DueDate      *time.Time `json:"due_date,omitempty"`
	Notes        string     `json:"notes,omitempty"`
	Resolution   string     `json:"resolution,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type CreateRemediationRequest struct {
	FindingID    uuid.UUID  `json:"finding_id"`
	Priority     string     `json:"priority"`
	AssigneeID   *uuid.UUID `json:"assignee_id"`
	AssigneeName string     `json:"assignee_name"`
	DueDate      *time.Time `json:"due_date"`
	Notes        string     `json:"notes"`
}

type UpdateRemediationRequest struct {
	Status       *string    `json:"status"`
	AssigneeID   *uuid.UUID `json:"assignee_id"`
	AssigneeName *string    `json:"assignee_name"`
	DueDate      *time.Time `json:"due_date"`
	Notes        *string    `json:"notes"`
	Resolution   *string    `json:"resolution"`
}

// ─── Stats ────────────────────────────────────────────────────────────────────

type DSPMStats struct {
	TotalDataStores     int             `json:"total_data_stores"`
	UnencryptedStores   int             `json:"unencrypted_stores"`
	PubliclyAccessible  int             `json:"publicly_accessible"`
	HighRiskStores      int             `json:"high_risk_stores"`
	TotalFindings       int             `json:"total_findings"`
	OpenFindings        int             `json:"open_findings"`
	CriticalFindings    int             `json:"critical_findings"`
	PIIExposures        int             `json:"pii_exposures"`
	PCIExposures        int             `json:"pci_exposures"`
	TotalScans          int             `json:"total_scans"`
	ActiveScans         int             `json:"active_scans"`
	OpenRemediations    int             `json:"open_remediations"`
	OverdueRemediations int             `json:"overdue_remediations"`
	StoresByType        map[string]int  `json:"stores_by_type"`
	StoresByRisk        map[string]int  `json:"stores_by_risk"`
	FindingsByType      map[string]int  `json:"findings_by_type"`
	FindingsBySeverity  map[string]int  `json:"findings_by_severity"`
	TopRiskyStores      []DSPMDataStore `json:"top_risky_stores"`
	RecentFindings      []DSPMFinding   `json:"recent_findings"`
}
