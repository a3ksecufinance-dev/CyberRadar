package model

import (
	"time"

	"github.com/google/uuid"
)

// ─── Devices ──────────────────────────────────────────────────────────────────

type MobDevice struct {
	ID                  uuid.UUID  `json:"id"`
	TenantID            uuid.UUID  `json:"tenant_id"`
	DeviceName          string     `json:"device_name"`
	DeviceType          string     `json:"device_type"`
	Platform            string     `json:"platform"`
	OSVersion           string     `json:"os_version,omitempty"`
	Model               string     `json:"model,omitempty"`
	Manufacturer        string     `json:"manufacturer,omitempty"`
	SerialNumber        string     `json:"serial_number,omitempty"`
	IMEI                string     `json:"imei,omitempty"`
	UDID                string     `json:"udid,omitempty"`
	EnrollmentStatus    string     `json:"enrollment_status"`
	EnrollmentDate      time.Time  `json:"enrollment_date"`
	MDMProfileInstalled bool       `json:"mdm_profile_installed"`
	Ownership           string     `json:"ownership"`
	OwnerName           string     `json:"owner_name,omitempty"`
	OwnerID             *uuid.UUID `json:"owner_id,omitempty"`
	OwnerEmail          string     `json:"owner_email,omitempty"`
	Department          string     `json:"department,omitempty"`
	IsJailbroken        bool       `json:"is_jailbroken"`
	IsRooted            bool       `json:"is_rooted"`
	IsEncrypted         bool       `json:"is_encrypted"`
	IsScreenLock        bool       `json:"is_screen_lock"`
	IsCompliant         bool       `json:"is_compliant"`
	ComplianceIssues    []string   `json:"compliance_issues"`
	RiskScore           int        `json:"risk_score"`
	RiskLevel           string     `json:"risk_level"`
	LastLocation        string     `json:"last_location,omitempty"`
	LastSeenAt          time.Time  `json:"last_seen_at"`
	LastCheckinAt       time.Time  `json:"last_checkin_at"`
	LastIP              string     `json:"last_ip,omitempty"`
	Carrier             string     `json:"carrier,omitempty"`
	Tags                []string   `json:"tags"`
	Notes               string     `json:"notes,omitempty"`
	CreatedBy           *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	// Computed
	AppCount    int `json:"app_count,omitempty"`
	ThreatCount int `json:"threat_count,omitempty"`
}

type CreateDeviceRequest struct {
	DeviceName   string     `json:"device_name"`
	DeviceType   string     `json:"device_type"`
	Platform     string     `json:"platform"`
	OSVersion    string     `json:"os_version"`
	Model        string     `json:"model"`
	Manufacturer string     `json:"manufacturer"`
	SerialNumber string     `json:"serial_number"`
	IMEI         string     `json:"imei"`
	UDID         string     `json:"udid"`
	Ownership    string     `json:"ownership"`
	OwnerName    string     `json:"owner_name"`
	OwnerID      *uuid.UUID `json:"owner_id"`
	OwnerEmail   string     `json:"owner_email"`
	Department   string     `json:"department"`
	IsEncrypted  bool       `json:"is_encrypted"`
	IsScreenLock bool       `json:"is_screen_lock"`
	Carrier      string     `json:"carrier"`
	Tags         []string   `json:"tags"`
}

type UpdateDeviceRequest struct {
	DeviceName          *string  `json:"device_name"`
	OSVersion           *string  `json:"os_version"`
	EnrollmentStatus    *string  `json:"enrollment_status"`
	MDMProfileInstalled *bool    `json:"mdm_profile_installed"`
	IsJailbroken        *bool    `json:"is_jailbroken"`
	IsRooted            *bool    `json:"is_rooted"`
	IsEncrypted         *bool    `json:"is_encrypted"`
	IsScreenLock        *bool    `json:"is_screen_lock"`
	IsCompliant         *bool    `json:"is_compliant"`
	ComplianceIssues    []string `json:"compliance_issues"`
	LastLocation        *string  `json:"last_location"`
	LastIP              *string  `json:"last_ip"`
	Notes               *string  `json:"notes"`
	Tags                []string `json:"tags"`
}

type ListDevicesFilter struct {
	Platform         string
	EnrollmentStatus string
	Ownership        string
	RiskLevel        string
	IsCompliant      *bool
	Department       string
	Limit            int
	Offset           int
}

// ─── Apps ─────────────────────────────────────────────────────────────────────

type MobApp struct {
	ID              uuid.UUID `json:"id"`
	TenantID        uuid.UUID `json:"tenant_id"`
	AppName         string    `json:"app_name"`
	BundleID        string    `json:"bundle_id"`
	Version         string    `json:"version"`
	Platform        string    `json:"platform"`
	StoreSource     string    `json:"store_source"`
	IsManaged       bool      `json:"is_managed"`
	IsApproved      bool      `json:"is_approved"`
	RiskLevel       string    `json:"risk_level"`
	Permissions     []string  `json:"permissions"`
	HasKnownVulns   bool      `json:"has_known_vulns"`
	VulnCount       int       `json:"vuln_count"`
	IsBlocklisted   bool      `json:"is_blocklisted"`
	BlocklistReason string    `json:"blocklist_reason,omitempty"`
	Developer       string    `json:"developer,omitempty"`
	Category        string    `json:"category,omitempty"`
	InstallCount    int       `json:"install_count"`
	Tags            []string  `json:"tags"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type CreateAppRequest struct {
	AppName     string   `json:"app_name"`
	BundleID    string   `json:"bundle_id"`
	Version     string   `json:"version"`
	Platform    string   `json:"platform"`
	StoreSource string   `json:"store_source"`
	IsManaged   bool     `json:"is_managed"`
	Permissions []string `json:"permissions"`
	Developer   string   `json:"developer"`
	Category    string   `json:"category"`
	Tags        []string `json:"tags"`
}

type UpdateAppRequest struct {
	IsApproved      *bool    `json:"is_approved"`
	IsBlocklisted   *bool    `json:"is_blocklisted"`
	BlocklistReason *string  `json:"blocklist_reason"`
	HasKnownVulns   *bool    `json:"has_known_vulns"`
	VulnCount       *int     `json:"vuln_count"`
	RiskLevel       *string  `json:"risk_level"`
	Tags            []string `json:"tags"`
}

type ListAppsFilter struct {
	Platform      string
	IsApproved    *bool
	IsBlocklisted *bool
	HasVulns      *bool
	Limit         int
	Offset        int
}

// ─── Policies ─────────────────────────────────────────────────────────────────

type MobPolicy struct {
	ID            uuid.UUID      `json:"id"`
	TenantID      uuid.UUID      `json:"tenant_id"`
	Name          string         `json:"name"`
	Description   string         `json:"description,omitempty"`
	PolicyType    string         `json:"policy_type"`
	Platform      string         `json:"platform"`
	Rules         map[string]any `json:"rules"`
	Action        string         `json:"action"`
	IsActive      bool           `json:"is_active"`
	AppliesTo     string         `json:"applies_to"`
	Department    string         `json:"department,omitempty"`
	AssignedCount int            `json:"assigned_count"`
	CreatedBy     *uuid.UUID     `json:"created_by,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

type CreatePolicyRequest struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	PolicyType  string         `json:"policy_type"`
	Platform    string         `json:"platform"`
	Rules       map[string]any `json:"rules"`
	Action      string         `json:"action"`
	AppliesTo   string         `json:"applies_to"`
	Department  string         `json:"department"`
}

type UpdatePolicyRequest struct {
	Name        *string        `json:"name"`
	Description *string        `json:"description"`
	Rules       map[string]any `json:"rules"`
	Action      *string        `json:"action"`
	IsActive    *bool          `json:"is_active"`
	AppliesTo   *string        `json:"applies_to"`
}

// ─── Threats ──────────────────────────────────────────────────────────────────

type MobThreat struct {
	ID              uuid.UUID      `json:"id"`
	TenantID        uuid.UUID      `json:"tenant_id"`
	DeviceID        uuid.UUID      `json:"device_id"`
	ThreatType      string         `json:"threat_type"`
	Severity        string         `json:"severity"`
	Status          string         `json:"status"`
	Title           string         `json:"title"`
	Description     string         `json:"description,omitempty"`
	ThreatIndicator string         `json:"threat_indicator,omitempty"`
	AffectedApp     string         `json:"affected_app,omitempty"`
	NetworkDetails  map[string]any `json:"network_details,omitempty"`
	DetectedBy      string         `json:"detected_by,omitempty"`
	DetectedAt      time.Time      `json:"detected_at"`
	AutoRemediated  bool           `json:"auto_remediated"`
	Remediation     string         `json:"remediation,omitempty"`
	ResolvedBy      string         `json:"resolved_by,omitempty"`
	ResolvedAt      *time.Time     `json:"resolved_at,omitempty"`
	Tags            []string       `json:"tags"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

type CreateThreatRequest struct {
	DeviceID        uuid.UUID      `json:"device_id"`
	ThreatType      string         `json:"threat_type"`
	Severity        string         `json:"severity"`
	Title           string         `json:"title"`
	Description     string         `json:"description"`
	ThreatIndicator string         `json:"threat_indicator"`
	AffectedApp     string         `json:"affected_app"`
	NetworkDetails  map[string]any `json:"network_details"`
	DetectedBy      string         `json:"detected_by"`
	Tags            []string       `json:"tags"`
}

type UpdateThreatRequest struct {
	Status      *string `json:"status"`
	Remediation *string `json:"remediation"`
	ResolvedBy  *string `json:"resolved_by"`
}

type ListThreatsFilter struct {
	DeviceID   *uuid.UUID
	ThreatType string
	Severity   string
	Status     string
	Limit      int
	Offset     int
}

// ─── Compliance ───────────────────────────────────────────────────────────────

type MobComplianceCheck struct {
	ID              uuid.UUID  `json:"id"`
	TenantID        uuid.UUID  `json:"tenant_id"`
	DeviceID        uuid.UUID  `json:"device_id"`
	PolicyID        *uuid.UUID `json:"policy_id,omitempty"`
	IsCompliant     bool       `json:"is_compliant"`
	Violations      []any      `json:"violations"`
	ComplianceScore int        `json:"compliance_score"`
	ActionTaken     string     `json:"action_taken,omitempty"`
	CheckedAt       time.Time  `json:"checked_at"`
	NextCheckAt     *time.Time `json:"next_check_at,omitempty"`
}

type RunComplianceRequest struct {
	DeviceID uuid.UUID  `json:"device_id"`
	PolicyID *uuid.UUID `json:"policy_id"`
}

// ─── Remote Actions ───────────────────────────────────────────────────────────

type MobRemoteAction struct {
	ID            uuid.UUID      `json:"id"`
	TenantID      uuid.UUID      `json:"tenant_id"`
	DeviceID      uuid.UUID      `json:"device_id"`
	ActionType    string         `json:"action_type"`
	Status        string         `json:"status"`
	Payload       map[string]any `json:"payload,omitempty"`
	Message       string         `json:"message,omitempty"`
	RequestedBy   string         `json:"requested_by,omitempty"`
	RequestedByID *uuid.UUID     `json:"requested_by_id,omitempty"`
	SentAt        *time.Time     `json:"sent_at,omitempty"`
	CompletedAt   *time.Time     `json:"completed_at,omitempty"`
	FailureReason string         `json:"failure_reason,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

type CreateRemoteActionRequest struct {
	DeviceID      uuid.UUID      `json:"device_id"`
	ActionType    string         `json:"action_type"`
	Payload       map[string]any `json:"payload"`
	Message       string         `json:"message"`
	RequestedBy   string         `json:"requested_by"`
	RequestedByID *uuid.UUID     `json:"requested_by_id"`
}

type UpdateRemoteActionRequest struct {
	Status        *string `json:"status"`
	FailureReason *string `json:"failure_reason"`
}

// ─── Stats ────────────────────────────────────────────────────────────────────

type MobStats struct {
	TotalDevices        int            `json:"total_devices"`
	EnrolledDevices     int            `json:"enrolled_devices"`
	NonCompliantDevices int            `json:"non_compliant_devices"`
	JailbrokenDevices   int            `json:"jailbroken_devices"`
	HighRiskDevices     int            `json:"high_risk_devices"`
	TotalApps           int            `json:"total_apps"`
	BlocklistedApps     int            `json:"blocklisted_apps"`
	VulnerableApps      int            `json:"vulnerable_apps"`
	ActiveThreats       int            `json:"active_threats"`
	CriticalThreats     int            `json:"critical_threats"`
	PendingActions      int            `json:"pending_actions"`
	DevicesByPlatform   map[string]int `json:"devices_by_platform"`
	DevicesByOwnership  map[string]int `json:"devices_by_ownership"`
	ThreatsBySeverity   map[string]int `json:"threats_by_severity"`
	ThreatsByType       map[string]int `json:"threats_by_type"`
	TopRiskyDevices     []MobDevice    `json:"top_risky_devices"`
	RecentThreats       []MobThreat    `json:"recent_threats"`
}
