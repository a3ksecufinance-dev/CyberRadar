package model

import (
	"time"

	"github.com/google/uuid"
)

// ─── Assets ───────────────────────────────────────────────────────────────────

type OTAsset struct {
	ID              uuid.UUID      `json:"id"`
	TenantID        uuid.UUID      `json:"tenant_id"`
	Name            string         `json:"name"`
	Description     string         `json:"description,omitempty"`
	AssetType       string         `json:"asset_type"`
	Vendor          string         `json:"vendor,omitempty"`
	Model           string         `json:"model,omitempty"`
	FirmwareVersion string         `json:"firmware_version,omitempty"`
	SerialNumber    string         `json:"serial_number,omitempty"`
	IPAddress       string         `json:"ip_address,omitempty"`
	MACAddress      string         `json:"mac_address,omitempty"`
	Protocol        []string       `json:"protocol"`
	Site            string         `json:"site,omitempty"`
	Zone            string         `json:"zone,omitempty"`
	PurdueLevel     int            `json:"purdue_level"`
	RiskScore       int            `json:"risk_score"`
	RiskLevel       string         `json:"risk_level"`
	IsInternetFacing bool          `json:"is_internet_facing"`
	IsPatched       bool           `json:"is_patched"`
	LastPatchedAt   *time.Time     `json:"last_patched_at,omitempty"`
	IsActive        bool           `json:"is_active"`
	Criticality     string         `json:"criticality"`
	InstallDate     *time.Time     `json:"install_date,omitempty"`
	EndOfLifeDate   *time.Time     `json:"end_of_life_date,omitempty"`
	Tags            []string       `json:"tags"`
	Metadata        map[string]any `json:"metadata,omitempty"`
	CreatedBy       *uuid.UUID     `json:"created_by,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	// Computed
	VulnCount  int `json:"vuln_count,omitempty"`
	EventCount int `json:"event_count,omitempty"`
}

type CreateAssetRequest struct {
	Name            string         `json:"name"`
	Description     string         `json:"description"`
	AssetType       string         `json:"asset_type"`
	Vendor          string         `json:"vendor"`
	Model           string         `json:"model"`
	FirmwareVersion string         `json:"firmware_version"`
	SerialNumber    string         `json:"serial_number"`
	IPAddress       string         `json:"ip_address"`
	MACAddress      string         `json:"mac_address"`
	Protocol        []string       `json:"protocol"`
	Site            string         `json:"site"`
	Zone            string         `json:"zone"`
	PurdueLevel     int            `json:"purdue_level"`
	Criticality     string         `json:"criticality"`
	IsInternetFacing bool          `json:"is_internet_facing"`
	InstallDate     *time.Time     `json:"install_date"`
	EndOfLifeDate   *time.Time     `json:"end_of_life_date"`
	Tags            []string       `json:"tags"`
	Metadata        map[string]any `json:"metadata"`
}

type UpdateAssetRequest struct {
	Name            *string        `json:"name"`
	Description     *string        `json:"description"`
	FirmwareVersion *string        `json:"firmware_version"`
	IPAddress       *string        `json:"ip_address"`
	Site            *string        `json:"site"`
	Zone            *string        `json:"zone"`
	PurdueLevel     *int           `json:"purdue_level"`
	RiskScore       *int           `json:"risk_score"`
	RiskLevel       *string        `json:"risk_level"`
	IsInternetFacing *bool         `json:"is_internet_facing"`
	IsPatched       *bool          `json:"is_patched"`
	IsActive        *bool          `json:"is_active"`
	Criticality     *string        `json:"criticality"`
	Protocol        []string       `json:"protocol"`
	Tags            []string       `json:"tags"`
	Metadata        map[string]any `json:"metadata"`
}

type ListAssetsFilter struct {
	Site        string
	AssetType   string
	RiskLevel   string
	PurdueLevel int
	IsActive    *bool
	Limit       int
	Offset      int
}

// ─── Zones ────────────────────────────────────────────────────────────────────

type OTZone struct {
	ID             uuid.UUID  `json:"id"`
	TenantID       uuid.UUID  `json:"tenant_id"`
	Name           string     `json:"name"`
	Description    string     `json:"description,omitempty"`
	ZoneType       string     `json:"zone_type"`
	PurdueLevel    int        `json:"purdue_level"`
	Site           string     `json:"site,omitempty"`
	IsAirGapped    bool       `json:"is_air_gapped"`
	FirewallPresent bool      `json:"firewall_present"`
	IDSPresent     bool       `json:"ids_present"`
	RiskScore      int        `json:"risk_score"`
	AssetCount     int        `json:"asset_count"`
	NetworkRanges  []string   `json:"network_ranges"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type CreateZoneRequest struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	ZoneType       string   `json:"zone_type"`
	PurdueLevel    int      `json:"purdue_level"`
	Site           string   `json:"site"`
	IsAirGapped    bool     `json:"is_air_gapped"`
	FirewallPresent bool    `json:"firewall_present"`
	IDSPresent     bool     `json:"ids_present"`
	NetworkRanges  []string `json:"network_ranges"`
}

type UpdateZoneRequest struct {
	Name           *string  `json:"name"`
	Description    *string  `json:"description"`
	IsAirGapped    *bool    `json:"is_air_gapped"`
	FirewallPresent *bool   `json:"firewall_present"`
	IDSPresent     *bool    `json:"ids_present"`
	RiskScore      *int     `json:"risk_score"`
	NetworkRanges  []string `json:"network_ranges"`
}

// ─── Communications ───────────────────────────────────────────────────────────

type OTCommunication struct {
	ID           uuid.UUID  `json:"id"`
	TenantID     uuid.UUID  `json:"tenant_id"`
	SrcAssetID   *uuid.UUID `json:"src_asset_id,omitempty"`
	DstAssetID   *uuid.UUID `json:"dst_asset_id,omitempty"`
	SrcZoneID    *uuid.UUID `json:"src_zone_id,omitempty"`
	DstZoneID    *uuid.UUID `json:"dst_zone_id,omitempty"`
	Protocol     string     `json:"protocol,omitempty"`
	Port         int        `json:"port,omitempty"`
	Direction    string     `json:"direction"`
	IsAuthorized bool       `json:"is_authorized"`
	IsAnomalous  bool       `json:"is_anomalous"`
	FirstSeenAt  time.Time  `json:"first_seen_at"`
	LastSeenAt   time.Time  `json:"last_seen_at"`
	PacketCount  int64      `json:"packet_count"`
	CreatedAt    time.Time  `json:"created_at"`
}

type CreateCommunicationRequest struct {
	SrcAssetID   *uuid.UUID `json:"src_asset_id"`
	DstAssetID   *uuid.UUID `json:"dst_asset_id"`
	SrcZoneID    *uuid.UUID `json:"src_zone_id"`
	DstZoneID    *uuid.UUID `json:"dst_zone_id"`
	Protocol     string     `json:"protocol"`
	Port         int        `json:"port"`
	Direction    string     `json:"direction"`
	IsAuthorized bool       `json:"is_authorized"`
	IsAnomalous  bool       `json:"is_anomalous"`
}

// ─── Vulnerabilities ──────────────────────────────────────────────────────────

type OTVulnerability struct {
	ID                  uuid.UUID  `json:"id"`
	TenantID            uuid.UUID  `json:"tenant_id"`
	AssetID             uuid.UUID  `json:"asset_id"`
	CVEID               string     `json:"cve_id,omitempty"`
	ICSCertID           string     `json:"ics_cert_id,omitempty"`
	Title               string     `json:"title"`
	Description         string     `json:"description,omitempty"`
	Severity            string     `json:"severity"`
	CVSSScore           *float64   `json:"cvss_score,omitempty"`
	AffectsAvailability bool       `json:"affects_availability"`
	AffectsSafety       bool       `json:"affects_safety"`
	PotentialImpact     string     `json:"potential_impact,omitempty"`
	Status              string     `json:"status"`
	PatchAvailable      bool       `json:"patch_available"`
	PatchNotes          string     `json:"patch_notes,omitempty"`
	Workaround          string     `json:"workaround,omitempty"`
	DiscoveredAt        time.Time  `json:"discovered_at"`
	RemediatedAt        *time.Time `json:"remediated_at,omitempty"`
	Tags                []string   `json:"tags"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

type CreateVulnerabilityRequest struct {
	AssetID             uuid.UUID `json:"asset_id"`
	CVEID               string    `json:"cve_id"`
	ICSCertID           string    `json:"ics_cert_id"`
	Title               string    `json:"title"`
	Description         string    `json:"description"`
	Severity            string    `json:"severity"`
	CVSSScore           *float64  `json:"cvss_score"`
	AffectsAvailability bool      `json:"affects_availability"`
	AffectsSafety       bool      `json:"affects_safety"`
	PotentialImpact     string    `json:"potential_impact"`
	PatchAvailable      bool      `json:"patch_available"`
	PatchNotes          string    `json:"patch_notes"`
	Workaround          string    `json:"workaround"`
	Tags                []string  `json:"tags"`
}

type UpdateVulnerabilityRequest struct {
	Status         *string `json:"status"`
	PatchAvailable *bool   `json:"patch_available"`
	PatchNotes     *string `json:"patch_notes"`
	Workaround     *string `json:"workaround"`
}

type ListVulnsFilter struct {
	AssetID  *uuid.UUID
	Severity string
	Status   string
	Limit    int
	Offset   int
}

// ─── Events ───────────────────────────────────────────────────────────────────

type OTEvent struct {
	ID             uuid.UUID  `json:"id"`
	TenantID       uuid.UUID  `json:"tenant_id"`
	AssetID        *uuid.UUID `json:"asset_id,omitempty"`
	ZoneID         *uuid.UUID `json:"zone_id,omitempty"`
	EventType      string     `json:"event_type"`
	Severity       string     `json:"severity"`
	Status         string     `json:"status"`
	Title          string     `json:"title"`
	Description    string     `json:"description,omitempty"`
	SourceIP       string     `json:"source_ip,omitempty"`
	DestIP         string     `json:"dest_ip,omitempty"`
	Protocol       string     `json:"protocol,omitempty"`
	RawPayload     string     `json:"raw_payload,omitempty"`
	DetectedBy     string     `json:"detected_by,omitempty"`
	DetectionRule  string     `json:"detection_rule,omitempty"`
	AcknowledgedBy string     `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	ResolvedBy     string     `json:"resolved_by,omitempty"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	EventTime      time.Time  `json:"event_time"`
	Tags           []string   `json:"tags"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type CreateEventRequest struct {
	AssetID       *uuid.UUID `json:"asset_id"`
	ZoneID        *uuid.UUID `json:"zone_id"`
	EventType     string     `json:"event_type"`
	Severity      string     `json:"severity"`
	Title         string     `json:"title"`
	Description   string     `json:"description"`
	SourceIP      string     `json:"source_ip"`
	DestIP        string     `json:"dest_ip"`
	Protocol      string     `json:"protocol"`
	RawPayload    string     `json:"raw_payload"`
	DetectedBy    string     `json:"detected_by"`
	DetectionRule string     `json:"detection_rule"`
	EventTime     *time.Time `json:"event_time"`
	Tags          []string   `json:"tags"`
}

type UpdateEventRequest struct {
	Status         *string `json:"status"`
	AcknowledgedBy *string `json:"acknowledged_by"`
	ResolvedBy     *string `json:"resolved_by"`
}

type ListEventsFilter struct {
	AssetID   *uuid.UUID
	EventType string
	Severity  string
	Status    string
	Limit     int
	Offset    int
}

// ─── Policies ─────────────────────────────────────────────────────────────────

type OTPolicy struct {
	ID          uuid.UUID      `json:"id"`
	TenantID    uuid.UUID      `json:"tenant_id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	PolicyType  string         `json:"policy_type"`
	Scope       string         `json:"scope"`
	ScopeRef    *uuid.UUID     `json:"scope_ref,omitempty"`
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
	Scope       string         `json:"scope"`
	ScopeRef    *uuid.UUID     `json:"scope_ref"`
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

// ─── Patches ──────────────────────────────────────────────────────────────────

type OTPatch struct {
	ID               uuid.UUID  `json:"id"`
	TenantID         uuid.UUID  `json:"tenant_id"`
	AssetID          uuid.UUID  `json:"asset_id"`
	PatchType        string     `json:"patch_type"`
	Title            string     `json:"title"`
	Description      string     `json:"description,omitempty"`
	VersionBefore    string     `json:"version_before,omitempty"`
	VersionAfter     string     `json:"version_after,omitempty"`
	CVEIDs           []string   `json:"cve_ids"`
	Status           string     `json:"status"`
	RiskLevel        string     `json:"risk_level"`
	RequiresDowntime bool       `json:"requires_downtime"`
	ScheduledAt      *time.Time `json:"scheduled_at,omitempty"`
	MaintenanceWindow string    `json:"maintenance_window,omitempty"`
	AppliedAt        *time.Time `json:"applied_at,omitempty"`
	AppliedBy        string     `json:"applied_by,omitempty"`
	RollbackPlan     string     `json:"rollback_plan,omitempty"`
	Notes            string     `json:"notes,omitempty"`
	CreatedBy        *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type CreatePatchRequest struct {
	AssetID          uuid.UUID  `json:"asset_id"`
	PatchType        string     `json:"patch_type"`
	Title            string     `json:"title"`
	Description      string     `json:"description"`
	VersionBefore    string     `json:"version_before"`
	VersionAfter     string     `json:"version_after"`
	CVEIDs           []string   `json:"cve_ids"`
	RiskLevel        string     `json:"risk_level"`
	RequiresDowntime bool       `json:"requires_downtime"`
	ScheduledAt      *time.Time `json:"scheduled_at"`
	MaintenanceWindow string    `json:"maintenance_window"`
	RollbackPlan     string     `json:"rollback_plan"`
	Notes            string     `json:"notes"`
}

type UpdatePatchRequest struct {
	Status    *string    `json:"status"`
	AppliedBy *string    `json:"applied_by"`
	AppliedAt *time.Time `json:"applied_at"`
	Notes     *string    `json:"notes"`
}

// ─── Stats ────────────────────────────────────────────────────────────────────

type OTStats struct {
	TotalAssets         int            `json:"total_assets"`
	ActiveAssets        int            `json:"active_assets"`
	CriticalAssets      int            `json:"critical_assets"`
	InternetFacingAssets int           `json:"internet_facing_assets"`
	UnpatchedAssets     int            `json:"unpatched_assets"`
	TotalZones          int            `json:"total_zones"`
	TotalVulnerabilities int           `json:"total_vulnerabilities"`
	CriticalVulns       int            `json:"critical_vulns"`
	SafetyImpactVulns   int            `json:"safety_impact_vulns"`
	OpenEvents          int            `json:"open_events"`
	CriticalEvents      int            `json:"critical_events"`
	AnomalousCommunications int        `json:"anomalous_communications"`
	PendingPatches      int            `json:"pending_patches"`
	AssetsByType        map[string]int `json:"assets_by_type"`
	AssetsByPurdue      map[string]int `json:"assets_by_purdue"`
	EventsBySeverity    map[string]int `json:"events_by_severity"`
	VulnsBySeverity     map[string]int `json:"vulns_by_severity"`
	TopRiskyAssets      []OTAsset      `json:"top_risky_assets"`
	RecentEvents        []OTEvent      `json:"recent_events"`
}
