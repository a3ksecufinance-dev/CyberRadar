package model

import (
	"time"

	"github.com/google/uuid"
)

// AssetType categorises an asset.
type AssetType string

const (
	// IT Infrastructure
	AssetTypeServer          AssetType = "server"
	AssetTypeWorkstation     AssetType = "workstation"
	AssetTypeNetworkDevice   AssetType = "network_device"   // router, switch
	AssetTypeFirewall        AssetType = "firewall"
	AssetTypeLoadBalancer    AssetType = "load_balancer"
	AssetTypeDatabase        AssetType = "database"
	AssetTypeStorage         AssetType = "storage"
	AssetTypeCloudInstance   AssetType = "cloud_instance"
	AssetTypeContainer       AssetType = "container"
	AssetTypeVPN             AssetType = "vpn"
	AssetTypeProxy           AssetType = "proxy"
	AssetTypePrinter         AssetType = "printer"
	AssetTypeIoT             AssetType = "iot"
	AssetTypeMobile          AssetType = "mobile"

	// Banking-native
	AssetTypeCBSServer       AssetType = "cbs_server"        // Core Banking System
	AssetTypeATM             AssetType = "atm"
	AssetTypeSWIFTGateway    AssetType = "swift_gateway"
	AssetTypePaymentTerminal AssetType = "payment_terminal"  // POS, mPOS
	AssetTypeMonetique       AssetType = "monetique"          // card processing hub
	AssetTypeHSM             AssetType = "hsm"                // Hardware Security Module
)

// Criticality is a 1–4 scale.
type Criticality int

const (
	CriticalityLow      Criticality = 1
	CriticalityMedium   Criticality = 2
	CriticalityHigh     Criticality = 3
	CriticalityCritical Criticality = 4
)

// AssetStatus reflects the operational state.
type AssetStatus string

const (
	AssetStatusActive         AssetStatus = "active"
	AssetStatusInactive       AssetStatus = "inactive"
	AssetStatusDecommissioned AssetStatus = "decommissioned"
	AssetStatusUnknown        AssetStatus = "unknown"
)

// RelationshipType describes directed relationships between assets.
type RelationshipType string

const (
	RelConnectsTo   RelationshipType = "CONNECTS_TO"
	RelRunsOn       RelationshipType = "RUNS_ON"
	RelDependsOn    RelationshipType = "DEPENDS_ON"
	RelHosts        RelationshipType = "HOSTS"
	RelManagedBy    RelationshipType = "MANAGED_BY"
	RelBacksUp      RelationshipType = "BACKS_UP"
	RelReplicatesTo RelationshipType = "REPLICATES_TO"
)

// ─── Core models ─────────────────────────────────────────────────────────────

// Asset represents a tracked IT/OT/banking asset.
type Asset struct {
	ID             uuid.UUID   `json:"id"`
	TenantID       uuid.UUID   `json:"tenant_id"`
	Name           string      `json:"name"`
	Hostname       string      `json:"hostname,omitempty"`
	FQDN           string      `json:"fqdn,omitempty"`
	IPAddresses    []string    `json:"ip_addresses"`
	MACAddresses   []string    `json:"mac_addresses"`
	AssetType      AssetType   `json:"asset_type"`
	OS             string      `json:"os,omitempty"`
	OSVersion      string      `json:"os_version,omitempty"`
	Criticality    Criticality `json:"criticality"`
	Status         AssetStatus `json:"status"`
	Environment    string      `json:"environment"`
	OwnerID        *uuid.UUID  `json:"owner_id,omitempty"`
	Department     string      `json:"department,omitempty"`
	Location       string      `json:"location,omitempty"`
	BusinessService string     `json:"business_service,omitempty"`

	// Banking flags
	IsCBSConnected  bool `json:"is_cbs_connected"`
	IsSWIFTConnected bool `json:"is_swift_connected"`
	IsPCIScope      bool `json:"is_pci_scope"`

	// Risk
	RiskScore   float64 `json:"risk_score"`
	VulnCritical int    `json:"vuln_critical"`
	VulnHigh     int    `json:"vuln_high"`
	VulnMedium   int    `json:"vuln_medium"`
	VulnLow      int    `json:"vuln_low"`

	Tags     []string               `json:"tags"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	DiscoveredBy string     `json:"discovered_by"`
	LastSeenAt   *time.Time `json:"last_seen_at,omitempty"`
	FirstSeenAt  time.Time  `json:"first_seen_at"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// AssetRelationship is a directed edge between two assets.
type AssetRelationship struct {
	ID               uuid.UUID        `json:"id"`
	TenantID         uuid.UUID        `json:"tenant_id"`
	SourceID         uuid.UUID        `json:"source_id"`
	TargetID         uuid.UUID        `json:"target_id"`
	RelationshipType RelationshipType `json:"relationship_type"`
	Bidirectional    bool             `json:"bidirectional"`
	Properties       map[string]any   `json:"properties,omitempty"`
	CreatedAt        time.Time        `json:"created_at"`
}

// AssetScan holds results of a single vulnerability/compliance scan.
type AssetScan struct {
	ID            uuid.UUID  `json:"id"`
	TenantID      uuid.UUID  `json:"tenant_id"`
	AssetID       uuid.UUID  `json:"asset_id"`
	ScanType      string     `json:"scan_type"`
	Status        string     `json:"status"`
	Scanner       string     `json:"scanner,omitempty"`
	FindingsCount int        `json:"findings_count"`
	CriticalCount int        `json:"critical_count"`
	HighCount     int        `json:"high_count"`
	MediumCount   int        `json:"medium_count"`
	LowCount      int        `json:"low_count"`
	StartedAt     time.Time  `json:"started_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
}

// DiscoveryCandidate is an auto-detected host not yet in inventory.
type DiscoveryCandidate struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	Hostname    string     `json:"hostname,omitempty"`
	IPAddress   string     `json:"ip_address"`
	SourceType  string     `json:"source_type"`
	ConnectorID string     `json:"connector_id"`
	EventCount  int        `json:"event_count"`
	FirstSeenAt time.Time  `json:"first_seen_at"`
	LastSeenAt  time.Time  `json:"last_seen_at"`
}

// ─── Request / Response models ────────────────────────────────────────────────

// CreateAssetRequest is the payload to register a new asset.
type CreateAssetRequest struct {
	Name            string      `json:"name"         validate:"required,min=2,max=255"`
	Hostname        string      `json:"hostname"`
	FQDN            string      `json:"fqdn"`
	IPAddresses     []string    `json:"ip_addresses"`
	MACAddresses    []string    `json:"mac_addresses"`
	AssetType       AssetType   `json:"asset_type"   validate:"required"`
	OS              string      `json:"os"`
	OSVersion       string      `json:"os_version"`
	Criticality     Criticality `json:"criticality"  validate:"required,min=1,max=4"`
	Environment     string      `json:"environment"`
	OwnerID         *uuid.UUID  `json:"owner_id"`
	Department      string      `json:"department"`
	Location        string      `json:"location"`
	BusinessService string      `json:"business_service"`
	IsCBSConnected  bool        `json:"is_cbs_connected"`
	IsSWIFTConnected bool       `json:"is_swift_connected"`
	IsPCIScope      bool        `json:"is_pci_scope"`
	Tags            []string    `json:"tags"`
	Metadata        map[string]any `json:"metadata"`
}

// UpdateAssetRequest allows partial updates.
type UpdateAssetRequest struct {
	Name            *string      `json:"name"`
	Hostname        *string      `json:"hostname"`
	FQDN            *string      `json:"fqdn"`
	IPAddresses     []string     `json:"ip_addresses"`
	OS              *string      `json:"os"`
	OSVersion       *string      `json:"os_version"`
	Criticality     *Criticality `json:"criticality"  validate:"omitempty,min=1,max=4"`
	Status          *AssetStatus `json:"status"`
	Environment     *string      `json:"environment"`
	OwnerID         *uuid.UUID   `json:"owner_id"`
	Department      *string      `json:"department"`
	Location        *string      `json:"location"`
	BusinessService *string      `json:"business_service"`
	IsCBSConnected  *bool        `json:"is_cbs_connected"`
	IsSWIFTConnected *bool       `json:"is_swift_connected"`
	IsPCIScope      *bool        `json:"is_pci_scope"`
	Tags            []string     `json:"tags"`
	Metadata        map[string]any `json:"metadata"`
}

// CreateRelationshipRequest links two assets.
type CreateRelationshipRequest struct {
	TargetID         uuid.UUID        `json:"target_id"         validate:"required"`
	RelationshipType RelationshipType `json:"relationship_type" validate:"required"`
	Bidirectional    bool             `json:"bidirectional"`
	Properties       map[string]any   `json:"properties"`
}

// AssetFilter holds query parameters for listing assets.
type AssetFilter struct {
	TenantID        uuid.UUID
	AssetType       string
	Criticality     int
	Status          string
	Environment     string
	BusinessService string
	Tag             string
	Search          string // partial match on name/hostname/ip
	IsCBSConnected  *bool
	IsPCIScope      *bool
	Limit           int
	Offset          int
}

// AssetList is the paginated response.
type AssetList struct {
	Assets []*Asset `json:"assets"`
	Total  int      `json:"total"`
	Limit  int      `json:"limit"`
	Offset int      `json:"offset"`
}

// AssetStats provides a summary view.
type AssetStats struct {
	Total           int              `json:"total"`
	ByType          map[string]int   `json:"by_type"`
	ByCriticality   map[string]int   `json:"by_criticality"`
	ByStatus        map[string]int   `json:"by_status"`
	HighRisk        int              `json:"high_risk"`        // risk_score >= 7
	CBSConnected    int              `json:"cbs_connected"`
	SWIFTConnected  int              `json:"swift_connected"`
	PCIScope        int              `json:"pci_scope"`
	NeverSeen       int              `json:"never_seen"`       // last_seen_at IS NULL
	Stale           int              `json:"stale"`            // last_seen_at < 30d
	DiscoveryQueue  int              `json:"discovery_queue"`  // unresolved candidates
}

// RiskBreakdown details the risk contributors for a single asset.
type RiskBreakdown struct {
	AssetID         uuid.UUID `json:"asset_id"`
	TotalScore      float64   `json:"total_score"`
	CriticalityScore float64  `json:"criticality_score"`
	VulnScore       float64   `json:"vuln_score"`
	ExposureScore   float64   `json:"exposure_score"`
	BehaviorScore   float64   `json:"behavior_score"`
	ContextScore    float64   `json:"context_score"`
	Factors         []string  `json:"factors"`
}
