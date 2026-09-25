package model

import (
	"time"

	"github.com/google/uuid"
)

// ─── Zone types ───────────────────────────────────────────────────────────────

const (
	ZoneTypeDMZ         = "dmz"
	ZoneTypeProduction  = "production"
	ZoneTypeManagement  = "management"
	ZoneTypeSWIFT       = "swift"
	ZoneTypeATM         = "atm"
	ZoneTypeInternet    = "internet"
	ZoneTypeGuest       = "guest"
	ZoneTypeIoT         = "iot"
	ZoneTypeDevelopment = "development"
	ZoneTypeDR          = "dr"
	ZoneTypeRestricted  = "restricted"
)

// ─── Policy actions ───────────────────────────────────────────────────────────

const (
	PolicyActionAllow   = "allow"
	PolicyActionDeny    = "deny"
	PolicyActionLog     = "log"
	PolicyActionInspect = "inspect"
)

// ─── Anomaly types ────────────────────────────────────────────────────────────

const (
	AnomalyPortScan        = "port_scan"
	AnomalyLateralMovement = "lateral_movement"
	AnomalyDataExfil       = "data_exfiltration"
	AnomalyBeaconing       = "beaconing"
	AnomalyDNSTunneling    = "dns_tunneling"
	AnomalyPolicyViolation = "policy_violation"
	AnomalyUnusualVolume   = "unusual_volume"
	AnomalyEastWest        = "east_west_anomaly"
	AnomalyC2              = "c2_traffic"
)

// ─── Severities ───────────────────────────────────────────────────────────────

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// ─── Device types ─────────────────────────────────────────────────────────────

const (
	DeviceFirewall     = "firewall"
	DeviceSwitch       = "switch"
	DeviceRouter       = "router"
	DeviceLoadBalancer = "load_balancer"
	DeviceIDSIPS       = "ids_ips"
	DeviceWAF          = "waf"
	DeviceVPNGateway   = "vpn_gateway"
	DeviceProxy        = "proxy"
	DeviceDNS          = "dns"
)

// ─── Core structs ─────────────────────────────────────────────────────────────

type NetSecZone struct {
	ID          uuid.UUID      `json:"id"`
	TenantID    uuid.UUID      `json:"tenant_id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	ZoneType    string         `json:"zone_type"`
	TrustLevel  int            `json:"trust_level"`
	CIDRBlocks  []string       `json:"cidr_blocks"`
	Color       string         `json:"color"`
	IsActive    bool           `json:"is_active"`
	Metadata    map[string]any `json:"metadata"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

type NetSecPolicy struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	SrcZoneID   *uuid.UUID `json:"src_zone_id,omitempty"`
	SrcZoneName string     `json:"src_zone_name,omitempty"`
	DstZoneID   *uuid.UUID `json:"dst_zone_id,omitempty"`
	DstZoneName string     `json:"dst_zone_name,omitempty"`
	SrcCIDR     string     `json:"src_cidr,omitempty"`
	DstCIDR     string     `json:"dst_cidr,omitempty"`
	Protocol    string     `json:"protocol"`
	Ports       []string   `json:"ports"`
	Action      string     `json:"action"`
	Priority    int        `json:"priority"`
	IsActive    bool       `json:"is_active"`
	HitCount    int64      `json:"hit_count"`
	LastHitAt   *time.Time `json:"last_hit_at,omitempty"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type NetSecFlow struct {
	ID           uuid.UUID  `json:"id"`
	TenantID     uuid.UUID  `json:"tenant_id"`
	SrcIP        string     `json:"src_ip"`
	DstIP        string     `json:"dst_ip"`
	SrcPort      *int       `json:"src_port,omitempty"`
	DstPort      *int       `json:"dst_port,omitempty"`
	Protocol     string     `json:"protocol,omitempty"`
	BytesSent    int64      `json:"bytes_sent"`
	BytesRecv    int64      `json:"bytes_recv"`
	Packets      int64      `json:"packets"`
	DurationMs   int        `json:"duration_ms"`
	SrcZoneID    *uuid.UUID `json:"src_zone_id,omitempty"`
	SrcZoneName  string     `json:"src_zone_name,omitempty"`
	DstZoneID    *uuid.UUID `json:"dst_zone_id,omitempty"`
	DstZoneName  string     `json:"dst_zone_name,omitempty"`
	Action       string     `json:"action"`
	AnomalyScore int        `json:"anomaly_score"`
	Flags        []string   `json:"flags"`
	FlowStart    time.Time  `json:"flow_start"`
	FlowEnd      *time.Time `json:"flow_end,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

type NetSecAnomaly struct {
	ID          uuid.UUID      `json:"id"`
	TenantID    uuid.UUID      `json:"tenant_id"`
	AnomalyType string         `json:"anomaly_type"`
	Severity    string         `json:"severity"`
	SrcIP       string         `json:"src_ip,omitempty"`
	DstIP       string         `json:"dst_ip,omitempty"`
	SrcZoneID   *uuid.UUID     `json:"src_zone_id,omitempty"`
	DstZoneID   *uuid.UUID     `json:"dst_zone_id,omitempty"`
	FlowIDs     []uuid.UUID    `json:"flow_ids"`
	Description string         `json:"description"`
	Evidence    map[string]any `json:"evidence"`
	Status      string         `json:"status"`
	ResolvedAt  *time.Time     `json:"resolved_at,omitempty"`
	DetectedAt  time.Time      `json:"detected_at"`
	CreatedAt   time.Time      `json:"created_at"`
}

type NetSecDevice struct {
	ID         uuid.UUID      `json:"id"`
	TenantID   uuid.UUID      `json:"tenant_id"`
	Name       string         `json:"name"`
	DeviceType string         `json:"device_type"`
	IPAddress  string         `json:"ip_address"`
	ZoneID     *uuid.UUID     `json:"zone_id,omitempty"`
	ZoneName   string         `json:"zone_name,omitempty"`
	Vendor     string         `json:"vendor,omitempty"`
	Model      string         `json:"model,omitempty"`
	Firmware   string         `json:"firmware,omitempty"`
	IsManaged  bool           `json:"is_managed"`
	LastSeenAt time.Time      `json:"last_seen_at"`
	Status     string         `json:"status"`
	Metadata   map[string]any `json:"metadata"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

type NetSecStats struct {
	TotalZones      int               `json:"total_zones"`
	TotalPolicies   int               `json:"total_policies"`
	ActivePolicies  int               `json:"active_policies"`
	TotalDevices    int               `json:"total_devices"`
	OfflineDevices  int               `json:"offline_devices"`
	OpenAnomalies   int               `json:"open_anomalies"`
	FlowsLast24h    int               `json:"flows_last_24h"`
	BlockedFlows24h int               `json:"blocked_flows_24h"`
	AnomaliesBySev  map[string]int    `json:"anomalies_by_severity"`
	AnomaliesByType map[string]int    `json:"anomalies_by_type"`
	TopSrcIPs       []*IPStats        `json:"top_src_ips"`
	PolicyHits      []*PolicyHitStats `json:"top_policy_hits"`
}

type IPStats struct {
	IP        string `json:"ip"`
	FlowCount int    `json:"flow_count"`
	BytesSent int64  `json:"bytes_sent"`
}

type PolicyHitStats struct {
	PolicyID   uuid.UUID `json:"policy_id"`
	PolicyName string    `json:"policy_name"`
	HitCount   int64     `json:"hit_count"`
}

// ─── Topology view ────────────────────────────────────────────────────────────

type ZoneTopology struct {
	Zones    []*NetSecZone   `json:"zones"`
	Devices  []*NetSecDevice `json:"devices"`
	Policies []*NetSecPolicy `json:"policies"`
}

// ─── Request models ───────────────────────────────────────────────────────────

type CreateZoneRequest struct {
	Name        string         `json:"name"       validate:"required"`
	Description string         `json:"description"`
	ZoneType    string         `json:"zone_type"  validate:"required"`
	TrustLevel  int            `json:"trust_level"`
	CIDRBlocks  []string       `json:"cidr_blocks"`
	Color       string         `json:"color"`
	Metadata    map[string]any `json:"metadata"`
}

type UpdateZoneRequest struct {
	Description string         `json:"description"`
	TrustLevel  *int           `json:"trust_level"`
	CIDRBlocks  []string       `json:"cidr_blocks"`
	Color       string         `json:"color"`
	IsActive    *bool          `json:"is_active"`
	Metadata    map[string]any `json:"metadata"`
}

type CreatePolicyRequest struct {
	Name        string     `json:"name"   validate:"required"`
	Description string     `json:"description"`
	SrcZoneID   *uuid.UUID `json:"src_zone_id"`
	DstZoneID   *uuid.UUID `json:"dst_zone_id"`
	SrcCIDR     string     `json:"src_cidr"`
	DstCIDR     string     `json:"dst_cidr"`
	Protocol    string     `json:"protocol"`
	Ports       []string   `json:"ports"`
	Action      string     `json:"action"  validate:"required"`
	Priority    int        `json:"priority"`
}

type UpdatePolicyRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Protocol    string   `json:"protocol"`
	Ports       []string `json:"ports"`
	Action      string   `json:"action"`
	Priority    *int     `json:"priority"`
	IsActive    *bool    `json:"is_active"`
}

type IngestFlowRequest struct {
	SrcIP      string     `json:"src_ip"    validate:"required"`
	DstIP      string     `json:"dst_ip"    validate:"required"`
	SrcPort    *int       `json:"src_port"`
	DstPort    *int       `json:"dst_port"`
	Protocol   string     `json:"protocol"`
	BytesSent  int64      `json:"bytes_sent"`
	BytesRecv  int64      `json:"bytes_recv"`
	Packets    int64      `json:"packets"`
	DurationMs int        `json:"duration_ms"`
	Action     string     `json:"action"`
	FlowStart  time.Time  `json:"flow_start" validate:"required"`
	FlowEnd    *time.Time `json:"flow_end"`
}

type CreateAnomalyRequest struct {
	AnomalyType string         `json:"anomaly_type" validate:"required"`
	Severity    string         `json:"severity"     validate:"required"`
	SrcIP       string         `json:"src_ip"`
	DstIP       string         `json:"dst_ip"`
	SrcZoneID   *uuid.UUID     `json:"src_zone_id"`
	DstZoneID   *uuid.UUID     `json:"dst_zone_id"`
	FlowIDs     []uuid.UUID    `json:"flow_ids"`
	Description string         `json:"description"  validate:"required"`
	Evidence    map[string]any `json:"evidence"`
}

type UpdateAnomalyRequest struct {
	Status string `json:"status" validate:"required"`
}

type RegisterDeviceRequest struct {
	Name       string         `json:"name"        validate:"required"`
	DeviceType string         `json:"device_type" validate:"required"`
	IPAddress  string         `json:"ip_address"  validate:"required"`
	ZoneID     *uuid.UUID     `json:"zone_id"`
	Vendor     string         `json:"vendor"`
	Model      string         `json:"model"`
	Firmware   string         `json:"firmware"`
	IsManaged  *bool          `json:"is_managed"`
	Metadata   map[string]any `json:"metadata"`
}

type UpdateDeviceRequest struct {
	ZoneID   *uuid.UUID     `json:"zone_id"`
	Vendor   string         `json:"vendor"`
	Model    string         `json:"model"`
	Firmware string         `json:"firmware"`
	Status   string         `json:"status"`
	Metadata map[string]any `json:"metadata"`
}

type ListFlowsFilter struct {
	SrcIP     string
	DstIP     string
	SrcZoneID *uuid.UUID
	DstZoneID *uuid.UUID
	Action    string
	MinScore  *int
	Page      int
	PageSize  int
}

type ListAnomaliesFilter struct {
	AnomalyType string
	Severity    string
	Status      string
	Page        int
	PageSize    int
}
