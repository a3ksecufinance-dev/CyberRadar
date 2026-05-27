package model

import (
	"time"

	"github.com/google/uuid"
)

// Node types
const (
	NodeTypeAsset    = "asset"
	NodeTypeIdentity = "identity"
	NodeTypeService  = "service"
	NodeTypeNetwork  = "network"
	NodeTypeCloud    = "cloud"
)

// Edge types
const (
	EdgeTypeNetworkAccess    = "network_access"
	EdgeTypeCredentialReuse  = "credential_reuse"
	EdgeTypeExploit          = "exploit"
	EdgeTypeTrust            = "trust_relationship"
	EdgeTypeRDP              = "rdp"
	EdgeTypeSSH              = "ssh"
	EdgeTypeSMB              = "smb"
	EdgeTypeAPICall          = "api_call"
	EdgeTypeSupplyChain      = "supply_chain"
)

// Path types
const (
	PathTypeLateralMovement    = "lateral_movement"
	PathTypePrivEscalation     = "privilege_escalation"
	PathTypeDataAccess         = "data_access"
	PathTypeExfiltration       = "exfiltration"
)

// Scenario statuses
const (
	ScenarioStatusPending   = "pending"
	ScenarioStatusRunning   = "running"
	ScenarioStatusCompleted = "completed"
	ScenarioStatusFailed    = "failed"
)

// AttackNode is a vertex in the attack graph.
type AttackNode struct {
	ID               uuid.UUID      `json:"id"`
	TenantID         uuid.UUID      `json:"tenant_id"`
	RefID            uuid.UUID      `json:"ref_id"`
	NodeType         string         `json:"node_type"`
	Label            string         `json:"label"`
	RiskScore        float64        `json:"risk_score"`
	Criticality      int            `json:"criticality"`
	IsInternetFacing bool           `json:"is_internet_facing"`
	IsPrivileged     bool           `json:"is_privileged"`
	IsCriticalSystem bool           `json:"is_critical_system"`
	IsCompromised    bool           `json:"is_compromised"`
	HasCriticalVuln  bool           `json:"has_critical_vuln"`
	HasKnownExploit  bool           `json:"has_known_exploit"`
	OpenVulnCount    int            `json:"open_vuln_count"`
	NetworkZone      string         `json:"network_zone,omitempty"`
	IPAddress        string         `json:"ip_address,omitempty"`
	Hostname         string         `json:"hostname,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
	LastUpdatedAt    time.Time      `json:"last_updated_at"`
	CreatedAt        time.Time      `json:"created_at"`
}

// AttackEdge is a directed edge in the attack graph.
type AttackEdge struct {
	ID                  uuid.UUID      `json:"id"`
	TenantID            uuid.UUID      `json:"tenant_id"`
	SourceID            uuid.UUID      `json:"source_id"`
	TargetID            uuid.UUID      `json:"target_id"`
	EdgeType            string         `json:"edge_type"`
	AttackComplexity    string         `json:"attack_complexity"`
	PrivilegesRequired  string         `json:"privileges_required"`
	VulnID              *uuid.UUID     `json:"vuln_id,omitempty"`
	CVEID               string         `json:"cve_id,omitempty"`
	MitreTechnique      string         `json:"mitre_technique,omitempty"`
	Weight              float64        `json:"weight"`
	IsActive            bool           `json:"is_active"`
	EvidenceSource      string         `json:"evidence_source"`
	Properties          map[string]any `json:"properties,omitempty"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           time.Time      `json:"updated_at"`
}

// AttackScenario defines a simulation: entry points + high-value targets.
type AttackScenario struct {
	ID            uuid.UUID  `json:"id"`
	TenantID      uuid.UUID  `json:"tenant_id"`
	Name          string     `json:"name"`
	Description   string     `json:"description,omitempty"`
	EntryNodeIDs  []uuid.UUID `json:"entry_node_ids"`
	TargetNodeIDs []uuid.UUID `json:"target_node_ids"`
	MaxHops       int         `json:"max_hops"`
	IncludeTypes  []string    `json:"include_types"`
	Status        string      `json:"status"`
	PathCount     int         `json:"path_count"`
	ShortestPath  *int        `json:"shortest_path,omitempty"`
	CriticalPath  *int        `json:"critical_path,omitempty"`
	LastRunAt     *time.Time  `json:"last_run_at,omitempty"`
	LastRunMS     int         `json:"last_run_ms,omitempty"`
	RiskScore     float64     `json:"risk_score"`
	CreatedBy     *uuid.UUID  `json:"created_by,omitempty"`
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
}

// AttackPath is a discovered chain of nodes and edges from entry to target.
type AttackPath struct {
	ID                uuid.UUID   `json:"id"`
	TenantID          uuid.UUID   `json:"tenant_id"`
	ScenarioID        uuid.UUID   `json:"scenario_id"`
	EntryNodeID       uuid.UUID   `json:"entry_node_id"`
	TargetNodeID      uuid.UUID   `json:"target_node_id"`
	NodeSequence      []uuid.UUID `json:"node_sequence"`
	EdgeSequence      []uuid.UUID `json:"edge_sequence"`
	HopCount          int         `json:"hop_count"`
	PathScore         float64     `json:"path_score"`
	Likelihood        float64     `json:"likelihood"`
	Impact            float64     `json:"impact"`
	PathType          string      `json:"path_type"`
	HasInternetEntry  bool        `json:"has_internet_entry"`
	HasExploitStep    bool        `json:"has_exploit_step"`
	HasPrivEsc        bool        `json:"has_priv_esc"`
	MitreTactics      []string    `json:"mitre_tactics"`
	ChokePointNodeID  *uuid.UUID  `json:"choke_point_node_id,omitempty"`
	ChokePointEdgeID  *uuid.UUID  `json:"choke_point_edge_id,omitempty"`
	DiscoveredAt      time.Time   `json:"discovered_at"`
	// Enriched for API responses
	Nodes []AttackNode `json:"nodes,omitempty"`
	Edges []AttackEdge `json:"edges,omitempty"`
}

// AttackGraphStats is the dashboard summary.
type AttackGraphStats struct {
	TotalNodes          int     `json:"total_nodes"`
	TotalEdges          int     `json:"total_edges"`
	InternetFacingNodes int     `json:"internet_facing_nodes"`
	CriticalSystemNodes int     `json:"critical_system_nodes"`
	CompromisedNodes    int     `json:"compromised_nodes"`
	TotalScenarios      int     `json:"total_scenarios"`
	TotalPaths          int     `json:"total_paths"`
	HighRiskPaths       int     `json:"high_risk_paths"`   // path_score >= 7
	ShortestPath        int     `json:"shortest_path"`     // across all scenarios
	AvgPathLength       float64 `json:"avg_path_length"`
	PathsWithExploit    int     `json:"paths_with_exploit"`
	PathsWithPrivEsc    int     `json:"paths_with_priv_esc"`
}

// ChokePoint identifies the most impactful node/edge to remediate.
type ChokePoint struct {
	NodeID     uuid.UUID `json:"node_id"`
	Label      string    `json:"label"`
	PathsBlocked int     `json:"paths_blocked"`  // how many paths go through this node
	RiskReduction float64 `json:"risk_reduction"` // estimated risk score reduction
}

// ─── Request / filter models ──────────────────────────────────────────────────

type CreateNodeRequest struct {
	RefID            uuid.UUID      `json:"ref_id"      validate:"required"`
	NodeType         string         `json:"node_type"   validate:"required,oneof=asset identity service network cloud"`
	Label            string         `json:"label"       validate:"required,min=1"`
	RiskScore        float64        `json:"risk_score"  validate:"min=0,max=10"`
	Criticality      int            `json:"criticality" validate:"min=1,max=4"`
	IsInternetFacing bool           `json:"is_internet_facing"`
	IsPrivileged     bool           `json:"is_privileged"`
	IsCriticalSystem bool           `json:"is_critical_system"`
	HasCriticalVuln  bool           `json:"has_critical_vuln"`
	HasKnownExploit  bool           `json:"has_known_exploit"`
	OpenVulnCount    int            `json:"open_vuln_count"`
	NetworkZone      string         `json:"network_zone"`
	IPAddress        string         `json:"ip_address"`
	Hostname         string         `json:"hostname"`
	Properties       map[string]any `json:"properties"`
}

type CreateEdgeRequest struct {
	SourceID           uuid.UUID      `json:"source_id"            validate:"required"`
	TargetID           uuid.UUID      `json:"target_id"            validate:"required"`
	EdgeType           string         `json:"edge_type"            validate:"required"`
	AttackComplexity   string         `json:"attack_complexity"    validate:"omitempty,oneof=LOW MEDIUM HIGH"`
	PrivilegesRequired string         `json:"privileges_required"  validate:"omitempty,oneof=NONE LOW HIGH"`
	VulnID             *uuid.UUID     `json:"vuln_id"`
	CVEID              string         `json:"cve_id"`
	MitreTechnique     string         `json:"mitre_technique"`
	EvidenceSource     string         `json:"evidence_source"      validate:"omitempty,oneof=computed scan alert manual"`
	Properties         map[string]any `json:"properties"`
}

type CreateScenarioRequest struct {
	Name          string      `json:"name"            validate:"required,min=2,max=100"`
	Description   string      `json:"description"`
	EntryNodeIDs  []uuid.UUID `json:"entry_node_ids"  validate:"required,min=1"`
	TargetNodeIDs []uuid.UUID `json:"target_node_ids" validate:"required,min=1"`
	MaxHops       int         `json:"max_hops"        validate:"omitempty,min=1,max=20"`
	IncludeTypes  []string    `json:"include_types"`
}

type NodeFilter struct {
	TenantID         uuid.UUID
	NodeType         string
	NetworkZone      string
	IsInternetFacing *bool
	IsCriticalSystem *bool
	IsCompromised    *bool
	MinRisk          float64
	Limit            int
	Offset           int
}

type PathFilter struct {
	TenantID   uuid.UUID
	ScenarioID *uuid.UUID
	TargetID   *uuid.UUID
	MinScore   float64
	PathType   string
	Limit      int
	Offset     int
}
