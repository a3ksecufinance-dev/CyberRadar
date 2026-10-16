package model

import (
	"time"

	"github.com/google/uuid"
)

// ── Entity types ──────────────────────────────────────────────────────────────

const (
	EntityTypeAsset         = "asset"
	EntityTypeIdentity      = "identity"
	EntityTypeIP            = "ip"
	EntityTypeDomain        = "domain"
	EntityTypeURL           = "url"
	EntityTypeHash          = "hash"
	EntityTypeVulnerability = "vulnerability"
	EntityTypeIOC           = "ioc"
	EntityTypeAlert         = "alert"
	EntityTypeIncident      = "incident"
	EntityTypeThreatActor   = "threat_actor"
	EntityTypeSoftware      = "software"
)

// ── Relationship types ────────────────────────────────────────────────────────

const (
	RelConnectTo        = "CONNECTS_TO"
	RelExploits         = "EXPLOITS"
	RelTargets          = "TARGETS"
	RelCommunicatesWith = "COMMUNICATES_WITH"
	RelBelongsTo        = "BELONGS_TO"
	RelResolvesTo       = "RESOLVES_TO"
	RelAssociatedWith   = "ASSOCIATED_WITH"
	RelAttributedTo     = "ATTRIBUTED_TO"
	RelMitigates        = "MITIGATES"
	RelHasVulnerability = "HAS_VULNERABILITY"
	RelIndicatorOf      = "INDICATOR_OF"
	RelUses             = "USES"
)

// ── Evidence sources ──────────────────────────────────────────────────────────

const (
	SourceSIEM       = "siem"
	SourceUEBA       = "ueba"
	SourceTI         = "ti"
	SourceVuln       = "vuln"
	SourceAttackPath = "attackpath"
	SourceCollector  = "collector"
	SourceManual     = "manual"
	SourceComputed   = "computed"
)

// ─── Core models ──────────────────────────────────────────────────────────────

// KGEntity is a vertex in the knowledge graph.
type KGEntity struct {
	ID          uuid.UUID      `json:"id"`
	TenantID    uuid.UUID      `json:"tenant_id"`
	EntityType  string         `json:"entity_type"`
	ExternalID  string         `json:"external_id,omitempty"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	RiskScore   float64        `json:"risk_score"`
	Confidence  float64        `json:"confidence"`
	Tags        []string       `json:"tags"`
	Properties  map[string]any `json:"properties,omitempty"`
	FirstSeenAt time.Time      `json:"first_seen_at"`
	LastSeenAt  time.Time      `json:"last_seen_at"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// KGRelationship is a directed typed edge between two entities.
type KGRelationship struct {
	ID               uuid.UUID      `json:"id"`
	TenantID         uuid.UUID      `json:"tenant_id"`
	SourceID         uuid.UUID      `json:"source_id"`
	TargetID         uuid.UUID      `json:"target_id"`
	RelationshipType string         `json:"relationship_type"`
	Weight           float64        `json:"weight"`
	Confidence       float64        `json:"confidence"`
	EvidenceSource   string         `json:"evidence_source,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
	ValidFrom        *time.Time     `json:"valid_from,omitempty"`
	ValidUntil       *time.Time     `json:"valid_until,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

// KGObservation is a timestamped event sighting for an entity.
type KGObservation struct {
	ID            uuid.UUID      `json:"id"`
	TenantID      uuid.UUID      `json:"tenant_id"`
	EntityID      uuid.UUID      `json:"entity_id"`
	ObservedAt    time.Time      `json:"observed_at"`
	SourceService string         `json:"source_service"`
	EventType     string         `json:"event_type"`
	Severity      string         `json:"severity,omitempty"`
	Description   string         `json:"description,omitempty"`
	Properties    map[string]any `json:"properties,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
}

// KGNeighbor is a traversal result: entity + the relationship leading to it.
type KGNeighbor struct {
	Entity       KGEntity       `json:"entity"`
	Relationship KGRelationship `json:"relationship"`
	Depth        int            `json:"depth"`
	Path         []uuid.UUID    `json:"path"` // entity IDs from root to this node
}

// KGSubgraph is the enriched graph returned for visualization.
type KGSubgraph struct {
	Entities      []KGEntity       `json:"entities"`
	Relationships []KGRelationship `json:"relationships"`
}

// EnrichedEntity bundles an entity with its neighbors and recent observations.
type EnrichedEntity struct {
	Entity       KGEntity        `json:"entity"`
	Neighbors    []KGNeighbor    `json:"neighbors"`
	Observations []KGObservation `json:"observations"`
}

// KGStats is the dashboard summary for the knowledge graph.
type KGStats struct {
	TotalEntities      int            `json:"total_entities"`
	EntitiesByType     map[string]int `json:"entities_by_type"`
	TotalRelationships int            `json:"total_relationships"`
	RelsByType         map[string]int `json:"relationships_by_type"`
	TotalObservations  int            `json:"total_observations"`
	HighRiskEntities   int            `json:"high_risk_entities"`  // risk_score >= 7
	RecentObservations int            `json:"recent_observations"` // last 24h
}

// ── Request / filter models ───────────────────────────────────────────────────

type UpsertEntityRequest struct {
	EntityType  string         `json:"entity_type"  validate:"required,oneof=asset identity ip domain url hash vulnerability ioc alert incident threat_actor software"`
	ExternalID  string         `json:"external_id"`
	Name        string         `json:"name"         validate:"required,min=1,max=500"`
	Description string         `json:"description"`
	RiskScore   float64        `json:"risk_score"   validate:"min=0,max=10"`
	Confidence  float64        `json:"confidence"   validate:"min=0,max=1"`
	Tags        []string       `json:"tags"`
	Properties  map[string]any `json:"properties"`
}

type UpdateEntityRequest struct {
	Name        *string        `json:"name"`
	Description *string        `json:"description"`
	RiskScore   *float64       `json:"risk_score"  validate:"omitempty,min=0,max=10"`
	Confidence  *float64       `json:"confidence"  validate:"omitempty,min=0,max=1"`
	Tags        []string       `json:"tags"`
	Properties  map[string]any `json:"properties"`
}

type UpsertRelationshipRequest struct {
	SourceID         uuid.UUID      `json:"source_id"         validate:"required"`
	TargetID         uuid.UUID      `json:"target_id"         validate:"required"`
	RelationshipType string         `json:"relationship_type" validate:"required,oneof=CONNECTS_TO EXPLOITS TARGETS COMMUNICATES_WITH BELONGS_TO RESOLVES_TO ASSOCIATED_WITH ATTRIBUTED_TO MITIGATES HAS_VULNERABILITY INDICATOR_OF USES"`
	Weight           float64        `json:"weight"            validate:"omitempty,min=0"`
	Confidence       float64        `json:"confidence"        validate:"omitempty,min=0,max=1"`
	EvidenceSource   string         `json:"evidence_source"   validate:"omitempty,oneof=siem ueba ti vuln attackpath collector manual computed"`
	Properties       map[string]any `json:"properties"`
	ValidFrom        *time.Time     `json:"valid_from"`
	ValidUntil       *time.Time     `json:"valid_until"`
}

type CreateObservationRequest struct {
	EntityID      uuid.UUID      `json:"entity_id"      validate:"required"`
	ObservedAt    *time.Time     `json:"observed_at"`
	SourceService string         `json:"source_service" validate:"required,oneof=siem ueba ti vuln attackpath collector manual"`
	EventType     string         `json:"event_type"     validate:"required,min=1,max=100"`
	Severity      string         `json:"severity"       validate:"omitempty,oneof=CRITICAL HIGH MEDIUM LOW INFO"`
	Description   string         `json:"description"`
	Properties    map[string]any `json:"properties"`
}

type EntityFilter struct {
	TenantID   uuid.UUID
	EntityType string
	Search     string // name ILIKE
	MinRisk    float64
	Tags       []string
	Limit      int
	Offset     int
}

type ObservationFilter struct {
	TenantID      uuid.UUID
	EntityID      uuid.UUID
	SourceService string
	Severity      string
	Since         *time.Time
	Limit         int
	Offset        int
}

type NeighborQuery struct {
	TenantID  uuid.UUID
	EntityID  uuid.UUID
	MaxHops   int    // 1-5
	Direction string // "outbound", "inbound", "both"
	RelTypes  []string
}

type EnrichQuery struct {
	TenantID   uuid.UUID
	EntityType string `validate:"required"`
	Name       string `validate:"required,min=1"`
}
