package model

import (
	"time"

	"github.com/google/uuid"
)

// Entity types
const (
	EntityTypeUser  = "user"
	EntityTypeAsset = "asset"
)

// Anomaly types
const (
	AnomalyOffHoursAccess   = "OFF_HOURS_ACCESS"
	AnomalyNewCountry       = "NEW_COUNTRY"
	AnomalyNewIPPrefix      = "NEW_IP_PREFIX"
	AnomalyVelocitySpike    = "VELOCITY_SPIKE"
	AnomalyPrivEscalation   = "PRIVILEGE_ESCALATION"
	AnomalyLateralMovement  = "LATERAL_MOVEMENT"
	AnomalyDataExfiltration = "DATA_EXFILTRATION"
	AnomalyBruteForce       = "BRUTE_FORCE"
)

// Anomaly statuses
const (
	AnomalyStatusOpen          = "open"
	AnomalyStatusAcknowledged  = "acknowledged"
	AnomalyStatusResolved      = "resolved"
	AnomalyStatusFalsePositive = "false_positive"
)

// Severity levels (matching SIEM convention)
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// EntityProfile holds the learned behavioral baseline and risk scores for one entity.
type EntityProfile struct {
	ID               uuid.UUID  `json:"id"`
	TenantID         uuid.UUID  `json:"tenant_id"`
	EntityID         uuid.UUID  `json:"entity_id"`
	EntityType       string     `json:"entity_type"`
	NormalHours      []int32    `json:"normal_hours"` // UTC hours seen (0-23)
	NormalCountries  []string   `json:"normal_countries"`
	NormalIPPrefixes []string   `json:"normal_ip_prefixes"` // /24 CIDR blocks
	NormalEventTypes []string   `json:"normal_event_types"`
	RiskScore        float64    `json:"risk_score"`
	LoginScore       float64    `json:"login_score"`
	AccessScore      float64    `json:"access_score"`
	DataScore        float64    `json:"data_score"`
	PeerScore        float64    `json:"peer_score"`
	TemporalScore    float64    `json:"temporal_score"`
	EventCount       int        `json:"event_count"`
	AnomalyCount     int        `json:"anomaly_count"`
	LastSeenAt       *time.Time `json:"last_seen_at,omitempty"`
	BaselineReady    bool       `json:"baseline_ready"`
	PeerGroupID      *uuid.UUID `json:"peer_group_id,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// Anomaly is a detected behavioral deviation.
type Anomaly struct {
	ID            uuid.UUID      `json:"id"`
	TenantID      uuid.UUID      `json:"tenant_id"`
	EntityID      uuid.UUID      `json:"entity_id"`
	EntityType    string         `json:"entity_type"`
	AnomalyType   string         `json:"anomaly_type"`
	Severity      string         `json:"severity"`
	Score         float64        `json:"score"`
	BaselineVal   string         `json:"baseline_val,omitempty"`
	ObservedVal   string         `json:"observed_val,omitempty"`
	Details       map[string]any `json:"details,omitempty"`
	SourceEventID *uuid.UUID     `json:"source_event_id,omitempty"`
	Status        string         `json:"status"`
	AssigneeID    *uuid.UUID     `json:"assignee_id,omitempty"`
	Notes         string         `json:"notes,omitempty"`
	DetectedAt    time.Time      `json:"detected_at"`
	ResolvedAt    *time.Time     `json:"resolved_at,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

// BehaviorEvent is the ClickHouse record for one behavioral data point.
type BehaviorEvent struct {
	EventID    uuid.UUID      `json:"event_id"`
	TenantID   string         `json:"tenant_id"`
	EntityID   string         `json:"entity_id"`
	EntityType string         `json:"entity_type"`
	EventType  string         `json:"event_type"`
	SourceType string         `json:"source_type"`
	Action     string         `json:"action"`
	Outcome    string         `json:"outcome"`
	IPSource   string         `json:"ip_source"`
	GeoCountry string         `json:"geo_country"`
	RiskScore  float32        `json:"risk_score"`
	HourOfDay  uint8          `json:"hour_of_day"`
	DayOfWeek  uint8          `json:"day_of_week"`
	Attributes map[string]any `json:"attributes,omitempty"`
	EventTime  time.Time      `json:"event_time"`
}

// PeerGroup groups entities with similar roles for peer-comparison analysis.
type PeerGroup struct {
	ID           uuid.UUID      `json:"id"`
	TenantID     uuid.UUID      `json:"tenant_id"`
	Name         string         `json:"name"`
	Description  string         `json:"description,omitempty"`
	Criteria     map[string]any `json:"criteria"`
	AvgRiskScore float64        `json:"avg_risk_score"`
	MemberCount  int            `json:"member_count"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
}

// UEBAStats is the dashboard summary.
type UEBAStats struct {
	TotalProfiles    int              `json:"total_profiles"`
	HighRiskEntities int              `json:"high_risk_entities"`
	OpenAnomalies    int              `json:"open_anomalies"`
	AnomaliesLast24h int              `json:"anomalies_last_24h"`
	AnomaliesLast7d  int              `json:"anomalies_last_7d"`
	ByAnomalyType    map[string]int   `json:"by_anomaly_type"`
	BySeverity       map[string]int   `json:"by_severity"`
	TopRiskyEntities []*EntityProfile `json:"top_risky_entities"`
}

// ─── Request / filter models ──────────────────────────────────────────────────

type AnomalyFilter struct {
	TenantID    uuid.UUID
	EntityID    *uuid.UUID
	Status      string
	Severity    string
	AnomalyType string
	From        *time.Time
	To          *time.Time
	Limit       int
	Offset      int
}

type ProfileFilter struct {
	TenantID      uuid.UUID
	EntityType    string
	MinRisk       float64
	BaselineReady *bool
	Limit         int
	Offset        int
}

type UpdateAnomalyRequest struct {
	Status     *string    `json:"status"      validate:"omitempty,oneof=open acknowledged resolved false_positive"`
	AssigneeID *uuid.UUID `json:"assignee_id"`
	Notes      *string    `json:"notes"`
}

type CreatePeerGroupRequest struct {
	Name        string         `json:"name"        validate:"required,min=2,max=100"`
	Description string         `json:"description"`
	Criteria    map[string]any `json:"criteria"`
}
