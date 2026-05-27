package event

import (
	"time"

	"github.com/google/uuid"
)

// Topic constants — all CRP Kafka topics.
const (
	TopicRaw        = "crp.events.raw"
	TopicNormalized = "crp.events.normalized"
	TopicEnriched   = "crp.events.enriched"
	TopicAlerts     = "crp.events.alerts"
	TopicDLQ        = "crp.events.dlq"
)

// Category classifies the event domain.
type Category string

const (
	CategorySecurity    Category = "Security"
	CategoryFraud       Category = "Fraud"
	CategoryNetwork     Category = "Network"
	CategoryIAM         Category = "IAM"
	CategoryCompliance  Category = "Compliance"
	CategoryTransaction Category = "Transaction"
	CategoryOther       Category = "Other"
)

// Severity is the event severity level.
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Outcome is the event outcome.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeUnknown Outcome = "unknown"
)

// Format is the raw event format type.
type Format string

const (
	FormatJSON      Format = "json"
	FormatCEF       Format = "cef"
	FormatSyslog    Format = "syslog"
	FormatLEEF      Format = "leef"
	FormatWinEvent  Format = "winevent"
	FormatNetflow   Format = "netflow"
	FormatCLF       Format = "clf" // Common Log Format (Apache/Nginx)
)

// ─── Raw Event ───────────────────────────────────────────────────────────────

// RawEvent is an event exactly as received from a source, before normalization.
type RawEvent struct {
	ID          uuid.UUID `json:"id"`
	TenantID    string    `json:"tenant_id"`
	ConnectorID string    `json:"connector_id"`
	Source      string    `json:"source"`       // hostname, IP, or service name
	SourceType  string    `json:"source_type"`  // firewall, edr, iam, cbs, atm, etc.
	Format      Format    `json:"format"`
	ReceivedAt  time.Time `json:"received_at"`
	Raw         string    `json:"raw"` // original payload (UTF-8)
}

// ─── CRP Common Event Format (normalized) ────────────────────────────────────

// NormalizedEvent is the CRP canonical event format after normalization.
// All fields use snake_case JSON. Nullable fields use pointers.
type NormalizedEvent struct {
	// Core identity
	EventID     uuid.UUID `json:"event_id"`
	TenantID    string    `json:"tenant_id"`
	Timestamp   time.Time `json:"timestamp"`
	IngestedAt  time.Time `json:"ingested_at"`
	SchemaVersion uint8   `json:"schema_version"`

	// Lineage
	ConnectorID string `json:"connector_id"`
	Source      string `json:"source"`
	SourceType  string `json:"source_type"`
	RawEventID  string `json:"raw_event_id,omitempty"`

	// Identity context
	UserID         *string  `json:"user_id,omitempty"`
	UserName       *string  `json:"user_name,omitempty"`
	UserEmail      *string  `json:"user_email,omitempty"`
	UserDepartment *string  `json:"user_department,omitempty"`
	UserRiskScore  *float32 `json:"user_risk_score,omitempty"`

	// Asset context
	AssetID          *string  `json:"asset_id,omitempty"`
	AssetHostname    *string  `json:"asset_hostname,omitempty"`
	AssetType        *string  `json:"asset_type,omitempty"`
	AssetCriticality *float32 `json:"asset_criticality,omitempty"`

	// Network context
	IPSource      *string `json:"ip_source,omitempty"`
	IPDestination *string `json:"ip_destination,omitempty"`
	PortSource    *uint16 `json:"port_source,omitempty"`
	PortDest      *uint16 `json:"port_dest,omitempty"`

	// Classification
	Action   string   `json:"action"`
	Category Category `json:"category"`
	Severity Severity `json:"severity"`
	Outcome  Outcome  `json:"outcome"`

	// Threat enrichment (populated by pipeline)
	ThreatScore     float32  `json:"threat_score"`
	MitreTactic     *string  `json:"mitre_tactic,omitempty"`
	MitreTechnique  *string  `json:"mitre_technique,omitempty"`
	IOCMatched      []string `json:"ioc_matched,omitempty"`
	GeoCountry      *string  `json:"geo_country,omitempty"`
	GeoASN          *string  `json:"geo_asn,omitempty"`

	// Risk
	RiskScore float32 `json:"risk_score"`

	// Business context
	BusinessService *string `json:"business_service,omitempty"`
	CBSImpact       uint8   `json:"cbs_impact"`
	SWIFTImpact     uint8   `json:"swift_impact"`

	// Original payload
	RawEvent string `json:"raw_event"`
}

// IsHighRisk returns true if the event should trigger immediate alerting.
func (e *NormalizedEvent) IsHighRisk() bool {
	return e.Severity == SeverityCritical || e.Severity == SeverityHigh || e.RiskScore >= 7.0
}

// ─── DLQ envelope ────────────────────────────────────────────────────────────

// DLQMessage wraps a failed event with error context for the dead letter queue.
type DLQMessage struct {
	OriginalTopic string    `json:"original_topic"`
	Offset        int64     `json:"offset"`
	Partition     int       `json:"partition"`
	Payload       []byte    `json:"payload"`
	Error         string    `json:"error"`
	FailedAt      time.Time `json:"failed_at"`
	TenantID      string    `json:"tenant_id"`
}
