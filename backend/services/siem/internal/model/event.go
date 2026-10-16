package model

import (
	"time"

	"github.com/google/uuid"
)

// Event is one normalized event as the analyst reads it back.
//
// It mirrors crp_audit.cyber_events, which the pipeline fills. The platform
// wrote to that table from the first day and nothing ever read it: an analyst
// who received an alert could not look at what surrounded it. This type, and
// the search behind it, exist to close that.
type Event struct {
	EventID     uuid.UUID `json:"event_id"`
	TenantID    string    `json:"tenant_id"`
	Timestamp   time.Time `json:"timestamp"`
	IngestedAt  time.Time `json:"ingested_at"`
	Source      string    `json:"source"`
	SourceType  string    `json:"source_type"`
	ConnectorID string    `json:"connector_id,omitempty"`

	UserID        string `json:"user_id,omitempty"`
	UserName      string `json:"user_name,omitempty"`
	AssetHostname string `json:"asset_hostname,omitempty"`
	IPSource      string `json:"ip_source,omitempty"`
	IPDestination string `json:"ip_destination,omitempty"`
	GeoCountry    string `json:"geo_country,omitempty"`

	Action   string `json:"action,omitempty"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Outcome  string `json:"outcome"`

	ThreatScore    float32  `json:"threat_score"`
	RiskScore      float32  `json:"risk_score"`
	MitreTactic    string   `json:"mitre_tactic,omitempty"`
	MitreTechnique string   `json:"mitre_technique,omitempty"`
	IOCMatched     []string `json:"ioc_matched,omitempty"`

	BusinessService string `json:"business_service,omitempty"`
	CBSImpact       uint8  `json:"cbs_impact"`
	SWIFTImpact     uint8  `json:"swift_impact"`

	RawEvent string `json:"raw_event,omitempty"`
}

// Event search bounds.
//
// A search over cyber_events with no time bound is a full scan of every event
// the platform ever ingested, and one analyst running it stalls ingestion for
// everyone. So a window is not optional — it is defaulted, and it is capped.
const (
	// DefaultEventWindow is the window applied when the caller names no From.
	DefaultEventWindow = 24 * time.Hour
	// MaxEventWindow is the widest span a single search may cover.
	MaxEventWindow = 366 * 24 * time.Hour
	// DefaultEventLimit is the page size when none is given.
	DefaultEventLimit = 50
	// MaxEventLimit caps the page size a caller may ask for.
	MaxEventLimit = 500
)

// EventFilter is a search over the normalized events of one tenant.
//
// TenantID is not a filter the caller supplies — the handler takes it from the
// authenticated context. It is in this struct so the repository cannot build a
// query without one.
type EventFilter struct {
	TenantID uuid.UUID

	From *time.Time
	To   *time.Time

	// Text is matched case-insensitively inside raw_event. It is the only
	// filter here that cannot use an index, so it is the expensive one.
	Text string

	Category      string
	Severity      string
	Outcome       string
	SourceType    string
	Source        string
	Action        string
	UserID        string
	IPSource      string
	IPDestination string
	GeoCountry    string
	MitreTactic   string

	MinRiskScore   *float32
	MinThreatScore *float32

	// CBSImpact and SWIFTImpact select banking flows. Pointers because "not
	// asked" and "asked for zero" are different questions.
	CBSImpact   *uint8
	SWIFTImpact *uint8

	// IOCOnly keeps only events that matched a known indicator.
	IOCOnly bool

	Limit  int
	Offset int
}
