package model

import (
	"time"

	"github.com/google/uuid"
)

// AlertStatus tracks alert lifecycle in PostgreSQL.
type AlertStatus string

const (
	AlertOpen          AlertStatus = "open"
	AlertAcknowledged  AlertStatus = "acknowledged"
	AlertInProgress    AlertStatus = "in_progress"
	AlertClosed        AlertStatus = "closed"
	AlertFalsePositive AlertStatus = "false_positive"
	AlertSuppressed    AlertStatus = "suppressed"
)

// CaseStatus tracks incident lifecycle.
type CaseStatus string

const (
	CaseOpen         CaseStatus = "open"
	CaseInProgress   CaseStatus = "in_progress"
	CasePending      CaseStatus = "pending"
	CaseResolved     CaseStatus = "resolved"
	CaseClosed       CaseStatus = "closed"
	CaseFalsePositive CaseStatus = "false_positive"
)

// ─── Alert ────────────────────────────────────────────────────────────────────

// Alert is a fired detection rule event (stored in ClickHouse).
type Alert struct {
	AlertID        uuid.UUID  `json:"alert_id"`
	TenantID       string     `json:"tenant_id"`
	RuleID         string     `json:"rule_id"`
	RuleName       string     `json:"rule_name"`
	Severity       Severity   `json:"severity"`
	Category       string     `json:"category"`
	MitreTactic    string     `json:"mitre_tactic,omitempty"`
	MitreTechnique string     `json:"mitre_technique,omitempty"`
	EntityType     string     `json:"entity_type"`
	EntityValue    string     `json:"entity_value"`
	SourceEventID  string     `json:"source_event_id,omitempty"`
	UserID         string     `json:"user_id,omitempty"`
	IPSource       string     `json:"ip_source,omitempty"`
	IPDestination  string     `json:"ip_destination,omitempty"`
	Title          string     `json:"title"`
	Description    string     `json:"description"`
	RawEvidence    string     `json:"raw_evidence,omitempty"`
	DedupKey       string     `json:"dedup_key"`
	EventTime      time.Time  `json:"event_time"`
	DetectedAt     time.Time  `json:"detected_at"`
	EventCount     uint32     `json:"event_count"`
	RiskScore      float32    `json:"risk_score"`

	// Joined from PostgreSQL alert_metadata
	Status     AlertStatus `json:"status,omitempty"`
	AssigneeID *uuid.UUID  `json:"assignee_id,omitempty"`
	CaseID     *uuid.UUID  `json:"case_id,omitempty"`
	Notes      string      `json:"notes,omitempty"`
}

// AlertMetadata is the mutable state of an alert (PostgreSQL).
type AlertMetadata struct {
	AlertID    uuid.UUID   `json:"alert_id"`
	TenantID   uuid.UUID   `json:"tenant_id"`
	RuleID     *uuid.UUID  `json:"rule_id,omitempty"`
	Status     AlertStatus `json:"status"`
	AssigneeID *uuid.UUID  `json:"assignee_id,omitempty"`
	CaseID     *uuid.UUID  `json:"case_id,omitempty"`
	Notes      string      `json:"notes,omitempty"`
	CreatedAt  time.Time   `json:"created_at"`
	UpdatedAt  time.Time   `json:"updated_at"`
}

// UpdateAlertRequest updates alert status/assignment.
type UpdateAlertRequest struct {
	Status     *AlertStatus `json:"status"      validate:"omitempty,oneof=open acknowledged in_progress closed false_positive suppressed"`
	AssigneeID *uuid.UUID   `json:"assignee_id"`
	Notes      *string      `json:"notes"`
}

// AlertFilter for listing alerts.
type AlertFilter struct {
	TenantID   uuid.UUID
	RuleID     string
	Severity   string
	Status     string
	EntityType string
	Search     string
	From       *time.Time
	To         *time.Time
	Limit      int
	Offset     int
}

// AlertStats summarises alert volume.
type AlertStats struct {
	Total          int            `json:"total"`
	Open           int            `json:"open"`
	BySeverity     map[string]int `json:"by_severity"`
	ByCategory     map[string]int `json:"by_category"`
	TopRules       []RuleStat     `json:"top_rules"`
	FiredLast24h   int            `json:"fired_last_24h"`
	FiredLast7d    int            `json:"fired_last_7d"`
}

// RuleStat is a per-rule alert count entry.
type RuleStat struct {
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Count    int    `json:"count"`
}

// ─── Cases ────────────────────────────────────────────────────────────────────

// Case is a security incident case.
type Case struct {
	ID             uuid.UUID  `json:"id"`
	TenantID       uuid.UUID  `json:"tenant_id"`
	Title          string     `json:"title"`
	Description    string     `json:"description,omitempty"`
	Severity       Severity   `json:"severity"`
	Status         CaseStatus `json:"status"`
	Priority       int        `json:"priority"`
	AssigneeID     *uuid.UUID `json:"assignee_id,omitempty"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	MitreTactic    string     `json:"mitre_tactic,omitempty"`
	MitreTechnique string     `json:"mitre_technique,omitempty"`
	OpenedAt       time.Time  `json:"opened_at"`
	DueAt          *time.Time `json:"due_at,omitempty"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	ClosedAt       *time.Time `json:"closed_at,omitempty"`
	AlertCount     int        `json:"alert_count"`
	MTTRSeconds    *int       `json:"mttr_seconds,omitempty"`
	Tags           []string   `json:"tags"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// CaseComment is a timeline entry on a case.
type CaseComment struct {
	ID         uuid.UUID `json:"id"`
	TenantID   uuid.UUID `json:"tenant_id"`
	CaseID     uuid.UUID `json:"case_id"`
	AuthorID   *uuid.UUID `json:"author_id,omitempty"`
	Comment    string    `json:"comment"`
	IsInternal bool      `json:"is_internal"`
	CreatedAt  time.Time `json:"created_at"`
}

// Observable is an IOC linked to a case.
type Observable struct {
	ID        uuid.UUID `json:"id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	CaseID    uuid.UUID `json:"case_id"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	TLP       int       `json:"tlp"`
	IsIOC     bool      `json:"is_ioc"`
	Notes     string    `json:"notes,omitempty"`
	AddedBy   *uuid.UUID `json:"added_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateCaseRequest is the payload to open a new case.
type CreateCaseRequest struct {
	Title          string     `json:"title"    validate:"required,min=5,max=512"`
	Description    string     `json:"description"`
	Severity       Severity   `json:"severity" validate:"required,oneof=LOW MEDIUM HIGH CRITICAL"`
	Priority       int        `json:"priority" validate:"min=1,max=4"`
	AssigneeID     *uuid.UUID `json:"assignee_id"`
	MitreTactic    string     `json:"mitre_tactic"`
	MitreTechnique string     `json:"mitre_technique"`
	DueAt          *time.Time `json:"due_at"`
	Tags           []string   `json:"tags"`
	AlertIDs       []uuid.UUID `json:"alert_ids"` // alerts to link
}

// UpdateCaseRequest allows partial case updates.
type UpdateCaseRequest struct {
	Title          *string     `json:"title"`
	Description    *string     `json:"description"`
	Severity       *Severity   `json:"severity"`
	Status         *CaseStatus `json:"status"`
	Priority       *int        `json:"priority"`
	AssigneeID     *uuid.UUID  `json:"assignee_id"`
	DueAt          *time.Time  `json:"due_at"`
	Tags           []string    `json:"tags"`
}

// AddCommentRequest adds a timeline entry.
type AddCommentRequest struct {
	Comment    string `json:"comment"     validate:"required,min=1,max=10000"`
	IsInternal bool   `json:"is_internal"`
}

// AddObservableRequest links an observable to a case.
type AddObservableRequest struct {
	Type  string `json:"type"  validate:"required,oneof=ip domain hash_md5 hash_sha256 url email user"`
	Value string `json:"value" validate:"required,min=1,max=1024"`
	TLP   int    `json:"tlp"   validate:"min=0,max=4"`
	IsIOC bool   `json:"is_ioc"`
	Notes string `json:"notes"`
}

// CaseFilter for listing cases.
type CaseFilter struct {
	TenantID   uuid.UUID
	Status     string
	Severity   string
	AssigneeID *uuid.UUID
	Limit      int
	Offset     int
}
