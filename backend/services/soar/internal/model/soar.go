package model

import (
	"time"

	"github.com/google/uuid"
)

// ── Incident statuses ─────────────────────────────────────────────────────────
const (
	IncidentStatusOpen       = "open"
	IncidentStatusInProgress = "in_progress"
	IncidentStatusContained  = "contained"
	IncidentStatusResolved   = "resolved"
	IncidentStatusClosed     = "closed"
)

// ── Playbook trigger types ────────────────────────────────────────────────────
const (
	TriggerManual   = "manual"
	TriggerAlert    = "alert"
	TriggerIOCMatch = "ioc_match"
	TriggerAnomaly  = "anomaly"
	TriggerVuln     = "vuln"
	TriggerSchedule = "schedule"
)

// ── Action types ──────────────────────────────────────────────────────────────
const (
	ActionBlockIP          = "block_ip"
	ActionUnblockIP        = "unblock_ip"
	ActionDisableUser      = "disable_user"
	ActionEnableUser       = "enable_user"
	ActionIsolateHost      = "isolate_host"
	ActionUnisolateHost    = "unisolate_host"
	ActionEnrichIOC        = "enrich_ioc"
	ActionAddToBlocklist   = "add_to_blocklist"
	ActionCreateTicket     = "create_ticket"
	ActionCloseTicket      = "close_ticket"
	ActionSendNotification = "send_notification"
	ActionRunSIEMQuery     = "run_siem_query"
	ActionTagEntity        = "tag_entity"
	ActionMarkCompromised  = "mark_compromised"
	ActionCreateIncident   = "create_incident"
	ActionWait             = "wait"
)

// ── SLA durations by severity ─────────────────────────────────────────────────
var IncidentSLAHours = map[string]int{
	"CRITICAL": 4,
	"HIGH":     24,
	"MEDIUM":   72,
	"LOW":      168,
}

// ─── Core models ──────────────────────────────────────────────────────────────

// Incident is a security incident under investigation.
type Incident struct {
	ID              uuid.UUID      `json:"id"`
	TenantID        uuid.UUID      `json:"tenant_id"`
	Title           string         `json:"title"`
	Description     string         `json:"description,omitempty"`
	Severity        string         `json:"severity"`
	Status          string         `json:"status"`
	SourceService   string         `json:"source_service,omitempty"`
	SourceEventID   *uuid.UUID     `json:"source_event_id,omitempty"`
	AssigneeID      *uuid.UUID     `json:"assignee_id,omitempty"`
	MitreTactics    []string       `json:"mitre_tactics"`
	MitreTechniques []string       `json:"mitre_techniques"`
	AffectedAssets  []uuid.UUID    `json:"affected_assets"`
	IOCIDs          []uuid.UUID    `json:"ioc_ids"`
	Tags            []string       `json:"tags"`
	Properties      map[string]any `json:"properties,omitempty"`
	SLADueAt        *time.Time     `json:"sla_due_at,omitempty"`
	ContainedAt     *time.Time     `json:"contained_at,omitempty"`
	ResolvedAt      *time.Time     `json:"resolved_at,omitempty"`
	ClosedAt        *time.Time     `json:"closed_at,omitempty"`
	CreatedBy       *uuid.UUID     `json:"created_by,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

// IncidentEvent is a timeline entry for an incident.
type IncidentEvent struct {
	ID         uuid.UUID      `json:"id"`
	TenantID   uuid.UUID      `json:"tenant_id"`
	IncidentID uuid.UUID      `json:"incident_id"`
	EventType  string         `json:"event_type"`
	ActorID    *uuid.UUID     `json:"actor_id,omitempty"`
	ActorType  string         `json:"actor_type"`
	Details    map[string]any `json:"details,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
}

// Playbook defines automation logic triggered by security events.
type Playbook struct {
	ID                uuid.UUID      `json:"id"`
	TenantID          uuid.UUID      `json:"tenant_id"`
	Name              string         `json:"name"`
	Description       string         `json:"description,omitempty"`
	TriggerType       string         `json:"trigger_type"`
	TriggerConditions map[string]any `json:"trigger_conditions,omitempty"`
	IsActive          bool           `json:"is_active"`
	RunCount          int            `json:"run_count"`
	SuccessCount      int            `json:"success_count"`
	FailureCount      int            `json:"failure_count"`
	LastRunAt         *time.Time     `json:"last_run_at,omitempty"`
	Steps             []PlaybookStep `json:"steps,omitempty"`
	CreatedBy         *uuid.UUID     `json:"created_by,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}

// PlaybookStep is one action within a playbook.
type PlaybookStep struct {
	ID           uuid.UUID      `json:"id"`
	PlaybookID   uuid.UUID      `json:"playbook_id"`
	StepOrder    int            `json:"step_order"`
	Name         string         `json:"name"`
	ActionType   string         `json:"action_type"`
	ActionParams map[string]any `json:"action_params,omitempty"`
	OnFailure    string         `json:"on_failure"`
	RetryCount   int            `json:"retry_count"`
	TimeoutSec   int            `json:"timeout_sec"`
}

// Execution is a running or completed playbook instance.
type Execution struct {
	ID             uuid.UUID       `json:"id"`
	TenantID       uuid.UUID       `json:"tenant_id"`
	PlaybookID     uuid.UUID       `json:"playbook_id"`
	IncidentID     *uuid.UUID      `json:"incident_id,omitempty"`
	TriggerEvent   map[string]any  `json:"trigger_event,omitempty"`
	Status         string          `json:"status"`
	StepsTotal     int             `json:"steps_total"`
	StepsCompleted int             `json:"steps_completed"`
	StepsFailed    int             `json:"steps_failed"`
	ResultSummary  map[string]any  `json:"result_summary,omitempty"`
	ErrorMessage   string          `json:"error_message,omitempty"`
	TriggeredBy    *uuid.UUID      `json:"triggered_by,omitempty"`
	StartedAt      *time.Time      `json:"started_at,omitempty"`
	CompletedAt    *time.Time      `json:"completed_at,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	Steps          []ExecutionStep `json:"steps,omitempty"`
}

// ExecutionStep tracks the result of one step within an execution.
type ExecutionStep struct {
	ID           uuid.UUID      `json:"id"`
	ExecutionID  uuid.UUID      `json:"execution_id"`
	StepID       uuid.UUID      `json:"step_id"`
	StepOrder    int            `json:"step_order"`
	ActionType   string         `json:"action_type"`
	Status       string         `json:"status"`
	Output       map[string]any `json:"output,omitempty"`
	ErrorMessage string         `json:"error_message,omitempty"`
	Attempts     int            `json:"attempts"`
	StartedAt    *time.Time     `json:"started_at,omitempty"`
	CompletedAt  *time.Time     `json:"completed_at,omitempty"`
}

// SOARStats is the dashboard summary.
type SOARStats struct {
	OpenIncidents       int     `json:"open_incidents"`
	CriticalIncidents   int     `json:"critical_incidents"`
	InProgressIncidents int     `json:"in_progress_incidents"`
	ResolvedToday       int     `json:"resolved_today"`
	SLABreached         int     `json:"sla_breached"`
	TotalPlaybooks      int     `json:"total_playbooks"`
	ActivePlaybooks     int     `json:"active_playbooks"`
	ExecutionsToday     int     `json:"executions_today"`
	ExecutionSuccess    int     `json:"execution_success_today"`
	ExecutionFailed     int     `json:"execution_failed_today"`
	MeanTimeToContain   float64 `json:"mean_time_to_contain_hours"`
	MeanTimeToResolve   float64 `json:"mean_time_to_resolve_hours"`
}

// ── Request / filter models ───────────────────────────────────────────────────

type CreateIncidentRequest struct {
	Title           string         `json:"title"         validate:"required,min=3,max=300"`
	Description     string         `json:"description"`
	Severity        string         `json:"severity"      validate:"required,oneof=CRITICAL HIGH MEDIUM LOW"`
	SourceService   string         `json:"source_service" validate:"omitempty,oneof=siem ueba ti vuln attackpath manual"`
	SourceEventID   *uuid.UUID     `json:"source_event_id"`
	AssigneeID      *uuid.UUID     `json:"assignee_id"`
	MitreTactics    []string       `json:"mitre_tactics"`
	MitreTechniques []string       `json:"mitre_techniques"`
	AffectedAssets  []uuid.UUID    `json:"affected_assets"`
	IOCIDs          []uuid.UUID    `json:"ioc_ids"`
	Tags            []string       `json:"tags"`
	Properties      map[string]any `json:"properties"`
}

type UpdateIncidentRequest struct {
	Title       *string        `json:"title"`
	Description *string        `json:"description"`
	Severity    *string        `json:"severity"   validate:"omitempty,oneof=CRITICAL HIGH MEDIUM LOW"`
	Status      *string        `json:"status"     validate:"omitempty,oneof=open in_progress contained resolved closed"`
	AssigneeID  *uuid.UUID     `json:"assignee_id"`
	Tags        []string       `json:"tags"`
	Properties  map[string]any `json:"properties"`
	Note        string         `json:"note"` // appended to incident timeline
}

type CreatePlaybookRequest struct {
	Name              string                      `json:"name"         validate:"required,min=2,max=200"`
	Description       string                      `json:"description"`
	TriggerType       string                      `json:"trigger_type" validate:"required,oneof=manual alert ioc_match anomaly vuln schedule"`
	TriggerConditions map[string]any              `json:"trigger_conditions"`
	IsActive          bool                        `json:"is_active"`
	Steps             []CreatePlaybookStepRequest `json:"steps" validate:"required,min=1"`
}

type CreatePlaybookStepRequest struct {
	Name         string         `json:"name"        validate:"required,min=1,max=200"`
	ActionType   string         `json:"action_type" validate:"required,oneof=block_ip unblock_ip disable_user enable_user isolate_host unisolate_host enrich_ioc add_to_blocklist create_ticket close_ticket send_notification run_siem_query tag_entity mark_compromised create_incident wait"`
	ActionParams map[string]any `json:"action_params"`
	OnFailure    string         `json:"on_failure"  validate:"omitempty,oneof=abort continue retry"`
	RetryCount   int            `json:"retry_count" validate:"omitempty,min=0,max=5"`
	TimeoutSec   int            `json:"timeout_sec" validate:"omitempty,min=1,max=300"`
}

type RunPlaybookRequest struct {
	IncidentID   *uuid.UUID     `json:"incident_id"`
	TriggerEvent map[string]any `json:"trigger_event"`
}

type IncidentFilter struct {
	TenantID  uuid.UUID
	Status    string
	Severity  string
	Assignee  *uuid.UUID
	Source    string
	SLABreach bool // only overdue
	Limit     int
	Offset    int
}

type ExecutionFilter struct {
	TenantID   uuid.UUID
	PlaybookID *uuid.UUID
	IncidentID *uuid.UUID
	Status     string
	Limit      int
	Offset     int
}
