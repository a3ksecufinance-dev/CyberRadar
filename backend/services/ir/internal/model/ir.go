package model

import (
	"time"

	"github.com/google/uuid"
)

// ─── Playbooks ────────────────────────────────────────────────────────────────

type IRPlaybook struct {
	ID             uuid.UUID  `json:"id"`
	TenantID       uuid.UUID  `json:"tenant_id"`
	Name           string     `json:"name"`
	Description    string     `json:"description,omitempty"`
	IncidentType   string     `json:"incident_type"`
	Severity       string     `json:"severity"`
	Tasks          []any      `json:"tasks"`
	EstimatedHours int        `json:"estimated_hours"`
	IsActive       bool       `json:"is_active"`
	Version        int        `json:"version"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type CreatePlaybookRequest struct {
	Name           string `json:"name"`
	Description    string `json:"description"`
	IncidentType   string `json:"incident_type"`
	Severity       string `json:"severity"`
	Tasks          []any  `json:"tasks"`
	EstimatedHours int    `json:"estimated_hours"`
}

type UpdatePlaybookRequest struct {
	Name           *string `json:"name"`
	Description    *string `json:"description"`
	Severity       *string `json:"severity"`
	Tasks          []any   `json:"tasks"`
	EstimatedHours *int    `json:"estimated_hours"`
	IsActive       *bool   `json:"is_active"`
}

// ─── Incidents ────────────────────────────────────────────────────────────────

type IRIncident struct {
	ID                   uuid.UUID  `json:"id"`
	TenantID             uuid.UUID  `json:"tenant_id"`
	IncidentNumber       string     `json:"incident_number"`
	Title                string     `json:"title"`
	Description          string     `json:"description,omitempty"`
	IncidentType         string     `json:"incident_type"`
	Severity             string     `json:"severity"`
	Status               string     `json:"status"`
	Priority             int        `json:"priority"`
	Source               string     `json:"source,omitempty"`
	SourceRef            string     `json:"source_ref,omitempty"`
	AffectedSystems      []string   `json:"affected_systems"`
	AffectedUsers        []string   `json:"affected_users"`
	AffectedData         []string   `json:"affected_data"`
	IsContained          bool       `json:"is_contained"`
	DataExfiltrated      bool       `json:"data_exfiltrated"`
	EstimatedImpact      string     `json:"estimated_impact,omitempty"`
	AttackVector         string     `json:"attack_vector,omitempty"`
	IOCs                 []any      `json:"iocs"`
	MITRETactics         []string   `json:"mitre_tactics"`
	MITRETechniques      []string   `json:"mitre_techniques"`
	LeadID               *uuid.UUID `json:"lead_id,omitempty"`
	LeadName             string     `json:"lead_name,omitempty"`
	TeamMembers          []string   `json:"team_members"`
	PlaybookID           *uuid.UUID `json:"playbook_id,omitempty"`
	DetectedAt           time.Time  `json:"detected_at"`
	ReportedAt           *time.Time `json:"reported_at,omitempty"`
	ContainedAt          *time.Time `json:"contained_at,omitempty"`
	EradicatedAt         *time.Time `json:"eradicated_at,omitempty"`
	RecoveredAt          *time.Time `json:"recovered_at,omitempty"`
	ClosedAt             *time.Time `json:"closed_at,omitempty"`
	MTTDMinutes          *int       `json:"mttd_minutes,omitempty"`
	MTTRMinutes          *int       `json:"mttr_minutes,omitempty"`
	RequiresNotification bool       `json:"requires_notification"`
	NotificationSentAt   *time.Time `json:"notification_sent_at,omitempty"`
	Tags                 []string   `json:"tags"`
	CreatedBy            *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
	// Computed
	TaskCount     int `json:"task_count,omitempty"`
	TimelineCount int `json:"timeline_count,omitempty"`
	EvidenceCount int `json:"evidence_count,omitempty"`
}

type CreateIncidentRequest struct {
	Title           string     `json:"title"`
	Description     string     `json:"description"`
	IncidentType    string     `json:"incident_type"`
	Severity        string     `json:"severity"`
	Priority        int        `json:"priority"`
	Source          string     `json:"source"`
	SourceRef       string     `json:"source_ref"`
	AffectedSystems []string   `json:"affected_systems"`
	AffectedUsers   []string   `json:"affected_users"`
	AffectedData    []string   `json:"affected_data"`
	AttackVector    string     `json:"attack_vector"`
	PlaybookID      *uuid.UUID `json:"playbook_id"`
	DetectedAt      *time.Time `json:"detected_at"`
	Tags            []string   `json:"tags"`
}

type UpdateIncidentRequest struct {
	Title                *string    `json:"title"`
	Description          *string    `json:"description"`
	Severity             *string    `json:"severity"`
	Status               *string    `json:"status"`
	Priority             *int       `json:"priority"`
	IsContained          *bool      `json:"is_contained"`
	DataExfiltrated      *bool      `json:"data_exfiltrated"`
	EstimatedImpact      *string    `json:"estimated_impact"`
	AttackVector         *string    `json:"attack_vector"`
	IOCs                 []any      `json:"iocs"`
	MITRETactics         []string   `json:"mitre_tactics"`
	MITRETechniques      []string   `json:"mitre_techniques"`
	LeadID               *uuid.UUID `json:"lead_id"`
	LeadName             *string    `json:"lead_name"`
	TeamMembers          []string   `json:"team_members"`
	AffectedSystems      []string   `json:"affected_systems"`
	AffectedUsers        []string   `json:"affected_users"`
	RequiresNotification *bool      `json:"requires_notification"`
	Tags                 []string   `json:"tags"`
}

type ListIncidentsFilter struct {
	Status       string
	Severity     string
	IncidentType string
	Limit        int
	Offset       int
}

// ─── Timeline ─────────────────────────────────────────────────────────────────

type IRTimeline struct {
	ID           uuid.UUID  `json:"id"`
	TenantID     uuid.UUID  `json:"tenant_id"`
	IncidentID   uuid.UUID  `json:"incident_id"`
	EventTime    time.Time  `json:"event_time"`
	EventType    string     `json:"event_type"`
	Title        string     `json:"title"`
	Description  string     `json:"description,omitempty"`
	Actor        string     `json:"actor,omitempty"`
	ActorType    string     `json:"actor_type"`
	SourceSystem string     `json:"source_system,omitempty"`
	IOCs         []string   `json:"iocs"`
	EvidenceRefs []string   `json:"evidence_refs"`
	IsVerified   bool       `json:"is_verified"`
	CreatedBy    *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

type CreateTimelineEventRequest struct {
	EventTime    time.Time `json:"event_time"`
	EventType    string    `json:"event_type"`
	Title        string    `json:"title"`
	Description  string    `json:"description"`
	Actor        string    `json:"actor"`
	ActorType    string    `json:"actor_type"`
	SourceSystem string    `json:"source_system"`
	IOCs         []string  `json:"iocs"`
	IsVerified   bool      `json:"is_verified"`
}

// ─── Tasks ────────────────────────────────────────────────────────────────────

type IRTask struct {
	ID             uuid.UUID  `json:"id"`
	TenantID       uuid.UUID  `json:"tenant_id"`
	IncidentID     uuid.UUID  `json:"incident_id"`
	Title          string     `json:"title"`
	Description    string     `json:"description,omitempty"`
	TaskType       string     `json:"task_type"`
	Phase          string     `json:"phase"`
	Status         string     `json:"status"`
	Priority       int        `json:"priority"`
	AssignedTo     string     `json:"assigned_to,omitempty"`
	AssignedID     *uuid.UUID `json:"assigned_id,omitempty"`
	DueAt          *time.Time `json:"due_at,omitempty"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
	CompletionNote string     `json:"completion_note,omitempty"`
	OrderIdx       int        `json:"order_idx"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type CreateTaskRequest struct {
	Title       string     `json:"title"`
	Description string     `json:"description"`
	TaskType    string     `json:"task_type"`
	Phase       string     `json:"phase"`
	Priority    int        `json:"priority"`
	AssignedTo  string     `json:"assigned_to"`
	AssignedID  *uuid.UUID `json:"assigned_id"`
	DueAt       *time.Time `json:"due_at"`
	OrderIdx    int        `json:"order_idx"`
}

type UpdateTaskRequest struct {
	Status         *string    `json:"status"`
	AssignedTo     *string    `json:"assigned_to"`
	AssignedID     *uuid.UUID `json:"assigned_id"`
	DueAt          *time.Time `json:"due_at"`
	CompletionNote *string    `json:"completion_note"`
	Priority       *int       `json:"priority"`
}

// ─── Evidence ─────────────────────────────────────────────────────────────────

type IREvidence struct {
	ID               uuid.UUID      `json:"id"`
	TenantID         uuid.UUID      `json:"tenant_id"`
	IncidentID       uuid.UUID      `json:"incident_id"`
	Name             string         `json:"name"`
	Description      string         `json:"description,omitempty"`
	EvidenceType     string         `json:"evidence_type"`
	FileName         string         `json:"file_name,omitempty"`
	FileSize         *int64         `json:"file_size,omitempty"`
	FileHashMD5      string         `json:"file_hash_md5,omitempty"`
	FileHashSHA256   string         `json:"file_hash_sha256,omitempty"`
	StoragePath      string         `json:"storage_path,omitempty"`
	CollectedBy      string         `json:"collected_by,omitempty"`
	CollectedAt      time.Time      `json:"collected_at"`
	CollectionMethod string         `json:"collection_method,omitempty"`
	Status           string         `json:"status"`
	AnalysisNotes    string         `json:"analysis_notes,omitempty"`
	AnalyzedBy       string         `json:"analyzed_by,omitempty"`
	AnalyzedAt       *time.Time     `json:"analyzed_at,omitempty"`
	IsSensitive      bool           `json:"is_sensitive"`
	Tags             []string       `json:"tags"`
	Metadata         map[string]any `json:"metadata"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

type CreateEvidenceRequest struct {
	Name             string         `json:"name"`
	Description      string         `json:"description"`
	EvidenceType     string         `json:"evidence_type"`
	FileName         string         `json:"file_name"`
	FileSize         *int64         `json:"file_size"`
	FileHashMD5      string         `json:"file_hash_md5"`
	FileHashSHA256   string         `json:"file_hash_sha256"`
	StoragePath      string         `json:"storage_path"`
	CollectedBy      string         `json:"collected_by"`
	CollectionMethod string         `json:"collection_method"`
	IsSensitive      bool           `json:"is_sensitive"`
	Tags             []string       `json:"tags"`
	Metadata         map[string]any `json:"metadata"`
}

type UpdateEvidenceRequest struct {
	Status        *string `json:"status"`
	AnalysisNotes *string `json:"analysis_notes"`
	AnalyzedBy    *string `json:"analyzed_by"`
}

// ─── Stats ────────────────────────────────────────────────────────────────────

type IRStats struct {
	TotalIncidents      int            `json:"total_incidents"`
	OpenIncidents       int            `json:"open_incidents"`
	CriticalIncidents   int            `json:"critical_incidents"`
	AvgMTTDMinutes      float64        `json:"avg_mttd_minutes"`
	AvgMTTRMinutes      float64        `json:"avg_mttr_minutes"`
	ByStatus            map[string]int `json:"by_status"`
	BySeverity          map[string]int `json:"by_severity"`
	ByType              map[string]int `json:"by_type"`
	RecentIncidents     []IRIncident   `json:"recent_incidents"`
	TotalPlaybooks      int            `json:"total_playbooks"`
	TotalEvidence       int            `json:"total_evidence"`
	RequireNotification int            `json:"require_notification"`
}
