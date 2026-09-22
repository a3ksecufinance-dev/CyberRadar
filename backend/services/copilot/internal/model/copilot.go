package model

import (
	"time"

	"github.com/google/uuid"
)

// ── Role constants ────────────────────────────────────────────────────────────
const (
	RoleUser      = "user"
	RoleAssistant = "assistant"
	RoleTool      = "tool"
)

// ── Hunt job types ────────────────────────────────────────────────────────────
const (
	HuntTypeThreatHunt         = "threat_hunt"
	HuntTypeIncidentTriage     = "incident_triage"
	HuntTypeVulnPrioritization = "vuln_prioritization"
	HuntTypeAttackPathSummary  = "attack_path_summary"
	HuntTypeIOCCorrelation     = "ioc_correlation"
	HuntTypeEntityProfiling    = "entity_profiling"
)

// ── Tool names exposed to Claude ──────────────────────────────────────────────
const (
	ToolQueryAlerts       = "query_alerts"
	ToolLookupIOC         = "lookup_ioc"
	ToolGetIncident       = "get_incident"
	ToolQueryAnomalies    = "query_anomalies"
	ToolQueryVulns        = "query_vulnerabilities"
	ToolAnalyzeAttackPath = "analyze_attack_path"
	ToolSearchEntities    = "search_entities"
	ToolGetAsset          = "get_asset"
	ToolQueryStats        = "query_platform_stats"
	ToolHuntThreats       = "hunt_threats"
)

// ─── Core models ──────────────────────────────────────────────────────────────

// Session is a multi-turn conversation context.
type Session struct {
	ID            uuid.UUID      `json:"id"`
	TenantID      uuid.UUID      `json:"tenant_id"`
	UserID        uuid.UUID      `json:"user_id"`
	Title         string         `json:"title,omitempty"`
	Context       map[string]any `json:"context,omitempty"`
	IsActive      bool           `json:"is_active"`
	MessageCount  int            `json:"message_count"`
	LastMessageAt *time.Time     `json:"last_message_at,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

// Message is one turn in a copilot session.
type Message struct {
	ID           uuid.UUID      `json:"id"`
	SessionID    uuid.UUID      `json:"session_id"`
	TenantID     uuid.UUID      `json:"tenant_id"`
	Role         string         `json:"role"`
	Content      string         `json:"content"`
	ToolName     string         `json:"tool_name,omitempty"`
	ToolInput    map[string]any `json:"tool_input,omitempty"`
	ToolOutput   map[string]any `json:"tool_output,omitempty"`
	InputTokens  int            `json:"input_tokens"`
	OutputTokens int            `json:"output_tokens"`
	LatencyMS    int            `json:"latency_ms"`
	CreatedAt    time.Time      `json:"created_at"`
}

// HuntJob is an async AI analysis task.
type HuntJob struct {
	ID            uuid.UUID      `json:"id"`
	TenantID      uuid.UUID      `json:"tenant_id"`
	UserID        uuid.UUID      `json:"user_id"`
	SessionID     *uuid.UUID     `json:"session_id,omitempty"`
	HuntType      string         `json:"hunt_type"`
	Query         string         `json:"query"`
	Status        string         `json:"status"`
	ResultSummary string         `json:"result_summary,omitempty"`
	ResultPayload map[string]any `json:"result_payload,omitempty"`
	ErrorMessage  string         `json:"error_message,omitempty"`
	InputTokens   int            `json:"input_tokens"`
	OutputTokens  int            `json:"output_tokens"`
	StartedAt     *time.Time     `json:"started_at,omitempty"`
	CompletedAt   *time.Time     `json:"completed_at,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
}

// CopilotStats is the usage summary.
type CopilotStats struct {
	TotalSessions     int `json:"total_sessions"`
	ActiveSessions    int `json:"active_sessions"`
	TotalMessages     int `json:"total_messages"`
	TotalHuntJobs     int `json:"total_hunt_jobs"`
	PendingJobs       int `json:"pending_jobs"`
	TotalInputTokens  int `json:"total_input_tokens"`
	TotalOutputTokens int `json:"total_output_tokens"`
}

// ── Anthropic API types ───────────────────────────────────────────────────────

// AnthropicMessage is one message in the Claude Messages API format.
type AnthropicMessage struct {
	Role    string             `json:"role"`
	Content []AnthropicContent `json:"content"`
}

// AnthropicContent is a content block (text or tool_use/tool_result).
type AnthropicContent struct {
	Type      string         `json:"type"`
	Text      string         `json:"text,omitempty"`
	ID        string         `json:"id,omitempty"`          // tool_use block id
	Name      string         `json:"name,omitempty"`        // tool name
	Input     map[string]any `json:"input,omitempty"`       // tool input
	ToolUseID string         `json:"tool_use_id,omitempty"` // for tool_result
	Content   string         `json:"content,omitempty"`     // for tool_result
	IsError   bool           `json:"is_error,omitempty"`
}

// AnthropicTool defines a tool for Claude tool use.
type AnthropicTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

// AnthropicRequest is the full payload for POST /v1/messages.
type AnthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system"`
	Messages  []AnthropicMessage `json:"messages"`
	Tools     []AnthropicTool    `json:"tools,omitempty"`
}

// AnthropicResponse is the response from the Claude Messages API.
type AnthropicResponse struct {
	ID         string             `json:"id"`
	Type       string             `json:"type"`
	Role       string             `json:"role"`
	Content    []AnthropicContent `json:"content"`
	StopReason string             `json:"stop_reason"`
	Usage      AnthropicUsage     `json:"usage"`
}

// AnthropicUsage holds token counts.
type AnthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// ── Request models ────────────────────────────────────────────────────────────

type CreateSessionRequest struct {
	Context map[string]any `json:"context"`
}

type SendMessageRequest struct {
	Content string `json:"content" validate:"required,min=1,max=10000"`
}

type CreateHuntJobRequest struct {
	HuntType  string         `json:"hunt_type"  validate:"required,oneof=threat_hunt incident_triage vuln_prioritization attack_path_summary ioc_correlation entity_profiling"`
	Query     string         `json:"query"      validate:"required,min=5,max=2000"`
	SessionID *uuid.UUID     `json:"session_id"`
	Context   map[string]any `json:"context"`
}

type SessionFilter struct {
	TenantID uuid.UUID
	UserID   uuid.UUID
	Active   *bool
	Limit    int
	Offset   int
}
