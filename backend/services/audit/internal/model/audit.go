package model

import (
	"time"

	"github.com/google/uuid"
)

// AuditEvent represents an immutable audit log entry.
// SECURITY: Once written, audit events must never be modified or deleted.
type AuditEvent struct {
	ID           uuid.UUID `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Timestamp    time.Time `json:"timestamp"`

	// Actor
	ActorID      string    `json:"actor_id"`
	ActorType    string    `json:"actor_type"`    // user, service, system, api
	ActorEmail   string    `json:"actor_email"`

	// Action
	Action       string    `json:"action"`        // login, config_change, alert_suppression, etc.
	ResourceType string    `json:"resource_type"` // tenant, user, connector, rule, etc.
	ResourceID   string    `json:"resource_id"`

	// Context
	IPAddress    string    `json:"ip_address"`
	UserAgent    string    `json:"user_agent"`
	SessionID    string    `json:"session_id"`
	RequestID    string    `json:"request_id"`

	// Outcome
	Result       string    `json:"result"`        // success, failure
	Details      string    `json:"details"`       // JSON payload

	// Integrity
	Checksum     string    `json:"checksum"`      // SHA-256 of canonical fields
}

// AuditEventFilter holds search parameters for querying audit logs.
type AuditEventFilter struct {
	TenantID     string
	ActorID      string
	Action       string
	ResourceType string
	ResourceID   string
	Result       string
	From         *time.Time
	To           *time.Time
	Page         int
	Limit        int
}

// AuditEventList is a paginated list of audit events.
type AuditEventList struct {
	Events []*AuditEvent `json:"events"`
	Total  int64         `json:"total"`
	Page   int           `json:"page"`
	Limit  int           `json:"limit"`
}

// WriteAuditRequest is the payload for writing an audit event.
// Called by other services via the audit-service API.
type WriteAuditRequest struct {
	TenantID     string `json:"tenant_id"     validate:"required"`
	ActorID      string `json:"actor_id"      validate:"required"`
	ActorType    string `json:"actor_type"    validate:"required,oneof=user service system api"`
	ActorEmail   string `json:"actor_email"`
	Action       string `json:"action"        validate:"required"`
	ResourceType string `json:"resource_type" validate:"required"`
	ResourceID   string `json:"resource_id"`
	IPAddress    string `json:"ip_address"`
	UserAgent    string `json:"user_agent"`
	SessionID    string `json:"session_id"`
	RequestID    string `json:"request_id"`
	Result       string `json:"result"        validate:"required,oneof=success failure"`
	Details      string `json:"details"`
}

// Standard audit actions — exhaustive list for consistency.
const (
	ActionLogin             = "login"
	ActionLogout            = "logout"
	ActionLoginFailed       = "login_failed"
	ActionPrivilegeEscalate = "privilege_escalation"
	ActionConfigChange      = "config_change"
	ActionConnectorChange   = "connector_change"
	ActionAlertSuppress     = "alert_suppression"
	ActionPolicyUpdate      = "policy_update"
	ActionSecretAccess      = "secret_access"
	ActionUserCreate        = "user_create"
	ActionUserDisable       = "user_disable"
	ActionTenantCreate      = "tenant_create"
	ActionTenantDelete      = "tenant_delete"
	ActionRuleCreate        = "rule_create"
	ActionRuleDelete        = "rule_delete"
	ActionPlaybookExecute   = "playbook_execute"
	ActionReportExport      = "report_export"
	ActionAuditExport       = "audit_export"
	ActionMFAEnroll         = "mfa_enroll"
	ActionMFADisable        = "mfa_disable"
)
