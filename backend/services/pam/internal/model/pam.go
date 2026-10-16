package model

import (
	"time"

	"github.com/google/uuid"
)

// AccountType classifies privileged accounts.
type AccountType string

const (
	AccountLocalAdmin  AccountType = "local_admin"
	AccountDomainAdmin AccountType = "domain_admin"
	AccountService     AccountType = "service"
	AccountShared      AccountType = "shared"
	AccountEmergency   AccountType = "emergency"
	AccountAPIKey      AccountType = "api_key"
)

// Protocol is the access protocol for a privileged session.
type Protocol string

const (
	ProtocolSSH     Protocol = "ssh"
	ProtocolRDP     Protocol = "rdp"
	ProtocolDB      Protocol = "db"
	ProtocolAPI     Protocol = "api"
	ProtocolConsole Protocol = "console"
	ProtocolWinRM   Protocol = "winrm"
)

// RequestStatus tracks the JIT request lifecycle.
type RequestStatus string

const (
	RequestPending   RequestStatus = "pending"
	RequestApproved  RequestStatus = "approved"
	RequestRejected  RequestStatus = "rejected"
	RequestExpired   RequestStatus = "expired"
	RequestCancelled RequestStatus = "cancelled"
	RequestRevoked   RequestStatus = "revoked"
)

// SessionStatus tracks a privileged session's state.
type SessionStatus string

const (
	SessionActive     SessionStatus = "active"
	SessionTerminated SessionStatus = "terminated"
	SessionExpired    SessionStatus = "expired"
	SessionSuspicious SessionStatus = "suspicious"
	SessionLocked     SessionStatus = "locked"
)

// ─── Core models ─────────────────────────────────────────────────────────────

// PrivilegedAccount is a vaulted privileged account.
type PrivilegedAccount struct {
	ID                  uuid.UUID   `json:"id"`
	TenantID            uuid.UUID   `json:"tenant_id"`
	AccountName         string      `json:"account_name"`
	AccountType         AccountType `json:"account_type"`
	TargetAssetID       *uuid.UUID  `json:"target_asset_id,omitempty"`
	TargetAssetHostname string      `json:"target_asset_hostname,omitempty"`
	TargetProtocol      Protocol    `json:"target_protocol"`
	CredentialStored    bool        `json:"credential_stored"`
	CredentialRef       string      `json:"credential_ref,omitempty"` // Vault path only
	LastRotatedAt       *time.Time  `json:"last_rotated_at,omitempty"`
	RotationPolicyDays  int         `json:"rotation_policy_days"`
	AutoRotate          bool        `json:"auto_rotate"`
	RequiresApproval    bool        `json:"requires_approval"`
	MaxSessionMinutes   int         `json:"max_session_minutes"`
	AllowedRoles        []string    `json:"allowed_roles"`
	IsActive            bool        `json:"is_active"`
	LastUsedAt          *time.Time  `json:"last_used_at,omitempty"`
	UseCount            int         `json:"use_count"`
	CreatedAt           time.Time   `json:"created_at"`
	UpdatedAt           time.Time   `json:"updated_at"`
}

// AccessRequest is a JIT privileged access request.
type AccessRequest struct {
	ID                   uuid.UUID     `json:"id"`
	TenantID             uuid.UUID     `json:"tenant_id"`
	RequesterID          uuid.UUID     `json:"requester_id"`
	PrivilegedAccountID  *uuid.UUID    `json:"privileged_account_id,omitempty"`
	TargetAssetID        *uuid.UUID    `json:"target_asset_id,omitempty"`
	Reason               string        `json:"reason"`
	TicketRef            string        `json:"ticket_ref,omitempty"`
	RequestedDurationMin int           `json:"requested_duration_min"`
	Status               RequestStatus `json:"status"`
	ApproverID           *uuid.UUID    `json:"approver_id,omitempty"`
	ApprovalNote         string        `json:"approval_note,omitempty"`
	ValidFrom            *time.Time    `json:"valid_from,omitempty"`
	ValidUntil           *time.Time    `json:"valid_until,omitempty"`
	ExpiresAt            time.Time     `json:"expires_at"`
	CreatedAt            time.Time     `json:"created_at"`
	ResolvedAt           *time.Time    `json:"resolved_at,omitempty"`
}

// PrivilegedSession is an active or completed privileged session.
type PrivilegedSession struct {
	ID                  uuid.UUID     `json:"id"`
	TenantID            uuid.UUID     `json:"tenant_id"`
	RequestID           *uuid.UUID    `json:"request_id,omitempty"`
	UserID              uuid.UUID     `json:"user_id"`
	PrivilegedAccountID *uuid.UUID    `json:"privileged_account_id,omitempty"`
	TargetAssetID       *uuid.UUID    `json:"target_asset_id,omitempty"`
	Protocol            Protocol      `json:"protocol,omitempty"`
	Status              SessionStatus `json:"status"`
	StartedAt           time.Time     `json:"started_at"`
	ExpiresAt           time.Time     `json:"expires_at"`
	TerminatedAt        *time.Time    `json:"terminated_at,omitempty"`
	ClientIP            string        `json:"client_ip,omitempty"`
	MFAVerified         bool          `json:"mfa_verified"`
	CommandsCount       int           `json:"commands_count"`
	BytesTransferred    int64         `json:"bytes_transferred"`
	RiskScore           float64       `json:"risk_score"`
	RiskFlags           []string      `json:"risk_flags,omitempty"`
	RecordingRef        string        `json:"recording_ref,omitempty"`
}

// SessionEvent is a single auditable action within a privileged session.
type SessionEvent struct {
	ID         uuid.UUID `json:"id"`
	TenantID   uuid.UUID `json:"tenant_id"`
	SessionID  uuid.UUID `json:"session_id"`
	Timestamp  time.Time `json:"timestamp"`
	EventType  string    `json:"event_type"`
	Content    string    `json:"content,omitempty"`
	RiskFlag   bool      `json:"risk_flag"`
	RiskReason string    `json:"risk_reason,omitempty"`
}

// ─── Request / Response models ────────────────────────────────────────────────

// CreateAccountRequest registers a new privileged account.
type CreateAccountRequest struct {
	AccountName         string      `json:"account_name"      validate:"required,min=1,max=255"`
	AccountType         AccountType `json:"account_type"      validate:"required"`
	TargetAssetID       *uuid.UUID  `json:"target_asset_id"`
	TargetAssetHostname string      `json:"target_asset_hostname"`
	TargetProtocol      Protocol    `json:"target_protocol"   validate:"required"`
	CredentialRef       string      `json:"credential_ref"`
	RotationPolicyDays  int         `json:"rotation_policy_days"`
	RequiresApproval    bool        `json:"requires_approval"`
	MaxSessionMinutes   int         `json:"max_session_minutes"`
	AllowedRoles        []string    `json:"allowed_roles"`
}

// CreateRequestRequest is the JIT access request payload.
type CreateRequestRequest struct {
	PrivilegedAccountID  *uuid.UUID `json:"privileged_account_id"`
	TargetAssetID        *uuid.UUID `json:"target_asset_id"`
	Reason               string     `json:"reason"    validate:"required,min=10,max=2000"`
	TicketRef            string     `json:"ticket_ref"`
	RequestedDurationMin int        `json:"requested_duration_min" validate:"required,min=1,max=480"`
}

// ApproveRequestRequest is the approval/rejection payload.
type ApproveRequestRequest struct {
	Approved bool   `json:"approved" validate:"required"`
	Note     string `json:"note"     validate:"max=1000"`
}

// OpenSessionRequest opens a privileged session after an approved request.
type OpenSessionRequest struct {
	RequestID           uuid.UUID `json:"request_id"            validate:"required"`
	PrivilegedAccountID uuid.UUID `json:"privileged_account_id" validate:"required"`
	ClientIP            string    `json:"client_ip"`
	MFAVerified         bool      `json:"mfa_verified"`
}

// RecordEventRequest records an event inside an active session.
type RecordEventRequest struct {
	EventType string `json:"event_type" validate:"required,oneof=command file_access network clipboard screen auth transfer"`
	Content   string `json:"content"    validate:"max=10000"`
}

// AccessRequestFilter for listing requests.
type AccessRequestFilter struct {
	TenantID    uuid.UUID
	RequesterID *uuid.UUID
	Status      string
	Limit       int
	Offset      int
}

// SessionFilter for listing sessions.
type SessionFilter struct {
	TenantID uuid.UUID
	UserID   *uuid.UUID
	Status   string
	Limit    int
	Offset   int
}
