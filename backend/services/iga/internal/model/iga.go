package model

import (
	"time"

	"github.com/google/uuid"
)

// ─── Role types ───────────────────────────────────────────────────────────────

const (
	RoleTypeBusiness    = "business"
	RoleTypeTechnical   = "technical"
	RoleTypePrivileged  = "privileged"
	RoleTypeApplication = "application"
	RoleTypeEmergency   = "emergency"
)

// ─── Assignment types ─────────────────────────────────────────────────────────

const (
	AssignmentDirect    = "direct"
	AssignmentDelegated = "delegated"
	AssignmentEmergency = "emergency"
	AssignmentInherited = "inherited"
)

// ─── Assignment statuses ──────────────────────────────────────────────────────

const (
	AssignmentActive          = "active"
	AssignmentPendingApproval = "pending_approval"
	AssignmentSuspended       = "suspended"
	AssignmentExpired         = "expired"
	AssignmentRevoked         = "revoked"
)

// ─── Campaign types ───────────────────────────────────────────────────────────

const (
	CampaignPeriodic           = "periodic"
	CampaignTriggered          = "triggered"
	CampaignPrivilegedAccess   = "privileged_access"
	CampaignRoleCleanup        = "role_cleanup"
	CampaignRegulatory         = "regulatory"
	CampaignSeparationOfDuties = "separation_of_duties"
)

// ─── Risk flags ───────────────────────────────────────────────────────────────

const (
	FlagDormantAccount  = "dormant_account"
	FlagExcessiveAccess = "excessive_access"
	FlagSoDConflict     = "sod_conflict"
	FlagPrivilegedRole  = "privileged_role"
	FlagOrphanAccount   = "orphan_account"
	FlagMultipleRoles   = "multiple_roles"
)

// ─── Core structs ─────────────────────────────────────────────────────────────

type IGARole struct {
	ID              uuid.UUID          `json:"id"`
	TenantID        uuid.UUID          `json:"tenant_id"`
	Name            string             `json:"name"`
	Description     string             `json:"description,omitempty"`
	RoleType        string             `json:"role_type"`
	Category        string             `json:"category,omitempty"`
	Owner           string             `json:"owner,omitempty"`
	RiskLevel       string             `json:"risk_level"`
	IsActive        bool               `json:"is_active"`
	RequiresMFA     bool               `json:"requires_mfa"`
	MaxDurationDays *int               `json:"max_duration_days,omitempty"`
	Entitlements    []*RoleEntitlement `json:"entitlements,omitempty"`
	AssignmentCount int                `json:"assignment_count,omitempty"`
	Metadata        map[string]any     `json:"metadata"`
	CreatedAt       time.Time          `json:"created_at"`
	UpdatedAt       time.Time          `json:"updated_at"`
}

type RoleEntitlement struct {
	ID              uuid.UUID `json:"id"`
	TenantID        uuid.UUID `json:"tenant_id"`
	RoleID          uuid.UUID `json:"role_id"`
	SystemName      string    `json:"system_name"`
	Entitlement     string    `json:"entitlement"`
	EntitlementType string    `json:"entitlement_type"`
	CreatedAt       time.Time `json:"created_at"`
}

type RoleAssignment struct {
	ID             uuid.UUID  `json:"id"`
	TenantID       uuid.UUID  `json:"tenant_id"`
	IdentityID     uuid.UUID  `json:"identity_id"`
	IdentityName   string     `json:"identity_name"`
	IdentityEmail  string     `json:"identity_email,omitempty"`
	RoleID         uuid.UUID  `json:"role_id"`
	RoleName       string     `json:"role_name"`
	AssignmentType string     `json:"assignment_type"`
	Status         string     `json:"status"`
	Justification  string     `json:"justification,omitempty"`
	RequestedBy    *uuid.UUID `json:"requested_by,omitempty"`
	ApprovedBy     *uuid.UUID `json:"approved_by,omitempty"`
	ApprovedAt     *time.Time `json:"approved_at,omitempty"`
	ValidFrom      time.Time  `json:"valid_from"`
	ValidUntil     *time.Time `json:"valid_until,omitempty"`
	LastReviewedAt *time.Time `json:"last_reviewed_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type Campaign struct {
	ID             uuid.UUID  `json:"id"`
	TenantID       uuid.UUID  `json:"tenant_id"`
	Name           string     `json:"name"`
	Description    string     `json:"description,omitempty"`
	CampaignType   string     `json:"campaign_type"`
	Scope          string     `json:"scope"`
	ScopeFilter    string     `json:"scope_filter,omitempty"`
	Status         string     `json:"status"`
	ReviewerType   string     `json:"reviewer_type"`
	TotalItems     int        `json:"total_items"`
	ReviewedItems  int        `json:"reviewed_items"`
	CertifiedItems int        `json:"certified_items"`
	RevokedItems   int        `json:"revoked_items"`
	StartDate      time.Time  `json:"start_date"`
	DueDate        time.Time  `json:"due_date"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type ReviewItem struct {
	ID             uuid.UUID  `json:"id"`
	TenantID       uuid.UUID  `json:"tenant_id"`
	CampaignID     uuid.UUID  `json:"campaign_id"`
	IdentityID     uuid.UUID  `json:"identity_id"`
	IdentityName   string     `json:"identity_name"`
	IdentityEmail  string     `json:"identity_email,omitempty"`
	RoleID         *uuid.UUID `json:"role_id,omitempty"`
	RoleName       string     `json:"role_name"`
	AssignmentID   *uuid.UUID `json:"assignment_id,omitempty"`
	Decision       string     `json:"decision,omitempty"`
	DecisionReason string     `json:"decision_reason,omitempty"`
	ReviewerID     *uuid.UUID `json:"reviewer_id,omitempty"`
	ReviewerName   string     `json:"reviewer_name,omitempty"`
	ReviewedAt     *time.Time `json:"reviewed_at,omitempty"`
	RiskFlags      []string   `json:"risk_flags"`
	RiskScore      int        `json:"risk_score"`
	CreatedAt      time.Time  `json:"created_at"`
}

type SoDPolicy struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	RoleAID     uuid.UUID `json:"role_a_id"`
	RoleAName   string    `json:"role_a_name"`
	RoleBID     uuid.UUID `json:"role_b_id"`
	RoleBName   string    `json:"role_b_name"`
	Severity    string    `json:"severity"`
	Action      string    `json:"action"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type SoDViolation struct {
	ID              uuid.UUID  `json:"id"`
	TenantID        uuid.UUID  `json:"tenant_id"`
	PolicyID        uuid.UUID  `json:"policy_id"`
	PolicyName      string     `json:"policy_name"`
	IdentityID      uuid.UUID  `json:"identity_id"`
	IdentityName    string     `json:"identity_name"`
	IdentityEmail   string     `json:"identity_email,omitempty"`
	RoleAID         uuid.UUID  `json:"role_a_id"`
	RoleAName       string     `json:"role_a_name"`
	RoleBID         uuid.UUID  `json:"role_b_id"`
	RoleBName       string     `json:"role_b_name"`
	Severity        string     `json:"severity"`
	Status          string     `json:"status"`
	ExceptionReason string     `json:"exception_reason,omitempty"`
	ExceptionBy     *uuid.UUID `json:"exception_by,omitempty"`
	ExceptionAt     *time.Time `json:"exception_at,omitempty"`
	DetectedAt      time.Time  `json:"detected_at"`
	CreatedAt       time.Time  `json:"created_at"`
}

// ─── Stats ────────────────────────────────────────────────────────────────────

type IGAStats struct {
	TotalRoles           int            `json:"total_roles"`
	TotalAssignments     int            `json:"total_assignments"`
	ActiveCampaigns      int            `json:"active_campaigns"`
	PendingReviews       int            `json:"pending_reviews"`
	OpenSoDViolations    int            `json:"open_sod_violations"`
	ExpiringSoon         int            `json:"expiring_soon"` // within 7 days
	RolesByType          map[string]int `json:"roles_by_type"`
	AssignmentsByStatus  map[string]int `json:"assignments_by_status"`
	ViolationsBySeverity map[string]int `json:"violations_by_severity"`
	TopRoles             []*IGARole     `json:"top_roles"` // most assigned
}

// ─── Request models ───────────────────────────────────────────────────────────

type CreateRoleRequest struct {
	Name            string             `json:"name"      validate:"required"`
	Description     string             `json:"description"`
	RoleType        string             `json:"role_type" validate:"required"`
	Category        string             `json:"category"`
	Owner           string             `json:"owner"`
	RiskLevel       string             `json:"risk_level"`
	RequiresMFA     bool               `json:"requires_mfa"`
	MaxDurationDays *int               `json:"max_duration_days"`
	Entitlements    []EntitlementInput `json:"entitlements"`
	Metadata        map[string]any     `json:"metadata"`
}

type EntitlementInput struct {
	SystemName      string `json:"system_name"      validate:"required"`
	Entitlement     string `json:"entitlement"      validate:"required"`
	EntitlementType string `json:"entitlement_type"`
}

type UpdateRoleRequest struct {
	Description     string         `json:"description"`
	Category        string         `json:"category"`
	Owner           string         `json:"owner"`
	RiskLevel       string         `json:"risk_level"`
	RequiresMFA     *bool          `json:"requires_mfa"`
	MaxDurationDays *int           `json:"max_duration_days"`
	IsActive        *bool          `json:"is_active"`
	Metadata        map[string]any `json:"metadata"`
}

type AssignRoleRequest struct {
	IdentityID     uuid.UUID  `json:"identity_id"    validate:"required"`
	IdentityName   string     `json:"identity_name"  validate:"required"`
	IdentityEmail  string     `json:"identity_email"`
	RoleID         uuid.UUID  `json:"role_id"        validate:"required"`
	AssignmentType string     `json:"assignment_type"`
	Justification  string     `json:"justification"  validate:"required"`
	ValidUntil     *time.Time `json:"valid_until"`
}

type UpdateAssignmentRequest struct {
	Status        string     `json:"status"`
	ValidUntil    *time.Time `json:"valid_until"`
	Justification string     `json:"justification"`
}

type CreateCampaignRequest struct {
	Name         string    `json:"name"          validate:"required"`
	Description  string    `json:"description"`
	CampaignType string    `json:"campaign_type" validate:"required"`
	Scope        string    `json:"scope"`
	ScopeFilter  string    `json:"scope_filter"`
	ReviewerType string    `json:"reviewer_type"`
	DueDate      time.Time `json:"due_date"      validate:"required"`
}

type ReviewDecisionRequest struct {
	Decision       string `json:"decision"        validate:"required"`
	DecisionReason string `json:"decision_reason"`
	ReviewerName   string `json:"reviewer_name"`
}

type CreateSoDPolicyRequest struct {
	Name        string    `json:"name"       validate:"required"`
	Description string    `json:"description"`
	RoleAID     uuid.UUID `json:"role_a_id"  validate:"required"`
	RoleBID     uuid.UUID `json:"role_b_id"  validate:"required"`
	Severity    string    `json:"severity"   validate:"required"`
	Action      string    `json:"action"`
}

type UpdateViolationRequest struct {
	Status          string `json:"status"           validate:"required"`
	ExceptionReason string `json:"exception_reason"`
}

type ListAssignmentsFilter struct {
	IdentityID *uuid.UUID
	RoleID     *uuid.UUID
	Status     string
	Page       int
	PageSize   int
}

type ListReviewItemsFilter struct {
	CampaignID *uuid.UUID
	IdentityID *uuid.UUID
	Decision   string
	Page       int
	PageSize   int
}
