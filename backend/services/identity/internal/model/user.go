package model

import (
	"time"

	"github.com/google/uuid"
)

// Identity represents a platform user (human or non-human).
type Identity struct {
	ID             uuid.UUID  `json:"id"`
	TenantID       uuid.UUID  `json:"tenant_id"`
	Username       string     `json:"username"`
	Email          string     `json:"email"`
	DisplayName    string     `json:"display_name,omitempty"`
	IdentityType   string     `json:"identity_type"`
	Department     string     `json:"department,omitempty"`
	BusinessUnit   string     `json:"business_unit,omitempty"`
	ManagerID      *uuid.UUID `json:"manager_id,omitempty"`
	PrivilegeLevel string     `json:"privilege_level"`
	MFAEnabled     bool       `json:"mfa_enabled"`
	PAMManaged     bool       `json:"pam_managed"`
	RiskScore      float64    `json:"risk_score"`
	BehaviorScore  float64    `json:"behavior_score"`
	Status         string     `json:"status"`
	LastActivity   *time.Time `json:"last_activity,omitempty"`
	SourceSystems  []byte     `json:"source_systems,omitempty"`
	Roles          []string   `json:"roles,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`

	// Internal fields — stripped before API responses (never JSON-exported when set)
	PasswordHash string `json:"-"`
	MFASecret    string `json:"-"`
}

// CreateUserRequest is the validated payload for user creation.
type CreateUserRequest struct {
	Username       string      `json:"username"       validate:"required,min=3,max=255"`
	Email          string      `json:"email"          validate:"required,email"`
	DisplayName    string      `json:"display_name"`
	Password       string      `json:"password"       validate:"required,min=12"`
	IdentityType   string      `json:"identity_type"  validate:"omitempty,oneof=user admin service_account machine bot"`
	Department     string      `json:"department"`
	BusinessUnit   string      `json:"business_unit"`
	PrivilegeLevel string      `json:"privilege_level" validate:"omitempty,oneof=standard elevated admin"`
	RoleIDs        []uuid.UUID `json:"role_ids"`
}

// UpdateUserRequest is the validated payload for partial user update.
type UpdateUserRequest struct {
	DisplayName    *string     `json:"display_name"`
	Department     *string     `json:"department"`
	BusinessUnit   *string     `json:"business_unit"`
	PrivilegeLevel *string     `json:"privilege_level" validate:"omitempty,oneof=standard elevated admin super_admin"`
	Status         *string     `json:"status"          validate:"omitempty,oneof=active dormant disabled"`
	RoleIDs        []uuid.UUID `json:"role_ids"`
}

// ListUsersFilter holds query parameters for listing identities.
type ListUsersFilter struct {
	TenantID       uuid.UUID
	Status         string
	IdentityType   string
	PrivilegeLevel string
	Search         string
	Page           int
	Limit          int
}

// UserList is a paginated list of identities.
type UserList struct {
	Users []*Identity `json:"users"`
	Total int64       `json:"total"`
	Page  int         `json:"page"`
	Limit int         `json:"limit"`
}

// LoginRequest is the auth payload.
type LoginRequest struct {
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required"`
	MFACode  string `json:"mfa_code"`
}

// LoginResponse is returned on successful authentication.
type LoginResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
	User         *Identity `json:"user"`
	MFARequired  bool      `json:"mfa_required"`
}

// RefreshRequest is the payload to refresh tokens.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// ChangePasswordRequest is the payload for password change.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password"     validate:"required,min=12"`
}

// MFAEnrollResponse is returned when initiating MFA enrolment.
type MFAEnrollResponse struct {
	Secret    string `json:"secret"`
	QRCodeURL string `json:"qr_code_url"`
}

// MFAVerifyRequest is the payload to confirm MFA enrolment.
type MFAVerifyRequest struct {
	Code string `json:"code" validate:"required,len=6"`
}
