package model

import (
	"time"

	"github.com/google/uuid"
)

// Service account scopes. A 'tenant' account only ever gets tokens for its own
// tenant; a 'platform' account may name the tenant it wants to act for, which
// is what lets one SOAR process work an alert belonging to any customer.
const (
	ScopeTenant   = "tenant"
	ScopePlatform = "platform"
)

// ServiceAccount is a machine principal: a credential attached to an identity
// of type service_account, so roles and permissions resolve exactly as they do
// for a person.
type ServiceAccount struct {
	ID          uuid.UUID  `json:"id"`
	IdentityID  uuid.UUID  `json:"identity_id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	ClientID    string     `json:"client_id"`
	Scope       string     `json:"scope"`
	Description string     `json:"description,omitempty"`
	Enabled     bool       `json:"enabled"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`

	// SecretHash never leaves the repository layer.
	SecretHash string `json:"-"`
}

// ServiceTokenRequest is the client-credentials payload a machine presents.
type ServiceTokenRequest struct {
	ClientID     string `json:"client_id"     validate:"required"`
	ClientSecret string `json:"client_secret" validate:"required"`

	// TenantID is required for a platform-scoped account and rejected for a
	// tenant-scoped one. Every token names exactly one tenant — there is no
	// token that means "all tenants", because a handler reading tenant_id
	// would then have to invent one.
	TenantID string `json:"tenant_id" validate:"omitempty,uuid"`
}

// ServiceTokenResponse is what a machine gets back. No refresh token: it holds
// a credential and can ask again.
type ServiceTokenResponse struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresAt   time.Time `json:"expires_at"`
	ServiceID   string    `json:"service_id"`
	TenantID    string    `json:"tenant_id"`
}

// CreateServiceAccountRequest creates a machine principal and its credential.
type CreateServiceAccountRequest struct {
	ClientID      string      `json:"client_id"   validate:"required,min=3,max=128"`
	Description   string      `json:"description"`
	Scope         string      `json:"scope"       validate:"omitempty,oneof=tenant platform"`
	RoleIDs       []uuid.UUID `json:"role_ids"    validate:"required,min=1"`
	ExpiresInDays int         `json:"expires_in_days" validate:"omitempty,min=1,max=3650"`
}

// CreateServiceAccountResponse carries the generated secret. It is returned
// once, at creation, and never again: only its bcrypt hash is stored.
type CreateServiceAccountResponse struct {
	ServiceAccount
	ClientSecret string `json:"client_secret"`
}
