package model

import (
	"time"

	"github.com/google/uuid"
)

// Tenant represents an isolated organisation within CRP.
// Strict invariant: every other entity in the platform carries a TenantID
// sourced from a verified JWT — never from user input.
type Tenant struct {
	ID        uuid.UUID  `json:"id"`
	Name      string     `json:"name"`
	Slug      string     `json:"slug"`
	ParentID  *uuid.UUID `json:"parent_id,omitempty"`
	Plan      string     `json:"plan"`
	Status    string     `json:"status"`
	Config    JSONB      `json:"config"`
	Features  JSONB      `json:"features"`
	Limits    JSONB      `json:"limits"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// JSONB is a raw JSON byte slice for JSONB columns.
type JSONB []byte

func (j JSONB) MarshalJSON() ([]byte, error) {
	if len(j) == 0 {
		return []byte("{}"), nil
	}
	return j, nil
}

// CreateTenantRequest is the validated payload for tenant creation.
type CreateTenantRequest struct {
	Name     string     `json:"name"     validate:"required,min=2,max=255"`
	Slug     string     `json:"slug"     validate:"required,min=2,max=100,alphanum"`
	ParentID *uuid.UUID `json:"parent_id"`
	Plan     string     `json:"plan"     validate:"required,oneof=standard professional enterprise"`
}

// UpdateTenantRequest is the validated payload for tenant update.
type UpdateTenantRequest struct {
	Name     *string `json:"name"    validate:"omitempty,min=2,max=255"`
	Plan     *string `json:"plan"    validate:"omitempty,oneof=standard professional enterprise"`
	Status   *string `json:"status"  validate:"omitempty,oneof=active suspended"`
	Config   JSONB   `json:"config"`
	Features JSONB   `json:"features"`
	Limits   JSONB   `json:"limits"`
}

// ListTenantsFilter holds query parameters for listing tenants.
type ListTenantsFilter struct {
	ParentID *uuid.UUID
	Status   string
	Plan     string
	Page     int
	Limit    int
}

// TenantList is a paginated list of tenants.
type TenantList struct {
	Tenants []*Tenant `json:"tenants"`
	Total   int64     `json:"total"`
	Page    int       `json:"page"`
	Limit   int       `json:"limit"`
}
