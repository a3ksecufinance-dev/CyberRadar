package model

import (
	"time"

	"github.com/google/uuid"
)

// Role is an RBAC role that groups permissions.
type Role struct {
	ID          uuid.UUID    `json:"id"`
	TenantID    uuid.UUID    `json:"tenant_id"`
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	IsSystem    bool         `json:"is_system"`
	Permissions []Permission `json:"permissions,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// Permission represents a fine-grained capability.
type Permission struct {
	ID          uuid.UUID `json:"id"`
	Resource    string    `json:"resource"`
	Action      string    `json:"action"`
	Description string    `json:"description,omitempty"`
}

// CreateRoleRequest is the validated payload for role creation.
type CreateRoleRequest struct {
	Name          string      `json:"name"           validate:"required,min=2,max=100"`
	Description   string      `json:"description"`
	PermissionIDs []uuid.UUID `json:"permission_ids"`
}

// AssignRolesRequest assigns roles to a user.
type AssignRolesRequest struct {
	RoleIDs []uuid.UUID `json:"role_ids" validate:"required,min=1"`
}

// HasPermission reports whether the role grants resource:action.
func (r *Role) HasPermission(resource, action string) bool {
	for _, p := range r.Permissions {
		if p.Resource == resource && p.Action == action {
			return true
		}
	}
	return false
}
