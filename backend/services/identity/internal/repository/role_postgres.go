package repository

import (
	"context"
	"fmt"

	"github.com/cyberradar/platform/services/identity/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RoleRepository handles role and permission persistence.
type RoleRepository struct {
	db *pgxpool.Pool
}

// NewRoleRepository creates a RoleRepository.
func NewRoleRepository(db *pgxpool.Pool) *RoleRepository {
	return &RoleRepository{db: db}
}

// GetByTenant returns all roles for a given tenant.
func (r *RoleRepository) GetByTenant(ctx context.Context, tenantID uuid.UUID) ([]*model.Role, error) {
	const q = `
		SELECT r.id, r.tenant_id, r.name, r.description, r.is_system, r.created_at, r.updated_at
		FROM roles r
		WHERE r.tenant_id = $1
		ORDER BY r.name`

	rows, err := r.db.Query(ctx, q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("get roles: %w", err)
	}
	defer rows.Close()

	var roles []*model.Role
	for rows.Next() {
		role := &model.Role{}
		if err := rows.Scan(
			&role.ID, &role.TenantID, &role.Name,
			&role.Description, &role.IsSystem,
			&role.CreatedAt, &role.UpdatedAt,
		); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

// GetByID retrieves a role with its permissions.
func (r *RoleRepository) GetByID(ctx context.Context, tenantID, roleID uuid.UUID) (*model.Role, error) {
	const q = `
		SELECT r.id, r.tenant_id, r.name, r.description, r.is_system, r.created_at, r.updated_at
		FROM roles r
		WHERE r.id = $1 AND r.tenant_id = $2`

	role := &model.Role{}
	err := r.db.QueryRow(ctx, q, roleID, tenantID).Scan(
		&role.ID, &role.TenantID, &role.Name,
		&role.Description, &role.IsSystem,
		&role.CreatedAt, &role.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get role: %w", err)
	}

	perms, err := r.getPermissionsByRole(ctx, roleID)
	if err != nil {
		return nil, err
	}
	role.Permissions = perms
	return role, nil
}

// Create creates a new role in the tenant.
func (r *RoleRepository) Create(ctx context.Context, tenantID uuid.UUID, req *model.CreateRoleRequest) (*model.Role, error) {
	const q = `
		INSERT INTO roles (tenant_id, name, description, is_system)
		VALUES ($1, $2, $3, false)
		RETURNING id, tenant_id, name, description, is_system, created_at, updated_at`

	role := &model.Role{}
	err := r.db.QueryRow(ctx, q, tenantID, req.Name, req.Description).Scan(
		&role.ID, &role.TenantID, &role.Name,
		&role.Description, &role.IsSystem,
		&role.CreatedAt, &role.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create role: %w", err)
	}

	if len(req.PermissionIDs) > 0 {
		if err := r.SetPermissions(ctx, role.ID, req.PermissionIDs); err != nil {
			return nil, err
		}
		perms, _ := r.getPermissionsByRole(ctx, role.ID)
		role.Permissions = perms
	}

	return role, nil
}

// GetRoleNamesByUser returns role names for a given user.
func (r *RoleRepository) GetRoleNamesByUser(ctx context.Context, userID uuid.UUID) ([]string, error) {
	const q = `
		SELECT ro.name
		FROM identity_roles ir
		JOIN roles ro ON ro.id = ir.role_id
		WHERE ir.identity_id = $1`

	rows, err := r.db.Query(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// GetPermissionsByUser returns the distinct "resource:action" permissions a
// user holds through all of their roles. These go into the access token so
// every service can authorize locally, without querying identity per request.
func (r *RoleRepository) GetPermissionsByUser(ctx context.Context, userID uuid.UUID) ([]string, error) {
	const q = `
		SELECT DISTINCT p.resource || ':' || p.action
		FROM identity_roles ir
		JOIN role_permissions rp ON rp.role_id = ir.role_id
		JOIN permissions p ON p.id = rp.permission_id
		WHERE ir.identity_id = $1
		ORDER BY 1`

	rows, err := r.db.Query(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, rows.Err()
}

// AssignRoles assigns roles to a user (additive — does not remove existing).
func (r *RoleRepository) AssignRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error {
	for _, roleID := range roleIDs {
		_, err := r.db.Exec(ctx, `
			INSERT INTO identity_roles (identity_id, role_id)
			VALUES ($1, $2)
			ON CONFLICT DO NOTHING`,
			userID, roleID)
		if err != nil {
			return fmt.Errorf("assign role %s: %w", roleID, err)
		}
	}
	return nil
}

// SyncRoles replaces the user's roles with the given set.
func (r *RoleRepository) SyncRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, "DELETE FROM identity_roles WHERE identity_id = $1", userID); err != nil {
		return err
	}

	for _, roleID := range roleIDs {
		if _, err := tx.Exec(ctx, `
			INSERT INTO identity_roles (identity_id, role_id) VALUES ($1, $2)
			ON CONFLICT DO NOTHING`,
			userID, roleID,
		); err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

// SetPermissions replaces role permissions.
func (r *RoleRepository) SetPermissions(ctx context.Context, roleID uuid.UUID, permIDs []uuid.UUID) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, "DELETE FROM role_permissions WHERE role_id = $1", roleID); err != nil {
		return err
	}

	for _, permID := range permIDs {
		if _, err := tx.Exec(ctx,
			"INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
			roleID, permID,
		); err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

// GetAllPermissions returns all platform permissions.
func (r *RoleRepository) GetAllPermissions(ctx context.Context) ([]model.Permission, error) {
	const q = `SELECT id, resource, action, description FROM permissions ORDER BY resource, action`
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []model.Permission
	for rows.Next() {
		var p model.Permission
		if err := rows.Scan(&p.ID, &p.Resource, &p.Action, &p.Description); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, rows.Err()
}

// HasPermission checks if a user (via their roles) has the given resource:action.
func (r *RoleRepository) HasPermission(ctx context.Context, userID uuid.UUID, resource, action string) (bool, error) {
	var exists bool
	err := r.db.QueryRow(ctx, `
		SELECT EXISTS(
		    SELECT 1
		    FROM identity_roles ir
		    JOIN role_permissions rp ON rp.role_id = ir.role_id
		    JOIN permissions p ON p.id = rp.permission_id
		    WHERE ir.identity_id = $1
		      AND p.resource = $2
		      AND p.action = $3
		)`, userID, resource, action).Scan(&exists)
	return exists, err
}

// ─── Private helpers ──────────────────────────────────────────────────────────

func (r *RoleRepository) getPermissionsByRole(ctx context.Context, roleID uuid.UUID) ([]model.Permission, error) {
	const q = `
		SELECT p.id, p.resource, p.action, p.description
		FROM role_permissions rp
		JOIN permissions p ON p.id = rp.permission_id
		WHERE rp.role_id = $1`

	rows, err := r.db.Query(ctx, q, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []model.Permission
	for rows.Next() {
		var p model.Permission
		if err := rows.Scan(&p.ID, &p.Resource, &p.Action, &p.Description); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, rows.Err()
}
