package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cyberradar/platform/services/tenant/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TenantRepository handles all tenant persistence.
type TenantRepository struct {
	db *pgxpool.Pool
}

// NewTenantRepository creates a new TenantRepository.
func NewTenantRepository(db *pgxpool.Pool) *TenantRepository {
	return &TenantRepository{db: db}
}

// Create inserts a new tenant.
func (r *TenantRepository) Create(ctx context.Context, req *model.CreateTenantRequest) (*model.Tenant, error) {
	const q = `
		INSERT INTO tenants (name, slug, parent_id, plan, status, config, features, limits)
		VALUES ($1, $2, $3, $4, 'active', '{}', '{}', '{"max_users":100,"max_assets":10000,"max_eps":1000}')
		RETURNING id, name, slug, parent_id, plan, status, config, features, limits, created_at, updated_at`

	row := r.db.QueryRow(ctx, q,
		req.Name,
		req.Slug,
		req.ParentID,
		req.Plan,
	)

	return scanTenant(row)
}

// GetByID retrieves a tenant by its ID.
func (r *TenantRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.Tenant, error) {
	const q = `
		SELECT id, name, slug, parent_id, plan, status, config, features, limits, created_at, updated_at
		FROM tenants
		WHERE id = $1 AND deleted_at IS NULL`

	row := r.db.QueryRow(ctx, q, id)
	t, err := scanTenant(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("tenant not found")
	}
	return t, err
}

// GetBySlug retrieves a tenant by its slug.
func (r *TenantRepository) GetBySlug(ctx context.Context, slug string) (*model.Tenant, error) {
	const q = `
		SELECT id, name, slug, parent_id, plan, status, config, features, limits, created_at, updated_at
		FROM tenants
		WHERE slug = $1 AND deleted_at IS NULL`

	row := r.db.QueryRow(ctx, q, slug)
	t, err := scanTenant(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil // nil, nil = not found
	}
	return t, err
}

// List returns a paginated list of tenants.
func (r *TenantRepository) List(ctx context.Context, f *model.ListTenantsFilter) ([]*model.Tenant, int64, error) {
	offset := (f.Page - 1) * f.Limit
	if offset < 0 {
		offset = 0
	}

	args := []any{}
	where := "deleted_at IS NULL"
	argN := 1

	if f.Status != "" {
		where += fmt.Sprintf(" AND status = $%d", argN)
		args = append(args, f.Status)
		argN++
	}
	if f.ParentID != nil {
		where += fmt.Sprintf(" AND parent_id = $%d", argN)
		args = append(args, f.ParentID)
		argN++
	}

	// Count
	var total int64
	countQ := fmt.Sprintf("SELECT COUNT(*) FROM tenants WHERE %s", where)
	if err := r.db.QueryRow(ctx, countQ, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count tenants: %w", err)
	}

	// List
	listQ := fmt.Sprintf(`
		SELECT id, name, slug, parent_id, plan, status, config, features, limits, created_at, updated_at
		FROM tenants
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, where, argN, argN+1)

	args = append(args, f.Limit, offset)
	rows, err := r.db.Query(ctx, listQ, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list tenants: %w", err)
	}
	defer rows.Close()

	var tenants []*model.Tenant
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, 0, err
		}
		tenants = append(tenants, t)
	}

	return tenants, total, rows.Err()
}

// Update applies partial updates to a tenant.
func (r *TenantRepository) Update(ctx context.Context, id uuid.UUID, req *model.UpdateTenantRequest) (*model.Tenant, error) {
	sets := []string{}
	args := []any{}
	argN := 1

	if req.Name != nil {
		sets = append(sets, fmt.Sprintf("name = $%d", argN))
		args = append(args, *req.Name)
		argN++
	}
	if req.Plan != nil {
		sets = append(sets, fmt.Sprintf("plan = $%d", argN))
		args = append(args, *req.Plan)
		argN++
	}
	if req.Status != nil {
		sets = append(sets, fmt.Sprintf("status = $%d", argN))
		args = append(args, *req.Status)
		argN++
	}
	if len(req.Config) > 0 {
		sets = append(sets, fmt.Sprintf("config = $%d", argN))
		args = append(args, req.Config)
		argN++
	}
	if len(req.Features) > 0 {
		sets = append(sets, fmt.Sprintf("features = $%d", argN))
		args = append(args, req.Features)
		argN++
	}
	if len(req.Limits) > 0 {
		sets = append(sets, fmt.Sprintf("limits = $%d", argN))
		args = append(args, req.Limits)
		argN++
	}

	if len(sets) == 0 {
		return r.GetByID(ctx, id)
	}

	q := fmt.Sprintf(`
		UPDATE tenants SET %s
		WHERE id = $%d AND deleted_at IS NULL
		RETURNING id, name, slug, parent_id, plan, status, config, features, limits, created_at, updated_at`,
		joinSets(sets), argN)

	args = append(args, id)
	row := r.db.QueryRow(ctx, q, args...)
	t, err := scanTenant(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("tenant not found")
	}
	return t, err
}

// SoftDelete marks a tenant as deleted.
func (r *TenantRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	const q = `UPDATE tenants SET deleted_at = NOW(), status = 'deleted' WHERE id = $1 AND deleted_at IS NULL`
	tag, err := r.db.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("delete tenant: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("tenant not found")
	}
	return nil
}

// SlugExists checks whether a slug is already taken.
func (r *TenantRepository) SlugExists(ctx context.Context, slug string) (bool, error) {
	var exists bool
	err := r.db.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM tenants WHERE slug = $1 AND deleted_at IS NULL)",
		slug,
	).Scan(&exists)
	return exists, err
}

// ─── Scan helpers ─────────────────────────────────────────

type scannable interface {
	Scan(dest ...any) error
}

func scanTenant(row scannable) (*model.Tenant, error) {
	var t model.Tenant
	var configRaw, featuresRaw, limitsRaw []byte

	err := row.Scan(
		&t.ID, &t.Name, &t.Slug, &t.ParentID,
		&t.Plan, &t.Status,
		&configRaw, &featuresRaw, &limitsRaw,
		&t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	t.Config = coalesceJSON(configRaw)
	t.Features = coalesceJSON(featuresRaw)
	t.Limits = coalesceJSON(limitsRaw)

	return &t, nil
}

func coalesceJSON(b []byte) model.JSONB {
	if b == nil {
		return model.JSONB("{}")
	}
	return model.JSONB(b)
}

func joinSets(sets []string) string {
	result := ""
	for i, s := range sets {
		if i > 0 {
			result += ", "
		}
		result += s
	}
	return result
}

// Ensure json is importable (used via JSONB serialisation in future).
var _ = json.Marshal
