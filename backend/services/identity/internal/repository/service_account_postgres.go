package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cyberradar/platform/services/identity/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ServiceAccountRepository persists machine principals and their credentials.
type ServiceAccountRepository struct {
	db *pgxpool.Pool
}

// NewServiceAccountRepository creates a ServiceAccountRepository.
func NewServiceAccountRepository(db *pgxpool.Pool) *ServiceAccountRepository {
	return &ServiceAccountRepository{db: db}
}

// serviceAccountColumns coalesces description, which is nullable in the schema
// but scans into a plain string.
const serviceAccountColumns = `id, identity_id, tenant_id, client_id, secret_hash, scope,
	COALESCE(description, '') AS description,
	enabled, expires_at, last_used_at, revoked_at, created_at`

// GetByClientID looks a credential up platform-wide, since the tenant is not
// known until the account is found.
func (r *ServiceAccountRepository) GetByClientID(ctx context.Context, clientID string) (*model.ServiceAccount, error) {
	var a model.ServiceAccount
	err := r.db.QueryRow(ctx,
		`SELECT `+serviceAccountColumns+` FROM service_accounts WHERE client_id = $1`, clientID).
		Scan(&a.ID, &a.IdentityID, &a.TenantID, &a.ClientID, &a.SecretHash, &a.Scope,
			&a.Description, &a.Enabled, &a.ExpiresAt, &a.LastUsedAt, &a.RevokedAt, &a.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("service account not found")
	}
	if err != nil {
		return nil, fmt.Errorf("get service account: %w", err)
	}
	return &a, nil
}

// TouchLastUsed records that the credential authenticated. Best effort: a
// failure here must not deny a token that was otherwise earned.
func (r *ServiceAccountRepository) TouchLastUsed(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `UPDATE service_accounts SET last_used_at = NOW() WHERE id = $1`, id)
	return err
}

// Create inserts the identity, its role grants and the credential in one
// transaction, so a half-made account with no roles — which would authenticate
// and then be authorized for nothing — cannot be left behind.
func (r *ServiceAccountRepository) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	createdBy uuid.UUID,
	req *model.CreateServiceAccountRequest,
	secretHash string,
	expiresAt *time.Time,
) (*model.ServiceAccount, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// The identity carries no password hash: a service account must not be
	// able to sign in through /auth/login.
	var identityID uuid.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO identities (tenant_id, username, email, display_name, identity_type, privilege_level, status)
		VALUES ($1, $2, $3, $4, 'service_account', 'standard', 'active')
		RETURNING id`,
		tenantID, req.ClientID, req.ClientID+"@service.local", req.Description).Scan(&identityID)
	if err != nil {
		return nil, fmt.Errorf("insert service identity: %w", err)
	}

	for _, roleID := range req.RoleIDs {
		if _, err := tx.Exec(ctx,
			`INSERT INTO identity_roles (identity_id, role_id, assigned_by) VALUES ($1, $2, $3)`,
			identityID, roleID, createdBy); err != nil {
			return nil, fmt.Errorf("grant role %s: %w", roleID, err)
		}
	}

	scope := req.Scope
	if scope == "" {
		scope = model.ScopeTenant
	}

	var a model.ServiceAccount
	err = tx.QueryRow(ctx, `
		INSERT INTO service_accounts
			(identity_id, tenant_id, client_id, secret_hash, scope, description, expires_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING `+serviceAccountColumns,
		identityID, tenantID, req.ClientID, secretHash, scope, req.Description, expiresAt, createdBy).
		Scan(&a.ID, &a.IdentityID, &a.TenantID, &a.ClientID, &a.SecretHash, &a.Scope,
			&a.Description, &a.Enabled, &a.ExpiresAt, &a.LastUsedAt, &a.RevokedAt, &a.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("insert service account: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return &a, nil
}

// Revoke disables a credential. The identity row stays so the audit trail
// keeps resolving what the account did.
func (r *ServiceAccountRepository) Revoke(ctx context.Context, tenantID, id uuid.UUID) error {
	tag, err := r.db.Exec(ctx,
		`UPDATE service_accounts SET enabled = false, revoked_at = NOW()
		 WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL`, id, tenantID)
	if err != nil {
		return fmt.Errorf("revoke service account: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("service account not found")
	}
	return nil
}

// List returns a tenant's service accounts, newest first.
func (r *ServiceAccountRepository) List(ctx context.Context, tenantID uuid.UUID) ([]*model.ServiceAccount, error) {
	rows, err := r.db.Query(ctx,
		`SELECT `+serviceAccountColumns+` FROM service_accounts WHERE tenant_id = $1 ORDER BY created_at DESC`,
		tenantID)
	if err != nil {
		return nil, fmt.Errorf("list service accounts: %w", err)
	}
	defer rows.Close()

	var out []*model.ServiceAccount
	for rows.Next() {
		var a model.ServiceAccount
		if err := rows.Scan(&a.ID, &a.IdentityID, &a.TenantID, &a.ClientID, &a.SecretHash, &a.Scope,
			&a.Description, &a.Enabled, &a.ExpiresAt, &a.LastUsedAt, &a.RevokedAt, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan service account: %w", err)
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}
