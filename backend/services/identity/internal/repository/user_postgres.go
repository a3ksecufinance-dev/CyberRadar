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

// UserRepository handles identity persistence.
type UserRepository struct {
	db *pgxpool.Pool
}

// NewUserRepository creates a UserRepository.
func NewUserRepository(db *pgxpool.Pool) *UserRepository {
	return &UserRepository{db: db}
}

// identityColumns is the column list every identity query selects.
//
// display_name, password_hash, department, business_unit and mfa_secret are
// nullable in the schema but scan into plain strings, so they are coalesced
// here. Without this a NULL fails the scan, and Login reports the resulting
// error as "invalid credentials" — so a user with no department could never
// sign in, whatever their password.
const identityColumns = `id, tenant_id, username, email,
	COALESCE(display_name, '') AS display_name,
	COALESCE(password_hash, '') AS password_hash,
	identity_type,
	COALESCE(department, '') AS department,
	COALESCE(business_unit, '') AS business_unit,
	manager_id, privilege_level, mfa_enabled,
	COALESCE(mfa_secret, '') AS mfa_secret,
	pam_managed, risk_score, behavior_score, status, last_activity, source_systems,
	created_at, updated_at`

// GetByEmail retrieves a user by email within a specific tenant.
// tenant_id is mandatory — no cross-tenant lookup is possible.
func (r *UserRepository) GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*model.Identity, error) {
	const q = `
		SELECT ` + identityColumns + `
		FROM identities
		WHERE tenant_id = $1 AND email = $2 AND deleted_at IS NULL`

	row := r.db.QueryRow(ctx, q, tenantID, email)
	return scanIdentity(row)
}

// GetByID retrieves a user by ID.
// Note: tenantID enforcement happens in the service layer after this call.
func (r *UserRepository) GetByID(ctx context.Context, userID uuid.UUID) (*model.Identity, error) {
	const q = `
		SELECT ` + identityColumns + `
		FROM identities
		WHERE id = $1 AND deleted_at IS NULL`

	row := r.db.QueryRow(ctx, q, userID)
	u, err := scanIdentity(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("user not found")
	}
	return u, err
}

// Create inserts a new identity.
func (r *UserRepository) Create(ctx context.Context, tenantID uuid.UUID, req *model.CreateUserRequest, passwordHash string) (*model.Identity, error) {
	identityType := req.IdentityType
	if identityType == "" {
		identityType = "user"
	}
	privilegeLevel := req.PrivilegeLevel
	if privilegeLevel == "" {
		privilegeLevel = "standard"
	}

	const q = `
		INSERT INTO identities (
			tenant_id, username, email, display_name, password_hash,
			identity_type, department, business_unit,
			privilege_level, status, source_systems
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active', '[]')
		RETURNING ` + identityColumns + ``

	row := r.db.QueryRow(ctx, q,
		tenantID, req.Username, req.Email,
		req.DisplayName, passwordHash,
		identityType, req.Department, req.BusinessUnit,
		privilegeLevel,
	)
	return scanIdentity(row)
}

// List returns a paginated list of identities for a tenant.
func (r *UserRepository) List(ctx context.Context, f *model.ListUsersFilter) ([]*model.Identity, int64, error) {
	offset := (f.Page - 1) * f.Limit

	args := []any{f.TenantID}
	where := "tenant_id = $1 AND deleted_at IS NULL"
	argN := 2

	if f.Status != "" {
		where += fmt.Sprintf(" AND status = $%d", argN)
		args = append(args, f.Status)
		argN++
	}
	if f.IdentityType != "" {
		where += fmt.Sprintf(" AND identity_type = $%d", argN)
		args = append(args, f.IdentityType)
		argN++
	}
	if f.Search != "" {
		where += fmt.Sprintf(" AND (username ILIKE $%d OR email ILIKE $%d OR display_name ILIKE $%d)",
			argN, argN, argN)
		args = append(args, "%"+f.Search+"%")
		argN++
	}

	var total int64
	if err := r.db.QueryRow(ctx,
		fmt.Sprintf("SELECT COUNT(*) FROM identities WHERE %s", where), args...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count users: %w", err)
	}

	listQ := fmt.Sprintf(`
		SELECT `+identityColumns+`
		FROM identities
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, where, argN, argN+1)

	args = append(args, f.Limit, offset)
	rows, err := r.db.Query(ctx, listQ, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []*model.Identity
	for rows.Next() {
		u, err := scanIdentity(rows)
		if err != nil {
			return nil, 0, err
		}
		users = append(users, u)
	}
	return users, total, rows.Err()
}

// Update applies partial updates to a user.
func (r *UserRepository) Update(ctx context.Context, userID uuid.UUID, req *model.UpdateUserRequest) (*model.Identity, error) {
	sets := []string{}
	args := []any{}
	argN := 1

	if req.DisplayName != nil {
		sets = append(sets, fmt.Sprintf("display_name = $%d", argN))
		args = append(args, *req.DisplayName)
		argN++
	}
	if req.Department != nil {
		sets = append(sets, fmt.Sprintf("department = $%d", argN))
		args = append(args, *req.Department)
		argN++
	}
	if req.BusinessUnit != nil {
		sets = append(sets, fmt.Sprintf("business_unit = $%d", argN))
		args = append(args, *req.BusinessUnit)
		argN++
	}
	if req.PrivilegeLevel != nil {
		sets = append(sets, fmt.Sprintf("privilege_level = $%d", argN))
		args = append(args, *req.PrivilegeLevel)
		argN++
	}
	if req.Status != nil {
		sets = append(sets, fmt.Sprintf("status = $%d", argN))
		args = append(args, *req.Status)
		argN++
	}

	if len(sets) == 0 {
		return r.GetByID(ctx, userID)
	}

	query := fmt.Sprintf(`
		UPDATE identities SET %s
		WHERE id = $%d AND deleted_at IS NULL
		RETURNING `+identityColumns+``,
		joinSets(sets), argN)

	args = append(args, userID)
	row := r.db.QueryRow(ctx, query, args...)
	u, err := scanIdentity(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("user not found")
	}
	return u, err
}

// SetStatus updates the account status.
func (r *UserRepository) SetStatus(ctx context.Context, userID uuid.UUID, status string) error {
	_, err := r.db.Exec(ctx,
		"UPDATE identities SET status = $1 WHERE id = $2",
		status, userID)
	return err
}

// SetMFASecret stores the TOTP secret (encrypt in production).
func (r *UserRepository) SetMFASecret(ctx context.Context, userID uuid.UUID, secret string) error {
	_, err := r.db.Exec(ctx,
		"UPDATE identities SET mfa_secret = $1 WHERE id = $2",
		secret, userID)
	return err
}

// EnableMFA activates MFA for a user.
func (r *UserRepository) EnableMFA(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		"UPDATE identities SET mfa_enabled = true WHERE id = $1",
		userID)
	return err
}

// IncrementFailedLogin increments the failed login counter and locks the account if threshold is exceeded.
func (r *UserRepository) IncrementFailedLogin(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		UPDATE identities
		SET failed_login_count = failed_login_count + 1,
		    locked_until = CASE
		        WHEN failed_login_count + 1 >= 5
		        THEN NOW() + INTERVAL '15 minutes'
		        ELSE locked_until
		    END
		WHERE id = $1`, userID)
	return err
}

// ResetFailedLogin clears the failed login counter on successful auth.
func (r *UserRepository) ResetFailedLogin(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		"UPDATE identities SET failed_login_count = 0, locked_until = NULL WHERE id = $1",
		userID)
	return err
}

// UpdateLastActivity sets the last_activity timestamp.
func (r *UserRepository) UpdateLastActivity(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		"UPDATE identities SET last_activity = NOW() WHERE id = $1",
		userID)
	return err
}

// SaveRefreshToken stores the hashed refresh token.
func (r *UserRepository) SaveRefreshToken(ctx context.Context, userID, tenantID uuid.UUID, hash string, expiresAt time.Time) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO refresh_tokens (identity_id, tenant_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)`,
		userID, tenantID, hash, expiresAt)
	return err
}

// IsRefreshTokenValid checks whether a token hash is valid and not revoked.
func (r *UserRepository) IsRefreshTokenValid(ctx context.Context, hash string) (bool, error) {
	var valid bool
	err := r.db.QueryRow(ctx, `
		SELECT EXISTS(
		    SELECT 1 FROM refresh_tokens
		    WHERE token_hash = $1
		      AND revoked_at IS NULL
		      AND expires_at > NOW()
		)`, hash).Scan(&valid)
	return valid, err
}

// RevokeRefreshToken marks a token as revoked.
func (r *UserRepository) RevokeRefreshToken(ctx context.Context, hash string) error {
	_, err := r.db.Exec(ctx,
		"UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = $1",
		hash)
	return err
}

// ─── Scan helpers ─────────────────────────────────────────────────────────────

type scannable interface {
	Scan(dest ...any) error
}

func scanIdentity(row scannable) (*model.Identity, error) {
	var u model.Identity
	err := row.Scan(
		&u.ID, &u.TenantID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash,
		&u.IdentityType, &u.Department, &u.BusinessUnit, &u.ManagerID,
		&u.PrivilegeLevel, &u.MFAEnabled, &u.MFASecret, &u.PAMManaged,
		&u.RiskScore, &u.BehaviorScore, &u.Status, &u.LastActivity, &u.SourceSystems,
		&u.CreatedAt, &u.UpdatedAt,
	)
	return &u, err
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
