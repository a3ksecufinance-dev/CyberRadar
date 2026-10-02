package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyberradar/platform/services/tenant/internal/model"
)

// AttackPolicyRepository reads and writes attack-path weightings.
type AttackPolicyRepository struct {
	db *pgxpool.Pool
}

// NewAttackPolicyRepository creates an AttackPolicyRepository.
func NewAttackPolicyRepository(db *pgxpool.Pool) *AttackPolicyRepository {
	return &AttackPolicyRepository{db: db}
}

// ErrNoSuchAttackPolicy is returned when a caller names a standard stance that
// does not exist, so the answer can name it rather than being a bare 500.
var ErrNoSuchAttackPolicy = errors.New("no such standard attack policy")

const attackColumns = `
	id, tenant_id, code, name, COALESCE(description, ''), COALESCE(based_on, ''),
	version, effective_from, effective_to,
	base_cost, complexity_medium, complexity_high, privilege_low, privilege_high,
	hop_decay, impact_ceiling, unknown_target_impact, critical_system_bonus,
	many_paths_boost,
	COALESCE(notes, ''), created_by, created_at`

func scanAttackPolicy(row scannable) (*model.AttackPolicy, error) {
	var p model.AttackPolicy
	w := &p.Weights
	err := row.Scan(
		&p.ID, &p.TenantID, &p.Code, &p.Name, &p.Description, &p.BasedOn,
		&p.Version, &p.EffectiveFrom, &p.EffectiveTo,
		&w.BaseCost, &w.ComplexityMedium, &w.ComplexityHigh, &w.PrivilegeLow, &w.PrivilegeHigh,
		&w.HopDecay, &w.ImpactCeiling, &w.UnknownTargetImpact, &w.CriticalSystemBonus,
		&w.ManyPathsBoost,
		&p.Notes, &p.CreatedBy, &p.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Presets are the standard stances the platform ships.
func (r *AttackPolicyRepository) Presets(ctx context.Context) ([]*model.AttackPolicy, error) {
	rows, err := r.db.Query(ctx, `SELECT `+attackColumns+`
		FROM attack_policies
		WHERE tenant_id IS NULL AND effective_to IS NULL
		ORDER BY code`)
	if err != nil {
		return nil, fmt.Errorf("list standard attack policies: %w", err)
	}
	defer rows.Close()

	var out []*model.AttackPolicy
	for rows.Next() {
		p, err := scanAttackPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("scan standard attack policy: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Preset is one standard stance by code.
func (r *AttackPolicyRepository) Preset(ctx context.Context, code string) (*model.AttackPolicy, error) {
	row := r.db.QueryRow(ctx, `SELECT `+attackColumns+`
		FROM attack_policies
		WHERE tenant_id IS NULL AND code = $1 AND effective_to IS NULL`, code)
	p, err := scanAttackPolicy(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrNoSuchAttackPolicy, code)
	}
	if err != nil {
		return nil, fmt.Errorf("standard attack policy %s: %w", code, err)
	}
	return p, nil
}

// Active is the tenant's own stance in force, or nil when they have none.
func (r *AttackPolicyRepository) Active(ctx context.Context, tenantID uuid.UUID) (*model.AttackPolicy, error) {
	row := r.db.QueryRow(ctx, `SELECT `+attackColumns+`
		FROM attack_policies
		WHERE tenant_id = $1 AND effective_to IS NULL`, tenantID)
	p, err := scanAttackPolicy(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil //nolint:nilnil // "no stance of their own" is an answer, not an error
	}
	if err != nil {
		return nil, fmt.Errorf("active attack policy: %w", err)
	}
	return p, nil
}

// History is every version this tenant has had, newest first.
func (r *AttackPolicyRepository) History(ctx context.Context, tenantID uuid.UUID) ([]*model.AttackPolicy, error) {
	rows, err := r.db.Query(ctx, `SELECT `+attackColumns+`
		FROM attack_policies
		WHERE tenant_id = $1 ORDER BY version DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("attack policy history: %w", err)
	}
	defer rows.Close()

	var out []*model.AttackPolicy
	for rows.Next() {
		p, err := scanAttackPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("scan attack policy version: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Set records a new version, closing the previous one in the same transaction.
//
// Closed rather than replaced: a scenario records which version scored it, and
// an UPDATE would make last quarter's risk figure irreproducible with nothing
// saying why.
func (r *AttackPolicyRepository) Set(
	ctx context.Context,
	tenantID uuid.UUID,
	createdBy *uuid.UUID,
	p *model.AttackPolicy,
) (*model.AttackPolicy, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	if _, err := tx.Exec(ctx,
		`UPDATE attack_policies SET effective_to = NOW()
		 WHERE tenant_id = $1 AND effective_to IS NULL`, tenantID); err != nil {
		return nil, fmt.Errorf("close the previous version: %w", err)
	}

	var next int
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(MAX(version), 0) + 1 FROM attack_policies WHERE tenant_id = $1`,
		tenantID).Scan(&next); err != nil {
		return nil, fmt.Errorf("next version: %w", err)
	}

	w := p.Weights
	row := tx.QueryRow(ctx, `
		INSERT INTO attack_policies (
			tenant_id, code, name, description, based_on, version,
			base_cost, complexity_medium, complexity_high, privilege_low, privilege_high,
			hop_decay, impact_ceiling, unknown_target_impact, critical_system_bonus,
			many_paths_boost, notes, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		RETURNING `+attackColumns,
		tenantID, p.Code, p.Name, nvl(p.Description), nvl(p.BasedOn), next,
		w.BaseCost, w.ComplexityMedium, w.ComplexityHigh, w.PrivilegeLow, w.PrivilegeHigh,
		w.HopDecay, w.ImpactCeiling, w.UnknownTargetImpact, w.CriticalSystemBonus,
		w.ManyPathsBoost, nvl(p.Notes), createdBy,
	)
	saved, err := scanAttackPolicy(row)
	if err != nil {
		return nil, fmt.Errorf("insert attack policy: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return saved, nil
}
