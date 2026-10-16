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

// RemediationPolicyRepository reads and writes remediation deadlines.
type RemediationPolicyRepository struct {
	db *pgxpool.Pool
}

// NewRemediationPolicyRepository creates a RemediationPolicyRepository.
func NewRemediationPolicyRepository(db *pgxpool.Pool) *RemediationPolicyRepository {
	return &RemediationPolicyRepository{db: db}
}

// ErrNoSuchPolicy is returned when a caller names a standard policy that does
// not exist, so the answer can name it rather than being a bare 500.
var ErrNoSuchPolicy = errors.New("no such standard remediation policy")

const policyColumns = `
	id, tenant_id, code, name, COALESCE(description, ''), COALESCE(based_on, ''),
	version, effective_from, effective_to,
	critical_days, high_days, medium_days, low_days,
	exploited_days, dmz_days, cbs_days, swift_days, pci_days,
	minimum_days,
	COALESCE(notes, ''), created_by, created_at`

func scanPolicy(row scannable) (*model.RemediationPolicy, error) {
	var p model.RemediationPolicy
	d := &p.Deadlines
	err := row.Scan(
		&p.ID, &p.TenantID, &p.Code, &p.Name, &p.Description, &p.BasedOn,
		&p.Version, &p.EffectiveFrom, &p.EffectiveTo,
		&d.CriticalDays, &d.HighDays, &d.MediumDays, &d.LowDays,
		&d.ExploitedDays, &d.DMZDays, &d.CBSDays, &d.SWIFTDays, &d.PCIDays,
		&d.MinimumDays,
		&p.Notes, &p.CreatedBy, &p.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Presets are the standard policies the platform ships.
func (r *RemediationPolicyRepository) Presets(ctx context.Context) ([]*model.RemediationPolicy, error) {
	rows, err := r.db.Query(ctx, `SELECT `+policyColumns+`
		FROM remediation_policies
		WHERE tenant_id IS NULL AND effective_to IS NULL
		ORDER BY code`)
	if err != nil {
		return nil, fmt.Errorf("list standard policies: %w", err)
	}
	defer rows.Close()

	var out []*model.RemediationPolicy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("scan standard policy: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Preset is one standard policy by code.
func (r *RemediationPolicyRepository) Preset(ctx context.Context, code string) (*model.RemediationPolicy, error) {
	row := r.db.QueryRow(ctx, `SELECT `+policyColumns+`
		FROM remediation_policies
		WHERE tenant_id IS NULL AND code = $1 AND effective_to IS NULL`, code)
	p, err := scanPolicy(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrNoSuchPolicy, code)
	}
	if err != nil {
		return nil, fmt.Errorf("standard policy %s: %w", code, err)
	}
	return p, nil
}

// Active is the tenant's own policy in force, or nil when they have none.
func (r *RemediationPolicyRepository) Active(ctx context.Context, tenantID uuid.UUID) (*model.RemediationPolicy, error) {
	row := r.db.QueryRow(ctx, `SELECT `+policyColumns+`
		FROM remediation_policies
		WHERE tenant_id = $1 AND effective_to IS NULL`, tenantID)
	p, err := scanPolicy(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil //nolint:nilnil // "no policy of their own" is an answer, not an error
	}
	if err != nil {
		return nil, fmt.Errorf("active policy: %w", err)
	}
	return p, nil
}

// History is every version this tenant has had, newest first.
func (r *RemediationPolicyRepository) History(ctx context.Context, tenantID uuid.UUID) ([]*model.RemediationPolicy, error) {
	rows, err := r.db.Query(ctx, `SELECT `+policyColumns+`
		FROM remediation_policies
		WHERE tenant_id = $1 ORDER BY version DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("policy history: %w", err)
	}
	defer rows.Close()

	var out []*model.RemediationPolicy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("scan policy version: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Set records a new version, closing the previous one in the same transaction.
//
// Closed rather than replaced: whether a finding breached its deadline is a
// claim about the policy that was in force when it was raised, and an UPDATE
// would make last quarter's breach report unreproducible.
func (r *RemediationPolicyRepository) Set(
	ctx context.Context,
	tenantID uuid.UUID,
	createdBy *uuid.UUID,
	p *model.RemediationPolicy,
) (*model.RemediationPolicy, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	if _, err := tx.Exec(ctx,
		`UPDATE remediation_policies SET effective_to = NOW()
		 WHERE tenant_id = $1 AND effective_to IS NULL`, tenantID); err != nil {
		return nil, fmt.Errorf("close the previous version: %w", err)
	}

	var next int
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(MAX(version), 0) + 1 FROM remediation_policies WHERE tenant_id = $1`,
		tenantID).Scan(&next); err != nil {
		return nil, fmt.Errorf("next version: %w", err)
	}

	d := p.Deadlines
	row := tx.QueryRow(ctx, `
		INSERT INTO remediation_policies (
			tenant_id, code, name, description, based_on, version,
			critical_days, high_days, medium_days, low_days,
			exploited_days, dmz_days, cbs_days, swift_days, pci_days,
			minimum_days, notes, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		RETURNING `+policyColumns,
		tenantID, p.Code, p.Name, nvl(p.Description), nvl(p.BasedOn), next,
		d.CriticalDays, d.HighDays, d.MediumDays, d.LowDays,
		d.ExploitedDays, d.DMZDays, d.CBSDays, d.SWIFTDays, d.PCIDays,
		d.MinimumDays, nvl(p.Notes), createdBy,
	)
	saved, err := scanPolicy(row)
	if err != nil {
		return nil, fmt.Errorf("insert remediation policy: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return saved, nil
}
