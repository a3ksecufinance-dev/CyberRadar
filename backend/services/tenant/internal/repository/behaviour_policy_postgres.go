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

// BehaviourPolicyRepository reads and writes behavioural thresholds.
type BehaviourPolicyRepository struct {
	db *pgxpool.Pool
}

// NewBehaviourPolicyRepository creates a BehaviourPolicyRepository.
func NewBehaviourPolicyRepository(db *pgxpool.Pool) *BehaviourPolicyRepository {
	return &BehaviourPolicyRepository{db: db}
}

// ErrNoSuchBehaviourPolicy is returned when a caller names a standard policy
// that does not exist, so the answer can name it rather than being a bare 500.
var ErrNoSuchBehaviourPolicy = errors.New("no such standard behaviour policy")

const behaviourColumns = `
	id, tenant_id, code, name, COALESCE(description, ''), COALESCE(based_on, ''),
	version, effective_from, effective_to,
	min_hours_for_baseline, min_countries_for_baseline,
	velocity_threshold, velocity_window_s,
	brute_force_threshold, brute_force_window_s,
	off_hours_enabled, off_hours_severity, off_hours_score,
	new_country_enabled, new_country_severity, new_country_score,
	new_ip_prefix_enabled, new_ip_prefix_severity, new_ip_prefix_score,
	velocity_enabled, velocity_severity, velocity_score,
	brute_force_enabled, brute_force_severity, brute_force_score,
	priv_escalation_enabled, priv_escalation_severity, priv_escalation_score,
	lateral_movement_enabled, lateral_movement_severity, lateral_movement_score,
	data_exfiltration_enabled, data_exfiltration_severity, data_exfiltration_score,
	COALESCE(notes, ''), created_by, created_at`

func scanBehaviour(row scannable) (*model.BehaviourPolicy, error) {
	var p model.BehaviourPolicy
	t := &p.Thresholds
	s := &p.Signals
	err := row.Scan(
		&p.ID, &p.TenantID, &p.Code, &p.Name, &p.Description, &p.BasedOn,
		&p.Version, &p.EffectiveFrom, &p.EffectiveTo,
		&t.MinHoursForBaseline, &t.MinCountriesForBaseline,
		&t.VelocityThreshold, &t.VelocityWindowS,
		&t.BruteForceThreshold, &t.BruteForceWindowS,
		&s.OffHours.Enabled, &s.OffHours.Severity, &s.OffHours.Score,
		&s.NewCountry.Enabled, &s.NewCountry.Severity, &s.NewCountry.Score,
		&s.NewIPPrefix.Enabled, &s.NewIPPrefix.Severity, &s.NewIPPrefix.Score,
		&s.Velocity.Enabled, &s.Velocity.Severity, &s.Velocity.Score,
		&s.BruteForce.Enabled, &s.BruteForce.Severity, &s.BruteForce.Score,
		&s.PrivEscalation.Enabled, &s.PrivEscalation.Severity, &s.PrivEscalation.Score,
		&s.LateralMovement.Enabled, &s.LateralMovement.Severity, &s.LateralMovement.Score,
		&s.DataExfiltration.Enabled, &s.DataExfiltration.Severity, &s.DataExfiltration.Score,
		&p.Notes, &p.CreatedBy, &p.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Presets are the standard policies the platform ships.
func (r *BehaviourPolicyRepository) Presets(ctx context.Context) ([]*model.BehaviourPolicy, error) {
	rows, err := r.db.Query(ctx, `SELECT `+behaviourColumns+`
		FROM behaviour_policies
		WHERE tenant_id IS NULL AND effective_to IS NULL
		ORDER BY code`)
	if err != nil {
		return nil, fmt.Errorf("list standard behaviour policies: %w", err)
	}
	defer rows.Close()

	var out []*model.BehaviourPolicy
	for rows.Next() {
		p, err := scanBehaviour(rows)
		if err != nil {
			return nil, fmt.Errorf("scan standard behaviour policy: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Preset is one standard policy by code.
func (r *BehaviourPolicyRepository) Preset(ctx context.Context, code string) (*model.BehaviourPolicy, error) {
	row := r.db.QueryRow(ctx, `SELECT `+behaviourColumns+`
		FROM behaviour_policies
		WHERE tenant_id IS NULL AND code = $1 AND effective_to IS NULL`, code)
	p, err := scanBehaviour(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrNoSuchBehaviourPolicy, code)
	}
	if err != nil {
		return nil, fmt.Errorf("standard behaviour policy %s: %w", code, err)
	}
	return p, nil
}

// Active is the tenant's own policy in force, or nil when they have none.
func (r *BehaviourPolicyRepository) Active(ctx context.Context, tenantID uuid.UUID) (*model.BehaviourPolicy, error) {
	row := r.db.QueryRow(ctx, `SELECT `+behaviourColumns+`
		FROM behaviour_policies
		WHERE tenant_id = $1 AND effective_to IS NULL`, tenantID)
	p, err := scanBehaviour(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil //nolint:nilnil // "no policy of their own" is an answer, not an error
	}
	if err != nil {
		return nil, fmt.Errorf("active behaviour policy: %w", err)
	}
	return p, nil
}

// History is every version this tenant has had, newest first.
func (r *BehaviourPolicyRepository) History(ctx context.Context, tenantID uuid.UUID) ([]*model.BehaviourPolicy, error) {
	rows, err := r.db.Query(ctx, `SELECT `+behaviourColumns+`
		FROM behaviour_policies
		WHERE tenant_id = $1 ORDER BY version DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("behaviour policy history: %w", err)
	}
	defer rows.Close()

	var out []*model.BehaviourPolicy
	for rows.Next() {
		p, err := scanBehaviour(rows)
		if err != nil {
			return nil, fmt.Errorf("scan behaviour policy version: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Set records a new version, closing the previous one in the same transaction.
//
// Closed rather than replaced: "why did this not alert in March" is a question
// about the thresholds in force in March, and an UPDATE would erase the answer.
func (r *BehaviourPolicyRepository) Set(
	ctx context.Context,
	tenantID uuid.UUID,
	createdBy *uuid.UUID,
	p *model.BehaviourPolicy,
) (*model.BehaviourPolicy, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	if _, err := tx.Exec(ctx,
		`UPDATE behaviour_policies SET effective_to = NOW()
		 WHERE tenant_id = $1 AND effective_to IS NULL`, tenantID); err != nil {
		return nil, fmt.Errorf("close the previous version: %w", err)
	}

	var next int
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(MAX(version), 0) + 1 FROM behaviour_policies WHERE tenant_id = $1`,
		tenantID).Scan(&next); err != nil {
		return nil, fmt.Errorf("next version: %w", err)
	}

	t := p.Thresholds
	s := p.Signals
	row := tx.QueryRow(ctx, `
		INSERT INTO behaviour_policies (
			tenant_id, code, name, description, based_on, version,
			min_hours_for_baseline, min_countries_for_baseline,
			velocity_threshold, velocity_window_s,
			brute_force_threshold, brute_force_window_s,
			off_hours_enabled, off_hours_severity, off_hours_score, new_country_enabled, new_country_severity, new_country_score, new_ip_prefix_enabled, new_ip_prefix_severity, new_ip_prefix_score, velocity_enabled, velocity_severity, velocity_score, brute_force_enabled, brute_force_severity, brute_force_score, priv_escalation_enabled, priv_escalation_severity, priv_escalation_score, lateral_movement_enabled, lateral_movement_severity, lateral_movement_score, data_exfiltration_enabled, data_exfiltration_severity, data_exfiltration_score,
			notes, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38)
		RETURNING `+behaviourColumns,
		tenantID, p.Code, p.Name, nvl(p.Description), nvl(p.BasedOn), next,
		t.MinHoursForBaseline, t.MinCountriesForBaseline,
		t.VelocityThreshold, t.VelocityWindowS,
		t.BruteForceThreshold, t.BruteForceWindowS,
		s.OffHours.Enabled, s.OffHours.Severity, s.OffHours.Score,
		s.NewCountry.Enabled, s.NewCountry.Severity, s.NewCountry.Score,
		s.NewIPPrefix.Enabled, s.NewIPPrefix.Severity, s.NewIPPrefix.Score,
		s.Velocity.Enabled, s.Velocity.Severity, s.Velocity.Score,
		s.BruteForce.Enabled, s.BruteForce.Severity, s.BruteForce.Score,
		s.PrivEscalation.Enabled, s.PrivEscalation.Severity, s.PrivEscalation.Score,
		s.LateralMovement.Enabled, s.LateralMovement.Severity, s.LateralMovement.Score,
		s.DataExfiltration.Enabled, s.DataExfiltration.Severity, s.DataExfiltration.Score,
		nvl(p.Notes), createdBy,
	)
	saved, err := scanBehaviour(row)
	if err != nil {
		return nil, fmt.Errorf("insert behaviour policy: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return saved, nil
}
