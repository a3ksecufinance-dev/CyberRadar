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

// RiskProfileRepository reads and writes risk-appetite profiles.
type RiskProfileRepository struct {
	db *pgxpool.Pool
}

// NewRiskProfileRepository creates a RiskProfileRepository.
func NewRiskProfileRepository(db *pgxpool.Pool) *RiskProfileRepository {
	return &RiskProfileRepository{db: db}
}

// ErrNoSuchPreset is returned when a caller names a standard profile that does
// not exist — worth distinguishing so the answer can be 422 with the name in
// it rather than a bare 500.
var ErrNoSuchPreset = errors.New("no such standard risk profile")

const profileColumns = `
	id, tenant_id, code, name, COALESCE(description, ''), COALESCE(based_on, ''),
	version, effective_from, effective_to,
	criticality_step, criticality_cap,
	vuln_critical, vuln_high, vuln_medium, vuln_low, vuln_cap,
	cbs_connected, swift_connected, pci_scope, exposure_cap,
	never_seen, critical_production, banking_type, context_cap,
	total_cap, high_risk_threshold,
	COALESCE(notes, ''), created_by, created_at`

func scanProfile(row scannable) (*model.RiskProfile, error) {
	var p model.RiskProfile
	w := &p.Weights
	err := row.Scan(
		&p.ID, &p.TenantID, &p.Code, &p.Name, &p.Description, &p.BasedOn,
		&p.Version, &p.EffectiveFrom, &p.EffectiveTo,
		&w.CriticalityStep, &w.CriticalityCap,
		&w.VulnCritical, &w.VulnHigh, &w.VulnMedium, &w.VulnLow, &w.VulnCap,
		&w.CBSConnected, &w.SWIFTConnected, &w.PCIScope, &w.ExposureCap,
		&w.NeverSeen, &w.CriticalProduction, &w.BankingType, &w.ContextCap,
		&w.TotalCap, &w.HighRiskThreshold,
		&p.Notes, &p.CreatedBy, &p.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Presets are the standard profiles the platform ships.
func (r *RiskProfileRepository) Presets(ctx context.Context) ([]*model.RiskProfile, error) {
	rows, err := r.db.Query(ctx, `SELECT `+profileColumns+`
		FROM risk_profiles
		WHERE tenant_id IS NULL AND effective_to IS NULL
		ORDER BY CASE code WHEN 'balanced' THEN 0 ELSE 1 END, name`)
	if err != nil {
		return nil, fmt.Errorf("list standard profiles: %w", err)
	}
	defer rows.Close()

	var out []*model.RiskProfile
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan standard profile: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Preset returns one standard profile by code.
func (r *RiskProfileRepository) Preset(ctx context.Context, code string) (*model.RiskProfile, error) {
	row := r.db.QueryRow(ctx, `SELECT `+profileColumns+`
		FROM risk_profiles
		WHERE tenant_id IS NULL AND code = $1 AND effective_to IS NULL`, code)
	p, err := scanProfile(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrNoSuchPreset, code)
	}
	if err != nil {
		return nil, fmt.Errorf("standard profile %s: %w", code, err)
	}
	return p, nil
}

// Active is the tenant's own profile, or nil when it has not chosen one and is
// being scored under the standard profile.
//
// nil rather than the standard profile: "we adopted the default" and "we have
// not decided" are different answers, and an interface should be able to say
// which.
func (r *RiskProfileRepository) Active(ctx context.Context, tenantID uuid.UUID) (*model.RiskProfile, error) {
	row := r.db.QueryRow(ctx, `SELECT `+profileColumns+`
		FROM risk_profiles
		WHERE tenant_id = $1 AND effective_to IS NULL`, tenantID)
	p, err := scanProfile(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("active risk profile: %w", err)
	}
	return p, nil
}

// History is every version this tenant has had, newest first.
//
// It is the answer to the question an auditor asks first: what was the formula
// on the day that score drove a decision.
func (r *RiskProfileRepository) History(ctx context.Context, tenantID uuid.UUID) ([]*model.RiskProfile, error) {
	rows, err := r.db.Query(ctx, `SELECT `+profileColumns+`
		FROM risk_profiles
		WHERE tenant_id = $1
		ORDER BY version DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("risk profile history: %w", err)
	}
	defer rows.Close()

	var out []*model.RiskProfile
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan risk profile: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Set opens a new version and closes the previous one, in one transaction.
//
// Never an update in place. A score that drove a decision has to be explicable
// months later, and the first question is what the weights were that day; a row
// edited in place cannot answer it. The unique index on the active row is what
// makes the close-then-open ordering load-bearing rather than tidy.
func (r *RiskProfileRepository) Set(
	ctx context.Context,
	tenantID uuid.UUID,
	createdBy *uuid.UUID,
	p *model.RiskProfile,
) (*model.RiskProfile, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	if _, err := tx.Exec(ctx,
		`UPDATE risk_profiles SET effective_to = NOW()
		 WHERE tenant_id = $1 AND effective_to IS NULL`, tenantID); err != nil {
		return nil, fmt.Errorf("close the previous version: %w", err)
	}

	var next int
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(MAX(version), 0) + 1 FROM risk_profiles WHERE tenant_id = $1`,
		tenantID).Scan(&next); err != nil {
		return nil, fmt.Errorf("next version: %w", err)
	}

	w := p.Weights
	row := tx.QueryRow(ctx, `
		INSERT INTO risk_profiles (
			tenant_id, code, name, description, based_on, version,
			criticality_step, criticality_cap,
			vuln_critical, vuln_high, vuln_medium, vuln_low, vuln_cap,
			cbs_connected, swift_connected, pci_scope, exposure_cap,
			never_seen, critical_production, banking_type, context_cap,
			total_cap, high_risk_threshold, notes, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)
		RETURNING `+profileColumns,
		tenantID, p.Code, p.Name, nvl(p.Description), nvl(p.BasedOn), next,
		w.CriticalityStep, w.CriticalityCap,
		w.VulnCritical, w.VulnHigh, w.VulnMedium, w.VulnLow, w.VulnCap,
		w.CBSConnected, w.SWIFTConnected, w.PCIScope, w.ExposureCap,
		w.NeverSeen, w.CriticalProduction, w.BankingType, w.ContextCap,
		w.TotalCap, w.HighRiskThreshold, nvl(p.Notes), createdBy,
	)
	saved, err := scanProfile(row)
	if err != nil {
		return nil, fmt.Errorf("insert risk profile: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return saved, nil
}

func nvl(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
