package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cyberradar/platform/services/siem/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RuleRepository handles detection rules in PostgreSQL.
type RuleRepository struct {
	db *pgxpool.Pool
}

// NewRuleRepository creates a RuleRepository.
func NewRuleRepository(db *pgxpool.Pool) *RuleRepository {
	return &RuleRepository{db: db}
}

// Create inserts a new detection rule.
func (r *RuleRepository) Create(ctx context.Context, tenantID uuid.UUID, createdBy *uuid.UUID, req *model.CreateRuleRequest) (*model.DetectionRule, error) {
	id := uuid.New()
	condJSON, _ := json.Marshal(req.Conditions)
	actJSON, _ := json.Marshal(req.Actions)
	dedupW := req.DedupWindowS
	if dedupW <= 0 {
		dedupW = 300
	}

	const q = `
		INSERT INTO detection_rules
			(id, tenant_id, name, description, category, severity, conditions,
			 mitre_tactic, mitre_technique, actions, dedup_window_s, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING id, created_at, updated_at`

	var createdAt, updatedAt time.Time
	if err := r.db.QueryRow(ctx, q,
		id, tenantID, req.Name, nvl(req.Description), nvl(req.Category), req.Severity,
		condJSON, nvl(req.MitreTactic), nvl(req.MitreTechnique), actJSON, dedupW, createdBy,
	).Scan(&id, &createdAt, &updatedAt); err != nil {
		return nil, fmt.Errorf("create rule: %w", err)
	}
	return r.GetByID(ctx, tenantID, id)
}

// GetByID fetches a single rule.
func (r *RuleRepository) GetByID(ctx context.Context, tenantID, ruleID uuid.UUID) (*model.DetectionRule, error) {
	const q = `
		SELECT id, tenant_id, name, description, category, severity, conditions,
		       mitre_tactic, mitre_technique, actions, dedup_window_s,
		       enabled, is_system, false_positive_rate, alerts_total, last_fired_at,
		       created_by, created_at, updated_at
		FROM detection_rules WHERE id = $1 AND tenant_id = $2`
	row := r.db.QueryRow(ctx, q, ruleID, tenantID)
	return scanRule(row)
}

// ListEnabled returns all enabled rules for the tenant — used by the rule engine.
func (r *RuleRepository) ListEnabled(ctx context.Context, tenantID uuid.UUID) ([]*model.DetectionRule, error) {
	const q = `
		SELECT id, tenant_id, name, description, category, severity, conditions,
		       mitre_tactic, mitre_technique, actions, dedup_window_s,
		       enabled, is_system, false_positive_rate, alerts_total, last_fired_at,
		       created_by, created_at, updated_at
		FROM detection_rules
		WHERE tenant_id = $1 AND enabled = true
		ORDER BY severity DESC, name`
	rows, err := r.db.Query(ctx, q, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.DetectionRule
	for rows.Next() {
		rule, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	return out, nil
}

// List returns all rules (enabled and disabled) with optional filters.
func (r *RuleRepository) List(ctx context.Context, tenantID uuid.UUID, enabledOnly bool) ([]*model.DetectionRule, error) {
	q := `
		SELECT id, tenant_id, name, description, category, severity, conditions,
		       mitre_tactic, mitre_technique, actions, dedup_window_s,
		       enabled, is_system, false_positive_rate, alerts_total, last_fired_at,
		       created_by, created_at, updated_at
		FROM detection_rules WHERE tenant_id = $1`
	if enabledOnly {
		q += " AND enabled = true"
	}
	q += " ORDER BY severity DESC, name"
	rows, err := r.db.Query(ctx, q, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.DetectionRule
	for rows.Next() {
		rule, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	return out, nil
}

// Update applies a partial update to a rule.
func (r *RuleRepository) Update(ctx context.Context, tenantID, ruleID uuid.UUID, req *model.UpdateRuleRequest) (*model.DetectionRule, error) {
	sets := []string{}
	args := []any{}
	n := 1

	set := func(col string, val any) {
		sets = append(sets, fmt.Sprintf("%s = $%d", col, n))
		args = append(args, val)
		n++
	}

	if req.Name != nil {
		set("name", *req.Name)
	}
	if req.Description != nil {
		set("description", *req.Description)
	}
	if req.Severity != nil {
		set("severity", *req.Severity)
	}
	if req.Conditions != nil {
		b, _ := json.Marshal(req.Conditions)
		set("conditions", b)
	}
	if req.MitreTactic != nil {
		set("mitre_tactic", *req.MitreTactic)
	}
	if req.MitreTechnique != nil {
		set("mitre_technique", *req.MitreTechnique)
	}
	if req.Actions != nil {
		b, _ := json.Marshal(req.Actions)
		set("actions", b)
	}
	if req.DedupWindowS != nil {
		set("dedup_window_s", *req.DedupWindowS)
	}
	if req.Enabled != nil {
		set("enabled", *req.Enabled)
	}

	if len(sets) == 0 {
		return r.GetByID(ctx, tenantID, ruleID)
	}

	q := fmt.Sprintf(`UPDATE detection_rules SET %s WHERE id = $%d AND tenant_id = $%d AND is_system = false`,
		strings.Join(sets, ", "), n, n+1)
	args = append(args, ruleID, tenantID)

	if _, err := r.db.Exec(ctx, q, args...); err != nil {
		return nil, fmt.Errorf("update rule: %w", err)
	}
	return r.GetByID(ctx, tenantID, ruleID)
}

// Delete removes a non-system rule.
func (r *RuleRepository) Delete(ctx context.Context, tenantID, ruleID uuid.UUID) error {
	tag, err := r.db.Exec(ctx,
		`DELETE FROM detection_rules WHERE id = $1 AND tenant_id = $2 AND is_system = false`,
		ruleID, tenantID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// IncrementAlertCount bumps the alerts_total counter and updates last_fired_at.
func (r *RuleRepository) IncrementAlertCount(ctx context.Context, tenantID, ruleID uuid.UUID) {
	_, _ = r.db.Exec(ctx,
		`UPDATE detection_rules SET alerts_total = alerts_total + 1, last_fired_at = NOW() WHERE id = $1 AND tenant_id = $2`,
		ruleID, tenantID)
}

// ─── scanner ──────────────────────────────────────────────────────────────────

type scannable interface {
	Scan(dest ...any) error
}

func scanRule(row scannable) (*model.DetectionRule, error) {
	rule := &model.DetectionRule{}
	var (
		desc, cat, tactic, technique *string
		condRaw, actRaw              []byte
	)
	err := row.Scan(
		&rule.ID, &rule.TenantID, &rule.Name, &desc, &cat, &rule.Severity,
		&condRaw, &tactic, &technique, &actRaw, &rule.DedupWindowS,
		&rule.Enabled, &rule.IsSystem, &rule.FalsePositiveRate, &rule.AlertsTotal, &rule.LastFiredAt,
		&rule.CreatedBy, &rule.CreatedAt, &rule.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan rule: %w", err)
	}
	if desc != nil {
		rule.Description = *desc
	}
	if cat != nil {
		rule.Category = *cat
	}
	if tactic != nil {
		rule.MitreTactic = *tactic
	}
	if technique != nil {
		rule.MitreTechnique = *technique
	}
	if err := json.Unmarshal(condRaw, &rule.Conditions); err != nil {
		return nil, fmt.Errorf("unmarshal conditions: %w", err)
	}
	if len(actRaw) > 0 {
		_ = json.Unmarshal(actRaw, &rule.Actions)
	}
	if rule.Actions == nil {
		rule.Actions = []model.RuleAction{}
	}
	return rule, nil
}

func nvl(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
