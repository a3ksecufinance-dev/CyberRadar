package repository

import (
	"context"
	"fmt"
	"math"
	"strings"

	"github.com/cyberradar/platform/services/cspm/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CSPMRepository handles all persistence for the CSPM domain.
type CSPMRepository struct {
	pool *pgxpool.Pool
}

// NewCSPMRepository creates a CSPMRepository.
func NewCSPMRepository(pool *pgxpool.Pool) *CSPMRepository {
	return &CSPMRepository{pool: pool}
}

// ─── Accounts ─────────────────────────────────────────────────────────────────

const accountSelect = `
SELECT id, tenant_id, name, description, provider, account_id, region, environment,
       status, posture_score, critical_count, high_count, medium_count, low_count,
       resource_count, last_scanned_at, metadata, created_at, updated_at
FROM cspm_accounts`

func scanAccount(row pgx.Row) (*model.CSPMAccount, error) {
	a := &model.CSPMAccount{}
	err := row.Scan(
		&a.ID, &a.TenantID, &a.Name, &a.Description, &a.Provider, &a.AccountID, &a.Region, &a.Environment,
		&a.Status, &a.PostureScore, &a.CriticalCount, &a.HighCount, &a.MediumCount, &a.LowCount,
		&a.ResourceCount, &a.LastScannedAt, &a.Metadata, &a.CreatedAt, &a.UpdatedAt,
	)
	return a, err
}

func (r *CSPMRepository) RegisterAccount(ctx context.Context, tenantID uuid.UUID, req *model.RegisterAccountRequest) (*model.CSPMAccount, error) {
	env := req.Environment
	if env == "" {
		env = "production"
	}
	meta := req.Metadata
	if meta == nil {
		meta = map[string]any{}
	}
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `INSERT INTO cspm_accounts
		(tenant_id, name, description, provider, account_id, region, environment, metadata)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (tenant_id, provider, account_id) DO UPDATE SET
			name=EXCLUDED.name, description=EXCLUDED.description,
			region=EXCLUDED.region, environment=EXCLUDED.environment,
			metadata=EXCLUDED.metadata, status='active', updated_at=NOW()
		RETURNING id`,
		tenantID, req.Name, req.Description, req.Provider, req.AccountID, req.Region, env, meta,
	).Scan(&id)
	if err != nil {
		return nil, err
	}
	return r.GetAccount(ctx, tenantID, id)
}

func (r *CSPMRepository) GetAccount(ctx context.Context, tenantID, accountID uuid.UUID) (*model.CSPMAccount, error) {
	row := r.pool.QueryRow(ctx, accountSelect+` WHERE id=$1 AND tenant_id=$2`, accountID, tenantID)
	a, err := scanAccount(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return a, err
}

func (r *CSPMRepository) ListAccounts(ctx context.Context, tenantID uuid.UUID, provider, env string) ([]*model.CSPMAccount, error) {
	conditions := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if provider != "" {
		conditions = append(conditions, fmt.Sprintf("provider=$%d", n))
		args = append(args, provider)
		n++
	}
	if env != "" {
		conditions = append(conditions, fmt.Sprintf("environment=$%d", n))
		args = append(args, env)
		n++
	}
	where := "WHERE " + strings.Join(conditions, " AND ")
	rows, err := r.pool.Query(ctx, accountSelect+` `+where+` ORDER BY posture_score ASC, name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var accounts []*model.CSPMAccount
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, a)
	}
	return accounts, nil
}

func (r *CSPMRepository) UpdateAccount(ctx context.Context, tenantID, accountID uuid.UUID, req *model.UpdateAccountRequest) (*model.CSPMAccount, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{}
	n := 1
	if req.Name != "" {
		sets = append(sets, fmt.Sprintf("name=$%d", n)); args = append(args, req.Name); n++
	}
	if req.Description != "" {
		sets = append(sets, fmt.Sprintf("description=$%d", n)); args = append(args, req.Description); n++
	}
	if req.Region != "" {
		sets = append(sets, fmt.Sprintf("region=$%d", n)); args = append(args, req.Region); n++
	}
	if req.Environment != "" {
		sets = append(sets, fmt.Sprintf("environment=$%d", n)); args = append(args, req.Environment); n++
	}
	if req.Status != "" {
		sets = append(sets, fmt.Sprintf("status=$%d", n)); args = append(args, req.Status); n++
	}
	if req.Metadata != nil {
		sets = append(sets, fmt.Sprintf("metadata=$%d", n)); args = append(args, req.Metadata); n++
	}
	args = append(args, accountID, tenantID)
	_, err := r.pool.Exec(ctx,
		fmt.Sprintf(`UPDATE cspm_accounts SET %s WHERE id=$%d AND tenant_id=$%d`, strings.Join(sets, ","), n, n+1),
		args...)
	if err != nil {
		return nil, err
	}
	return r.GetAccount(ctx, tenantID, accountID)
}

// ─── Rules ────────────────────────────────────────────────────────────────────

const ruleSelect = `
SELECT id, tenant_id, rule_id, title, description, rationale, remediation,
       provider, resource_type, framework, framework_section, severity, is_active, created_at
FROM cspm_rules`

func scanRule(row pgx.Row) (*model.CSPMRule, error) {
	r := &model.CSPMRule{}
	err := row.Scan(
		&r.ID, &r.TenantID, &r.RuleID, &r.Title, &r.Description, &r.Rationale, &r.Remediation,
		&r.Provider, &r.ResourceType, &r.Framework, &r.FrameworkSection, &r.Severity, &r.IsActive, &r.CreatedAt,
	)
	return r, err
}

func (r *CSPMRepository) CreateRule(ctx context.Context, tenantID uuid.UUID, req *model.CreateRuleRequest) (*model.CSPMRule, error) {
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `INSERT INTO cspm_rules
		(tenant_id, rule_id, title, description, rationale, remediation,
		 provider, resource_type, framework, framework_section, severity)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (tenant_id, rule_id) DO UPDATE SET
			title=EXCLUDED.title, description=EXCLUDED.description,
			severity=EXCLUDED.severity, is_active=TRUE
		RETURNING id`,
		tenantID, req.RuleID, req.Title, req.Description, req.Rationale, req.Remediation,
		req.Provider, req.ResourceType, req.Framework, req.FrameworkSection, req.Severity,
	).Scan(&id)
	if err != nil {
		return nil, err
	}
	row := r.pool.QueryRow(ctx, ruleSelect+` WHERE id=$1`, id)
	return scanRule(row)
}

func (r *CSPMRepository) ListRules(ctx context.Context, tenantID uuid.UUID, provider, framework, severity string, page, pageSize int) ([]*model.CSPMRule, int, error) {
	conditions := []string{"tenant_id=$1", "is_active=TRUE"}
	args := []any{tenantID}
	n := 2
	if provider != "" {
		conditions = append(conditions, fmt.Sprintf("provider=$%d", n)); args = append(args, provider); n++
	}
	if framework != "" {
		conditions = append(conditions, fmt.Sprintf("framework=$%d", n)); args = append(args, framework); n++
	}
	if severity != "" {
		conditions = append(conditions, fmt.Sprintf("severity=$%d", n)); args = append(args, severity); n++
	}
	where := "WHERE " + strings.Join(conditions, " AND ")
	var total int
	r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM cspm_rules `+where, args...).Scan(&total)
	if page < 1 { page = 1 }
	if pageSize < 1 || pageSize > 500 { pageSize = 100 }
	offset := (page - 1) * pageSize
	args = append(args, pageSize, offset)
	rows, err := r.pool.Query(ctx, ruleSelect+` `+where+fmt.Sprintf(` ORDER BY severity, framework, rule_id LIMIT $%d OFFSET $%d`, n, n+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var rules []*model.CSPMRule
	for rows.Next() {
		rule, err := scanRule(rows)
		if err != nil {
			return nil, 0, err
		}
		rules = append(rules, rule)
	}
	return rules, total, nil
}

// SeedCISRules inserts a baseline set of CIS rules for a given provider.
func (r *CSPMRepository) SeedCISRules(ctx context.Context, tenantID uuid.UUID, provider string) (int, error) {
	rules := defaultCISRules(provider)
	count := 0
	for _, rule := range rules {
		_, err := r.pool.Exec(ctx, `INSERT INTO cspm_rules
			(tenant_id, rule_id, title, description, remediation, provider, resource_type, framework, framework_section, severity)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT (tenant_id, rule_id) DO NOTHING`,
			tenantID, rule.RuleID, rule.Title, rule.Description, rule.Remediation,
			rule.Provider, rule.ResourceType, rule.Framework, rule.FrameworkSection, rule.Severity)
		if err == nil {
			count++
		}
	}
	return count, nil
}

// ─── Resources ────────────────────────────────────────────────────────────────

const resourceSelect = `
SELECT id, tenant_id, account_id, resource_uid, name, resource_type, service,
       region, tags, risk_score, finding_count, is_public, last_seen_at, created_at, updated_at
FROM cspm_resources`

func scanResource(row pgx.Row) (*model.CSPMResource, error) {
	res := &model.CSPMResource{}
	err := row.Scan(
		&res.ID, &res.TenantID, &res.AccountID, &res.ResourceUID, &res.Name, &res.ResourceType, &res.Service,
		&res.Region, &res.Tags, &res.RiskScore, &res.FindingCount, &res.IsPublic, &res.LastSeenAt, &res.CreatedAt, &res.UpdatedAt,
	)
	return res, err
}

func (r *CSPMRepository) UpsertResource(ctx context.Context, tenantID uuid.UUID, req *model.UpsertResourceRequest) (*model.CSPMResource, error) {
	tags := req.Tags
	if tags == nil {
		tags = map[string]any{}
	}
	cfg := req.Configuration
	if cfg == nil {
		cfg = map[string]any{}
	}
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `INSERT INTO cspm_resources
		(tenant_id, account_id, resource_uid, name, resource_type, service, region, tags, configuration, is_public)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (account_id, resource_uid) DO UPDATE SET
			name=EXCLUDED.name, tags=EXCLUDED.tags, configuration=EXCLUDED.configuration,
			is_public=EXCLUDED.is_public, last_seen_at=NOW(), updated_at=NOW()
		RETURNING id`,
		tenantID, req.AccountID, req.ResourceUID, req.Name, req.ResourceType, req.Service,
		req.Region, tags, cfg, req.IsPublic,
	).Scan(&id)
	if err != nil {
		return nil, err
	}
	row := r.pool.QueryRow(ctx, resourceSelect+` WHERE id=$1`, id)
	return scanResource(row)
}

func (r *CSPMRepository) GetResource(ctx context.Context, tenantID, resourceID uuid.UUID) (*model.CSPMResource, error) {
	row := r.pool.QueryRow(ctx, resourceSelect+` WHERE id=$1 AND tenant_id=$2`, resourceID, tenantID)
	res, err := scanResource(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return res, err
}

func (r *CSPMRepository) ListResources(ctx context.Context, tenantID uuid.UUID, f model.ListResourcesFilter) ([]*model.CSPMResource, int, error) {
	conditions := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if f.AccountID != nil {
		conditions = append(conditions, fmt.Sprintf("account_id=$%d", n)); args = append(args, *f.AccountID); n++
	}
	if f.ResourceType != "" {
		conditions = append(conditions, fmt.Sprintf("resource_type=$%d", n)); args = append(args, f.ResourceType); n++
	}
	if f.Service != "" {
		conditions = append(conditions, fmt.Sprintf("service=$%d", n)); args = append(args, f.Service); n++
	}
	if f.IsPublic != nil {
		conditions = append(conditions, fmt.Sprintf("is_public=$%d", n)); args = append(args, *f.IsPublic); n++
	}
	if f.MinRiskScore != nil {
		conditions = append(conditions, fmt.Sprintf("risk_score>=$%d", n)); args = append(args, *f.MinRiskScore); n++
	}
	where := "WHERE " + strings.Join(conditions, " AND ")
	var total int
	r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM cspm_resources `+where, args...).Scan(&total)
	if f.Page < 1 { f.Page = 1 }
	if f.PageSize < 1 || f.PageSize > 200 { f.PageSize = 50 }
	offset := (f.Page - 1) * f.PageSize
	args = append(args, f.PageSize, offset)
	rows, err := r.pool.Query(ctx, resourceSelect+` `+where+fmt.Sprintf(` ORDER BY risk_score DESC, last_seen_at DESC LIMIT $%d OFFSET $%d`, n, n+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var resources []*model.CSPMResource
	for rows.Next() {
		res, err := scanResource(rows)
		if err != nil {
			return nil, 0, err
		}
		resources = append(resources, res)
	}
	return resources, total, nil
}

// ─── Findings ─────────────────────────────────────────────────────────────────

const findingSelect = `
SELECT id, tenant_id, account_id, resource_id, rule_id, rule_ref, title, severity, status,
       resource_uid, resource_type, region, evidence, remediation,
       first_seen_at, last_seen_at, resolved_at, suppressed_by, suppression_reason, scan_id, created_at
FROM cspm_findings`

func scanFinding(row pgx.Row) (*model.CSPMFinding, error) {
	f := &model.CSPMFinding{}
	var resourceID, suppressedBy, scanID *uuid.UUID
	err := row.Scan(
		&f.ID, &f.TenantID, &f.AccountID, &resourceID, &f.RuleID, &f.RuleRef, &f.Title, &f.Severity, &f.Status,
		&f.ResourceUID, &f.ResourceType, &f.Region, &f.Evidence, &f.Remediation,
		&f.FirstSeenAt, &f.LastSeenAt, &f.ResolvedAt, &suppressedBy, &f.SuppressionReason, &scanID, &f.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	f.ResourceID = resourceID
	f.SuppressedBy = suppressedBy
	f.ScanID = scanID
	return f, nil
}

func (r *CSPMRepository) ReportFinding(ctx context.Context, tenantID uuid.UUID, req *model.ReportFindingRequest) (*model.CSPMFinding, error) {
	// Fetch rule details
	var ruleRef, title, severity, remediation string
	if err := r.pool.QueryRow(ctx, `SELECT rule_id, title, severity, COALESCE(remediation,'') FROM cspm_rules WHERE id=$1`, req.RuleID).
		Scan(&ruleRef, &title, &severity, &remediation); err != nil {
		return nil, fmt.Errorf("rule not found: %w", err)
	}

	evidence := req.Evidence
	if evidence == nil {
		evidence = map[string]any{}
	}

	// Resolve resource_id if resource_uid provided
	var resourceID *uuid.UUID
	if req.ResourceUID != "" {
		var rid uuid.UUID
		if err := r.pool.QueryRow(ctx, `SELECT id FROM cspm_resources WHERE account_id=$1 AND resource_uid=$2`,
			req.AccountID, req.ResourceUID).Scan(&rid); err == nil {
			resourceID = &rid
		}
	}

	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `INSERT INTO cspm_findings
		(tenant_id, account_id, resource_id, rule_id, rule_ref, title, severity,
		 resource_uid, resource_type, region, evidence, remediation, scan_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		ON CONFLICT DO NOTHING
		RETURNING id`,
		tenantID, req.AccountID, resourceID, req.RuleID, ruleRef, title, severity,
		req.ResourceUID, req.ResourceType, req.Region, evidence, remediation, req.ScanID,
	).Scan(&id)
	if err != nil {
		// Finding may already exist — update last_seen_at
		r.pool.Exec(ctx, `UPDATE cspm_findings SET last_seen_at=NOW(), scan_id=$1 WHERE tenant_id=$2 AND account_id=$3 AND rule_id=$4 AND resource_uid=$5 AND status='open'`,
			req.ScanID, tenantID, req.AccountID, req.RuleID, req.ResourceUID)
		r.pool.QueryRow(ctx, `SELECT id FROM cspm_findings WHERE tenant_id=$1 AND account_id=$2 AND rule_id=$3 AND resource_uid=$4 ORDER BY created_at DESC LIMIT 1`,
			tenantID, req.AccountID, req.RuleID, req.ResourceUID).Scan(&id)
	}

	// Update resource risk score and finding count
	if resourceID != nil {
		r.updateResourceRisk(ctx, *resourceID)
	}

	row := r.pool.QueryRow(ctx, findingSelect+` WHERE id=$1`, id)
	return scanFinding(row)
}

func (r *CSPMRepository) updateResourceRisk(ctx context.Context, resourceID uuid.UUID) {
	var critCount, highCount, medCount int
	r.pool.QueryRow(ctx, `SELECT
		COUNT(*) FILTER (WHERE severity='critical' AND status='open'),
		COUNT(*) FILTER (WHERE severity='high' AND status='open'),
		COUNT(*) FILTER (WHERE severity='medium' AND status='open')
		FROM cspm_findings WHERE resource_id=$1`, resourceID).Scan(&critCount, &highCount, &medCount)

	score := int(math.Min(100, float64(critCount*40+highCount*20+medCount*10)))
	total := critCount + highCount + medCount
	r.pool.Exec(ctx, `UPDATE cspm_resources SET risk_score=$1, finding_count=$2, updated_at=NOW() WHERE id=$3`,
		score, total, resourceID)
}

func (r *CSPMRepository) ListFindings(ctx context.Context, tenantID uuid.UUID, f model.ListFindingsFilter) ([]*model.CSPMFinding, int, error) {
	conditions := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if f.AccountID != nil {
		conditions = append(conditions, fmt.Sprintf("account_id=$%d", n)); args = append(args, *f.AccountID); n++
	}
	if f.ResourceID != nil {
		conditions = append(conditions, fmt.Sprintf("resource_id=$%d", n)); args = append(args, *f.ResourceID); n++
	}
	if f.Severity != "" {
		conditions = append(conditions, fmt.Sprintf("severity=$%d", n)); args = append(args, f.Severity); n++
	}
	if f.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status=$%d", n)); args = append(args, f.Status); n++
	}
	if f.Provider != "" {
		conditions = append(conditions, fmt.Sprintf("rule_ref LIKE $%d", n)); args = append(args, strings.ToUpper(f.Provider)+"-%"); n++
	}
	where := "WHERE " + strings.Join(conditions, " AND ")
	var total int
	r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM cspm_findings `+where, args...).Scan(&total)
	if f.Page < 1 { f.Page = 1 }
	if f.PageSize < 1 || f.PageSize > 200 { f.PageSize = 50 }
	offset := (f.Page - 1) * f.PageSize
	args = append(args, f.PageSize, offset)
	rows, err := r.pool.Query(ctx, findingSelect+` `+where+fmt.Sprintf(` ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, last_seen_at DESC LIMIT $%d OFFSET $%d`, n, n+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var findings []*model.CSPMFinding
	for rows.Next() {
		finding, err := scanFinding(rows)
		if err != nil {
			return nil, 0, err
		}
		findings = append(findings, finding)
	}
	return findings, total, nil
}

func (r *CSPMRepository) UpdateFinding(ctx context.Context, tenantID, findingID, updatedBy uuid.UUID, req *model.UpdateFindingRequest) (*model.CSPMFinding, error) {
	sets := []string{fmt.Sprintf("status=$1")}
	args := []any{req.Status}
	n := 2
	if req.Status == "resolved" {
		sets = append(sets, "resolved_at=NOW()")
	}
	if req.Status == "suppressed" {
		sets = append(sets, fmt.Sprintf("suppressed_by=$%d", n)); args = append(args, updatedBy); n++
		if req.SuppressionReason != "" {
			sets = append(sets, fmt.Sprintf("suppression_reason=$%d", n)); args = append(args, req.SuppressionReason); n++
		}
	}
	args = append(args, findingID, tenantID)
	_, err := r.pool.Exec(ctx,
		fmt.Sprintf(`UPDATE cspm_findings SET %s WHERE id=$%d AND tenant_id=$%d`, strings.Join(sets, ","), n, n+1), args...)
	if err != nil {
		return nil, err
	}
	row := r.pool.QueryRow(ctx, findingSelect+` WHERE id=$1 AND tenant_id=$2`, findingID, tenantID)
	finding, err := scanFinding(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return finding, err
}

// ─── Scans ────────────────────────────────────────────────────────────────────

func (r *CSPMRepository) CreateScan(ctx context.Context, tenantID, accountID uuid.UUID, scanType string, triggeredBy uuid.UUID) (*model.CSPMScan, error) {
	if scanType == "" {
		scanType = "full"
	}
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `INSERT INTO cspm_scans (tenant_id, account_id, scan_type, triggered_by)
		VALUES ($1,$2,$3,$4) RETURNING id`, tenantID, accountID, scanType, triggeredBy).Scan(&id)
	if err != nil {
		return nil, err
	}
	return r.GetScan(ctx, tenantID, id)
}

func (r *CSPMRepository) GetScan(ctx context.Context, tenantID, scanID uuid.UUID) (*model.CSPMScan, error) {
	s := &model.CSPMScan{}
	var triggeredBy *uuid.UUID
	err := r.pool.QueryRow(ctx, `
		SELECT id, tenant_id, account_id, status, scan_type, resources_scanned,
		       rules_evaluated, findings_new, findings_resolved, posture_score,
		       error_message, started_at, completed_at, triggered_by, created_at
		FROM cspm_scans WHERE id=$1 AND tenant_id=$2`, scanID, tenantID).Scan(
		&s.ID, &s.TenantID, &s.AccountID, &s.Status, &s.ScanType, &s.ResourcesScanned,
		&s.RulesEvaluated, &s.FindingsNew, &s.FindingsResolved, &s.PostureScore,
		&s.ErrorMessage, &s.StartedAt, &s.CompletedAt, &triggeredBy, &s.CreatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	s.TriggeredBy = triggeredBy
	return s, err
}

func (r *CSPMRepository) ListScans(ctx context.Context, tenantID, accountID uuid.UUID, page, pageSize int) ([]*model.CSPMScan, int, error) {
	where := `WHERE tenant_id=$1 AND account_id=$2`
	args := []any{tenantID, accountID}
	var total int
	r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM cspm_scans `+where, args...).Scan(&total)
	if page < 1 { page = 1 }
	if pageSize < 1 || pageSize > 100 { pageSize = 20 }
	offset := (page - 1) * pageSize
	rows, err := r.pool.Query(ctx, `
		SELECT id, tenant_id, account_id, status, scan_type, resources_scanned,
		       rules_evaluated, findings_new, findings_resolved, posture_score,
		       error_message, started_at, completed_at, triggered_by, created_at
		FROM cspm_scans `+where+` ORDER BY created_at DESC LIMIT $3 OFFSET $4`,
		tenantID, accountID, pageSize, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var scans []*model.CSPMScan
	for rows.Next() {
		s := &model.CSPMScan{}
		var triggeredBy *uuid.UUID
		if err := rows.Scan(
			&s.ID, &s.TenantID, &s.AccountID, &s.Status, &s.ScanType, &s.ResourcesScanned,
			&s.RulesEvaluated, &s.FindingsNew, &s.FindingsResolved, &s.PostureScore,
			&s.ErrorMessage, &s.StartedAt, &s.CompletedAt, &triggeredBy, &s.CreatedAt,
		); err != nil {
			return nil, 0, err
		}
		s.TriggeredBy = triggeredBy
		scans = append(scans, s)
	}
	return scans, total, nil
}

func (r *CSPMRepository) CompleteScan(ctx context.Context, scanID uuid.UUID, resourcesScanned, rulesEvaluated, findingsNew, findingsResolved, postureScore int) error {
	_, err := r.pool.Exec(ctx, `UPDATE cspm_scans SET
		status='completed', resources_scanned=$1, rules_evaluated=$2,
		findings_new=$3, findings_resolved=$4, posture_score=$5,
		completed_at=NOW()
		WHERE id=$6`, resourcesScanned, rulesEvaluated, findingsNew, findingsResolved, postureScore, scanID)
	return err
}

func (r *CSPMRepository) FailScan(ctx context.Context, scanID uuid.UUID, errMsg string) error {
	_, err := r.pool.Exec(ctx, `UPDATE cspm_scans SET status='failed', error_message=$1, completed_at=NOW() WHERE id=$2`, errMsg, scanID)
	return err
}

// UpdateAccountPosture recalculates and stores posture score from open findings.
func (r *CSPMRepository) UpdateAccountPosture(ctx context.Context, tenantID, accountID uuid.UUID) error {
	var critCount, highCount, medCount, lowCount, resourceCount int
	r.pool.QueryRow(ctx, `SELECT
		COUNT(*) FILTER (WHERE severity='critical' AND status='open'),
		COUNT(*) FILTER (WHERE severity='high' AND status='open'),
		COUNT(*) FILTER (WHERE severity='medium' AND status='open'),
		COUNT(*) FILTER (WHERE severity='low' AND status='open')
		FROM cspm_findings WHERE tenant_id=$1 AND account_id=$2`,
		tenantID, accountID).Scan(&critCount, &highCount, &medCount, &lowCount)

	r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM cspm_resources WHERE tenant_id=$1 AND account_id=$2`,
		tenantID, accountID).Scan(&resourceCount)

	// Posture score: start at 100, deduct points per finding
	deduction := critCount*15 + highCount*8 + medCount*4 + lowCount*1
	score := int(math.Max(0, float64(100-deduction)))

	_, err := r.pool.Exec(ctx, `UPDATE cspm_accounts SET
		posture_score=$1, critical_count=$2, high_count=$3, medium_count=$4, low_count=$5,
		resource_count=$6, last_scanned_at=NOW(), updated_at=NOW()
		WHERE id=$7 AND tenant_id=$8`,
		score, critCount, highCount, medCount, lowCount, resourceCount, accountID, tenantID)
	return err
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (r *CSPMRepository) Stats(ctx context.Context, tenantID uuid.UUID) (*model.CSPMStats, error) {
	stats := &model.CSPMStats{
		FindingsBySeverity:  map[string]int{},
		FindingsByProvider:  map[string]int{},
		FindingsByFramework: map[string]int{},
	}

	r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM cspm_accounts WHERE tenant_id=$1 AND status='active'`, tenantID).Scan(&stats.TotalAccounts)
	r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM cspm_resources WHERE tenant_id=$1`, tenantID).Scan(&stats.TotalResources)
	r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM cspm_resources WHERE tenant_id=$1 AND is_public=TRUE`, tenantID).Scan(&stats.PublicResources)
	r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM cspm_findings WHERE tenant_id=$1 AND status='open'`, tenantID).Scan(&stats.OpenFindings)
	r.pool.QueryRow(ctx, `SELECT COALESCE(AVG(posture_score),0) FROM cspm_accounts WHERE tenant_id=$1 AND status='active'`, tenantID).Scan(&stats.AvgPostureScore)

	sevRows, _ := r.pool.Query(ctx, `SELECT severity, COUNT(*) FROM cspm_findings WHERE tenant_id=$1 AND status='open' GROUP BY severity`, tenantID)
	if sevRows != nil {
		defer sevRows.Close()
		for sevRows.Next() {
			var s string; var c int
			sevRows.Scan(&s, &c)
			stats.FindingsBySeverity[s] = c
		}
	}

	// Account postures
	accRows, _ := r.pool.Query(ctx, `SELECT id, name, provider, posture_score,
		(SELECT COUNT(*) FROM cspm_findings f WHERE f.account_id=a.id AND f.status='open')
		FROM cspm_accounts a WHERE tenant_id=$1 AND status='active' ORDER BY posture_score ASC LIMIT 10`, tenantID)
	if accRows != nil {
		defer accRows.Close()
		for accRows.Next() {
			ap := &model.AccountPosture{}
			accRows.Scan(&ap.AccountID, &ap.AccountName, &ap.Provider, &ap.PostureScore, &ap.OpenFindings)
			stats.AccountPostures = append(stats.AccountPostures, ap)
		}
	}

	// Top violated rules
	ruleRows, _ := r.pool.Query(ctx, `SELECT f.rule_id, f.rule_ref, r.title, r.severity, COUNT(*) as cnt
		FROM cspm_findings f JOIN cspm_rules r ON r.id=f.rule_id
		WHERE f.tenant_id=$1 AND f.status='open'
		GROUP BY f.rule_id, f.rule_ref, r.title, r.severity ORDER BY cnt DESC LIMIT 10`, tenantID)
	if ruleRows != nil {
		defer ruleRows.Close()
		for ruleRows.Next() {
			rv := &model.RuleViolationStats{}
			ruleRows.Scan(&rv.RuleID, &rv.RuleRef, &rv.Title, &rv.Severity, &rv.ViolationCount)
			stats.TopViolatedRules = append(stats.TopViolatedRules, rv)
		}
	}

	return stats, nil
}

// ─── Default CIS rules ────────────────────────────────────────────────────────

func defaultCISRules(provider string) []model.CreateRuleRequest {
	switch provider {
	case model.ProviderAWS:
		return []model.CreateRuleRequest{
			{RuleID: "CIS-AWS-1.1", Title: "Avoid the use of the root account", Provider: "aws", ResourceType: "iam_root", Framework: "cis", FrameworkSection: "1.1", Severity: "critical", Remediation: "Enable MFA on root account and avoid daily use."},
			{RuleID: "CIS-AWS-1.3", Title: "Ensure MFA is enabled for all IAM users with console access", Provider: "aws", ResourceType: "iam_user", Framework: "cis", FrameworkSection: "1.3", Severity: "high", Remediation: "Enable MFA for all IAM users that have a console password."},
			{RuleID: "CIS-AWS-1.4", Title: "Ensure access keys are rotated every 90 days", Provider: "aws", ResourceType: "iam_user", Framework: "cis", FrameworkSection: "1.4", Severity: "medium", Remediation: "Rotate IAM access keys every 90 days or less."},
			{RuleID: "CIS-AWS-2.1", Title: "Ensure CloudTrail is enabled in all regions", Provider: "aws", ResourceType: "cloudtrail", Framework: "cis", FrameworkSection: "2.1", Severity: "high", Remediation: "Enable CloudTrail in all regions."},
			{RuleID: "CIS-AWS-2.3", Title: "Ensure CloudTrail log file validation is enabled", Provider: "aws", ResourceType: "cloudtrail", Framework: "cis", FrameworkSection: "2.3", Severity: "medium", Remediation: "Enable log file validation for all CloudTrail trails."},
			{RuleID: "CIS-AWS-2.6", Title: "Ensure S3 bucket access logging is enabled on CloudTrail S3 bucket", Provider: "aws", ResourceType: "s3_bucket", Framework: "cis", FrameworkSection: "2.6", Severity: "medium", Remediation: "Enable access logging on the CloudTrail S3 bucket."},
			{RuleID: "CIS-AWS-3.1", Title: "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22", Provider: "aws", ResourceType: "security_group", Framework: "cis", FrameworkSection: "3.1", Severity: "critical", Remediation: "Restrict SSH access to known IP ranges."},
			{RuleID: "CIS-AWS-3.2", Title: "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389", Provider: "aws", ResourceType: "security_group", Framework: "cis", FrameworkSection: "3.2", Severity: "critical", Remediation: "Restrict RDP access to known IP ranges."},
			{RuleID: "CIS-AWS-3.3", Title: "Ensure VPC flow logging is enabled", Provider: "aws", ResourceType: "vpc", Framework: "cis", FrameworkSection: "3.3", Severity: "medium", Remediation: "Enable VPC flow logs for all VPCs."},
			{RuleID: "CIS-AWS-4.1", Title: "Ensure no S3 buckets are publicly accessible", Provider: "aws", ResourceType: "s3_bucket", Framework: "cis", FrameworkSection: "4.1", Severity: "critical", Remediation: "Block public access settings on all S3 buckets."},
			{RuleID: "CIS-AWS-4.2", Title: "Ensure S3 bucket versioning is enabled", Provider: "aws", ResourceType: "s3_bucket", Framework: "cis", FrameworkSection: "4.2", Severity: "low", Remediation: "Enable versioning on all S3 buckets."},
			{RuleID: "CIS-AWS-4.3", Title: "Ensure RDS instances are not publicly accessible", Provider: "aws", ResourceType: "rds_instance", Framework: "cis", FrameworkSection: "4.3", Severity: "critical", Remediation: "Set PubliclyAccessible=false on all RDS instances."},
		}
	case model.ProviderAzure:
		return []model.CreateRuleRequest{
			{RuleID: "CIS-AZ-1.1", Title: "Ensure multi-factor authentication is enabled for all users", Provider: "azure", ResourceType: "aad_user", Framework: "cis", FrameworkSection: "1.1", Severity: "critical", Remediation: "Enable MFA for all Azure AD users via Conditional Access."},
			{RuleID: "CIS-AZ-1.3", Title: "Ensure guest users are reviewed monthly", Provider: "azure", ResourceType: "aad_user", Framework: "cis", FrameworkSection: "1.3", Severity: "medium", Remediation: "Review and remove stale guest accounts monthly."},
			{RuleID: "CIS-AZ-2.1", Title: "Ensure Activity Log Diagnostic Setting captures all categories", Provider: "azure", ResourceType: "diagnostic_setting", Framework: "cis", FrameworkSection: "2.1", Severity: "high", Remediation: "Configure diagnostic settings to capture all audit events."},
			{RuleID: "CIS-AZ-3.1", Title: "Ensure storage account public access is disabled", Provider: "azure", ResourceType: "storage_account", Framework: "cis", FrameworkSection: "3.1", Severity: "critical", Remediation: "Disable public blob access on all storage accounts."},
			{RuleID: "CIS-AZ-3.2", Title: "Ensure SQL Server auditing is enabled", Provider: "azure", ResourceType: "sql_server", Framework: "cis", FrameworkSection: "3.2", Severity: "high", Remediation: "Enable auditing for all Azure SQL servers."},
			{RuleID: "CIS-AZ-4.1", Title: "Ensure Web Application Firewall is enabled on App Gateway", Provider: "azure", ResourceType: "app_gateway", Framework: "cis", FrameworkSection: "4.1", Severity: "high", Remediation: "Enable WAF on all Application Gateways."},
			{RuleID: "CIS-AZ-5.1", Title: "Ensure disk encryption is enabled for virtual machines", Provider: "azure", ResourceType: "virtual_machine", Framework: "cis", FrameworkSection: "5.1", Severity: "high", Remediation: "Enable Azure Disk Encryption on all VM disks."},
		}
	case model.ProviderGCP:
		return []model.CreateRuleRequest{
			{RuleID: "CIS-GCP-1.1", Title: "Ensure corporate login credentials are used", Provider: "gcp", ResourceType: "iam_user", Framework: "cis", FrameworkSection: "1.1", Severity: "high", Remediation: "Use corporate Google Workspace accounts instead of personal Gmail."},
			{RuleID: "CIS-GCP-2.1", Title: "Ensure Cloud Audit Logging is enabled for all services", Provider: "gcp", ResourceType: "audit_config", Framework: "cis", FrameworkSection: "2.1", Severity: "high", Remediation: "Enable Data Access audit logs for all GCP services."},
			{RuleID: "CIS-GCP-3.1", Title: "Ensure firewall rules do not allow unrestricted SSH", Provider: "gcp", ResourceType: "firewall_rule", Framework: "cis", FrameworkSection: "3.1", Severity: "critical", Remediation: "Restrict SSH (port 22) firewall rules to specific IP ranges."},
			{RuleID: "CIS-GCP-4.1", Title: "Ensure Cloud Storage buckets are not publicly accessible", Provider: "gcp", ResourceType: "storage_bucket", Framework: "cis", FrameworkSection: "4.1", Severity: "critical", Remediation: "Remove allUsers and allAuthenticatedUsers from bucket IAM policies."},
			{RuleID: "CIS-GCP-5.1", Title: "Ensure Cloud SQL instances require SSL", Provider: "gcp", ResourceType: "cloudsql_instance", Framework: "cis", FrameworkSection: "5.1", Severity: "high", Remediation: "Enable requireSsl on all Cloud SQL instances."},
		}
	}
	return nil
}
