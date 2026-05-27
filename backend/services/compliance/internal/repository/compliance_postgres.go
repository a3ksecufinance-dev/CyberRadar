package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cyberradar/platform/services/compliance/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ComplianceRepository handles all compliance persistence.
type ComplianceRepository struct {
	db *pgxpool.Pool
}

// NewComplianceRepository creates a ComplianceRepository.
func NewComplianceRepository(db *pgxpool.Pool) *ComplianceRepository {
	return &ComplianceRepository{db: db}
}

// ─── Frameworks ───────────────────────────────────────────────────────────────

func (r *ComplianceRepository) CreateFramework(ctx context.Context, tenantID uuid.UUID, req *model.CreateFrameworkRequest) (*model.Framework, error) {
	ver := req.Version
	if ver == "" {
		ver = "1.0"
	}
	var fw model.Framework
	err := r.db.QueryRow(ctx, `
		INSERT INTO comp_frameworks (tenant_id, code, name, description, version)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (tenant_id, code) DO UPDATE
		  SET name=$3, description=$4, version=$5, updated_at=NOW()
		RETURNING id, tenant_id, code, name, COALESCE(description,''), version,
		          total_controls, is_active, created_at, updated_at`,
		tenantID, req.Code, req.Name, req.Description, ver,
	).Scan(&fw.ID, &fw.TenantID, &fw.Code, &fw.Name, &fw.Description, &fw.Version,
		&fw.TotalControls, &fw.IsActive, &fw.CreatedAt, &fw.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &fw, nil
}

func (r *ComplianceRepository) GetFramework(ctx context.Context, tenantID, frameworkID uuid.UUID) (*model.Framework, error) {
	var fw model.Framework
	err := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, code, name, COALESCE(description,''), version,
		       total_controls, is_active, created_at, updated_at
		FROM comp_frameworks WHERE id=$1 AND tenant_id=$2`,
		frameworkID, tenantID,
	).Scan(&fw.ID, &fw.TenantID, &fw.Code, &fw.Name, &fw.Description, &fw.Version,
		&fw.TotalControls, &fw.IsActive, &fw.CreatedAt, &fw.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &fw, err
}

func (r *ComplianceRepository) ListFrameworks(ctx context.Context, f model.FrameworkFilter) ([]*model.Framework, error) {
	where := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	idx := 2

	if f.IsActive != nil {
		where = append(where, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *f.IsActive)
		idx++
	}
	_ = idx

	rows, err := r.db.Query(ctx,
		`SELECT id, tenant_id, code, name, COALESCE(description,''), version,
		        total_controls, is_active, created_at, updated_at
		 FROM comp_frameworks WHERE `+strings.Join(where, " AND ")+` ORDER BY code`,
		args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var frameworks []*model.Framework
	for rows.Next() {
		var fw model.Framework
		if err := rows.Scan(&fw.ID, &fw.TenantID, &fw.Code, &fw.Name, &fw.Description, &fw.Version,
			&fw.TotalControls, &fw.IsActive, &fw.CreatedAt, &fw.UpdatedAt); err != nil {
			return nil, err
		}
		frameworks = append(frameworks, &fw)
	}
	return frameworks, rows.Err()
}

func (r *ComplianceRepository) SetFrameworkActive(ctx context.Context, tenantID, frameworkID uuid.UUID, active bool) error {
	_, err := r.db.Exec(ctx,
		`UPDATE comp_frameworks SET is_active=$1, updated_at=NOW() WHERE id=$2 AND tenant_id=$3`,
		active, frameworkID, tenantID)
	return err
}

func (r *ComplianceRepository) UpdateFrameworkControlCount(ctx context.Context, frameworkID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE comp_frameworks SET total_controls=(SELECT COUNT(*) FROM comp_controls WHERE framework_id=$1), updated_at=NOW() WHERE id=$1`,
		frameworkID)
	return err
}

// ─── Controls ─────────────────────────────────────────────────────────────────

func (r *ComplianceRepository) CreateControl(ctx context.Context, tenantID uuid.UUID, req *model.CreateControlRequest) (*model.Control, error) {
	pri := req.Priority
	if pri == "" {
		pri = model.PriorityMedium
	}
	var c model.Control
	err := r.db.QueryRow(ctx, `
		INSERT INTO comp_controls (tenant_id, framework_id, control_id, domain, title, description, guidance, priority, is_automated)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id, tenant_id, framework_id, control_id, domain, title,
		          COALESCE(description,''), COALESCE(guidance,''), priority, is_automated, created_at`,
		tenantID, req.FrameworkID, req.ControlID, req.Domain, req.Title, req.Description, req.Guidance, pri, req.IsAutomated,
	).Scan(&c.ID, &c.TenantID, &c.FrameworkID, &c.ControlID, &c.Domain, &c.Title,
		&c.Description, &c.Guidance, &c.Priority, &c.IsAutomated, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = r.UpdateFrameworkControlCount(ctx, req.FrameworkID)
	return &c, nil
}

func (r *ComplianceRepository) GetControl(ctx context.Context, tenantID, controlID uuid.UUID) (*model.Control, error) {
	var c model.Control
	err := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, framework_id, control_id, domain, title,
		       COALESCE(description,''), COALESCE(guidance,''), priority, is_automated, created_at
		FROM comp_controls WHERE id=$1 AND tenant_id=$2`,
		controlID, tenantID,
	).Scan(&c.ID, &c.TenantID, &c.FrameworkID, &c.ControlID, &c.Domain, &c.Title,
		&c.Description, &c.Guidance, &c.Priority, &c.IsAutomated, &c.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &c, err
}

func (r *ComplianceRepository) ListControls(ctx context.Context, f model.ControlFilter) ([]*model.Control, int, error) {
	where := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	idx := 2

	if f.FrameworkID != nil {
		where = append(where, fmt.Sprintf("framework_id = $%d", idx))
		args = append(args, *f.FrameworkID)
		idx++
	}
	if f.Domain != "" {
		where = append(where, fmt.Sprintf("domain = $%d", idx))
		args = append(args, f.Domain)
		idx++
	}
	if f.Priority != "" {
		where = append(where, fmt.Sprintf("priority = $%d", idx))
		args = append(args, f.Priority)
		idx++
	}
	if f.IsAutomated != nil {
		where = append(where, fmt.Sprintf("is_automated = $%d", idx))
		args = append(args, *f.IsAutomated)
		idx++
	}

	whereStr := strings.Join(where, " AND ")
	var total int
	if err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM comp_controls WHERE `+whereStr, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	args = append(args, limit, f.Offset)
	rows, err := r.db.Query(ctx,
		`SELECT id, tenant_id, framework_id, control_id, domain, title,
		        COALESCE(description,''), COALESCE(guidance,''), priority, is_automated, created_at
		 FROM comp_controls WHERE `+whereStr+
			fmt.Sprintf(` ORDER BY domain, control_id LIMIT $%d OFFSET $%d`, idx, idx+1),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var controls []*model.Control
	for rows.Next() {
		var c model.Control
		if err := rows.Scan(&c.ID, &c.TenantID, &c.FrameworkID, &c.ControlID, &c.Domain, &c.Title,
			&c.Description, &c.Guidance, &c.Priority, &c.IsAutomated, &c.CreatedAt); err != nil {
			return nil, 0, err
		}
		controls = append(controls, &c)
	}
	return controls, total, rows.Err()
}

// ListAutomatedControls returns all is_automated=true controls for a tenant.
func (r *ComplianceRepository) ListAutomatedControls(ctx context.Context, tenantID uuid.UUID) ([]*model.Control, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, framework_id, control_id, domain, title,
		       COALESCE(description,''), COALESCE(guidance,''), priority, is_automated, created_at
		FROM comp_controls WHERE tenant_id=$1 AND is_automated=TRUE ORDER BY domain, control_id`,
		tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var controls []*model.Control
	for rows.Next() {
		var c model.Control
		if err := rows.Scan(&c.ID, &c.TenantID, &c.FrameworkID, &c.ControlID, &c.Domain, &c.Title,
			&c.Description, &c.Guidance, &c.Priority, &c.IsAutomated, &c.CreatedAt); err != nil {
			return nil, err
		}
		controls = append(controls, &c)
	}
	return controls, rows.Err()
}

// ─── Assessments ──────────────────────────────────────────────────────────────

const assessmentSelect = `
    id, tenant_id, framework_id, control_id, status, score,
    COALESCE(evidence_refs,'{}'), COALESCE(notes,''),
    assessed_by, assessed_at, next_review_at, created_at, updated_at`

func (r *ComplianceRepository) UpsertAssessment(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreateAssessmentRequest) (*model.Assessment, error) {
	refs := req.EvidenceRefs
	if refs == nil {
		refs = []string{}
	}
	score := req.Score
	if req.Status == model.StatusCompliant && score == 0 {
		score = 100
	}
	if req.Status == model.StatusPartial && score == 0 {
		score = 50
	}

	var a model.Assessment
	err := r.db.QueryRow(ctx, `
		INSERT INTO comp_assessments
		    (tenant_id, framework_id, control_id, status, score, evidence_refs, notes, assessed_by, assessed_at, next_review_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW(),$9)
		ON CONFLICT (tenant_id, control_id) DO UPDATE
		  SET framework_id   = EXCLUDED.framework_id,
		      status         = EXCLUDED.status,
		      score          = EXCLUDED.score,
		      evidence_refs  = EXCLUDED.evidence_refs,
		      notes          = EXCLUDED.notes,
		      assessed_by    = EXCLUDED.assessed_by,
		      assessed_at    = NOW(),
		      next_review_at = EXCLUDED.next_review_at,
		      updated_at     = NOW()
		RETURNING `+assessmentSelect,
		tenantID, req.FrameworkID, req.ControlID, req.Status, score,
		refs, req.Notes, callerID, req.NextReviewAt,
	).Scan(&a.ID, &a.TenantID, &a.FrameworkID, &a.ControlID, &a.Status, &a.Score,
		&a.EvidenceRefs, &a.Notes, &a.AssessedBy, &a.AssessedAt, &a.NextReviewAt,
		&a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (r *ComplianceRepository) GetAssessment(ctx context.Context, tenantID, assessmentID uuid.UUID) (*model.Assessment, error) {
	var a model.Assessment
	err := r.db.QueryRow(ctx,
		`SELECT `+assessmentSelect+` FROM comp_assessments WHERE id=$1 AND tenant_id=$2`,
		assessmentID, tenantID,
	).Scan(&a.ID, &a.TenantID, &a.FrameworkID, &a.ControlID, &a.Status, &a.Score,
		&a.EvidenceRefs, &a.Notes, &a.AssessedBy, &a.AssessedAt, &a.NextReviewAt,
		&a.CreatedAt, &a.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

func (r *ComplianceRepository) UpdateAssessment(ctx context.Context, tenantID, assessmentID uuid.UUID, req *model.UpdateAssessmentRequest, callerID *uuid.UUID) (*model.Assessment, error) {
	setClauses := []string{"updated_at = NOW()", "assessed_by = $3", "assessed_at = NOW()"}
	args := []any{assessmentID, tenantID, callerID}
	idx := 4

	if req.Status != nil {
		setClauses = append(setClauses, fmt.Sprintf("status = $%d", idx))
		args = append(args, *req.Status)
		idx++
	}
	if req.Score != nil {
		setClauses = append(setClauses, fmt.Sprintf("score = $%d", idx))
		args = append(args, *req.Score)
		idx++
	}
	if req.EvidenceRefs != nil {
		setClauses = append(setClauses, fmt.Sprintf("evidence_refs = $%d", idx))
		args = append(args, req.EvidenceRefs)
		idx++
	}
	if req.Notes != nil {
		setClauses = append(setClauses, fmt.Sprintf("notes = $%d", idx))
		args = append(args, *req.Notes)
		idx++
	}
	if req.NextReviewAt != nil {
		setClauses = append(setClauses, fmt.Sprintf("next_review_at = $%d", idx))
		args = append(args, *req.NextReviewAt)
		idx++
	}
	_ = idx

	q := fmt.Sprintf(`UPDATE comp_assessments SET %s WHERE id=$1 AND tenant_id=$2 RETURNING %s`,
		strings.Join(setClauses, ", "), assessmentSelect)
	var a model.Assessment
	err := r.db.QueryRow(ctx, q, args...).Scan(
		&a.ID, &a.TenantID, &a.FrameworkID, &a.ControlID, &a.Status, &a.Score,
		&a.EvidenceRefs, &a.Notes, &a.AssessedBy, &a.AssessedAt, &a.NextReviewAt,
		&a.CreatedAt, &a.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

func (r *ComplianceRepository) ListAssessments(ctx context.Context, f model.AssessmentFilter) ([]*model.Assessment, int, error) {
	where := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	idx := 2

	if f.FrameworkID != nil {
		where = append(where, fmt.Sprintf("framework_id = $%d", idx))
		args = append(args, *f.FrameworkID)
		idx++
	}
	if f.Status != "" {
		where = append(where, fmt.Sprintf("status = $%d", idx))
		args = append(args, f.Status)
		idx++
	}

	whereStr := strings.Join(where, " AND ")
	var total int
	if err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM comp_assessments WHERE `+whereStr, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	args = append(args, limit, f.Offset)
	rows, err := r.db.Query(ctx,
		`SELECT `+assessmentSelect+` FROM comp_assessments WHERE `+whereStr+
			fmt.Sprintf(` ORDER BY updated_at DESC LIMIT $%d OFFSET $%d`, idx, idx+1),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var assessments []*model.Assessment
	for rows.Next() {
		var a model.Assessment
		if err := rows.Scan(&a.ID, &a.TenantID, &a.FrameworkID, &a.ControlID, &a.Status, &a.Score,
			&a.EvidenceRefs, &a.Notes, &a.AssessedBy, &a.AssessedAt, &a.NextReviewAt,
			&a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, 0, err
		}
		assessments = append(assessments, &a)
	}
	return assessments, total, rows.Err()
}

func (r *ComplianceRepository) BulkUpsertAssessments(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, items []model.BulkAssessmentItem) (int, error) {
	count := 0
	for _, item := range items {
		req := &model.CreateAssessmentRequest{
			FrameworkID:  item.FrameworkID,
			ControlID:    item.ControlID,
			Status:       item.Status,
			Score:        item.Score,
			EvidenceRefs: item.EvidenceRefs,
			Notes:        item.Notes,
		}
		if _, err := r.UpsertAssessment(ctx, tenantID, callerID, req); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

// FrameworkScore computes the compliance score for a framework.
func (r *ComplianceRepository) FrameworkScore(ctx context.Context, tenantID, frameworkID uuid.UUID) (*model.ComplianceScore, error) {
	var fw model.Framework
	err := r.db.QueryRow(ctx,
		`SELECT id, tenant_id, code, name, COALESCE(description,''), version, total_controls, is_active, created_at, updated_at
		 FROM comp_frameworks WHERE id=$1 AND tenant_id=$2`,
		frameworkID, tenantID,
	).Scan(&fw.ID, &fw.TenantID, &fw.Code, &fw.Name, &fw.Description, &fw.Version,
		&fw.TotalControls, &fw.IsActive, &fw.CreatedAt, &fw.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	sc := &model.ComplianceScore{
		FrameworkID:   frameworkID,
		FrameworkCode: fw.Code,
		FrameworkName: fw.Name,
		TotalControls: fw.TotalControls,
	}

	r.db.QueryRow(ctx, `
		SELECT
		    COUNT(*) FILTER (WHERE ca.status IS NOT NULL),
		    COUNT(*) FILTER (WHERE ca.status = 'compliant'),
		    COUNT(*) FILTER (WHERE ca.status = 'partial'),
		    COUNT(*) FILTER (WHERE ca.status = 'non_compliant'),
		    COUNT(*) FILTER (WHERE ca.status = 'not_applicable'),
		    COUNT(*) FILTER (WHERE ca.status = 'not_assessed' OR ca.status IS NULL)
		FROM comp_controls cc
		LEFT JOIN comp_assessments ca ON ca.control_id = cc.id AND ca.tenant_id = cc.tenant_id
		WHERE cc.framework_id=$1 AND cc.tenant_id=$2`,
		frameworkID, tenantID,
	).Scan(&sc.Assessed, &sc.Compliant, &sc.Partial, &sc.NonCompliant, &sc.NotApplicable, &sc.NotAssessed)

	if sc.TotalControls > 0 {
		sc.ScorePct = float64(sc.Compliant*100+sc.Partial*50) / float64(sc.TotalControls)
	}
	return sc, nil
}

// ─── Risks ────────────────────────────────────────────────────────────────────

const riskSelect = `
    id, tenant_id, title, COALESCE(description,''), category,
    likelihood, impact, risk_score, status, owner_id,
    COALESCE(related_controls,'{}'), COALESCE(mitigation_plan,''),
    residual_likelihood, residual_impact, due_date,
    created_by, created_at, updated_at`

func (r *ComplianceRepository) CreateRisk(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreateRiskRequest) (*model.Risk, error) {
	related := req.RelatedControls
	if related == nil {
		related = []uuid.UUID{}
	}
	var risk model.Risk
	err := r.db.QueryRow(ctx, `
		INSERT INTO comp_risks
		    (tenant_id, title, description, category, likelihood, impact, status,
		     owner_id, related_controls, mitigation_plan, residual_likelihood, residual_impact, due_date, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,'open',$7,$8,$9,$10,$11,$12,$13)
		RETURNING `+riskSelect,
		tenantID, req.Title, req.Description, req.Category, req.Likelihood, req.Impact,
		req.OwnerID, related, req.MitigationPlan,
		req.ResidualLikelihood, req.ResidualImpact, req.DueDate, callerID,
	).Scan(&risk.ID, &risk.TenantID, &risk.Title, &risk.Description, &risk.Category,
		&risk.Likelihood, &risk.Impact, &risk.RiskScore, &risk.Status, &risk.OwnerID,
		&risk.RelatedControls, &risk.MitigationPlan,
		&risk.ResidualLikelihood, &risk.ResidualImpact, &risk.DueDate,
		&risk.CreatedBy, &risk.CreatedAt, &risk.UpdatedAt)
	return &risk, err
}

func (r *ComplianceRepository) GetRisk(ctx context.Context, tenantID, riskID uuid.UUID) (*model.Risk, error) {
	var risk model.Risk
	err := r.db.QueryRow(ctx,
		`SELECT `+riskSelect+` FROM comp_risks WHERE id=$1 AND tenant_id=$2`,
		riskID, tenantID,
	).Scan(&risk.ID, &risk.TenantID, &risk.Title, &risk.Description, &risk.Category,
		&risk.Likelihood, &risk.Impact, &risk.RiskScore, &risk.Status, &risk.OwnerID,
		&risk.RelatedControls, &risk.MitigationPlan,
		&risk.ResidualLikelihood, &risk.ResidualImpact, &risk.DueDate,
		&risk.CreatedBy, &risk.CreatedAt, &risk.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &risk, err
}

func (r *ComplianceRepository) UpdateRisk(ctx context.Context, tenantID, riskID uuid.UUID, req *model.UpdateRiskRequest) (*model.Risk, error) {
	setClauses := []string{"updated_at = NOW()"}
	args := []any{riskID, tenantID}
	idx := 3

	if req.Title != nil {
		setClauses = append(setClauses, fmt.Sprintf("title = $%d", idx))
		args = append(args, *req.Title)
		idx++
	}
	if req.Description != nil {
		setClauses = append(setClauses, fmt.Sprintf("description = $%d", idx))
		args = append(args, *req.Description)
		idx++
	}
	if req.Category != nil {
		setClauses = append(setClauses, fmt.Sprintf("category = $%d", idx))
		args = append(args, *req.Category)
		idx++
	}
	if req.Likelihood != nil {
		setClauses = append(setClauses, fmt.Sprintf("likelihood = $%d", idx))
		args = append(args, *req.Likelihood)
		idx++
	}
	if req.Impact != nil {
		setClauses = append(setClauses, fmt.Sprintf("impact = $%d", idx))
		args = append(args, *req.Impact)
		idx++
	}
	if req.Status != nil {
		setClauses = append(setClauses, fmt.Sprintf("status = $%d", idx))
		args = append(args, *req.Status)
		idx++
	}
	if req.OwnerID != nil {
		setClauses = append(setClauses, fmt.Sprintf("owner_id = $%d", idx))
		args = append(args, *req.OwnerID)
		idx++
	}
	if req.RelatedControls != nil {
		setClauses = append(setClauses, fmt.Sprintf("related_controls = $%d", idx))
		args = append(args, req.RelatedControls)
		idx++
	}
	if req.MitigationPlan != nil {
		setClauses = append(setClauses, fmt.Sprintf("mitigation_plan = $%d", idx))
		args = append(args, *req.MitigationPlan)
		idx++
	}
	if req.ResidualLikelihood != nil {
		setClauses = append(setClauses, fmt.Sprintf("residual_likelihood = $%d", idx))
		args = append(args, *req.ResidualLikelihood)
		idx++
	}
	if req.ResidualImpact != nil {
		setClauses = append(setClauses, fmt.Sprintf("residual_impact = $%d", idx))
		args = append(args, *req.ResidualImpact)
		idx++
	}
	if req.DueDate != nil {
		setClauses = append(setClauses, fmt.Sprintf("due_date = $%d", idx))
		args = append(args, *req.DueDate)
		idx++
	}
	_ = idx

	q := fmt.Sprintf(`UPDATE comp_risks SET %s WHERE id=$1 AND tenant_id=$2 RETURNING %s`,
		strings.Join(setClauses, ", "), riskSelect)
	var risk model.Risk
	err := r.db.QueryRow(ctx, q, args...).Scan(
		&risk.ID, &risk.TenantID, &risk.Title, &risk.Description, &risk.Category,
		&risk.Likelihood, &risk.Impact, &risk.RiskScore, &risk.Status, &risk.OwnerID,
		&risk.RelatedControls, &risk.MitigationPlan,
		&risk.ResidualLikelihood, &risk.ResidualImpact, &risk.DueDate,
		&risk.CreatedBy, &risk.CreatedAt, &risk.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &risk, err
}

func (r *ComplianceRepository) ListRisks(ctx context.Context, f model.RiskFilter) ([]*model.Risk, int, error) {
	where := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	idx := 2

	if f.Status != "" {
		where = append(where, fmt.Sprintf("status = $%d", idx))
		args = append(args, f.Status)
		idx++
	}
	if f.Category != "" {
		where = append(where, fmt.Sprintf("category = $%d", idx))
		args = append(args, f.Category)
		idx++
	}
	if f.OwnerID != nil {
		where = append(where, fmt.Sprintf("owner_id = $%d", idx))
		args = append(args, *f.OwnerID)
		idx++
	}
	if f.MinScore > 0 {
		where = append(where, fmt.Sprintf("risk_score >= $%d", idx))
		args = append(args, f.MinScore)
		idx++
	}

	whereStr := strings.Join(where, " AND ")
	var total int
	if err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM comp_risks WHERE `+whereStr, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	args = append(args, limit, f.Offset)
	rows, err := r.db.Query(ctx,
		`SELECT `+riskSelect+` FROM comp_risks WHERE `+whereStr+
			fmt.Sprintf(` ORDER BY risk_score DESC, created_at DESC LIMIT $%d OFFSET $%d`, idx, idx+1),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var risks []*model.Risk
	for rows.Next() {
		var risk model.Risk
		if err := rows.Scan(&risk.ID, &risk.TenantID, &risk.Title, &risk.Description, &risk.Category,
			&risk.Likelihood, &risk.Impact, &risk.RiskScore, &risk.Status, &risk.OwnerID,
			&risk.RelatedControls, &risk.MitigationPlan,
			&risk.ResidualLikelihood, &risk.ResidualImpact, &risk.DueDate,
			&risk.CreatedBy, &risk.CreatedAt, &risk.UpdatedAt); err != nil {
			return nil, 0, err
		}
		risks = append(risks, &risk)
	}
	return risks, total, rows.Err()
}

func (r *ComplianceRepository) CloseRisk(ctx context.Context, tenantID, riskID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE comp_risks SET status='closed', updated_at=NOW() WHERE id=$1 AND tenant_id=$2`,
		riskID, tenantID)
	return err
}

// ─── Evidence ─────────────────────────────────────────────────────────────────

func (r *ComplianceRepository) CreateEvidence(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreateEvidenceRequest) (*model.Evidence, error) {
	props, _ := json.Marshal(req.Properties)
	var ev model.Evidence
	var propsRaw []byte
	err := r.db.QueryRow(ctx, `
		INSERT INTO comp_evidence
		    (tenant_id, assessment_id, title, evidence_type, source_service, reference_url, collected_by, properties)
		VALUES ($1,$2,$3,$4,NULLIF($5,''),$6,$7,$8)
		RETURNING id, tenant_id, assessment_id, title, evidence_type,
		          COALESCE(source_service,''), COALESCE(reference_url,''),
		          collected_at, collected_by, properties, created_at`,
		tenantID, req.AssessmentID, req.Title, req.EvidenceType,
		req.SourceService, req.ReferenceURL, callerID, props,
	).Scan(&ev.ID, &ev.TenantID, &ev.AssessmentID, &ev.Title, &ev.EvidenceType,
		&ev.SourceService, &ev.ReferenceURL, &ev.CollectedAt, &ev.CollectedBy, &propsRaw, &ev.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(propsRaw, &ev.Properties)
	return &ev, nil
}

func (r *ComplianceRepository) ListEvidence(ctx context.Context, tenantID, assessmentID uuid.UUID) ([]*model.Evidence, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, assessment_id, title, evidence_type,
		       COALESCE(source_service,''), COALESCE(reference_url,''),
		       collected_at, collected_by, properties, created_at
		FROM comp_evidence WHERE tenant_id=$1 AND assessment_id=$2 ORDER BY created_at DESC`,
		tenantID, assessmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var evidences []*model.Evidence
	for rows.Next() {
		var ev model.Evidence
		var propsRaw []byte
		if err := rows.Scan(&ev.ID, &ev.TenantID, &ev.AssessmentID, &ev.Title, &ev.EvidenceType,
			&ev.SourceService, &ev.ReferenceURL, &ev.CollectedAt, &ev.CollectedBy, &propsRaw, &ev.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(propsRaw, &ev.Properties)
		evidences = append(evidences, &ev)
	}
	return evidences, rows.Err()
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (r *ComplianceRepository) Stats(ctx context.Context, tenantID uuid.UUID) (*model.ComplianceStats, error) {
	// All active frameworks
	frameworks, err := r.ListFrameworks(ctx, model.FrameworkFilter{TenantID: tenantID})
	if err != nil {
		return nil, err
	}

	scores := make([]model.ComplianceScore, 0, len(frameworks))
	for _, fw := range frameworks {
		sc, err := r.FrameworkScore(ctx, tenantID, fw.ID)
		if err != nil || sc == nil {
			continue
		}
		scores = append(scores, *sc)
	}

	// Top 5 open risks by risk_score DESC
	rows, err := r.db.Query(ctx,
		`SELECT `+riskSelect+` FROM comp_risks WHERE tenant_id=$1 AND status NOT IN ('closed','accepted')
		 ORDER BY risk_score DESC LIMIT 5`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var topRisks []*model.Risk
	for rows.Next() {
		var risk model.Risk
		if err := rows.Scan(&risk.ID, &risk.TenantID, &risk.Title, &risk.Description, &risk.Category,
			&risk.Likelihood, &risk.Impact, &risk.RiskScore, &risk.Status, &risk.OwnerID,
			&risk.RelatedControls, &risk.MitigationPlan,
			&risk.ResidualLikelihood, &risk.ResidualImpact, &risk.DueDate,
			&risk.CreatedBy, &risk.CreatedAt, &risk.UpdatedAt); err != nil {
			return nil, err
		}
		topRisks = append(topRisks, &risk)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return &model.ComplianceStats{
		Frameworks: scores,
		TopRisks:   topRisks,
	}, nil
}
