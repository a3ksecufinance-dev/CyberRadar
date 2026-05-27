package repository

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/cyberradar/platform/services/risk/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RiskRepository handles all persistence for the CRQ domain.
type RiskRepository struct {
	pool *pgxpool.Pool
}

// NewRiskRepository creates a RiskRepository.
func NewRiskRepository(pool *pgxpool.Pool) *RiskRepository {
	return &RiskRepository{pool: pool}
}

// ─── Assets ───────────────────────────────────────────────────────────────────

const assetSelect = `
SELECT id, tenant_id, name, description, asset_type, business_unit, owner,
       criticality, business_value, revenue_impact, regulatory_impact, reputational_impact,
       inherent_risk, residual_risk, control_effectiveness,
       threat_event_frequency, vulnerability, loss_magnitude, ale,
       is_active, metadata, created_at, updated_at
FROM risk_assets`

func scanAsset(row pgx.Row) (*model.RiskAsset, error) {
	a := &model.RiskAsset{}
	err := row.Scan(
		&a.ID, &a.TenantID, &a.Name, &a.Description, &a.AssetType, &a.BusinessUnit, &a.Owner,
		&a.Criticality, &a.BusinessValue, &a.RevenueImpact, &a.RegulatoryImpact, &a.ReputationalImpact,
		&a.InherentRisk, &a.ResidualRisk, &a.ControlEffectiveness,
		&a.ThreatEventFrequency, &a.Vulnerability, &a.LossMagnitude, &a.ALE,
		&a.IsActive, &a.Metadata, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (r *RiskRepository) CreateAsset(ctx context.Context, tenantID uuid.UUID, req *model.CreateRiskAssetRequest) (*model.RiskAsset, error) {
	criticality := req.Criticality
	if criticality == "" {
		criticality = model.CriticalityMedium
	}
	metadata := req.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}

	// Compute inherent risk from FAIR components
	inherentRisk, ale := computeFAIR(req.ThreatEventFrequency, req.Vulnerability, req.LossMagnitude, req.RevenueImpact)

	q := `INSERT INTO risk_assets
		(tenant_id, name, description, asset_type, business_unit, owner, criticality,
		 business_value, revenue_impact, regulatory_impact, reputational_impact,
		 inherent_risk, residual_risk, control_effectiveness,
		 threat_event_frequency, vulnerability, loss_magnitude, ale, is_active, metadata)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12,0,$13,$14,$15,$16,TRUE,$17)
		RETURNING ` + strings.TrimPrefix(assetSelect, "\nSELECT ") // reuse columns

	// Simpler: just use RETURNING id then fetch
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `INSERT INTO risk_assets
		(tenant_id, name, description, asset_type, business_unit, owner, criticality,
		 business_value, revenue_impact, regulatory_impact, reputational_impact,
		 inherent_risk, residual_risk, control_effectiveness,
		 threat_event_frequency, vulnerability, loss_magnitude, ale, is_active, metadata)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12,0,$13,$14,$15,$16,TRUE,$17)
		RETURNING id`,
		tenantID, req.Name, req.Description, req.AssetType, req.BusinessUnit, req.Owner, criticality,
		req.BusinessValue, req.RevenueImpact, req.RegulatoryImpact, req.ReputationalImpact,
		inherentRisk,
		req.ThreatEventFrequency, req.Vulnerability, req.LossMagnitude, ale,
		metadata,
	).Scan(&id)
	if err != nil {
		return nil, err
	}
	_ = q
	return r.GetAsset(ctx, tenantID, id)
}

func (r *RiskRepository) GetAsset(ctx context.Context, tenantID, assetID uuid.UUID) (*model.RiskAsset, error) {
	row := r.pool.QueryRow(ctx, assetSelect+` WHERE id=$1 AND tenant_id=$2`, assetID, tenantID)
	a, err := scanAsset(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return a, err
}

func (r *RiskRepository) ListAssets(ctx context.Context, tenantID uuid.UUID, f model.ListAssetsFilter) ([]*model.RiskAsset, int, error) {
	conditions := []string{"tenant_id=$1", "is_active=TRUE"}
	args := []any{tenantID}
	n := 2

	if f.AssetType != "" {
		conditions = append(conditions, fmt.Sprintf("asset_type=$%d", n))
		args = append(args, f.AssetType)
		n++
	}
	if f.Criticality != "" {
		conditions = append(conditions, fmt.Sprintf("criticality=$%d", n))
		args = append(args, f.Criticality)
		n++
	}
	if f.BusinessUnit != "" {
		conditions = append(conditions, fmt.Sprintf("business_unit=$%d", n))
		args = append(args, f.BusinessUnit)
		n++
	}

	where := "WHERE " + strings.Join(conditions, " AND ")

	var total int
	if err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM risk_assets `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	page, pageSize := f.Page, f.PageSize
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize
	args = append(args, pageSize, offset)

	rows, err := r.pool.Query(ctx, assetSelect+` `+where+
		fmt.Sprintf(` ORDER BY residual_risk DESC, criticality LIMIT $%d OFFSET $%d`, n, n+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var assets []*model.RiskAsset
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, 0, err
		}
		assets = append(assets, a)
	}
	return assets, total, nil
}

func (r *RiskRepository) UpdateAsset(ctx context.Context, tenantID, assetID uuid.UUID, req *model.UpdateRiskAssetRequest) (*model.RiskAsset, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{}
	n := 1

	if req.Description != "" {
		sets = append(sets, fmt.Sprintf("description=$%d", n))
		args = append(args, req.Description)
		n++
	}
	if req.BusinessUnit != "" {
		sets = append(sets, fmt.Sprintf("business_unit=$%d", n))
		args = append(args, req.BusinessUnit)
		n++
	}
	if req.Owner != "" {
		sets = append(sets, fmt.Sprintf("owner=$%d", n))
		args = append(args, req.Owner)
		n++
	}
	if req.Criticality != "" {
		sets = append(sets, fmt.Sprintf("criticality=$%d", n))
		args = append(args, req.Criticality)
		n++
	}
	if req.BusinessValue != nil {
		sets = append(sets, fmt.Sprintf("business_value=$%d", n))
		args = append(args, *req.BusinessValue)
		n++
	}
	if req.RevenueImpact != nil {
		sets = append(sets, fmt.Sprintf("revenue_impact=$%d", n))
		args = append(args, *req.RevenueImpact)
		n++
	}
	if req.RegulatoryImpact != nil {
		sets = append(sets, fmt.Sprintf("regulatory_impact=$%d", n))
		args = append(args, *req.RegulatoryImpact)
		n++
	}
	if req.ReputationalImpact != nil {
		sets = append(sets, fmt.Sprintf("reputational_impact=$%d", n))
		args = append(args, *req.ReputationalImpact)
		n++
	}
	if req.ThreatEventFrequency != nil {
		sets = append(sets, fmt.Sprintf("threat_event_frequency=$%d", n))
		args = append(args, *req.ThreatEventFrequency)
		n++
	}
	if req.Vulnerability != nil {
		sets = append(sets, fmt.Sprintf("vulnerability=$%d", n))
		args = append(args, *req.Vulnerability)
		n++
	}
	if req.LossMagnitude != nil {
		sets = append(sets, fmt.Sprintf("loss_magnitude=$%d", n))
		args = append(args, *req.LossMagnitude)
		n++
	}
	if req.IsActive != nil {
		sets = append(sets, fmt.Sprintf("is_active=$%d", n))
		args = append(args, *req.IsActive)
		n++
	}
	if req.Metadata != nil {
		sets = append(sets, fmt.Sprintf("metadata=$%d", n))
		args = append(args, req.Metadata)
		n++
	}

	args = append(args, assetID, tenantID)
	_, err := r.pool.Exec(ctx,
		fmt.Sprintf(`UPDATE risk_assets SET %s WHERE id=$%d AND tenant_id=$%d`,
			strings.Join(sets, ","), n, n+1),
		args...)
	if err != nil {
		return nil, err
	}
	return r.GetAsset(ctx, tenantID, assetID)
}

// ─── Scenarios ────────────────────────────────────────────────────────────────

const scenarioSelect = `
SELECT id, tenant_id, name, description, scenario_type, threat_actor,
       annual_probability, primary_loss, secondary_loss, total_loss,
       risk_level, risk_score, mitigating_controls,
       residual_probability, residual_loss, frameworks, asset_ids,
       status, reviewed_at, reviewed_by, created_by, created_at, updated_at
FROM risk_scenarios`

func scanScenario(row pgx.Row) (*model.RiskScenario, error) {
	s := &model.RiskScenario{}
	var reviewedBy, createdBy *uuid.UUID
	err := row.Scan(
		&s.ID, &s.TenantID, &s.Name, &s.Description, &s.ScenarioType, &s.ThreatActor,
		&s.AnnualProbability, &s.PrimaryLoss, &s.SecondaryLoss, &s.TotalLoss,
		&s.RiskLevel, &s.RiskScore, &s.MitigatingControls,
		&s.ResidualProbability, &s.ResidualLoss, &s.Frameworks, &s.AssetIDs,
		&s.Status, &s.ReviewedAt, &reviewedBy, &createdBy, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	s.ReviewedBy = reviewedBy
	s.CreatedBy = createdBy
	return s, nil
}

func (r *RiskRepository) CreateScenario(ctx context.Context, tenantID uuid.UUID, req *model.CreateScenarioRequest, createdBy uuid.UUID) (*model.RiskScenario, error) {
	riskScore, riskLevel := computeScenarioRisk(req.AnnualProbability, req.PrimaryLoss+req.SecondaryLoss)
	if req.MitigatingControls == nil {
		req.MitigatingControls = []string{}
	}
	if req.Frameworks == nil {
		req.Frameworks = []string{}
	}
	if req.AssetIDs == nil {
		req.AssetIDs = []uuid.UUID{}
	}

	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `INSERT INTO risk_scenarios
		(tenant_id, name, description, scenario_type, threat_actor,
		 annual_probability, primary_loss, secondary_loss, risk_level, risk_score,
		 mitigating_controls, residual_probability, residual_loss,
		 frameworks, asset_ids, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		RETURNING id`,
		tenantID, req.Name, req.Description, req.ScenarioType, req.ThreatActor,
		req.AnnualProbability, req.PrimaryLoss, req.SecondaryLoss, riskLevel, riskScore,
		req.MitigatingControls, req.ResidualProbability, req.ResidualLoss,
		req.Frameworks, req.AssetIDs, createdBy,
	).Scan(&id)
	if err != nil {
		return nil, err
	}
	return r.GetScenario(ctx, tenantID, id)
}

func (r *RiskRepository) GetScenario(ctx context.Context, tenantID, scenarioID uuid.UUID) (*model.RiskScenario, error) {
	row := r.pool.QueryRow(ctx, scenarioSelect+` WHERE id=$1 AND tenant_id=$2`, scenarioID, tenantID)
	s, err := scanScenario(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return s, err
}

func (r *RiskRepository) ListScenarios(ctx context.Context, tenantID uuid.UUID, f model.ListScenariosFilter) ([]*model.RiskScenario, int, error) {
	conditions := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2

	if f.ScenarioType != "" {
		conditions = append(conditions, fmt.Sprintf("scenario_type=$%d", n))
		args = append(args, f.ScenarioType)
		n++
	}
	if f.RiskLevel != "" {
		conditions = append(conditions, fmt.Sprintf("risk_level=$%d", n))
		args = append(args, f.RiskLevel)
		n++
	}
	if f.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status=$%d", n))
		args = append(args, f.Status)
		n++
	}
	if f.Framework != "" {
		conditions = append(conditions, fmt.Sprintf("$%d=ANY(frameworks)", n))
		args = append(args, f.Framework)
		n++
	}

	where := "WHERE " + strings.Join(conditions, " AND ")

	var total int
	if err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM risk_scenarios `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	page, pageSize := f.Page, f.PageSize
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize
	args = append(args, pageSize, offset)

	rows, err := r.pool.Query(ctx, scenarioSelect+` `+where+
		fmt.Sprintf(` ORDER BY risk_score DESC LIMIT $%d OFFSET $%d`, n, n+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var scenarios []*model.RiskScenario
	for rows.Next() {
		s, err := scanScenario(rows)
		if err != nil {
			return nil, 0, err
		}
		scenarios = append(scenarios, s)
	}
	return scenarios, total, nil
}

func (r *RiskRepository) UpdateScenario(ctx context.Context, tenantID, scenarioID uuid.UUID, req *model.UpdateScenarioRequest) (*model.RiskScenario, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{}
	n := 1

	if req.Name != nil {
		sets = append(sets, fmt.Sprintf("name=$%d", n))
		args = append(args, *req.Name)
		n++
	}
	if req.Description != "" {
		sets = append(sets, fmt.Sprintf("description=$%d", n))
		args = append(args, req.Description)
		n++
	}
	if req.AnnualProbability != nil {
		sets = append(sets, fmt.Sprintf("annual_probability=$%d", n))
		args = append(args, *req.AnnualProbability)
		n++
	}
	if req.PrimaryLoss != nil {
		sets = append(sets, fmt.Sprintf("primary_loss=$%d", n))
		args = append(args, *req.PrimaryLoss)
		n++
	}
	if req.SecondaryLoss != nil {
		sets = append(sets, fmt.Sprintf("secondary_loss=$%d", n))
		args = append(args, *req.SecondaryLoss)
		n++
	}
	if req.MitigatingControls != nil {
		sets = append(sets, fmt.Sprintf("mitigating_controls=$%d", n))
		args = append(args, req.MitigatingControls)
		n++
	}
	if req.ResidualProbability != nil {
		sets = append(sets, fmt.Sprintf("residual_probability=$%d", n))
		args = append(args, *req.ResidualProbability)
		n++
	}
	if req.ResidualLoss != nil {
		sets = append(sets, fmt.Sprintf("residual_loss=$%d", n))
		args = append(args, *req.ResidualLoss)
		n++
	}
	if req.Frameworks != nil {
		sets = append(sets, fmt.Sprintf("frameworks=$%d", n))
		args = append(args, req.Frameworks)
		n++
	}
	if req.AssetIDs != nil {
		sets = append(sets, fmt.Sprintf("asset_ids=$%d", n))
		args = append(args, req.AssetIDs)
		n++
	}
	if req.Status != "" {
		sets = append(sets, fmt.Sprintf("status=$%d", n))
		args = append(args, req.Status)
		n++
		if req.Status == "mitigated" || req.Status == "accepted" {
			sets = append(sets, "reviewed_at=NOW()")
		}
	}

	args = append(args, scenarioID, tenantID)
	_, err := r.pool.Exec(ctx,
		fmt.Sprintf(`UPDATE risk_scenarios SET %s WHERE id=$%d AND tenant_id=$%d`,
			strings.Join(sets, ","), n, n+1),
		args...)
	if err != nil {
		return nil, err
	}
	return r.GetScenario(ctx, tenantID, scenarioID)
}

// ─── Treatments ───────────────────────────────────────────────────────────────

const treatmentSelect = `
SELECT id, tenant_id, scenario_id, treatment_type, description,
       cost, roi, risk_reduction, due_date, assigned_to,
       status, completed_at, created_by, created_at, updated_at
FROM risk_treatments`

func scanTreatment(row pgx.Row) (*model.RiskTreatment, error) {
	t := &model.RiskTreatment{}
	var createdBy *uuid.UUID
	err := row.Scan(
		&t.ID, &t.TenantID, &t.ScenarioID, &t.TreatmentType, &t.Description,
		&t.Cost, &t.ROI, &t.RiskReduction, &t.DueDate, &t.AssignedTo,
		&t.Status, &t.CompletedAt, &createdBy, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	t.CreatedBy = createdBy
	return t, nil
}

func (r *RiskRepository) CreateTreatment(ctx context.Context, tenantID uuid.UUID, req *model.CreateTreatmentRequest, createdBy uuid.UUID) (*model.RiskTreatment, error) {
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `INSERT INTO risk_treatments
		(tenant_id, scenario_id, treatment_type, description, cost, risk_reduction, due_date, assigned_to, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id`,
		tenantID, req.ScenarioID, req.TreatmentType, req.Description,
		req.Cost, req.RiskReduction, req.DueDate, req.AssignedTo, createdBy,
	).Scan(&id)
	if err != nil {
		return nil, err
	}
	return r.GetTreatment(ctx, tenantID, id)
}

func (r *RiskRepository) GetTreatment(ctx context.Context, tenantID, treatmentID uuid.UUID) (*model.RiskTreatment, error) {
	row := r.pool.QueryRow(ctx, treatmentSelect+` WHERE id=$1 AND tenant_id=$2`, treatmentID, tenantID)
	t, err := scanTreatment(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return t, err
}

func (r *RiskRepository) ListTreatments(ctx context.Context, tenantID uuid.UUID, scenarioID *uuid.UUID, status string, page, pageSize int) ([]*model.RiskTreatment, int, error) {
	conditions := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2

	if scenarioID != nil {
		conditions = append(conditions, fmt.Sprintf("scenario_id=$%d", n))
		args = append(args, *scenarioID)
		n++
	}
	if status != "" {
		conditions = append(conditions, fmt.Sprintf("status=$%d", n))
		args = append(args, status)
		n++
	}

	where := "WHERE " + strings.Join(conditions, " AND ")

	var total int
	if err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM risk_treatments `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize
	args = append(args, pageSize, offset)

	rows, err := r.pool.Query(ctx, treatmentSelect+` `+where+
		fmt.Sprintf(` ORDER BY due_date ASC NULLS LAST, created_at DESC LIMIT $%d OFFSET $%d`, n, n+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var treatments []*model.RiskTreatment
	for rows.Next() {
		t, err := scanTreatment(rows)
		if err != nil {
			return nil, 0, err
		}
		treatments = append(treatments, t)
	}
	return treatments, total, nil
}

func (r *RiskRepository) UpdateTreatment(ctx context.Context, tenantID, treatmentID uuid.UUID, req *model.UpdateTreatmentRequest) (*model.RiskTreatment, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{}
	n := 1

	if req.Description != "" {
		sets = append(sets, fmt.Sprintf("description=$%d", n))
		args = append(args, req.Description)
		n++
	}
	if req.Cost != nil {
		sets = append(sets, fmt.Sprintf("cost=$%d", n))
		args = append(args, *req.Cost)
		n++
	}
	if req.RiskReduction != nil {
		sets = append(sets, fmt.Sprintf("risk_reduction=$%d", n))
		args = append(args, *req.RiskReduction)
		n++
	}
	if req.DueDate != nil {
		sets = append(sets, fmt.Sprintf("due_date=$%d", n))
		args = append(args, *req.DueDate)
		n++
	}
	if req.AssignedTo != "" {
		sets = append(sets, fmt.Sprintf("assigned_to=$%d", n))
		args = append(args, req.AssignedTo)
		n++
	}
	if req.Status != "" {
		sets = append(sets, fmt.Sprintf("status=$%d", n))
		args = append(args, req.Status)
		n++
		if req.Status == "completed" {
			sets = append(sets, "completed_at=NOW()")
		}
	}

	args = append(args, treatmentID, tenantID)
	_, err := r.pool.Exec(ctx,
		fmt.Sprintf(`UPDATE risk_treatments SET %s WHERE id=$%d AND tenant_id=$%d`,
			strings.Join(sets, ","), n, n+1),
		args...)
	if err != nil {
		return nil, err
	}
	return r.GetTreatment(ctx, tenantID, treatmentID)
}

// ─── Assessments ──────────────────────────────────────────────────────────────

const assessmentSelect = `
SELECT id, tenant_id, name, assessment_type, framework, scope, methodology,
       status, overall_risk_score, total_ale, scenarios_count, critical_count, high_count,
       key_findings, recommendations, assessment_date, next_review,
       approved_by, approved_at, created_by, created_at, updated_at
FROM risk_assessments`

func scanAssessment(row pgx.Row) (*model.RiskAssessment, error) {
	a := &model.RiskAssessment{}
	var approvedBy, createdBy *uuid.UUID
	err := row.Scan(
		&a.ID, &a.TenantID, &a.Name, &a.AssessmentType, &a.Framework, &a.Scope, &a.Methodology,
		&a.Status, &a.OverallRiskScore, &a.TotalALE, &a.ScenariosCount, &a.CriticalCount, &a.HighCount,
		&a.KeyFindings, &a.Recommendations, &a.AssessmentDate, &a.NextReview,
		&approvedBy, &a.ApprovedAt, &createdBy, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	a.ApprovedBy = approvedBy
	a.CreatedBy = createdBy
	return a, nil
}

func (r *RiskRepository) CreateAssessment(ctx context.Context, tenantID uuid.UUID, req *model.CreateAssessmentRequest, createdBy uuid.UUID) (*model.RiskAssessment, error) {
	methodology := req.Methodology
	if methodology == "" {
		methodology = "FAIR"
	}
	assessDate := time.Now()
	if req.AssessmentDate != nil {
		assessDate = *req.AssessmentDate
	}

	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `INSERT INTO risk_assessments
		(tenant_id, name, assessment_type, framework, scope, methodology,
		 assessment_date, next_review, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id`,
		tenantID, req.Name, req.AssessmentType, req.Framework, req.Scope, methodology,
		assessDate, req.NextReview, createdBy,
	).Scan(&id)
	if err != nil {
		return nil, err
	}
	return r.GetAssessment(ctx, tenantID, id)
}

func (r *RiskRepository) GetAssessment(ctx context.Context, tenantID, assessmentID uuid.UUID) (*model.RiskAssessment, error) {
	row := r.pool.QueryRow(ctx, assessmentSelect+` WHERE id=$1 AND tenant_id=$2`, assessmentID, tenantID)
	a, err := scanAssessment(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return a, err
}

func (r *RiskRepository) ListAssessments(ctx context.Context, tenantID uuid.UUID, status string, page, pageSize int) ([]*model.RiskAssessment, int, error) {
	conditions := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2

	if status != "" {
		conditions = append(conditions, fmt.Sprintf("status=$%d", n))
		args = append(args, status)
		n++
	}

	where := "WHERE " + strings.Join(conditions, " AND ")

	var total int
	if err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM risk_assessments `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize
	args = append(args, pageSize, offset)

	rows, err := r.pool.Query(ctx, assessmentSelect+` `+where+
		fmt.Sprintf(` ORDER BY assessment_date DESC LIMIT $%d OFFSET $%d`, n, n+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var assessments []*model.RiskAssessment
	for rows.Next() {
		a, err := scanAssessment(rows)
		if err != nil {
			return nil, 0, err
		}
		assessments = append(assessments, a)
	}
	return assessments, total, nil
}

// ComputeAssessment recalculates aggregates for an assessment from its scenarios.
func (r *RiskRepository) ComputeAssessment(ctx context.Context, tenantID, assessmentID uuid.UUID) error {
	// This would join assessment→scenarios in a real system.
	// For now, compute from all tenant scenarios.
	row := r.pool.QueryRow(ctx, `
		SELECT COUNT(*), COALESCE(SUM(total_loss * annual_probability),0),
		       COUNT(*) FILTER (WHERE risk_level='critical'),
		       COUNT(*) FILTER (WHERE risk_level='high'),
		       COALESCE(AVG(risk_score),0)
		FROM risk_scenarios
		WHERE tenant_id=$1 AND status='active'`, tenantID)

	var count, critCount, highCount int
	var totalALE int64
	var avgScore float64
	if err := row.Scan(&count, &totalALE, &critCount, &highCount, &avgScore); err != nil {
		return err
	}

	_, err := r.pool.Exec(ctx, `
		UPDATE risk_assessments SET
			scenarios_count=$1, total_ale=$2, critical_count=$3, high_count=$4,
			overall_risk_score=$5, status='in_progress', updated_at=NOW()
		WHERE id=$6 AND tenant_id=$7`,
		count, totalALE, critCount, highCount, int(avgScore), assessmentID, tenantID)
	return err
}

// ─── KRIs ─────────────────────────────────────────────────────────────────────

const kriSelect = `
SELECT id, tenant_id, name, description, category, metric_name, unit,
       current_value, threshold_green, threshold_amber,
       status, trend, source_service, last_updated_at, is_active, created_at, updated_at
FROM risk_kris`

func scanKRI(row pgx.Row) (*model.RiskKRI, error) {
	k := &model.RiskKRI{}
	err := row.Scan(
		&k.ID, &k.TenantID, &k.Name, &k.Description, &k.Category, &k.MetricName, &k.Unit,
		&k.CurrentValue, &k.ThresholdGreen, &k.ThresholdAmber,
		&k.Status, &k.Trend, &k.SourceService, &k.LastUpdatedAt, &k.IsActive, &k.CreatedAt, &k.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func (r *RiskRepository) CreateKRI(ctx context.Context, tenantID uuid.UUID, req *model.CreateKRIRequest) (*model.RiskKRI, error) {
	unit := req.Unit
	if unit == "" {
		unit = "%"
	}
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `INSERT INTO risk_kris
		(tenant_id, name, description, category, metric_name, unit,
		 threshold_green, threshold_amber, source_service)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id`,
		tenantID, req.Name, req.Description, req.Category, req.MetricName, unit,
		req.ThresholdGreen, req.ThresholdAmber, req.SourceService,
	).Scan(&id)
	if err != nil {
		return nil, err
	}
	return r.GetKRI(ctx, tenantID, id)
}

func (r *RiskRepository) GetKRI(ctx context.Context, tenantID, kriID uuid.UUID) (*model.RiskKRI, error) {
	row := r.pool.QueryRow(ctx, kriSelect+` WHERE id=$1 AND tenant_id=$2`, kriID, tenantID)
	k, err := scanKRI(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return k, err
}

func (r *RiskRepository) ListKRIs(ctx context.Context, tenantID uuid.UUID, category, status string) ([]*model.RiskKRI, error) {
	conditions := []string{"tenant_id=$1", "is_active=TRUE"}
	args := []any{tenantID}
	n := 2

	if category != "" {
		conditions = append(conditions, fmt.Sprintf("category=$%d", n))
		args = append(args, category)
		n++
	}
	if status != "" {
		conditions = append(conditions, fmt.Sprintf("status=$%d", n))
		args = append(args, status)
		n++
	}

	where := "WHERE " + strings.Join(conditions, " AND ")
	rows, err := r.pool.Query(ctx, kriSelect+` `+where+` ORDER BY category, name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var kris []*model.RiskKRI
	for rows.Next() {
		k, err := scanKRI(rows)
		if err != nil {
			return nil, err
		}
		kris = append(kris, k)
	}
	return kris, nil
}

func (r *RiskRepository) UpdateKRIValue(ctx context.Context, tenantID, kriID uuid.UUID, value float64) (*model.RiskKRI, error) {
	// Determine new status based on thresholds
	kri, err := r.GetKRI(ctx, tenantID, kriID)
	if err != nil || kri == nil {
		return kri, err
	}

	newStatus := "green"
	if kri.ThresholdAmber != nil && value >= *kri.ThresholdAmber {
		newStatus = "red"
	} else if kri.ThresholdGreen != nil && value >= *kri.ThresholdGreen {
		newStatus = "amber"
	}

	// Determine trend
	trend := "stable"
	if value > kri.CurrentValue*1.1 {
		trend = "degrading"
	} else if value < kri.CurrentValue*0.9 {
		trend = "improving"
	}

	_, err = r.pool.Exec(ctx, `
		UPDATE risk_kris SET current_value=$1, status=$2, trend=$3, last_updated_at=NOW(), updated_at=NOW()
		WHERE id=$4 AND tenant_id=$5`,
		value, newStatus, trend, kriID, tenantID)
	if err != nil {
		return nil, err
	}

	// Record history
	_, _ = r.pool.Exec(ctx, `INSERT INTO risk_kri_history (tenant_id, kri_id, value, status) VALUES ($1,$2,$3,$4)`,
		tenantID, kriID, value, newStatus)

	return r.GetKRI(ctx, tenantID, kriID)
}

func (r *RiskRepository) GetKRIHistory(ctx context.Context, tenantID, kriID uuid.UUID, limit int) ([]*model.RiskKRIHistory, error) {
	if limit < 1 || limit > 500 {
		limit = 90
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, tenant_id, kri_id, value, status, recorded_at
		FROM risk_kri_history WHERE kri_id=$1 AND tenant_id=$2
		ORDER BY recorded_at DESC LIMIT $3`,
		kriID, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []*model.RiskKRIHistory
	for rows.Next() {
		h := &model.RiskKRIHistory{}
		if err := rows.Scan(&h.ID, &h.TenantID, &h.KRIID, &h.Value, &h.Status, &h.RecordedAt); err != nil {
			return nil, err
		}
		history = append(history, h)
	}
	return history, nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (r *RiskRepository) Stats(ctx context.Context, tenantID uuid.UUID) (*model.RiskStats, error) {
	stats := &model.RiskStats{
		ScenariosByLevel:    map[string]int{},
		ScenariosByType:     map[string]int{},
		AssetsByCriticality: map[string]int{},
		KRIsByStatus:        map[string]int{},
	}

	// Totals
	r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM risk_assets WHERE tenant_id=$1 AND is_active=TRUE`, tenantID).Scan(&stats.TotalAssets)
	r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM risk_scenarios WHERE tenant_id=$1`, tenantID).Scan(&stats.TotalScenarios)
	r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM risk_treatments WHERE tenant_id=$1 AND status IN ('planned','in_progress')`, tenantID).Scan(&stats.OpenTreatments)
	r.pool.QueryRow(ctx, `SELECT COALESCE(SUM(ale),0) FROM risk_assets WHERE tenant_id=$1 AND is_active=TRUE`, tenantID).Scan(&stats.TotalALE)
	r.pool.QueryRow(ctx, `SELECT COALESCE(AVG(residual_risk),0) FROM risk_assets WHERE tenant_id=$1 AND is_active=TRUE`, tenantID).Scan(&stats.AvgResidualRisk)

	// Scenarios by level
	levelRows, _ := r.pool.Query(ctx, `SELECT risk_level, COUNT(*) FROM risk_scenarios WHERE tenant_id=$1 GROUP BY risk_level`, tenantID)
	if levelRows != nil {
		defer levelRows.Close()
		for levelRows.Next() {
			var lvl string
			var cnt int
			levelRows.Scan(&lvl, &cnt)
			stats.ScenariosByLevel[lvl] = cnt
		}
	}

	// Scenarios by type
	typeRows, _ := r.pool.Query(ctx, `SELECT scenario_type, COUNT(*) FROM risk_scenarios WHERE tenant_id=$1 GROUP BY scenario_type`, tenantID)
	if typeRows != nil {
		defer typeRows.Close()
		for typeRows.Next() {
			var t string
			var cnt int
			typeRows.Scan(&t, &cnt)
			stats.ScenariosByType[t] = cnt
		}
	}

	// Assets by criticality
	critRows, _ := r.pool.Query(ctx, `SELECT criticality, COUNT(*) FROM risk_assets WHERE tenant_id=$1 AND is_active=TRUE GROUP BY criticality`, tenantID)
	if critRows != nil {
		defer critRows.Close()
		for critRows.Next() {
			var c string
			var cnt int
			critRows.Scan(&c, &cnt)
			stats.AssetsByCriticality[c] = cnt
		}
	}

	// KRIs by status
	kriRows, _ := r.pool.Query(ctx, `SELECT status, COUNT(*) FROM risk_kris WHERE tenant_id=$1 AND is_active=TRUE GROUP BY status`, tenantID)
	if kriRows != nil {
		defer kriRows.Close()
		for kriRows.Next() {
			var s string
			var cnt int
			kriRows.Scan(&s, &cnt)
			stats.KRIsByStatus[s] = cnt
		}
	}

	// Top risky assets
	aRows, _ := r.pool.Query(ctx, assetSelect+` WHERE tenant_id=$1 AND is_active=TRUE ORDER BY residual_risk DESC LIMIT 5`, tenantID)
	if aRows != nil {
		defer aRows.Close()
		for aRows.Next() {
			a, _ := scanAsset(aRows)
			if a != nil {
				stats.TopRiskyAssets = append(stats.TopRiskyAssets, a)
			}
		}
	}

	// Top scenarios
	sRows, _ := r.pool.Query(ctx, scenarioSelect+` WHERE tenant_id=$1 ORDER BY risk_score DESC LIMIT 5`, tenantID)
	if sRows != nil {
		defer sRows.Close()
		for sRows.Next() {
			s, _ := scanScenario(sRows)
			if s != nil {
				stats.TopScenarios = append(stats.TopScenarios, s)
			}
		}
	}

	return stats, nil
}

// ─── FAIR helpers ─────────────────────────────────────────────────────────────

// computeFAIR calculates inherent risk score and ALE using simplified FAIR model.
// tef = threat event frequency (0–10 scale)
// vuln = vulnerability (0–10 scale)
// lm = loss magnitude (0–10 scale)
// revenueImpact = max annual revenue impact (thousands)
func computeFAIR(tef, vuln, lm float64, revenueImpact int64) (inherentRisk int, ale int64) {
	// LEF = TEF * Vulnerability (normalized)
	lef := (tef / 10.0) * (vuln / 10.0)
	// Risk = LEF * LossMagnitude
	rawRisk := lef * (lm / 10.0) * 100
	inherentRisk = int(math.Min(100, rawRisk))
	// ALE = annual loss expectancy (probability × revenue impact)
	ale = int64(lef * float64(revenueImpact))
	return
}

// computeScenarioRisk converts probability+loss into a risk score and level.
func computeScenarioRisk(annualProbability float64, totalLoss int64) (score int, level string) {
	// Score: probability (0-50) + loss magnitude normalized (0-50)
	probScore := int(annualProbability * 50)
	var lossScore int
	switch {
	case totalLoss >= 100000: // ≥ 100M
		lossScore = 50
	case totalLoss >= 10000: // ≥ 10M
		lossScore = 40
	case totalLoss >= 1000: // ≥ 1M
		lossScore = 30
	case totalLoss >= 100: // ≥ 100K
		lossScore = 20
	default:
		lossScore = 10
	}
	score = int(math.Min(100, float64(probScore+lossScore)))
	switch {
	case score >= 75:
		level = "critical"
	case score >= 50:
		level = "high"
	case score >= 25:
		level = "medium"
	default:
		level = "low"
	}
	return
}
