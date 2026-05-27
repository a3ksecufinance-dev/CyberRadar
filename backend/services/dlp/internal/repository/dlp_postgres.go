package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cyberradar/platform/services/dlp/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DLPRepository handles all DLP persistence.
type DLPRepository struct {
	db *pgxpool.Pool
}

// NewDLPRepository creates a DLPRepository.
func NewDLPRepository(db *pgxpool.Pool) *DLPRepository {
	return &DLPRepository{db: db}
}

// ─── Labels ───────────────────────────────────────────────────────────────────

func (r *DLPRepository) CreateLabel(ctx context.Context, tenantID uuid.UUID, req *model.CreateLabelRequest, createdBy uuid.UUID) (*model.DLPLabel, error) {
	if req.RegexPatterns == nil {
		req.RegexPatterns = []string{}
	}
	if req.Keywords == nil {
		req.Keywords = []string{}
	}
	color := req.Color
	if color == "" {
		color = "#6B7280"
	}
	var l model.DLPLabel
	err := r.db.QueryRow(ctx, `
		INSERT INTO dlp_labels (tenant_id, name, description, sensitivity, color, regex_patterns, keywords, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (tenant_id, name) DO UPDATE
		  SET sensitivity=EXCLUDED.sensitivity, color=EXCLUDED.color,
		      regex_patterns=EXCLUDED.regex_patterns, keywords=EXCLUDED.keywords, updated_at=NOW()
		RETURNING id, tenant_id, name, COALESCE(description,''), sensitivity, color,
		          COALESCE(regex_patterns,'{}'), COALESCE(keywords,'{}'), is_active, created_by, created_at, updated_at`,
		tenantID, req.Name, req.Description, req.Sensitivity, color, req.RegexPatterns, req.Keywords, createdBy,
	).Scan(
		&l.ID, &l.TenantID, &l.Name, &l.Description, &l.Sensitivity, &l.Color,
		&l.RegexPatterns, &l.Keywords, &l.IsActive, &l.CreatedBy, &l.CreatedAt, &l.UpdatedAt,
	)
	return &l, err
}

func (r *DLPRepository) GetLabel(ctx context.Context, tenantID, labelID uuid.UUID) (*model.DLPLabel, error) {
	var l model.DLPLabel
	err := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, name, COALESCE(description,''), sensitivity, color,
		       COALESCE(regex_patterns,'{}'), COALESCE(keywords,'{}'), is_active, created_by, created_at, updated_at
		FROM dlp_labels WHERE id=$1 AND tenant_id=$2`, labelID, tenantID,
	).Scan(
		&l.ID, &l.TenantID, &l.Name, &l.Description, &l.Sensitivity, &l.Color,
		&l.RegexPatterns, &l.Keywords, &l.IsActive, &l.CreatedBy, &l.CreatedAt, &l.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &l, err
}

func (r *DLPRepository) ListLabels(ctx context.Context, tenantID uuid.UUID, activeOnly bool, page, pageSize int) ([]*model.DLPLabel, int, error) {
	if pageSize <= 0 { pageSize = 50 }
	if page <= 0 { page = 1 }
	where := "tenant_id=$1"
	args := []any{tenantID}
	if activeOnly {
		where += " AND is_active=TRUE"
	}
	var total int
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM dlp_labels WHERE "+where, args...).Scan(&total)
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := r.db.Query(ctx, fmt.Sprintf(`
		SELECT id, tenant_id, name, COALESCE(description,''), sensitivity, color,
		       COALESCE(regex_patterns,'{}'), COALESCE(keywords,'{}'), is_active, created_by, created_at, updated_at
		FROM dlp_labels WHERE %s ORDER BY sensitivity, name LIMIT $2 OFFSET $3`, where), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var labels []*model.DLPLabel
	for rows.Next() {
		var l model.DLPLabel
		if err := rows.Scan(
			&l.ID, &l.TenantID, &l.Name, &l.Description, &l.Sensitivity, &l.Color,
			&l.RegexPatterns, &l.Keywords, &l.IsActive, &l.CreatedBy, &l.CreatedAt, &l.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		labels = append(labels, &l)
	}
	return labels, total, nil
}

func (r *DLPRepository) UpdateLabel(ctx context.Context, tenantID, labelID uuid.UUID, req *model.UpdateLabelRequest) (*model.DLPLabel, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{}
	n := 1
	if req.Name != "" { sets = append(sets, fmt.Sprintf("name=$%d", n)); args = append(args, req.Name); n++ }
	if req.Description != "" { sets = append(sets, fmt.Sprintf("description=$%d", n)); args = append(args, req.Description); n++ }
	if req.Sensitivity != "" { sets = append(sets, fmt.Sprintf("sensitivity=$%d", n)); args = append(args, req.Sensitivity); n++ }
	if req.Color != "" { sets = append(sets, fmt.Sprintf("color=$%d", n)); args = append(args, req.Color); n++ }
	if req.RegexPatterns != nil { sets = append(sets, fmt.Sprintf("regex_patterns=$%d", n)); args = append(args, req.RegexPatterns); n++ }
	if req.Keywords != nil { sets = append(sets, fmt.Sprintf("keywords=$%d", n)); args = append(args, req.Keywords); n++ }
	if req.IsActive != nil { sets = append(sets, fmt.Sprintf("is_active=$%d", n)); args = append(args, *req.IsActive); n++ }
	args = append(args, labelID, tenantID)
	var l model.DLPLabel
	err := r.db.QueryRow(ctx, fmt.Sprintf(`
		UPDATE dlp_labels SET %s WHERE id=$%d AND tenant_id=$%d
		RETURNING id, tenant_id, name, COALESCE(description,''), sensitivity, color,
		          COALESCE(regex_patterns,'{}'), COALESCE(keywords,'{}'), is_active, created_by, created_at, updated_at`,
		strings.Join(sets, ","), n, n+1), args...,
	).Scan(
		&l.ID, &l.TenantID, &l.Name, &l.Description, &l.Sensitivity, &l.Color,
		&l.RegexPatterns, &l.Keywords, &l.IsActive, &l.CreatedBy, &l.CreatedAt, &l.UpdatedAt,
	)
	if err == pgx.ErrNoRows { return nil, nil }
	return &l, err
}

// ─── Data Assets ──────────────────────────────────────────────────────────────

func scanAsset(row pgx.Row) (*model.DLPDataAsset, error) {
	var a model.DLPDataAsset
	var metaRaw []byte
	err := row.Scan(
		&a.ID, &a.TenantID, &a.Name, &a.AssetType, &a.Location,
		&a.LabelID, &a.LabelName, &a.DataCategories, &a.RecordCount, &a.SizeBytes,
		&a.LastScannedAt, &a.ScanStatus, &a.RiskScore, &a.Owner, &metaRaw, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil { return nil, err }
	_ = json.Unmarshal(metaRaw, &a.Metadata)
	return &a, nil
}

const assetSelect = `
	SELECT a.id, a.tenant_id, a.name, a.asset_type, a.location,
	       a.label_id, COALESCE(l.name,''), COALESCE(a.data_categories,'{}'),
	       a.record_count, a.size_bytes,
	       a.last_scanned_at, a.scan_status, a.risk_score, COALESCE(a.owner,''), a.metadata,
	       a.created_at, a.updated_at
	FROM dlp_data_assets a
	LEFT JOIN dlp_labels l ON l.id=a.label_id`

func (r *DLPRepository) CreateAsset(ctx context.Context, tenantID uuid.UUID, req *model.CreateAssetRequest) (*model.DLPDataAsset, error) {
	meta, _ := json.Marshal(req.Metadata)
	if req.DataCategories == nil { req.DataCategories = []string{} }
	_, err := r.db.Exec(ctx, `
		INSERT INTO dlp_data_assets (tenant_id, name, asset_type, location, label_id, data_categories, record_count, size_bytes, owner, metadata)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		tenantID, req.Name, req.AssetType, req.Location, req.LabelID, req.DataCategories, req.RecordCount, req.SizeBytes, req.Owner, meta,
	)
	if err != nil { return nil, err }
	var a model.DLPDataAsset
	var metaRaw []byte
	err = r.db.QueryRow(ctx, assetSelect+" WHERE a.tenant_id=$1 AND a.name=$2 AND a.asset_type=$3 ORDER BY a.created_at DESC LIMIT 1",
		tenantID, req.Name, req.AssetType,
	).Scan(
		&a.ID, &a.TenantID, &a.Name, &a.AssetType, &a.Location,
		&a.LabelID, &a.LabelName, &a.DataCategories, &a.RecordCount, &a.SizeBytes,
		&a.LastScannedAt, &a.ScanStatus, &a.RiskScore, &a.Owner, &metaRaw, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil { return nil, err }
	_ = json.Unmarshal(metaRaw, &a.Metadata)
	return &a, nil
}

func (r *DLPRepository) GetAsset(ctx context.Context, tenantID, assetID uuid.UUID) (*model.DLPDataAsset, error) {
	a, err := scanAsset(r.db.QueryRow(ctx, assetSelect+" WHERE a.id=$1 AND a.tenant_id=$2", assetID, tenantID))
	if err == pgx.ErrNoRows { return nil, nil }
	return a, err
}

func (r *DLPRepository) ListAssets(ctx context.Context, tenantID uuid.UUID, f model.ListAssetsFilter) ([]*model.DLPDataAsset, int, error) {
	if f.PageSize <= 0 { f.PageSize = 20 }
	if f.Page <= 0 { f.Page = 1 }
	conds := []string{"a.tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if f.AssetType != "" { conds = append(conds, fmt.Sprintf("a.asset_type=$%d", n)); args = append(args, f.AssetType); n++ }
	if f.ScanStatus != "" { conds = append(conds, fmt.Sprintf("a.scan_status=$%d", n)); args = append(args, f.ScanStatus); n++ }
	if f.MinRisk != nil { conds = append(conds, fmt.Sprintf("a.risk_score>=$%d", n)); args = append(args, *f.MinRisk); n++ }
	where := strings.Join(conds, " AND ")
	var total int
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM dlp_data_assets a WHERE "+where, args...).Scan(&total)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := r.db.Query(ctx, fmt.Sprintf(assetSelect+" WHERE %s ORDER BY a.risk_score DESC LIMIT $%d OFFSET $%d", where, n, n+1), args...)
	if err != nil { return nil, 0, err }
	defer rows.Close()
	var assets []*model.DLPDataAsset
	for rows.Next() {
		var a model.DLPDataAsset
		var metaRaw []byte
		if err := rows.Scan(
			&a.ID, &a.TenantID, &a.Name, &a.AssetType, &a.Location,
			&a.LabelID, &a.LabelName, &a.DataCategories, &a.RecordCount, &a.SizeBytes,
			&a.LastScannedAt, &a.ScanStatus, &a.RiskScore, &a.Owner, &metaRaw, &a.CreatedAt, &a.UpdatedAt,
		); err != nil { return nil, 0, err }
		_ = json.Unmarshal(metaRaw, &a.Metadata)
		assets = append(assets, &a)
	}
	return assets, total, nil
}

func (r *DLPRepository) UpdateAsset(ctx context.Context, tenantID, assetID uuid.UUID, req *model.UpdateAssetRequest) (*model.DLPDataAsset, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{}
	n := 1
	if req.LabelID != nil { sets = append(sets, fmt.Sprintf("label_id=$%d", n)); args = append(args, *req.LabelID); n++ }
	if req.DataCategories != nil { sets = append(sets, fmt.Sprintf("data_categories=$%d", n)); args = append(args, req.DataCategories); n++ }
	if req.RecordCount > 0 { sets = append(sets, fmt.Sprintf("record_count=$%d", n)); args = append(args, req.RecordCount); n++ }
	if req.SizeBytes > 0 { sets = append(sets, fmt.Sprintf("size_bytes=$%d", n)); args = append(args, req.SizeBytes); n++ }
	if req.Owner != "" { sets = append(sets, fmt.Sprintf("owner=$%d", n)); args = append(args, req.Owner); n++ }
	if req.RiskScore != nil { sets = append(sets, fmt.Sprintf("risk_score=$%d", n)); args = append(args, *req.RiskScore); n++ }
	if req.Metadata != nil { meta, _ := json.Marshal(req.Metadata); sets = append(sets, fmt.Sprintf("metadata=$%d", n)); args = append(args, meta); n++ }
	args = append(args, assetID, tenantID)
	_, err := r.db.Exec(ctx, fmt.Sprintf("UPDATE dlp_data_assets SET %s WHERE id=$%d AND tenant_id=$%d",
		strings.Join(sets, ","), n, n+1), args...)
	if err != nil { return nil, err }
	return r.GetAsset(ctx, tenantID, assetID)
}

func (r *DLPRepository) UpdateAssetScanStatus(ctx context.Context, assetID uuid.UUID, status string, violationsFound int, labelsDetected []string) error {
	now := time.Now()
	_, err := r.db.Exec(ctx, `
		UPDATE dlp_data_assets SET scan_status=$2, last_scanned_at=$3,
		  risk_score=CASE WHEN $4>0 THEN LEAST(100, risk_score+$4*10) ELSE risk_score END
		WHERE id=$1`, assetID, status, now, violationsFound)
	return err
}

// ─── Policies ─────────────────────────────────────────────────────────────────

func (r *DLPRepository) CreatePolicy(ctx context.Context, tenantID uuid.UUID, req *model.CreatePolicyRequest, createdBy uuid.UUID) (*model.DLPPolicy, error) {
	cond, _ := json.Marshal(req.Conditions)
	if req.SensitivityLevels == nil { req.SensitivityLevels = []string{} }
	if req.DataCategories == nil { req.DataCategories = []string{} }
	if req.Channels == nil { req.Channels = []string{} }
	var p model.DLPPolicy
	var condRaw []byte
	err := r.db.QueryRow(ctx, `
		INSERT INTO dlp_policies (tenant_id, name, description, policy_type, sensitivity_levels, data_categories, action, channels, conditions, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		RETURNING id, tenant_id, name, COALESCE(description,''), policy_type,
		          COALESCE(sensitivity_levels,'{}'), COALESCE(data_categories,'{}'),
		          action, COALESCE(channels,'{}'), conditions, is_active, violation_count, created_by, created_at, updated_at`,
		tenantID, req.Name, req.Description, req.PolicyType, req.SensitivityLevels,
		req.DataCategories, req.Action, req.Channels, cond, createdBy,
	).Scan(
		&p.ID, &p.TenantID, &p.Name, &p.Description, &p.PolicyType,
		&p.SensitivityLevels, &p.DataCategories, &p.Action, &p.Channels,
		&condRaw, &p.IsActive, &p.ViolationCount, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil { return nil, err }
	_ = json.Unmarshal(condRaw, &p.Conditions)
	return &p, nil
}

func (r *DLPRepository) GetPolicy(ctx context.Context, tenantID, policyID uuid.UUID) (*model.DLPPolicy, error) {
	var p model.DLPPolicy
	var condRaw []byte
	err := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, name, COALESCE(description,''), policy_type,
		       COALESCE(sensitivity_levels,'{}'), COALESCE(data_categories,'{}'),
		       action, COALESCE(channels,'{}'), conditions, is_active, violation_count, created_by, created_at, updated_at
		FROM dlp_policies WHERE id=$1 AND tenant_id=$2`, policyID, tenantID,
	).Scan(
		&p.ID, &p.TenantID, &p.Name, &p.Description, &p.PolicyType,
		&p.SensitivityLevels, &p.DataCategories, &p.Action, &p.Channels,
		&condRaw, &p.IsActive, &p.ViolationCount, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err == pgx.ErrNoRows { return nil, nil }
	if err != nil { return nil, err }
	_ = json.Unmarshal(condRaw, &p.Conditions)
	return &p, nil
}

func (r *DLPRepository) ListPolicies(ctx context.Context, tenantID uuid.UUID, policyType string, activeOnly bool, page, pageSize int) ([]*model.DLPPolicy, int, error) {
	if pageSize <= 0 { pageSize = 20 }
	if page <= 0 { page = 1 }
	conds := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if policyType != "" { conds = append(conds, fmt.Sprintf("policy_type=$%d", n)); args = append(args, policyType); n++ }
	if activeOnly { conds = append(conds, "is_active=TRUE") }
	where := strings.Join(conds, " AND ")
	var total int
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM dlp_policies WHERE "+where, args...).Scan(&total)
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := r.db.Query(ctx, fmt.Sprintf(`
		SELECT id, tenant_id, name, COALESCE(description,''), policy_type,
		       COALESCE(sensitivity_levels,'{}'), COALESCE(data_categories,'{}'),
		       action, COALESCE(channels,'{}'), conditions, is_active, violation_count, created_by, created_at, updated_at
		FROM dlp_policies WHERE %s ORDER BY violation_count DESC LIMIT $%d OFFSET $%d`, where, n, n+1), args...)
	if err != nil { return nil, 0, err }
	defer rows.Close()
	var policies []*model.DLPPolicy
	for rows.Next() {
		var p model.DLPPolicy
		var condRaw []byte
		if err := rows.Scan(
			&p.ID, &p.TenantID, &p.Name, &p.Description, &p.PolicyType,
			&p.SensitivityLevels, &p.DataCategories, &p.Action, &p.Channels,
			&condRaw, &p.IsActive, &p.ViolationCount, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
		); err != nil { return nil, 0, err }
		_ = json.Unmarshal(condRaw, &p.Conditions)
		policies = append(policies, &p)
	}
	return policies, total, nil
}

func (r *DLPRepository) UpdatePolicy(ctx context.Context, tenantID, policyID uuid.UUID, req *model.UpdatePolicyRequest) (*model.DLPPolicy, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{}
	n := 1
	if req.Name != "" { sets = append(sets, fmt.Sprintf("name=$%d", n)); args = append(args, req.Name); n++ }
	if req.Description != "" { sets = append(sets, fmt.Sprintf("description=$%d", n)); args = append(args, req.Description); n++ }
	if req.SensitivityLevels != nil { sets = append(sets, fmt.Sprintf("sensitivity_levels=$%d", n)); args = append(args, req.SensitivityLevels); n++ }
	if req.DataCategories != nil { sets = append(sets, fmt.Sprintf("data_categories=$%d", n)); args = append(args, req.DataCategories); n++ }
	if req.Action != "" { sets = append(sets, fmt.Sprintf("action=$%d", n)); args = append(args, req.Action); n++ }
	if req.Channels != nil { sets = append(sets, fmt.Sprintf("channels=$%d", n)); args = append(args, req.Channels); n++ }
	if req.Conditions != nil { cond, _ := json.Marshal(req.Conditions); sets = append(sets, fmt.Sprintf("conditions=$%d", n)); args = append(args, cond); n++ }
	if req.IsActive != nil { sets = append(sets, fmt.Sprintf("is_active=$%d", n)); args = append(args, *req.IsActive); n++ }
	args = append(args, policyID, tenantID)
	_, err := r.db.Exec(ctx, fmt.Sprintf("UPDATE dlp_policies SET %s WHERE id=$%d AND tenant_id=$%d",
		strings.Join(sets, ","), n, n+1), args...)
	if err != nil { return nil, err }
	return r.GetPolicy(ctx, tenantID, policyID)
}

func (r *DLPRepository) IncrementPolicyCounter(ctx context.Context, policyID uuid.UUID) {
	_, _ = r.db.Exec(ctx, "UPDATE dlp_policies SET violation_count=violation_count+1 WHERE id=$1", policyID)
}

// ─── Violations ───────────────────────────────────────────────────────────────

func (r *DLPRepository) CreateViolation(ctx context.Context, tenantID uuid.UUID, req *model.ReportViolationRequest) (*model.DLPViolation, error) {
	mc := req.MatchCount
	if mc == 0 { mc = 1 }
	var v model.DLPViolation
	err := r.db.QueryRow(ctx, `
		INSERT INTO dlp_violations
		  (tenant_id, policy_id, asset_id, label_id, violation_type, channel, severity,
		   user_id_src, endpoint, destination, data_snippet, match_count, action_taken)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		RETURNING id, tenant_id, policy_id, NULL::TEXT, asset_id, label_id,
		          violation_type, COALESCE(channel,''), severity,
		          COALESCE(user_id_src,''), COALESCE(endpoint,''), COALESCE(destination,''),
		          COALESCE(data_snippet,''), match_count, action_taken,
		          status, investigated_by, resolved_at, detected_at, created_at`,
		tenantID, req.PolicyID, req.AssetID, req.LabelID, req.ViolationType, req.Channel, req.Severity,
		req.UserIDSrc, req.Endpoint, req.Destination, req.DataSnippet, mc, req.ActionTaken,
	).Scan(
		&v.ID, &v.TenantID, &v.PolicyID, &v.PolicyName, &v.AssetID, &v.LabelID,
		&v.ViolationType, &v.Channel, &v.Severity,
		&v.UserIDSrc, &v.Endpoint, &v.Destination,
		&v.DataSnippet, &v.MatchCount, &v.ActionTaken,
		&v.Status, &v.InvestigatedBy, &v.ResolvedAt, &v.DetectedAt, &v.CreatedAt,
	)
	if err != nil { return nil, err }
	if req.PolicyID != nil {
		r.IncrementPolicyCounter(ctx, *req.PolicyID)
	}
	return &v, nil
}

func (r *DLPRepository) ListViolations(ctx context.Context, tenantID uuid.UUID, f model.ListViolationsFilter) ([]*model.DLPViolation, int, error) {
	if f.PageSize <= 0 { f.PageSize = 20 }
	if f.Page <= 0 { f.Page = 1 }
	conds := []string{"v.tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if f.PolicyID != nil { conds = append(conds, fmt.Sprintf("v.policy_id=$%d", n)); args = append(args, *f.PolicyID); n++ }
	if f.AssetID != nil { conds = append(conds, fmt.Sprintf("v.asset_id=$%d", n)); args = append(args, *f.AssetID); n++ }
	if f.Severity != "" { conds = append(conds, fmt.Sprintf("v.severity=$%d", n)); args = append(args, f.Severity); n++ }
	if f.Status != "" { conds = append(conds, fmt.Sprintf("v.status=$%d", n)); args = append(args, f.Status); n++ }
	if f.Channel != "" { conds = append(conds, fmt.Sprintf("v.channel=$%d", n)); args = append(args, f.Channel); n++ }
	where := strings.Join(conds, " AND ")
	var total int
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM dlp_violations v WHERE "+where, args...).Scan(&total)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := r.db.Query(ctx, fmt.Sprintf(`
		SELECT v.id, v.tenant_id, v.policy_id, COALESCE(p.name,''), v.asset_id, v.label_id,
		       v.violation_type, COALESCE(v.channel,''), v.severity,
		       COALESCE(v.user_id_src,''), COALESCE(v.endpoint,''), COALESCE(v.destination,''),
		       COALESCE(v.data_snippet,''), v.match_count, v.action_taken,
		       v.status, v.investigated_by, v.resolved_at, v.detected_at, v.created_at
		FROM dlp_violations v
		LEFT JOIN dlp_policies p ON p.id=v.policy_id
		WHERE %s ORDER BY v.detected_at DESC LIMIT $%d OFFSET $%d`, where, n, n+1), args...)
	if err != nil { return nil, 0, err }
	defer rows.Close()
	var viols []*model.DLPViolation
	for rows.Next() {
		var v model.DLPViolation
		if err := rows.Scan(
			&v.ID, &v.TenantID, &v.PolicyID, &v.PolicyName, &v.AssetID, &v.LabelID,
			&v.ViolationType, &v.Channel, &v.Severity,
			&v.UserIDSrc, &v.Endpoint, &v.Destination,
			&v.DataSnippet, &v.MatchCount, &v.ActionTaken,
			&v.Status, &v.InvestigatedBy, &v.ResolvedAt, &v.DetectedAt, &v.CreatedAt,
		); err != nil { return nil, 0, err }
		viols = append(viols, &v)
	}
	return viols, total, nil
}

func (r *DLPRepository) UpdateViolation(ctx context.Context, tenantID, violID uuid.UUID, req *model.UpdateViolationRequest) (*model.DLPViolation, error) {
	sets := []string{}
	args := []any{}
	n := 1
	if req.Status != "" {
		sets = append(sets, fmt.Sprintf("status=$%d", n)); args = append(args, req.Status); n++
		if req.Status == model.ViolationStatusResolved {
			sets = append(sets, fmt.Sprintf("resolved_at=$%d", n)); args = append(args, time.Now()); n++
		}
	}
	if req.InvestigatedBy != nil {
		sets = append(sets, fmt.Sprintf("investigated_by=$%d", n)); args = append(args, *req.InvestigatedBy); n++
	}
	if len(sets) == 0 { return nil, fmt.Errorf("no fields to update") }
	args = append(args, violID, tenantID)
	var v model.DLPViolation
	err := r.db.QueryRow(ctx, fmt.Sprintf(`
		UPDATE dlp_violations SET %s WHERE id=$%d AND tenant_id=$%d
		RETURNING id, tenant_id, policy_id, NULL::TEXT, asset_id, label_id,
		          violation_type, COALESCE(channel,''), severity,
		          COALESCE(user_id_src,''), COALESCE(endpoint,''), COALESCE(destination,''),
		          COALESCE(data_snippet,''), match_count, action_taken,
		          status, investigated_by, resolved_at, detected_at, created_at`,
		strings.Join(sets, ","), n, n+1), args...,
	).Scan(
		&v.ID, &v.TenantID, &v.PolicyID, &v.PolicyName, &v.AssetID, &v.LabelID,
		&v.ViolationType, &v.Channel, &v.Severity,
		&v.UserIDSrc, &v.Endpoint, &v.Destination,
		&v.DataSnippet, &v.MatchCount, &v.ActionTaken,
		&v.Status, &v.InvestigatedBy, &v.ResolvedAt, &v.DetectedAt, &v.CreatedAt,
	)
	if err == pgx.ErrNoRows { return nil, nil }
	return &v, err
}

// ─── Scans ────────────────────────────────────────────────────────────────────

func (r *DLPRepository) CreateScan(ctx context.Context, tenantID uuid.UUID, assetID *uuid.UUID, createdBy uuid.UUID) (*model.DLPScan, error) {
	var s model.DLPScan
	err := r.db.QueryRow(ctx, `
		INSERT INTO dlp_scans (tenant_id, asset_id, created_by)
		VALUES ($1,$2,$3)
		RETURNING id, tenant_id, asset_id, status, items_scanned, violations_found,
		          COALESCE(labels_detected,'{}'), started_at, completed_at, COALESCE(error_text,''), created_by, created_at`,
		tenantID, assetID, createdBy,
	).Scan(
		&s.ID, &s.TenantID, &s.AssetID, &s.Status, &s.ItemsScanned, &s.ViolationsFound,
		&s.LabelsDetected, &s.StartedAt, &s.CompletedAt, &s.ErrorText, &s.CreatedBy, &s.CreatedAt,
	)
	return &s, err
}

func (r *DLPRepository) UpdateScanStatus(ctx context.Context, scanID uuid.UUID, status string, items int64, violations int, labels []string, errText string) error {
	now := time.Now()
	var startedAt, completedAt *time.Time
	if status == "running" { startedAt = &now }
	if status == "completed" || status == "failed" { completedAt = &now }
	if labels == nil { labels = []string{} }
	_, err := r.db.Exec(ctx, `
		UPDATE dlp_scans SET status=$2, items_scanned=$3, violations_found=$4, labels_detected=$5, error_text=$6,
		  started_at=COALESCE($7, started_at), completed_at=$8 WHERE id=$1`,
		scanID, status, items, violations, labels, errText, startedAt, completedAt,
	)
	return err
}

func (r *DLPRepository) ListScans(ctx context.Context, tenantID uuid.UUID, assetID *uuid.UUID, page, pageSize int) ([]*model.DLPScan, int, error) {
	if pageSize <= 0 { pageSize = 20 }
	if page <= 0 { page = 1 }
	conds := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if assetID != nil { conds = append(conds, fmt.Sprintf("asset_id=$%d", n)); args = append(args, *assetID); n++ }
	where := strings.Join(conds, " AND ")
	var total int
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM dlp_scans WHERE "+where, args...).Scan(&total)
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := r.db.Query(ctx, fmt.Sprintf(`
		SELECT id, tenant_id, asset_id, status, items_scanned, violations_found,
		       COALESCE(labels_detected,'{}'), started_at, completed_at, COALESCE(error_text,''), created_by, created_at
		FROM dlp_scans WHERE %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, where, n, n+1), args...)
	if err != nil { return nil, 0, err }
	defer rows.Close()
	var scans []*model.DLPScan
	for rows.Next() {
		var s model.DLPScan
		if err := rows.Scan(
			&s.ID, &s.TenantID, &s.AssetID, &s.Status, &s.ItemsScanned, &s.ViolationsFound,
			&s.LabelsDetected, &s.StartedAt, &s.CompletedAt, &s.ErrorText, &s.CreatedBy, &s.CreatedAt,
		); err != nil { return nil, 0, err }
		scans = append(scans, &s)
	}
	return scans, total, nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (r *DLPRepository) Stats(ctx context.Context, tenantID uuid.UUID) (*model.DLPStats, error) {
	stats := &model.DLPStats{
		ViolationsBySeverity: make(map[string]int),
		ViolationsByType:     make(map[string]int),
		AssetsByCategory:     make(map[string]int),
	}
	_ = r.db.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE risk_score>=50)
		FROM dlp_data_assets WHERE tenant_id=$1`, tenantID,
	).Scan(&stats.TotalAssets, &stats.AssetsAtRisk)
	_ = r.db.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE is_active)
		FROM dlp_policies WHERE tenant_id=$1`, tenantID,
	).Scan(&stats.TotalPolicies, &stats.ActivePolicies)
	_ = r.db.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE status='open')
		FROM dlp_violations WHERE tenant_id=$1`, tenantID,
	).Scan(&stats.TotalViolations, &stats.OpenViolations)

	rows, _ := r.db.Query(ctx, "SELECT severity, COUNT(*) FROM dlp_violations WHERE tenant_id=$1 GROUP BY severity", tenantID)
	if rows != nil { defer rows.Close(); for rows.Next() { var s string; var c int; _ = rows.Scan(&s, &c); stats.ViolationsBySeverity[s] = c } }

	rows2, _ := r.db.Query(ctx, "SELECT violation_type, COUNT(*) FROM dlp_violations WHERE tenant_id=$1 GROUP BY violation_type", tenantID)
	if rows2 != nil { defer rows2.Close(); for rows2.Next() { var s string; var c int; _ = rows2.Scan(&s, &c); stats.ViolationsByType[s] = c } }

	rows3, _ := r.db.Query(ctx, `
		SELECT id, name, violation_count FROM dlp_policies WHERE tenant_id=$1 ORDER BY violation_count DESC LIMIT 5`, tenantID)
	if rows3 != nil {
		defer rows3.Close()
		for rows3.Next() {
			var ps model.PolicyViolStats
			_ = rows3.Scan(&ps.PolicyID, &ps.PolicyName, &ps.Count)
			stats.TopPolicies = append(stats.TopPolicies, &ps)
		}
	}
	return stats, nil
}
