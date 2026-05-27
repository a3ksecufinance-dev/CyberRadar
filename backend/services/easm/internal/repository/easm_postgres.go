package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/cyberradar/platform/services/easm/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EASMRepository handles all EASM persistence.
type EASMRepository struct {
	db *pgxpool.Pool
}

// NewEASMRepository creates an EASMRepository.
func NewEASMRepository(db *pgxpool.Pool) *EASMRepository {
	return &EASMRepository{db: db}
}

// ─── Assets ───────────────────────────────────────────────────────────────────

func (r *EASMRepository) CreateAsset(ctx context.Context, tenantID uuid.UUID, req *model.CreateAssetRequest) (*model.EASMAsset, error) {
	meta, _ := json.Marshal(req.Metadata)
	if req.Tags == nil {
		req.Tags = []string{}
	}
	var a model.EASMAsset
	var metaRaw []byte
	err := r.db.QueryRow(ctx, `
		INSERT INTO easm_assets (tenant_id, asset_type, value, source, tags, metadata)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (tenant_id, asset_type, value) DO UPDATE
		  SET last_seen_at=NOW(), status='active', updated_at=NOW()
		RETURNING id, tenant_id, asset_type, value,
		          COALESCE(source,''), status, risk_score, tags,
		          first_seen_at, last_seen_at, metadata, created_at, updated_at`,
		tenantID, req.AssetType, req.Value, req.Source, req.Tags, meta,
	).Scan(
		&a.ID, &a.TenantID, &a.AssetType, &a.Value,
		&a.Source, &a.Status, &a.RiskScore, &a.Tags,
		&a.FirstSeenAt, &a.LastSeenAt, &metaRaw, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(metaRaw, &a.Metadata)
	return &a, nil
}

func (r *EASMRepository) GetAsset(ctx context.Context, tenantID, assetID uuid.UUID) (*model.EASMAsset, error) {
	var a model.EASMAsset
	var metaRaw []byte
	err := r.db.QueryRow(ctx, `
		SELECT a.id, a.tenant_id, a.asset_type, a.value, COALESCE(a.source,''),
		       a.status, a.risk_score, a.tags,
		       a.first_seen_at, a.last_seen_at, a.metadata, a.created_at, a.updated_at,
		       COUNT(e.id) AS exposure_count
		FROM easm_assets a
		LEFT JOIN easm_exposures e ON e.asset_id=a.id AND NOT e.is_remediated
		WHERE a.id=$1 AND a.tenant_id=$2
		GROUP BY a.id`,
		assetID, tenantID,
	).Scan(
		&a.ID, &a.TenantID, &a.AssetType, &a.Value, &a.Source,
		&a.Status, &a.RiskScore, &a.Tags,
		&a.FirstSeenAt, &a.LastSeenAt, &metaRaw, &a.CreatedAt, &a.UpdatedAt,
		&a.ExposureCount,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(metaRaw, &a.Metadata)
	return &a, nil
}

func (r *EASMRepository) ListAssets(ctx context.Context, tenantID uuid.UUID, f model.ListAssetsFilter) ([]*model.EASMAsset, int, error) {
	if f.PageSize <= 0 {
		f.PageSize = 20
	}
	if f.Page <= 0 {
		f.Page = 1
	}
	offset := (f.Page - 1) * f.PageSize

	conditions := []string{"a.tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if f.AssetType != "" {
		conditions = append(conditions, fmt.Sprintf("a.asset_type=$%d", n))
		args = append(args, f.AssetType)
		n++
	}
	if f.Status != "" {
		conditions = append(conditions, fmt.Sprintf("a.status=$%d", n))
		args = append(args, f.Status)
		n++
	}
	if f.MinRiskScore != nil {
		conditions = append(conditions, fmt.Sprintf("a.risk_score>=$%d", n))
		args = append(args, *f.MinRiskScore)
		n++
	}
	where := strings.Join(conditions, " AND ")

	var total int
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM easm_assets a WHERE "+where, args...).Scan(&total)

	args = append(args, f.PageSize, offset)
	rows, err := r.db.Query(ctx, fmt.Sprintf(`
		SELECT a.id, a.tenant_id, a.asset_type, a.value, COALESCE(a.source,''),
		       a.status, a.risk_score, a.tags,
		       a.first_seen_at, a.last_seen_at, a.metadata, a.created_at, a.updated_at,
		       COUNT(e.id) AS exposure_count
		FROM easm_assets a
		LEFT JOIN easm_exposures e ON e.asset_id=a.id AND NOT e.is_remediated
		WHERE %s
		GROUP BY a.id
		ORDER BY a.risk_score DESC, a.last_seen_at DESC
		LIMIT $%d OFFSET $%d`, where, n, n+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var assets []*model.EASMAsset
	for rows.Next() {
		var a model.EASMAsset
		var metaRaw []byte
		if err := rows.Scan(
			&a.ID, &a.TenantID, &a.AssetType, &a.Value, &a.Source,
			&a.Status, &a.RiskScore, &a.Tags,
			&a.FirstSeenAt, &a.LastSeenAt, &metaRaw, &a.CreatedAt, &a.UpdatedAt,
			&a.ExposureCount,
		); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal(metaRaw, &a.Metadata)
		assets = append(assets, &a)
	}
	return assets, total, nil
}

func (r *EASMRepository) UpdateAsset(ctx context.Context, tenantID, assetID uuid.UUID, req *model.UpdateAssetRequest) (*model.EASMAsset, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{}
	n := 1
	if req.Status != "" {
		sets = append(sets, fmt.Sprintf("status=$%d", n))
		args = append(args, req.Status)
		n++
	}
	if req.RiskScore != nil {
		sets = append(sets, fmt.Sprintf("risk_score=$%d", n))
		args = append(args, *req.RiskScore)
		n++
	}
	if req.Tags != nil {
		sets = append(sets, fmt.Sprintf("tags=$%d", n))
		args = append(args, req.Tags)
		n++
	}
	if req.Metadata != nil {
		meta, _ := json.Marshal(req.Metadata)
		sets = append(sets, fmt.Sprintf("metadata=$%d", n))
		args = append(args, meta)
		n++
	}
	args = append(args, assetID, tenantID)
	var a model.EASMAsset
	var metaRaw []byte
	err := r.db.QueryRow(ctx, fmt.Sprintf(`
		UPDATE easm_assets SET %s
		WHERE id=$%d AND tenant_id=$%d
		RETURNING id, tenant_id, asset_type, value, COALESCE(source,''),
		          status, risk_score, tags, first_seen_at, last_seen_at, metadata, created_at, updated_at`,
		strings.Join(sets, ","), n, n+1), args...,
	).Scan(
		&a.ID, &a.TenantID, &a.AssetType, &a.Value, &a.Source,
		&a.Status, &a.RiskScore, &a.Tags,
		&a.FirstSeenAt, &a.LastSeenAt, &metaRaw, &a.CreatedAt, &a.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(metaRaw, &a.Metadata)
	return &a, nil
}

func (r *EASMRepository) DeleteAsset(ctx context.Context, tenantID, assetID uuid.UUID) error {
	res, err := r.db.Exec(ctx,
		"DELETE FROM easm_assets WHERE id=$1 AND tenant_id=$2", assetID, tenantID)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ─── Exposures ────────────────────────────────────────────────────────────────

func (r *EASMRepository) CreateExposure(ctx context.Context, tenantID uuid.UUID, req *model.CreateExposureRequest) (*model.EASMExposure, error) {
	var e model.EASMExposure
	err := r.db.QueryRow(ctx, `
		INSERT INTO easm_exposures (tenant_id, asset_id, exposure_type, port, protocol, title, description, severity)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id, tenant_id, asset_id, exposure_type,
		          port, COALESCE(protocol,''), title, COALESCE(description,''),
		          severity, is_remediated, first_detected_at, last_seen_at, remediated_at, created_at`,
		tenantID, req.AssetID, req.ExposureType, req.Port, req.Protocol,
		req.Title, req.Description, req.Severity,
	).Scan(
		&e.ID, &e.TenantID, &e.AssetID, &e.ExposureType,
		&e.Port, &e.Protocol, &e.Title, &e.Description,
		&e.Severity, &e.IsRemediated, &e.FirstDetectedAt, &e.LastSeenAt, &e.RemediatedAt, &e.CreatedAt,
	)
	return &e, err
}

func (r *EASMRepository) ListExposures(ctx context.Context, tenantID uuid.UUID, assetID *uuid.UUID, severity string, remediated *bool, page, pageSize int) ([]*model.EASMExposure, int, error) {
	if pageSize <= 0 {
		pageSize = 20
	}
	if page <= 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	conditions := []string{"e.tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if assetID != nil {
		conditions = append(conditions, fmt.Sprintf("e.asset_id=$%d", n))
		args = append(args, *assetID)
		n++
	}
	if severity != "" {
		conditions = append(conditions, fmt.Sprintf("e.severity=$%d", n))
		args = append(args, severity)
		n++
	}
	if remediated != nil {
		conditions = append(conditions, fmt.Sprintf("e.is_remediated=$%d", n))
		args = append(args, *remediated)
		n++
	}
	where := strings.Join(conditions, " AND ")

	var total int
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM easm_exposures e WHERE "+where, args...).Scan(&total)

	args = append(args, pageSize, offset)
	rows, err := r.db.Query(ctx, fmt.Sprintf(`
		SELECT e.id, e.tenant_id, e.asset_id, e.exposure_type,
		       e.port, COALESCE(e.protocol,''), e.title, COALESCE(e.description,''),
		       e.severity, e.is_remediated, e.first_detected_at, e.last_seen_at, e.remediated_at, e.created_at,
		       COALESCE(a.value,'') AS asset_value
		FROM easm_exposures e
		LEFT JOIN easm_assets a ON a.id=e.asset_id
		WHERE %s
		ORDER BY
		  CASE e.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END,
		  e.last_seen_at DESC
		LIMIT $%d OFFSET $%d`, where, n, n+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var exposures []*model.EASMExposure
	for rows.Next() {
		var e model.EASMExposure
		if err := rows.Scan(
			&e.ID, &e.TenantID, &e.AssetID, &e.ExposureType,
			&e.Port, &e.Protocol, &e.Title, &e.Description,
			&e.Severity, &e.IsRemediated, &e.FirstDetectedAt, &e.LastSeenAt, &e.RemediatedAt, &e.CreatedAt,
			&e.AssetValue,
		); err != nil {
			return nil, 0, err
		}
		exposures = append(exposures, &e)
	}
	return exposures, total, nil
}

func (r *EASMRepository) RemediateExposure(ctx context.Context, tenantID, exposureID uuid.UUID) (*model.EASMExposure, error) {
	var e model.EASMExposure
	err := r.db.QueryRow(ctx, `
		UPDATE easm_exposures SET is_remediated=TRUE, remediated_at=NOW()
		WHERE id=$1 AND tenant_id=$2
		RETURNING id, tenant_id, asset_id, exposure_type,
		          port, COALESCE(protocol,''), title, COALESCE(description,''),
		          severity, is_remediated, first_detected_at, last_seen_at, remediated_at, created_at`,
		exposureID, tenantID,
	).Scan(
		&e.ID, &e.TenantID, &e.AssetID, &e.ExposureType,
		&e.Port, &e.Protocol, &e.Title, &e.Description,
		&e.Severity, &e.IsRemediated, &e.FirstDetectedAt, &e.LastSeenAt, &e.RemediatedAt, &e.CreatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &e, err
}

// ─── Leaks ────────────────────────────────────────────────────────────────────

func (r *EASMRepository) CreateLeak(ctx context.Context, tenantID uuid.UUID, req *model.CreateLeakRequest) (*model.EASMLeak, error) {
	if req.DataTypes == nil {
		req.DataTypes = []string{}
	}
	var l model.EASMLeak
	err := r.db.QueryRow(ctx, `
		INSERT INTO easm_leaks (tenant_id, source, breach_date, data_types, affected_count, sample_data, severity)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id, tenant_id, source, breach_date, data_types, affected_count,
		          COALESCE(sample_data,''), severity, is_acknowledged, acknowledged_by, acknowledged_at, created_at`,
		tenantID, req.Source, req.BreachDate, req.DataTypes, req.AffectedCount, req.SampleData, req.Severity,
	).Scan(
		&l.ID, &l.TenantID, &l.Source, &l.BreachDate, &l.DataTypes, &l.AffectedCount,
		&l.SampleData, &l.Severity, &l.IsAcknowledged, &l.AcknowledgedBy, &l.AcknowledgedAt, &l.CreatedAt,
	)
	return &l, err
}

func (r *EASMRepository) ListLeaks(ctx context.Context, tenantID uuid.UUID, acknowledged *bool, severity string, page, pageSize int) ([]*model.EASMLeak, int, error) {
	if pageSize <= 0 {
		pageSize = 20
	}
	if page <= 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	conditions := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if acknowledged != nil {
		conditions = append(conditions, fmt.Sprintf("is_acknowledged=$%d", n))
		args = append(args, *acknowledged)
		n++
	}
	if severity != "" {
		conditions = append(conditions, fmt.Sprintf("severity=$%d", n))
		args = append(args, severity)
		n++
	}
	where := strings.Join(conditions, " AND ")

	var total int
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM easm_leaks WHERE "+where, args...).Scan(&total)

	args = append(args, pageSize, offset)
	rows, err := r.db.Query(ctx, fmt.Sprintf(`
		SELECT id, tenant_id, source, breach_date, data_types, affected_count,
		       COALESCE(sample_data,''), severity, is_acknowledged, acknowledged_by, acknowledged_at, created_at
		FROM easm_leaks WHERE %s
		ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, where, n, n+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var leaks []*model.EASMLeak
	for rows.Next() {
		var l model.EASMLeak
		if err := rows.Scan(
			&l.ID, &l.TenantID, &l.Source, &l.BreachDate, &l.DataTypes, &l.AffectedCount,
			&l.SampleData, &l.Severity, &l.IsAcknowledged, &l.AcknowledgedBy, &l.AcknowledgedAt, &l.CreatedAt,
		); err != nil {
			return nil, 0, err
		}
		leaks = append(leaks, &l)
	}
	return leaks, total, nil
}

func (r *EASMRepository) AcknowledgeLeak(ctx context.Context, tenantID, leakID, userID uuid.UUID) (*model.EASMLeak, error) {
	var l model.EASMLeak
	err := r.db.QueryRow(ctx, `
		UPDATE easm_leaks SET is_acknowledged=TRUE, acknowledged_by=$3, acknowledged_at=NOW()
		WHERE id=$1 AND tenant_id=$2
		RETURNING id, tenant_id, source, breach_date, data_types, affected_count,
		          COALESCE(sample_data,''), severity, is_acknowledged, acknowledged_by, acknowledged_at, created_at`,
		leakID, tenantID, userID,
	).Scan(
		&l.ID, &l.TenantID, &l.Source, &l.BreachDate, &l.DataTypes, &l.AffectedCount,
		&l.SampleData, &l.Severity, &l.IsAcknowledged, &l.AcknowledgedBy, &l.AcknowledgedAt, &l.CreatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &l, err
}

// ─── Brand alerts ─────────────────────────────────────────────────────────────

func (r *EASMRepository) CreateBrandAlert(ctx context.Context, tenantID uuid.UUID, req *model.CreateBrandAlertRequest) (*model.EASMBrandAlert, error) {
	var a model.EASMBrandAlert
	err := r.db.QueryRow(ctx, `
		INSERT INTO easm_brand_alerts (tenant_id, alert_type, value, similarity_score)
		VALUES ($1,$2,$3,$4)
		RETURNING id, tenant_id, alert_type, value, similarity_score,
		          status, detected_at, resolved_at, created_at`,
		tenantID, req.AlertType, req.Value, req.SimilarityScore,
	).Scan(
		&a.ID, &a.TenantID, &a.AlertType, &a.Value, &a.SimilarityScore,
		&a.Status, &a.DetectedAt, &a.ResolvedAt, &a.CreatedAt,
	)
	return &a, err
}

func (r *EASMRepository) ListBrandAlerts(ctx context.Context, tenantID uuid.UUID, alertType, status string, page, pageSize int) ([]*model.EASMBrandAlert, int, error) {
	if pageSize <= 0 {
		pageSize = 20
	}
	if page <= 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	conditions := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if alertType != "" {
		conditions = append(conditions, fmt.Sprintf("alert_type=$%d", n))
		args = append(args, alertType)
		n++
	}
	if status != "" {
		conditions = append(conditions, fmt.Sprintf("status=$%d", n))
		args = append(args, status)
		n++
	}
	where := strings.Join(conditions, " AND ")

	var total int
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM easm_brand_alerts WHERE "+where, args...).Scan(&total)

	args = append(args, pageSize, offset)
	rows, err := r.db.Query(ctx, fmt.Sprintf(`
		SELECT id, tenant_id, alert_type, value, similarity_score,
		       status, detected_at, resolved_at, created_at
		FROM easm_brand_alerts WHERE %s
		ORDER BY detected_at DESC LIMIT $%d OFFSET $%d`, where, n, n+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var alerts []*model.EASMBrandAlert
	for rows.Next() {
		var a model.EASMBrandAlert
		if err := rows.Scan(
			&a.ID, &a.TenantID, &a.AlertType, &a.Value, &a.SimilarityScore,
			&a.Status, &a.DetectedAt, &a.ResolvedAt, &a.CreatedAt,
		); err != nil {
			return nil, 0, err
		}
		alerts = append(alerts, &a)
	}
	return alerts, total, nil
}

func (r *EASMRepository) UpdateBrandAlert(ctx context.Context, tenantID, alertID uuid.UUID, status string) (*model.EASMBrandAlert, error) {
	var resolvedAt *time.Time
	if status == model.AlertStatusResolved || status == model.AlertStatusFalsePositive {
		t := time.Now()
		resolvedAt = &t
	}
	var a model.EASMBrandAlert
	err := r.db.QueryRow(ctx, `
		UPDATE easm_brand_alerts SET status=$3, resolved_at=$4
		WHERE id=$1 AND tenant_id=$2
		RETURNING id, tenant_id, alert_type, value, similarity_score,
		          status, detected_at, resolved_at, created_at`,
		alertID, tenantID, status, resolvedAt,
	).Scan(
		&a.ID, &a.TenantID, &a.AlertType, &a.Value, &a.SimilarityScore,
		&a.Status, &a.DetectedAt, &a.ResolvedAt, &a.CreatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

// ─── Scans ────────────────────────────────────────────────────────────────────

func (r *EASMRepository) CreateScan(ctx context.Context, tenantID uuid.UUID, req *model.CreateScanRequest, createdBy uuid.UUID) (*model.EASMScan, error) {
	var s model.EASMScan
	err := r.db.QueryRow(ctx, `
		INSERT INTO easm_scans (tenant_id, scan_type, targets, created_by)
		VALUES ($1,$2,$3,$4)
		RETURNING id, tenant_id, scan_type, status, targets,
		          assets_found, exposures_found, started_at, completed_at, error_text, created_by, created_at`,
		tenantID, req.ScanType, req.Targets, createdBy,
	).Scan(
		&s.ID, &s.TenantID, &s.ScanType, &s.Status, &s.Targets,
		&s.AssetsFound, &s.ExposuresFound, &s.StartedAt, &s.CompletedAt, &s.ErrorText, &s.CreatedBy, &s.CreatedAt,
	)
	return &s, err
}

func (r *EASMRepository) GetScan(ctx context.Context, tenantID, scanID uuid.UUID) (*model.EASMScan, error) {
	var s model.EASMScan
	err := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, scan_type, status, targets,
		       assets_found, exposures_found, started_at, completed_at,
		       COALESCE(error_text,''), created_by, created_at
		FROM easm_scans WHERE id=$1 AND tenant_id=$2`,
		scanID, tenantID,
	).Scan(
		&s.ID, &s.TenantID, &s.ScanType, &s.Status, &s.Targets,
		&s.AssetsFound, &s.ExposuresFound, &s.StartedAt, &s.CompletedAt, &s.ErrorText, &s.CreatedBy, &s.CreatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &s, err
}

func (r *EASMRepository) UpdateScanStatus(ctx context.Context, scanID uuid.UUID, status string, assetsFound, exposuresFound int, errText string) error {
	var startedAt, completedAt *time.Time
	now := time.Now()
	if status == "running" {
		startedAt = &now
	} else if status == "completed" || status == "failed" {
		completedAt = &now
	}
	_, err := r.db.Exec(ctx, `
		UPDATE easm_scans
		SET status=$2, assets_found=$3, exposures_found=$4, error_text=$5,
		    started_at=COALESCE($6, started_at),
		    completed_at=$7
		WHERE id=$1`,
		scanID, status, assetsFound, exposuresFound, errText, startedAt, completedAt,
	)
	return err
}

func (r *EASMRepository) ListScans(ctx context.Context, tenantID string, page, pageSize int) ([]*model.EASMScan, int, error) {
	if pageSize <= 0 {
		pageSize = 20
	}
	if page <= 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	var total int
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM easm_scans WHERE tenant_id=$1", tenantID).Scan(&total)

	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, scan_type, status, targets,
		       assets_found, exposures_found, started_at, completed_at,
		       COALESCE(error_text,''), created_by, created_at
		FROM easm_scans WHERE tenant_id=$1
		ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		tenantID, pageSize, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var scans []*model.EASMScan
	for rows.Next() {
		var s model.EASMScan
		if err := rows.Scan(
			&s.ID, &s.TenantID, &s.ScanType, &s.Status, &s.Targets,
			&s.AssetsFound, &s.ExposuresFound, &s.StartedAt, &s.CompletedAt, &s.ErrorText, &s.CreatedBy, &s.CreatedAt,
		); err != nil {
			return nil, 0, err
		}
		scans = append(scans, &s)
	}
	return scans, total, nil
}

// ─── Risk score ───────────────────────────────────────────────────────────────

func (r *EASMRepository) ComputeRiskScore(ctx context.Context, tenantID uuid.UUID) (*model.ExternalRiskScore, error) {
	score := &model.ExternalRiskScore{TenantID: tenantID, ComputedAt: time.Now()}

	// Asset score: log-scale based on active asset count
	var activeAssets int
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM easm_assets WHERE tenant_id=$1 AND status='active'", tenantID).Scan(&activeAssets)
	if activeAssets > 0 {
		score.AssetScore = int(math.Min(100, math.Log10(float64(activeAssets)+1)*50))
	}

	// Exposure score: weighted by severity, critical/high counts
	rows, err := r.db.Query(ctx, `
		SELECT severity, COUNT(*) FROM easm_exposures
		WHERE tenant_id=$1 AND NOT is_remediated
		GROUP BY severity`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	exposureScore := 0
	for rows.Next() {
		var sev string
		var cnt int
		_ = rows.Scan(&sev, &cnt)
		switch sev {
		case model.SeverityCritical:
			exposureScore += cnt * 25
			score.CriticalExposures += cnt
		case model.SeverityHigh:
			exposureScore += cnt * 10
			score.HighExposures += cnt
		case model.SeverityMedium:
			exposureScore += cnt * 4
		case model.SeverityLow:
			exposureScore += cnt * 1
		}
	}
	score.ExposureScore = int(math.Min(100, float64(exposureScore)))

	// Leak score
	var openLeaks int
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM easm_leaks WHERE tenant_id=$1 AND NOT is_acknowledged", tenantID).Scan(&openLeaks)
	score.ActiveLeaks = openLeaks
	score.LeakScore = int(math.Min(100, float64(openLeaks)*20))

	// Brand score
	var openAlerts int
	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM easm_brand_alerts WHERE tenant_id=$1 AND status NOT IN ('false_positive','resolved')", tenantID).Scan(&openAlerts)
	score.ActiveAlerts = openAlerts
	score.BrandScore = int(math.Min(100, float64(openAlerts)*15))

	// Overall weighted score
	overall := float64(score.ExposureScore)*0.4 +
		float64(score.LeakScore)*0.3 +
		float64(score.BrandScore)*0.2 +
		float64(score.AssetScore)*0.1
	score.OverallScore = int(math.Min(100, overall))

	return score, nil
}

func (r *EASMRepository) Stats(ctx context.Context, tenantID uuid.UUID) (*model.EASMStats, error) {
	stats := &model.EASMStats{
		ScansByStatus:       make(map[string]int),
		ExposuresBySeverity: make(map[string]int),
	}

	_ = r.db.QueryRow(ctx, "SELECT COUNT(*), COUNT(*) FILTER (WHERE status='active') FROM easm_assets WHERE tenant_id=$1", tenantID).
		Scan(&stats.TotalAssets, &stats.ActiveAssets)

	_ = r.db.QueryRow(ctx, "SELECT COUNT(*), COUNT(*) FILTER (WHERE is_remediated) FROM easm_exposures WHERE tenant_id=$1", tenantID).
		Scan(&stats.TotalExposures, &stats.RemediatedExposures)

	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM easm_leaks WHERE tenant_id=$1 AND NOT is_acknowledged", tenantID).
		Scan(&stats.OpenLeaks)

	_ = r.db.QueryRow(ctx, "SELECT COUNT(*) FROM easm_brand_alerts WHERE tenant_id=$1 AND status NOT IN ('false_positive','resolved')", tenantID).
		Scan(&stats.OpenAlerts)

	riskScore, err := r.ComputeRiskScore(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	stats.RiskScore = *riskScore

	// Scans by status
	rows, err := r.db.Query(ctx, "SELECT status, COUNT(*) FROM easm_scans WHERE tenant_id=$1 GROUP BY status", tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		var c int
		_ = rows.Scan(&s, &c)
		stats.ScansByStatus[s] = c
	}

	// Exposures by severity
	rows2, err := r.db.Query(ctx, "SELECT severity, COUNT(*) FROM easm_exposures WHERE tenant_id=$1 AND NOT is_remediated GROUP BY severity", tenantID)
	if err != nil {
		return nil, err
	}
	defer rows2.Close()
	for rows2.Next() {
		var s string
		var c int
		_ = rows2.Scan(&s, &c)
		stats.ExposuresBySeverity[s] = c
	}

	return stats, nil
}
