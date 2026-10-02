package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cyberradar/platform/services/dspm/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

type DSPMRepository struct {
	db  *pgxpool.Pool
	log zerolog.Logger
}

func NewDSPMRepository(pool *pgxpool.Pool, log zerolog.Logger) *DSPMRepository {
	return &DSPMRepository{db: pool, log: log}
}

// ─── Risk helpers ─────────────────────────────────────────────────────────────

func dataStoreRiskScore(sensitivityLevel string, isEncrypted, isAccessControlled, isPublic bool, openFindings int) int {
	score := 0
	switch sensitivityLevel {
	case "top_secret":
		score += 40
	case "restricted":
		score += 30
	case "confidential":
		score += 20
	case "internal":
		score += 10
	}
	if !isEncrypted {
		score += 20
	}
	if !isAccessControlled {
		score += 15
	}
	if isPublic {
		score += 15
	}
	score += openFindings * 5
	if score > 100 {
		score = 100
	}
	return score
}

func riskLevelFromScore(score int) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
}

// ─── refreshStoreRisk (goroutine) ─────────────────────────────────────────────

func (r *DSPMRepository) refreshStoreRisk(storeID uuid.UUID) {
	ctx := context.Background()
	var sensitivityLevel string
	var isEncrypted, isAccessControlled bool
	var openFindings int

	err := r.db.QueryRow(ctx,
		`SELECT sensitivity_level, is_encrypted, is_access_controlled,
		        (SELECT COUNT(*) FROM dspm_findings
		         WHERE data_store_id=$1 AND status NOT IN ('remediated','false_positive'))
		 FROM dspm_data_stores WHERE id=$1`,
		storeID,
	).Scan(&sensitivityLevel, &isEncrypted, &isAccessControlled, &openFindings)
	if err != nil {
		r.log.Error().Err(err).Str("store_id", storeID.String()).Msg("refreshStoreRisk fetch")
		return
	}

	score := dataStoreRiskScore(sensitivityLevel, isEncrypted, isAccessControlled, false, openFindings)
	level := riskLevelFromScore(score)

	_, err = r.db.Exec(ctx,
		`UPDATE dspm_data_stores SET risk_score=$1, risk_level=$2, updated_at=NOW() WHERE id=$3`,
		score, level, storeID,
	)
	if err != nil {
		r.log.Error().Err(err).Str("store_id", storeID.String()).Msg("refreshStoreRisk update")
	}
}

// ─── Data Stores ──────────────────────────────────────────────────────────────

func (r *DSPMRepository) CreateDataStore(ctx context.Context, tenantID uuid.UUID, req model.CreateDataStoreRequest, createdBy *uuid.UUID) (*model.DSPMDataStore, error) {
	if req.DataCategories == nil {
		req.DataCategories = []string{}
	}
	if req.Tags == nil {
		req.Tags = []string{}
	}
	sensitivityLevel := req.SensitivityLevel
	if sensitivityLevel == "" {
		sensitivityLevel = "internal"
	}
	score := dataStoreRiskScore(sensitivityLevel, req.IsEncrypted, req.IsAccessControlled, false, 0)
	level := riskLevelFromScore(score)

	var ds model.DSPMDataStore
	err := r.db.QueryRow(ctx,
		`INSERT INTO dspm_data_stores
		 (tenant_id,name,store_type,cloud_provider,region,endpoint,
		  sensitivity_level,data_categories,is_encrypted,is_access_controlled,
		  is_monitored,is_backup_enabled,owner,owner_id,department,
		  risk_score,risk_level,tags,created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
		 RETURNING id,tenant_id,name,store_type,cloud_provider,region,endpoint,
		           sensitivity_level,data_categories,is_encrypted,is_access_controlled,
		           is_monitored,is_backup_enabled,owner,owner_id,department,
		           risk_score,risk_level,last_scanned_at,scan_status,tags,notes,
		           created_by,created_at,updated_at`,
		tenantID, req.Name, req.StoreType, req.CloudProvider, req.Region, req.Endpoint,
		sensitivityLevel, req.DataCategories, req.IsEncrypted, req.IsAccessControlled,
		req.IsMonitored, req.IsBackupEnabled, req.Owner, req.OwnerID, req.Department,
		score, level, req.Tags, createdBy,
	).Scan(
		&ds.ID, &ds.TenantID, &ds.Name, &ds.StoreType, &ds.CloudProvider, &ds.Region, &ds.Endpoint,
		&ds.SensitivityLevel, &ds.DataCategories, &ds.IsEncrypted, &ds.IsAccessControlled,
		&ds.IsMonitored, &ds.IsBackupEnabled, &ds.Owner, &ds.OwnerID, &ds.Department,
		&ds.RiskScore, &ds.RiskLevel, &ds.LastScannedAt, &ds.ScanStatus, &ds.Tags, &ds.Notes,
		&ds.CreatedBy, &ds.CreatedAt, &ds.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create data store: %w", err)
	}
	if ds.DataCategories == nil {
		ds.DataCategories = []string{}
	}
	if ds.Tags == nil {
		ds.Tags = []string{}
	}
	return &ds, nil
}

func (r *DSPMRepository) GetDataStore(ctx context.Context, tenantID, storeID uuid.UUID) (*model.DSPMDataStore, error) {
	var ds model.DSPMDataStore
	err := r.db.QueryRow(ctx,
		`SELECT d.id,d.tenant_id,d.name,d.store_type,d.cloud_provider,d.region,d.endpoint,
		        d.sensitivity_level,d.data_categories,d.is_encrypted,d.is_access_controlled,
		        d.is_monitored,d.is_backup_enabled,d.owner,d.owner_id,d.department,
		        d.risk_score,d.risk_level,d.last_scanned_at,d.scan_status,d.tags,d.notes,
		        d.created_by,d.created_at,d.updated_at,
		        COUNT(f.id) FILTER (WHERE f.status NOT IN ('remediated','false_positive')) AS open_finding_count,
		        COUNT(f.id) AS finding_count
		 FROM dspm_data_stores d
		 LEFT JOIN dspm_findings f ON f.data_store_id=d.id
		 WHERE d.tenant_id=$1 AND d.id=$2
		 GROUP BY d.id`,
		tenantID, storeID,
	).Scan(
		&ds.ID, &ds.TenantID, &ds.Name, &ds.StoreType, &ds.CloudProvider, &ds.Region, &ds.Endpoint,
		&ds.SensitivityLevel, &ds.DataCategories, &ds.IsEncrypted, &ds.IsAccessControlled,
		&ds.IsMonitored, &ds.IsBackupEnabled, &ds.Owner, &ds.OwnerID, &ds.Department,
		&ds.RiskScore, &ds.RiskLevel, &ds.LastScannedAt, &ds.ScanStatus, &ds.Tags, &ds.Notes,
		&ds.CreatedBy, &ds.CreatedAt, &ds.UpdatedAt,
		&ds.OpenFindingCount, &ds.FindingCount,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get data store: %w", err)
	}
	if ds.DataCategories == nil {
		ds.DataCategories = []string{}
	}
	if ds.Tags == nil {
		ds.Tags = []string{}
	}
	return &ds, nil
}

func (r *DSPMRepository) ListDataStores(ctx context.Context, tenantID uuid.UUID, f model.ListDataStoresFilter) ([]model.DSPMDataStore, int, error) {
	cond := []string{"d.tenant_id=$1"}
	args := []any{tenantID}
	n := 2

	if f.StoreType != "" {
		cond = append(cond, fmt.Sprintf("d.store_type=$%d", n))
		args = append(args, f.StoreType)
		n++
	}
	if f.SensitivityLevel != "" {
		cond = append(cond, fmt.Sprintf("d.sensitivity_level=$%d", n))
		args = append(args, f.SensitivityLevel)
		n++
	}
	if f.RiskLevel != "" {
		cond = append(cond, fmt.Sprintf("d.risk_level=$%d", n))
		args = append(args, f.RiskLevel)
		n++
	}
	if f.IsEncrypted != nil {
		cond = append(cond, fmt.Sprintf("d.is_encrypted=$%d", n))
		args = append(args, *f.IsEncrypted)
		n++
	}
	if f.Department != "" {
		cond = append(cond, fmt.Sprintf("d.department=$%d", n))
		args = append(args, f.Department)
		n++
	}

	where := strings.Join(cond, " AND ")
	var total int
	_ = r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM dspm_data_stores d WHERE `+where,
		args...,
	).Scan(&total)

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	args = append(args, limit, f.Offset)

	rows, err := r.db.Query(ctx,
		`SELECT d.id,d.tenant_id,d.name,d.store_type,d.cloud_provider,d.region,d.endpoint,
		        d.sensitivity_level,d.data_categories,d.is_encrypted,d.is_access_controlled,
		        d.is_monitored,d.is_backup_enabled,d.owner,d.owner_id,d.department,
		        d.risk_score,d.risk_level,d.last_scanned_at,d.scan_status,d.tags,d.notes,
		        d.created_by,d.created_at,d.updated_at,
		        COUNT(f.id) FILTER (WHERE f.status NOT IN ('remediated','false_positive')) AS open_finding_count,
		        COUNT(f.id) AS finding_count
		 FROM dspm_data_stores d
		 LEFT JOIN dspm_findings f ON f.data_store_id=d.id
		 WHERE `+where+
			fmt.Sprintf(` GROUP BY d.id ORDER BY d.risk_score DESC LIMIT $%d OFFSET $%d`, n, n+1),
		args...,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("list data stores: %w", err)
	}
	defer rows.Close()

	var stores []model.DSPMDataStore
	for rows.Next() {
		var ds model.DSPMDataStore
		if err := rows.Scan(
			&ds.ID, &ds.TenantID, &ds.Name, &ds.StoreType, &ds.CloudProvider, &ds.Region, &ds.Endpoint,
			&ds.SensitivityLevel, &ds.DataCategories, &ds.IsEncrypted, &ds.IsAccessControlled,
			&ds.IsMonitored, &ds.IsBackupEnabled, &ds.Owner, &ds.OwnerID, &ds.Department,
			&ds.RiskScore, &ds.RiskLevel, &ds.LastScannedAt, &ds.ScanStatus, &ds.Tags, &ds.Notes,
			&ds.CreatedBy, &ds.CreatedAt, &ds.UpdatedAt,
			&ds.OpenFindingCount, &ds.FindingCount,
		); err != nil {
			return nil, 0, err
		}
		if ds.DataCategories == nil {
			ds.DataCategories = []string{}
		}
		if ds.Tags == nil {
			ds.Tags = []string{}
		}
		stores = append(stores, ds)
	}
	if stores == nil {
		stores = []model.DSPMDataStore{}
	}
	return stores, total, nil
}

func (r *DSPMRepository) UpdateDataStore(ctx context.Context, tenantID, storeID uuid.UUID, req model.UpdateDataStoreRequest) (*model.DSPMDataStore, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{tenantID, storeID}
	n := 3

	if req.Name != nil {
		sets = append(sets, fmt.Sprintf("name=$%d", n))
		args = append(args, *req.Name)
		n++
	}
	if req.StoreType != nil {
		sets = append(sets, fmt.Sprintf("store_type=$%d", n))
		args = append(args, *req.StoreType)
		n++
	}
	if req.CloudProvider != nil {
		sets = append(sets, fmt.Sprintf("cloud_provider=$%d", n))
		args = append(args, *req.CloudProvider)
		n++
	}
	if req.Region != nil {
		sets = append(sets, fmt.Sprintf("region=$%d", n))
		args = append(args, *req.Region)
		n++
	}
	if req.Endpoint != nil {
		sets = append(sets, fmt.Sprintf("endpoint=$%d", n))
		args = append(args, *req.Endpoint)
		n++
	}
	if req.SensitivityLevel != nil {
		sets = append(sets, fmt.Sprintf("sensitivity_level=$%d", n))
		args = append(args, *req.SensitivityLevel)
		n++
	}
	if req.DataCategories != nil {
		sets = append(sets, fmt.Sprintf("data_categories=$%d", n))
		args = append(args, req.DataCategories)
		n++
	}
	if req.IsEncrypted != nil {
		sets = append(sets, fmt.Sprintf("is_encrypted=$%d", n))
		args = append(args, *req.IsEncrypted)
		n++
	}
	if req.IsAccessControlled != nil {
		sets = append(sets, fmt.Sprintf("is_access_controlled=$%d", n))
		args = append(args, *req.IsAccessControlled)
		n++
	}
	if req.IsMonitored != nil {
		sets = append(sets, fmt.Sprintf("is_monitored=$%d", n))
		args = append(args, *req.IsMonitored)
		n++
	}
	if req.IsBackupEnabled != nil {
		sets = append(sets, fmt.Sprintf("is_backup_enabled=$%d", n))
		args = append(args, *req.IsBackupEnabled)
		n++
	}
	if req.Owner != nil {
		sets = append(sets, fmt.Sprintf("owner=$%d", n))
		args = append(args, *req.Owner)
		n++
	}
	if req.OwnerID != nil {
		sets = append(sets, fmt.Sprintf("owner_id=$%d", n))
		args = append(args, *req.OwnerID)
		n++
	}
	if req.Department != nil {
		sets = append(sets, fmt.Sprintf("department=$%d", n))
		args = append(args, *req.Department)
		n++
	}
	if req.ScanStatus != nil {
		sets = append(sets, fmt.Sprintf("scan_status=$%d", n))
		args = append(args, *req.ScanStatus)
		n++
	}
	if req.Tags != nil {
		sets = append(sets, fmt.Sprintf("tags=$%d", n))
		args = append(args, req.Tags)
		n++
	}
	if req.Notes != nil {
		sets = append(sets, fmt.Sprintf("notes=$%d", n))
		args = append(args, *req.Notes)
		n++
	}

	_ = n
	var ds model.DSPMDataStore
	err := r.db.QueryRow(ctx,
		`UPDATE dspm_data_stores SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND id=$2
		 RETURNING id,tenant_id,name,store_type,cloud_provider,region,endpoint,
		           sensitivity_level,data_categories,is_encrypted,is_access_controlled,
		           is_monitored,is_backup_enabled,owner,owner_id,department,
		           risk_score,risk_level,last_scanned_at,scan_status,tags,notes,
		           created_by,created_at,updated_at`,
		args...,
	).Scan(
		&ds.ID, &ds.TenantID, &ds.Name, &ds.StoreType, &ds.CloudProvider, &ds.Region, &ds.Endpoint,
		&ds.SensitivityLevel, &ds.DataCategories, &ds.IsEncrypted, &ds.IsAccessControlled,
		&ds.IsMonitored, &ds.IsBackupEnabled, &ds.Owner, &ds.OwnerID, &ds.Department,
		&ds.RiskScore, &ds.RiskLevel, &ds.LastScannedAt, &ds.ScanStatus, &ds.Tags, &ds.Notes,
		&ds.CreatedBy, &ds.CreatedAt, &ds.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("update data store: %w", err)
	}
	if ds.DataCategories == nil {
		ds.DataCategories = []string{}
	}
	if ds.Tags == nil {
		ds.Tags = []string{}
	}
	go r.refreshStoreRisk(storeID)
	return &ds, nil
}

func (r *DSPMRepository) DeleteDataStore(ctx context.Context, tenantID, storeID uuid.UUID) error {
	var id uuid.UUID
	err := r.db.QueryRow(ctx,
		`SELECT id FROM dspm_data_stores WHERE tenant_id=$1 AND id=$2`,
		tenantID, storeID,
	).Scan(&id)
	if err == pgx.ErrNoRows {
		return fmt.Errorf("data store not found")
	}
	if err != nil {
		return fmt.Errorf("delete data store check: %w", err)
	}
	_, err = r.db.Exec(ctx,
		`DELETE FROM dspm_data_stores WHERE tenant_id=$1 AND id=$2`,
		tenantID, storeID,
	)
	return err
}

// ─── Scan Jobs ────────────────────────────────────────────────────────────────

func (r *DSPMRepository) CreateScanJob(ctx context.Context, tenantID uuid.UUID, req model.CreateScanJobRequest) (*model.DSPMScanJob, error) {
	triggeredBy := req.TriggeredBy
	if triggeredBy == "" {
		triggeredBy = "manual"
	}
	var j model.DSPMScanJob
	err := r.db.QueryRow(ctx,
		`INSERT INTO dspm_scan_jobs (tenant_id,data_store_id,scan_type,triggered_by,started_at)
		 VALUES ($1,$2,$3,$4,NOW())
		 RETURNING id,tenant_id,data_store_id,scan_type,status,findings_count,
		           sensitive_findings_count,scanned_objects,error_message,triggered_by,
		           started_at,completed_at,duration_seconds,created_at,updated_at`,
		tenantID, req.DataStoreID, req.ScanType, triggeredBy,
	).Scan(
		&j.ID, &j.TenantID, &j.DataStoreID, &j.ScanType, &j.Status,
		&j.FindingsCount, &j.SensitiveFindingsCount, &j.ScannedObjects, &j.ErrorMessage,
		&j.TriggeredBy, &j.StartedAt, &j.CompletedAt, &j.DurationSeconds,
		&j.CreatedAt, &j.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create scan job: %w", err)
	}
	// Update data store scan_status asynchronously
	go func() {
		_, _ = r.db.Exec(context.Background(),
			`UPDATE dspm_data_stores SET scan_status='pending', updated_at=NOW() WHERE id=$1`,
			req.DataStoreID,
		)
	}()
	return &j, nil
}

func (r *DSPMRepository) GetScanJob(ctx context.Context, tenantID, jobID uuid.UUID) (*model.DSPMScanJob, error) {
	var j model.DSPMScanJob
	err := r.db.QueryRow(ctx,
		`SELECT id,tenant_id,data_store_id,scan_type,status,findings_count,
		        sensitive_findings_count,scanned_objects,error_message,triggered_by,
		        started_at,completed_at,duration_seconds,created_at,updated_at
		 FROM dspm_scan_jobs WHERE tenant_id=$1 AND id=$2`,
		tenantID, jobID,
	).Scan(
		&j.ID, &j.TenantID, &j.DataStoreID, &j.ScanType, &j.Status,
		&j.FindingsCount, &j.SensitiveFindingsCount, &j.ScannedObjects, &j.ErrorMessage,
		&j.TriggeredBy, &j.StartedAt, &j.CompletedAt, &j.DurationSeconds,
		&j.CreatedAt, &j.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get scan job: %w", err)
	}
	return &j, nil
}

func (r *DSPMRepository) ListScanJobs(ctx context.Context, tenantID, storeID uuid.UUID) ([]model.DSPMScanJob, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,data_store_id,scan_type,status,findings_count,
		        sensitive_findings_count,scanned_objects,error_message,triggered_by,
		        started_at,completed_at,duration_seconds,created_at,updated_at
		 FROM dspm_scan_jobs WHERE tenant_id=$1 AND data_store_id=$2
		 ORDER BY created_at DESC LIMIT 50`,
		tenantID, storeID,
	)
	if err != nil {
		return nil, fmt.Errorf("list scan jobs: %w", err)
	}
	defer rows.Close()

	var jobs []model.DSPMScanJob
	for rows.Next() {
		var j model.DSPMScanJob
		if err := rows.Scan(
			&j.ID, &j.TenantID, &j.DataStoreID, &j.ScanType, &j.Status,
			&j.FindingsCount, &j.SensitiveFindingsCount, &j.ScannedObjects, &j.ErrorMessage,
			&j.TriggeredBy, &j.StartedAt, &j.CompletedAt, &j.DurationSeconds,
			&j.CreatedAt, &j.UpdatedAt,
		); err != nil {
			return nil, err
		}
		jobs = append(jobs, j)
	}
	if jobs == nil {
		jobs = []model.DSPMScanJob{}
	}
	return jobs, nil
}

func (r *DSPMRepository) UpdateScanJob(ctx context.Context, tenantID, jobID uuid.UUID, req model.UpdateScanJobRequest) (*model.DSPMScanJob, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{tenantID, jobID}
	n := 3

	var completedStatus bool
	var terminalScanStatus string
	if req.Status != nil {
		sets = append(sets, fmt.Sprintf("status=$%d", n))
		args = append(args, *req.Status)
		n++
		if *req.Status == "completed" {
			completedStatus = true
			terminalScanStatus = "completed"
			sets = append(sets, "completed_at=NOW()")
			sets = append(sets, "duration_seconds=EXTRACT(EPOCH FROM (NOW()-started_at))::INT")
		} else if *req.Status == "failed" {
			completedStatus = true
			terminalScanStatus = "failed"
		}
	}
	if req.FindingsCount != nil {
		sets = append(sets, fmt.Sprintf("findings_count=$%d", n))
		args = append(args, *req.FindingsCount)
		n++
	}
	if req.SensitiveFindingsCount != nil {
		sets = append(sets, fmt.Sprintf("sensitive_findings_count=$%d", n))
		args = append(args, *req.SensitiveFindingsCount)
		n++
	}
	if req.ScannedObjects != nil {
		sets = append(sets, fmt.Sprintf("scanned_objects=$%d", n))
		args = append(args, *req.ScannedObjects)
		n++
	}
	if req.ErrorMessage != nil {
		sets = append(sets, fmt.Sprintf("error_message=$%d", n))
		args = append(args, *req.ErrorMessage)
		n++
	}

	_ = n
	var j model.DSPMScanJob
	err := r.db.QueryRow(ctx,
		`UPDATE dspm_scan_jobs SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND id=$2
		 RETURNING id,tenant_id,data_store_id,scan_type,status,findings_count,
		           sensitive_findings_count,scanned_objects,error_message,triggered_by,
		           started_at,completed_at,duration_seconds,created_at,updated_at`,
		args...,
	).Scan(
		&j.ID, &j.TenantID, &j.DataStoreID, &j.ScanType, &j.Status,
		&j.FindingsCount, &j.SensitiveFindingsCount, &j.ScannedObjects, &j.ErrorMessage,
		&j.TriggeredBy, &j.StartedAt, &j.CompletedAt, &j.DurationSeconds,
		&j.CreatedAt, &j.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("update scan job: %w", err)
	}
	// On completion or failure, update the data store last_scanned_at and scan_status
	if completedStatus {
		scanStatus := terminalScanStatus
		go func() {
			_, _ = r.db.Exec(context.Background(),
				`UPDATE dspm_data_stores SET last_scanned_at=NOW(), scan_status=$1, updated_at=NOW() WHERE id=$2`,
				scanStatus, j.DataStoreID,
			)
		}()
	}
	return &j, nil
}

// ─── Findings ─────────────────────────────────────────────────────────────────

func (r *DSPMRepository) CreateFinding(ctx context.Context, tenantID uuid.UUID, req model.CreateFindingRequest) (*model.DSPMFinding, error) {
	if req.ComplianceViolations == nil {
		req.ComplianceViolations = []string{}
	}
	if req.Tags == nil {
		req.Tags = []string{}
	}
	var f model.DSPMFinding
	err := r.db.QueryRow(ctx,
		`INSERT INTO dspm_findings
		 (tenant_id,data_store_id,scan_job_id,finding_type,severity,location_path,
		  location_field,record_count,is_public_accessible,is_encrypted,title,
		  description,evidence,remediation,compliance_violations,tags)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		 RETURNING id,tenant_id,data_store_id,scan_job_id,finding_type,severity,status,
		           location_path,location_field,record_count,is_public_accessible,is_encrypted,
		           title,description,evidence,remediation,compliance_violations,
		           resolved_by,resolved_at,tags,detected_at,created_at,updated_at`,
		tenantID, req.DataStoreID, req.ScanJobID, req.FindingType, req.Severity,
		req.LocationPath, req.LocationField, req.RecordCount, req.IsPublicAccessible,
		req.IsEncrypted, req.Title, req.Description, req.Evidence, req.Remediation,
		req.ComplianceViolations, req.Tags,
	).Scan(
		&f.ID, &f.TenantID, &f.DataStoreID, &f.ScanJobID, &f.FindingType, &f.Severity, &f.Status,
		&f.LocationPath, &f.LocationField, &f.RecordCount, &f.IsPublicAccessible, &f.IsEncrypted,
		&f.Title, &f.Description, &f.Evidence, &f.Remediation, &f.ComplianceViolations,
		&f.ResolvedBy, &f.ResolvedAt, &f.Tags, &f.DetectedAt, &f.CreatedAt, &f.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create finding: %w", err)
	}
	if f.ComplianceViolations == nil {
		f.ComplianceViolations = []string{}
	}
	if f.Tags == nil {
		f.Tags = []string{}
	}
	go r.refreshStoreRisk(req.DataStoreID)
	return &f, nil
}

func (r *DSPMRepository) GetFinding(ctx context.Context, tenantID, findingID uuid.UUID) (*model.DSPMFinding, error) {
	var f model.DSPMFinding
	err := r.db.QueryRow(ctx,
		`SELECT f.id,f.tenant_id,f.data_store_id,f.scan_job_id,f.finding_type,f.severity,f.status,
		        f.location_path,f.location_field,f.record_count,f.is_public_accessible,f.is_encrypted,
		        f.title,f.description,f.evidence,f.remediation,f.compliance_violations,
		        f.resolved_by,f.resolved_at,f.tags,f.detected_at,f.created_at,f.updated_at,
		        COUNT(ri.id) AS remediation_count
		 FROM dspm_findings f
		 LEFT JOIN dspm_remediation_items ri ON ri.finding_id=f.id
		 WHERE f.tenant_id=$1 AND f.id=$2
		 GROUP BY f.id`,
		tenantID, findingID,
	).Scan(
		&f.ID, &f.TenantID, &f.DataStoreID, &f.ScanJobID, &f.FindingType, &f.Severity, &f.Status,
		&f.LocationPath, &f.LocationField, &f.RecordCount, &f.IsPublicAccessible, &f.IsEncrypted,
		&f.Title, &f.Description, &f.Evidence, &f.Remediation, &f.ComplianceViolations,
		&f.ResolvedBy, &f.ResolvedAt, &f.Tags, &f.DetectedAt, &f.CreatedAt, &f.UpdatedAt,
		&f.RemediationCount,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get finding: %w", err)
	}
	if f.ComplianceViolations == nil {
		f.ComplianceViolations = []string{}
	}
	if f.Tags == nil {
		f.Tags = []string{}
	}
	return &f, nil
}

func (r *DSPMRepository) ListFindings(ctx context.Context, tenantID uuid.UUID, filter model.ListFindingsFilter) ([]model.DSPMFinding, int, error) {
	cond := []string{"f.tenant_id=$1"}
	args := []any{tenantID}
	n := 2

	if filter.DataStoreID != nil {
		cond = append(cond, fmt.Sprintf("f.data_store_id=$%d", n))
		args = append(args, *filter.DataStoreID)
		n++
	}
	if filter.FindingType != "" {
		cond = append(cond, fmt.Sprintf("f.finding_type=$%d", n))
		args = append(args, filter.FindingType)
		n++
	}
	if filter.Severity != "" {
		cond = append(cond, fmt.Sprintf("f.severity=$%d", n))
		args = append(args, filter.Severity)
		n++
	}
	if filter.Status != "" {
		cond = append(cond, fmt.Sprintf("f.status=$%d", n))
		args = append(args, filter.Status)
		n++
	}

	where := strings.Join(cond, " AND ")
	var total int
	_ = r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM dspm_findings f WHERE `+where,
		args...,
	).Scan(&total)

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	args = append(args, limit, filter.Offset)

	rows, err := r.db.Query(ctx,
		`SELECT f.id,f.tenant_id,f.data_store_id,f.scan_job_id,f.finding_type,f.severity,f.status,
		        f.location_path,f.location_field,f.record_count,f.is_public_accessible,f.is_encrypted,
		        f.title,f.description,f.evidence,f.remediation,f.compliance_violations,
		        f.resolved_by,f.resolved_at,f.tags,f.detected_at,f.created_at,f.updated_at
		 FROM dspm_findings f
		 WHERE `+where+
			fmt.Sprintf(` ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, f.detected_at DESC LIMIT $%d OFFSET $%d`, n, n+1),
		args...,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()

	var findings []model.DSPMFinding
	for rows.Next() {
		var f model.DSPMFinding
		if err := rows.Scan(
			&f.ID, &f.TenantID, &f.DataStoreID, &f.ScanJobID, &f.FindingType, &f.Severity, &f.Status,
			&f.LocationPath, &f.LocationField, &f.RecordCount, &f.IsPublicAccessible, &f.IsEncrypted,
			&f.Title, &f.Description, &f.Evidence, &f.Remediation, &f.ComplianceViolations,
			&f.ResolvedBy, &f.ResolvedAt, &f.Tags, &f.DetectedAt, &f.CreatedAt, &f.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		if f.ComplianceViolations == nil {
			f.ComplianceViolations = []string{}
		}
		if f.Tags == nil {
			f.Tags = []string{}
		}
		findings = append(findings, f)
	}
	if findings == nil {
		findings = []model.DSPMFinding{}
	}
	return findings, total, nil
}

func (r *DSPMRepository) UpdateFinding(ctx context.Context, tenantID, findingID uuid.UUID, req model.UpdateFindingRequest) (*model.DSPMFinding, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{tenantID, findingID}
	n := 3

	var resolvedStatus bool
	if req.Status != nil {
		sets = append(sets, fmt.Sprintf("status=$%d", n))
		args = append(args, *req.Status)
		n++
		if *req.Status == "remediated" || *req.Status == "accepted_risk" {
			resolvedStatus = true
			sets = append(sets, "resolved_at=NOW()")
		}
	}
	if req.Remediation != nil {
		sets = append(sets, fmt.Sprintf("remediation=$%d", n))
		args = append(args, *req.Remediation)
		n++
	}
	if req.ResolvedBy != nil {
		sets = append(sets, fmt.Sprintf("resolved_by=$%d", n))
		args = append(args, *req.ResolvedBy)
		n++
	}

	_ = n
	_ = resolvedStatus
	var f model.DSPMFinding
	err := r.db.QueryRow(ctx,
		`UPDATE dspm_findings SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND id=$2
		 RETURNING id,tenant_id,data_store_id,scan_job_id,finding_type,severity,status,
		           location_path,location_field,record_count,is_public_accessible,is_encrypted,
		           title,description,evidence,remediation,compliance_violations,
		           resolved_by,resolved_at,tags,detected_at,created_at,updated_at`,
		args...,
	).Scan(
		&f.ID, &f.TenantID, &f.DataStoreID, &f.ScanJobID, &f.FindingType, &f.Severity, &f.Status,
		&f.LocationPath, &f.LocationField, &f.RecordCount, &f.IsPublicAccessible, &f.IsEncrypted,
		&f.Title, &f.Description, &f.Evidence, &f.Remediation, &f.ComplianceViolations,
		&f.ResolvedBy, &f.ResolvedAt, &f.Tags, &f.DetectedAt, &f.CreatedAt, &f.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("update finding: %w", err)
	}
	if f.ComplianceViolations == nil {
		f.ComplianceViolations = []string{}
	}
	if f.Tags == nil {
		f.Tags = []string{}
	}
	go r.refreshStoreRisk(f.DataStoreID)
	return &f, nil
}

// ─── Policies ─────────────────────────────────────────────────────────────────

func (r *DSPMRepository) CreatePolicy(ctx context.Context, tenantID uuid.UUID, req model.CreatePolicyRequest, createdBy *uuid.UUID) (*model.DSPMPolicy, error) {
	if req.AppliesToCategories == nil {
		req.AppliesToCategories = []string{}
	}
	if req.AppliesToTypes == nil {
		req.AppliesToTypes = []string{}
	}
	if req.ComplianceFrameworks == nil {
		req.ComplianceFrameworks = []string{}
	}
	rulesJSON, err := json.Marshal(req.Rules)
	if err != nil {
		return nil, fmt.Errorf("marshal rules: %w", err)
	}
	action := req.Action
	if action == "" {
		action = "alert"
	}

	var p model.DSPMPolicy
	var rulesRaw []byte
	err = r.db.QueryRow(ctx,
		`INSERT INTO dspm_policies
		 (tenant_id,name,description,policy_type,rules,action,
		  applies_to_categories,applies_to_types,compliance_frameworks,created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 RETURNING id,tenant_id,name,description,policy_type,rules,action,is_active,
		           applies_to_categories,applies_to_types,compliance_frameworks,
		           violation_count,created_by,created_at,updated_at`,
		tenantID, req.Name, req.Description, req.PolicyType, rulesJSON, action,
		req.AppliesToCategories, req.AppliesToTypes, req.ComplianceFrameworks, createdBy,
	).Scan(
		&p.ID, &p.TenantID, &p.Name, &p.Description, &p.PolicyType, &rulesRaw, &p.Action, &p.IsActive,
		&p.AppliesToCategories, &p.AppliesToTypes, &p.ComplianceFrameworks,
		&p.ViolationCount, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create policy: %w", err)
	}
	_ = json.Unmarshal(rulesRaw, &p.Rules)
	if p.Rules == nil {
		p.Rules = map[string]any{}
	}
	if p.AppliesToCategories == nil {
		p.AppliesToCategories = []string{}
	}
	if p.AppliesToTypes == nil {
		p.AppliesToTypes = []string{}
	}
	if p.ComplianceFrameworks == nil {
		p.ComplianceFrameworks = []string{}
	}
	return &p, nil
}

func (r *DSPMRepository) GetPolicy(ctx context.Context, tenantID, policyID uuid.UUID) (*model.DSPMPolicy, error) {
	var p model.DSPMPolicy
	var rulesRaw []byte
	err := r.db.QueryRow(ctx,
		`SELECT id,tenant_id,name,description,policy_type,rules,action,is_active,
		        applies_to_categories,applies_to_types,compliance_frameworks,
		        violation_count,created_by,created_at,updated_at
		 FROM dspm_policies WHERE tenant_id=$1 AND id=$2`,
		tenantID, policyID,
	).Scan(
		&p.ID, &p.TenantID, &p.Name, &p.Description, &p.PolicyType, &rulesRaw, &p.Action, &p.IsActive,
		&p.AppliesToCategories, &p.AppliesToTypes, &p.ComplianceFrameworks,
		&p.ViolationCount, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get policy: %w", err)
	}
	_ = json.Unmarshal(rulesRaw, &p.Rules)
	if p.Rules == nil {
		p.Rules = map[string]any{}
	}
	if p.AppliesToCategories == nil {
		p.AppliesToCategories = []string{}
	}
	if p.AppliesToTypes == nil {
		p.AppliesToTypes = []string{}
	}
	if p.ComplianceFrameworks == nil {
		p.ComplianceFrameworks = []string{}
	}
	return &p, nil
}

func (r *DSPMRepository) ListPolicies(ctx context.Context, tenantID uuid.UUID) ([]model.DSPMPolicy, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,name,description,policy_type,rules,action,is_active,
		        applies_to_categories,applies_to_types,compliance_frameworks,
		        violation_count,created_by,created_at,updated_at
		 FROM dspm_policies WHERE tenant_id=$1
		 ORDER BY policy_type, name`,
		tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	defer rows.Close()

	var policies []model.DSPMPolicy
	for rows.Next() {
		var p model.DSPMPolicy
		var rulesRaw []byte
		if err := rows.Scan(
			&p.ID, &p.TenantID, &p.Name, &p.Description, &p.PolicyType, &rulesRaw, &p.Action, &p.IsActive,
			&p.AppliesToCategories, &p.AppliesToTypes, &p.ComplianceFrameworks,
			&p.ViolationCount, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(rulesRaw, &p.Rules)
		if p.Rules == nil {
			p.Rules = map[string]any{}
		}
		if p.AppliesToCategories == nil {
			p.AppliesToCategories = []string{}
		}
		if p.AppliesToTypes == nil {
			p.AppliesToTypes = []string{}
		}
		if p.ComplianceFrameworks == nil {
			p.ComplianceFrameworks = []string{}
		}
		policies = append(policies, p)
	}
	if policies == nil {
		policies = []model.DSPMPolicy{}
	}
	return policies, nil
}

func (r *DSPMRepository) UpdatePolicy(ctx context.Context, tenantID, policyID uuid.UUID, req model.UpdatePolicyRequest) (*model.DSPMPolicy, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{tenantID, policyID}
	n := 3

	if req.Name != nil {
		sets = append(sets, fmt.Sprintf("name=$%d", n))
		args = append(args, *req.Name)
		n++
	}
	if req.Description != nil {
		sets = append(sets, fmt.Sprintf("description=$%d", n))
		args = append(args, *req.Description)
		n++
	}
	if req.Rules != nil {
		rulesJSON, _ := json.Marshal(req.Rules)
		sets = append(sets, fmt.Sprintf("rules=$%d", n))
		args = append(args, rulesJSON)
		n++
	}
	if req.Action != nil {
		sets = append(sets, fmt.Sprintf("action=$%d", n))
		args = append(args, *req.Action)
		n++
	}
	if req.IsActive != nil {
		sets = append(sets, fmt.Sprintf("is_active=$%d", n))
		args = append(args, *req.IsActive)
		n++
	}

	_ = n
	var p model.DSPMPolicy
	var rulesRaw []byte
	err := r.db.QueryRow(ctx,
		`UPDATE dspm_policies SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND id=$2
		 RETURNING id,tenant_id,name,description,policy_type,rules,action,is_active,
		           applies_to_categories,applies_to_types,compliance_frameworks,
		           violation_count,created_by,created_at,updated_at`,
		args...,
	).Scan(
		&p.ID, &p.TenantID, &p.Name, &p.Description, &p.PolicyType, &rulesRaw, &p.Action, &p.IsActive,
		&p.AppliesToCategories, &p.AppliesToTypes, &p.ComplianceFrameworks,
		&p.ViolationCount, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("update policy: %w", err)
	}
	_ = json.Unmarshal(rulesRaw, &p.Rules)
	if p.Rules == nil {
		p.Rules = map[string]any{}
	}
	if p.AppliesToCategories == nil {
		p.AppliesToCategories = []string{}
	}
	if p.AppliesToTypes == nil {
		p.AppliesToTypes = []string{}
	}
	if p.ComplianceFrameworks == nil {
		p.ComplianceFrameworks = []string{}
	}
	return &p, nil
}

func (r *DSPMRepository) DeletePolicy(ctx context.Context, tenantID, policyID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`DELETE FROM dspm_policies WHERE tenant_id=$1 AND id=$2`,
		tenantID, policyID,
	)
	return err
}

// ─── Remediation Items ────────────────────────────────────────────────────────

func (r *DSPMRepository) CreateRemediationItem(ctx context.Context, tenantID uuid.UUID, req model.CreateRemediationRequest) (*model.DSPMRemediationItem, error) {
	priority := req.Priority
	if priority == "" {
		priority = "medium"
	}
	var item model.DSPMRemediationItem
	err := r.db.QueryRow(ctx,
		`INSERT INTO dspm_remediation_items
		 (tenant_id,finding_id,priority,assignee_id,assignee_name,due_date,notes)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)
		 RETURNING id,tenant_id,finding_id,status,priority,assignee_id,assignee_name,
		           due_date,notes,resolution,created_at,updated_at`,
		tenantID, req.FindingID, priority, req.AssigneeID, req.AssigneeName, req.DueDate, req.Notes,
	).Scan(
		&item.ID, &item.TenantID, &item.FindingID, &item.Status, &item.Priority,
		&item.AssigneeID, &item.AssigneeName, &item.DueDate, &item.Notes, &item.Resolution,
		&item.CreatedAt, &item.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create remediation item: %w", err)
	}
	return &item, nil
}

func (r *DSPMRepository) GetRemediationItem(ctx context.Context, tenantID, itemID uuid.UUID) (*model.DSPMRemediationItem, error) {
	var item model.DSPMRemediationItem
	err := r.db.QueryRow(ctx,
		`SELECT id,tenant_id,finding_id,status,priority,assignee_id,assignee_name,
		        due_date,notes,resolution,created_at,updated_at
		 FROM dspm_remediation_items WHERE tenant_id=$1 AND id=$2`,
		tenantID, itemID,
	).Scan(
		&item.ID, &item.TenantID, &item.FindingID, &item.Status, &item.Priority,
		&item.AssigneeID, &item.AssigneeName, &item.DueDate, &item.Notes, &item.Resolution,
		&item.CreatedAt, &item.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get remediation item: %w", err)
	}
	return &item, nil
}

func (r *DSPMRepository) ListRemediationItems(ctx context.Context, tenantID, findingID uuid.UUID) ([]model.DSPMRemediationItem, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,finding_id,status,priority,assignee_id,assignee_name,
		        due_date,notes,resolution,created_at,updated_at
		 FROM dspm_remediation_items WHERE tenant_id=$1 AND finding_id=$2
		 ORDER BY CASE priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, created_at`,
		tenantID, findingID,
	)
	if err != nil {
		return nil, fmt.Errorf("list remediation items: %w", err)
	}
	defer rows.Close()

	var items []model.DSPMRemediationItem
	for rows.Next() {
		var item model.DSPMRemediationItem
		if err := rows.Scan(
			&item.ID, &item.TenantID, &item.FindingID, &item.Status, &item.Priority,
			&item.AssigneeID, &item.AssigneeName, &item.DueDate, &item.Notes, &item.Resolution,
			&item.CreatedAt, &item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if items == nil {
		items = []model.DSPMRemediationItem{}
	}
	return items, nil
}

func (r *DSPMRepository) UpdateRemediationItem(ctx context.Context, tenantID, itemID uuid.UUID, req model.UpdateRemediationRequest) (*model.DSPMRemediationItem, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{tenantID, itemID}
	n := 3

	if req.Status != nil {
		sets = append(sets, fmt.Sprintf("status=$%d", n))
		args = append(args, *req.Status)
		n++
	}
	if req.AssigneeID != nil {
		sets = append(sets, fmt.Sprintf("assignee_id=$%d", n))
		args = append(args, *req.AssigneeID)
		n++
	}
	if req.AssigneeName != nil {
		sets = append(sets, fmt.Sprintf("assignee_name=$%d", n))
		args = append(args, *req.AssigneeName)
		n++
	}
	if req.DueDate != nil {
		sets = append(sets, fmt.Sprintf("due_date=$%d", n))
		args = append(args, *req.DueDate)
		n++
	}
	if req.Notes != nil {
		sets = append(sets, fmt.Sprintf("notes=$%d", n))
		args = append(args, *req.Notes)
		n++
	}
	if req.Resolution != nil {
		sets = append(sets, fmt.Sprintf("resolution=$%d", n))
		args = append(args, *req.Resolution)
		n++
	}

	_ = n
	var item model.DSPMRemediationItem
	err := r.db.QueryRow(ctx,
		`UPDATE dspm_remediation_items SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND id=$2
		 RETURNING id,tenant_id,finding_id,status,priority,assignee_id,assignee_name,
		           due_date,notes,resolution,created_at,updated_at`,
		args...,
	).Scan(
		&item.ID, &item.TenantID, &item.FindingID, &item.Status, &item.Priority,
		&item.AssigneeID, &item.AssigneeName, &item.DueDate, &item.Notes, &item.Resolution,
		&item.CreatedAt, &item.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("update remediation item: %w", err)
	}
	return &item, nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (r *DSPMRepository) GetStats(ctx context.Context, tenantID uuid.UUID) (*model.DSPMStats, error) {
	stats := &model.DSPMStats{
		StoresByType:       map[string]int{},
		StoresByRisk:       map[string]int{},
		FindingsByType:     map[string]int{},
		FindingsBySeverity: map[string]int{},
		TopRiskyStores:     []model.DSPMDataStore{},
		RecentFindings:     []model.DSPMFinding{},
	}

	// Main aggregate query
	err := r.db.QueryRow(ctx,
		`SELECT
		    COUNT(DISTINCT ds.id) AS total_data_stores,
		    COUNT(DISTINCT ds.id) FILTER (WHERE ds.is_encrypted=FALSE) AS unencrypted_stores,
		    (SELECT COUNT(*) FROM dspm_findings WHERE tenant_id=$1 AND is_public_accessible=TRUE AND status NOT IN ('remediated','false_positive')) AS publicly_accessible,
		    COUNT(DISTINCT ds.id) FILTER (WHERE ds.risk_level IN ('critical','high')) AS high_risk_stores,
		    (SELECT COUNT(*) FROM dspm_findings WHERE tenant_id=$1) AS total_findings,
		    (SELECT COUNT(*) FROM dspm_findings WHERE tenant_id=$1 AND status='open') AS open_findings,
		    (SELECT COUNT(*) FROM dspm_findings WHERE tenant_id=$1 AND severity='critical' AND status NOT IN ('remediated','false_positive')) AS critical_findings,
		    (SELECT COUNT(*) FROM dspm_findings WHERE tenant_id=$1 AND finding_type='pii' AND status NOT IN ('remediated','false_positive')) AS pii_exposures,
		    (SELECT COUNT(*) FROM dspm_findings WHERE tenant_id=$1 AND finding_type='pci_data' AND status NOT IN ('remediated','false_positive')) AS pci_exposures,
		    (SELECT COUNT(*) FROM dspm_scan_jobs WHERE tenant_id=$1) AS total_scans,
		    (SELECT COUNT(*) FROM dspm_scan_jobs WHERE tenant_id=$1 AND status IN ('pending','running')) AS active_scans,
		    (SELECT COUNT(*) FROM dspm_remediation_items WHERE tenant_id=$1 AND status IN ('open','in_progress')) AS open_remediations,
		    (SELECT COUNT(*) FROM dspm_remediation_items WHERE tenant_id=$1 AND status IN ('open','in_progress') AND due_date < NOW()) AS overdue_remediations
		 FROM dspm_data_stores ds WHERE ds.tenant_id=$1`,
		tenantID,
	).Scan(
		&stats.TotalDataStores, &stats.UnencryptedStores, &stats.PubliclyAccessible,
		&stats.HighRiskStores, &stats.TotalFindings, &stats.OpenFindings,
		&stats.CriticalFindings, &stats.PIIExposures, &stats.PCIExposures,
		&stats.TotalScans, &stats.ActiveScans, &stats.OpenRemediations, &stats.OverdueRemediations,
	)
	if err != nil && err != pgx.ErrNoRows {
		return nil, fmt.Errorf("get stats main: %w", err)
	}

	// StoresByType
	rows, err := r.db.Query(ctx,
		`SELECT store_type, COUNT(*) FROM dspm_data_stores WHERE tenant_id=$1 GROUP BY store_type`,
		tenantID,
	)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var k string
			var v int
			if err := rows.Scan(&k, &v); err == nil {
				stats.StoresByType[k] = v
			}
		}
	}

	// StoresByRisk
	rows2, err := r.db.Query(ctx,
		`SELECT risk_level, COUNT(*) FROM dspm_data_stores WHERE tenant_id=$1 GROUP BY risk_level`,
		tenantID,
	)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var k string
			var v int
			if err := rows2.Scan(&k, &v); err == nil {
				stats.StoresByRisk[k] = v
			}
		}
	}

	// FindingsByType
	rows3, err := r.db.Query(ctx,
		`SELECT finding_type, COUNT(*) FROM dspm_findings
		 WHERE tenant_id=$1 AND status NOT IN ('remediated','false_positive')
		 GROUP BY finding_type`,
		tenantID,
	)
	if err == nil {
		defer rows3.Close()
		for rows3.Next() {
			var k string
			var v int
			if err := rows3.Scan(&k, &v); err == nil {
				stats.FindingsByType[k] = v
			}
		}
	}

	// FindingsBySeverity
	rows4, err := r.db.Query(ctx,
		`SELECT severity, COUNT(*) FROM dspm_findings
		 WHERE tenant_id=$1 AND status='open'
		 GROUP BY severity`,
		tenantID,
	)
	if err == nil {
		defer rows4.Close()
		for rows4.Next() {
			var k string
			var v int
			if err := rows4.Scan(&k, &v); err == nil {
				stats.FindingsBySeverity[k] = v
			}
		}
	}

	// TopRiskyStores
	rows5, err := r.db.Query(ctx,
		`SELECT id,tenant_id,name,store_type,cloud_provider,region,endpoint,
		        sensitivity_level,data_categories,is_encrypted,is_access_controlled,
		        is_monitored,is_backup_enabled,owner,owner_id,department,
		        risk_score,risk_level,last_scanned_at,scan_status,tags,notes,
		        created_by,created_at,updated_at
		 FROM dspm_data_stores WHERE tenant_id=$1
		 ORDER BY risk_score DESC LIMIT 5`,
		tenantID,
	)
	if err == nil {
		defer rows5.Close()
		for rows5.Next() {
			var ds model.DSPMDataStore
			if err := rows5.Scan(
				&ds.ID, &ds.TenantID, &ds.Name, &ds.StoreType, &ds.CloudProvider, &ds.Region, &ds.Endpoint,
				&ds.SensitivityLevel, &ds.DataCategories, &ds.IsEncrypted, &ds.IsAccessControlled,
				&ds.IsMonitored, &ds.IsBackupEnabled, &ds.Owner, &ds.OwnerID, &ds.Department,
				&ds.RiskScore, &ds.RiskLevel, &ds.LastScannedAt, &ds.ScanStatus, &ds.Tags, &ds.Notes,
				&ds.CreatedBy, &ds.CreatedAt, &ds.UpdatedAt,
			); err == nil {
				if ds.DataCategories == nil {
					ds.DataCategories = []string{}
				}
				if ds.Tags == nil {
					ds.Tags = []string{}
				}
				stats.TopRiskyStores = append(stats.TopRiskyStores, ds)
			}
		}
	}
	if stats.TopRiskyStores == nil {
		stats.TopRiskyStores = []model.DSPMDataStore{}
	}

	// RecentFindings
	rows6, err := r.db.Query(ctx,
		`SELECT id,tenant_id,data_store_id,scan_job_id,finding_type,severity,status,
		        location_path,location_field,record_count,is_public_accessible,is_encrypted,
		        title,description,evidence,remediation,compliance_violations,
		        resolved_by,resolved_at,tags,detected_at,created_at,updated_at
		 FROM dspm_findings WHERE tenant_id=$1
		 ORDER BY detected_at DESC LIMIT 10`,
		tenantID,
	)
	if err == nil {
		defer rows6.Close()
		for rows6.Next() {
			var f model.DSPMFinding
			if err := rows6.Scan(
				&f.ID, &f.TenantID, &f.DataStoreID, &f.ScanJobID, &f.FindingType, &f.Severity, &f.Status,
				&f.LocationPath, &f.LocationField, &f.RecordCount, &f.IsPublicAccessible, &f.IsEncrypted,
				&f.Title, &f.Description, &f.Evidence, &f.Remediation, &f.ComplianceViolations,
				&f.ResolvedBy, &f.ResolvedAt, &f.Tags, &f.DetectedAt, &f.CreatedAt, &f.UpdatedAt,
			); err == nil {
				if f.ComplianceViolations == nil {
					f.ComplianceViolations = []string{}
				}
				if f.Tags == nil {
					f.Tags = []string{}
				}
				stats.RecentFindings = append(stats.RecentFindings, f)
			}
		}
	}
	if stats.RecentFindings == nil {
		stats.RecentFindings = []model.DSPMFinding{}
	}

	return stats, nil
}
