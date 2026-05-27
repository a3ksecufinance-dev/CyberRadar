package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cyberradar/platform/services/mobile/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type MobileRepository struct {
	db *pgxpool.Pool
}

func NewMobileRepository(pool *pgxpool.Pool) *MobileRepository {
	return &MobileRepository{db: pool}
}

// ─── Risk helpers ─────────────────────────────────────────────────────────────

func deviceRiskScore(isJailbroken, isRooted, isEncrypted, isScreenLock bool, complianceIssues int, threatCount int) int {
	score := 0
	if isJailbroken {
		score += 40
	}
	if isRooted {
		score += 40
	}
	if !isEncrypted {
		score += 20
	}
	if !isScreenLock {
		score += 15
	}
	score += complianceIssues * 5
	score += threatCount * 8
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

// ─── Devices ──────────────────────────────────────────────────────────────────

func (r *MobileRepository) CreateDevice(ctx context.Context, tenantID uuid.UUID, req model.CreateDeviceRequest) (*model.MobDevice, error) {
	ownership := req.Ownership
	if ownership == "" {
		ownership = "corporate"
	}
	tags := req.Tags
	if tags == nil {
		tags = []string{}
	}
	riskScore := deviceRiskScore(false, false, req.IsEncrypted, req.IsScreenLock, 0, 0)
	riskLevel := riskLevelFromScore(riskScore)

	var d model.MobDevice
	err := r.db.QueryRow(ctx,
		`INSERT INTO mob_devices
		 (tenant_id,device_name,device_type,platform,os_version,model,manufacturer,
		  serial_number,imei,udid,ownership,owner_name,owner_id,owner_email,department,
		  is_encrypted,is_screen_lock,risk_score,risk_level,carrier,tags)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
		 RETURNING id,tenant_id,device_name,device_type,platform,os_version,model,manufacturer,
		           serial_number,imei,udid,enrollment_status,enrollment_date,mdm_profile_installed,
		           ownership,owner_name,owner_id,owner_email,department,
		           is_jailbroken,is_rooted,is_encrypted,is_screen_lock,is_compliant,
		           compliance_issues,risk_score,risk_level,last_location,last_seen_at,
		           last_checkin_at,last_ip,carrier,tags,notes,created_by,created_at,updated_at`,
		tenantID, req.DeviceName, req.DeviceType, req.Platform, req.OSVersion,
		req.Model, req.Manufacturer, req.SerialNumber, req.IMEI, req.UDID,
		ownership, req.OwnerName, req.OwnerID, req.OwnerEmail, req.Department,
		req.IsEncrypted, req.IsScreenLock, riskScore, riskLevel,
		req.Carrier, tags,
	).Scan(&d.ID, &d.TenantID, &d.DeviceName, &d.DeviceType, &d.Platform,
		&d.OSVersion, &d.Model, &d.Manufacturer, &d.SerialNumber, &d.IMEI, &d.UDID,
		&d.EnrollmentStatus, &d.EnrollmentDate, &d.MDMProfileInstalled,
		&d.Ownership, &d.OwnerName, &d.OwnerID, &d.OwnerEmail, &d.Department,
		&d.IsJailbroken, &d.IsRooted, &d.IsEncrypted, &d.IsScreenLock, &d.IsCompliant,
		&d.ComplianceIssues, &d.RiskScore, &d.RiskLevel, &d.LastLocation,
		&d.LastSeenAt, &d.LastCheckinAt, &d.LastIP, &d.Carrier,
		&d.Tags, &d.Notes, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt)
	return &d, err
}

func (r *MobileRepository) GetDevice(ctx context.Context, tenantID, id uuid.UUID) (*model.MobDevice, error) {
	var d model.MobDevice
	err := r.db.QueryRow(ctx,
		`SELECT d.id,d.tenant_id,d.device_name,d.device_type,d.platform,d.os_version,d.model,d.manufacturer,
		        d.serial_number,d.imei,d.udid,d.enrollment_status,d.enrollment_date,d.mdm_profile_installed,
		        d.ownership,d.owner_name,d.owner_id,d.owner_email,d.department,
		        d.is_jailbroken,d.is_rooted,d.is_encrypted,d.is_screen_lock,d.is_compliant,
		        d.compliance_issues,d.risk_score,d.risk_level,d.last_location,d.last_seen_at,
		        d.last_checkin_at,d.last_ip,d.carrier,d.tags,d.notes,d.created_by,d.created_at,d.updated_at,
		        COUNT(DISTINCT da.app_id) FILTER (WHERE da.is_active) AS app_count,
		        COUNT(DISTINCT t.id) FILTER (WHERE t.status NOT IN ('resolved','false_positive')) AS threat_count
		 FROM mob_devices d
		 LEFT JOIN mob_device_apps da ON da.device_id=d.id
		 LEFT JOIN mob_threats t ON t.device_id=d.id
		 WHERE d.tenant_id=$1 AND d.id=$2
		 GROUP BY d.id`,
		tenantID, id,
	).Scan(&d.ID, &d.TenantID, &d.DeviceName, &d.DeviceType, &d.Platform,
		&d.OSVersion, &d.Model, &d.Manufacturer, &d.SerialNumber, &d.IMEI, &d.UDID,
		&d.EnrollmentStatus, &d.EnrollmentDate, &d.MDMProfileInstalled,
		&d.Ownership, &d.OwnerName, &d.OwnerID, &d.OwnerEmail, &d.Department,
		&d.IsJailbroken, &d.IsRooted, &d.IsEncrypted, &d.IsScreenLock, &d.IsCompliant,
		&d.ComplianceIssues, &d.RiskScore, &d.RiskLevel, &d.LastLocation,
		&d.LastSeenAt, &d.LastCheckinAt, &d.LastIP, &d.Carrier,
		&d.Tags, &d.Notes, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt,
		&d.AppCount, &d.ThreatCount)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &d, err
}

func (r *MobileRepository) ListDevices(ctx context.Context, tenantID uuid.UUID, f model.ListDevicesFilter) ([]model.MobDevice, int, error) {
	cond := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if f.Platform != "" {
		cond = append(cond, fmt.Sprintf("platform=$%d", n)); args = append(args, f.Platform); n++
	}
	if f.EnrollmentStatus != "" {
		cond = append(cond, fmt.Sprintf("enrollment_status=$%d", n)); args = append(args, f.EnrollmentStatus); n++
	}
	if f.Ownership != "" {
		cond = append(cond, fmt.Sprintf("ownership=$%d", n)); args = append(args, f.Ownership); n++
	}
	if f.RiskLevel != "" {
		cond = append(cond, fmt.Sprintf("risk_level=$%d", n)); args = append(args, f.RiskLevel); n++
	}
	if f.IsCompliant != nil {
		cond = append(cond, fmt.Sprintf("is_compliant=$%d", n)); args = append(args, *f.IsCompliant); n++
	}
	if f.Department != "" {
		cond = append(cond, fmt.Sprintf("department=$%d", n)); args = append(args, f.Department); n++
	}
	where := strings.Join(cond, " AND ")
	var total int
	_ = r.db.QueryRow(ctx, `SELECT COUNT(*) FROM mob_devices WHERE `+where, args...).Scan(&total)

	limit := f.Limit
	if limit == 0 {
		limit = 50
	}
	args = append(args, limit, f.Offset)
	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,device_name,device_type,platform,os_version,model,manufacturer,
		        serial_number,imei,udid,enrollment_status,enrollment_date,mdm_profile_installed,
		        ownership,owner_name,owner_id,owner_email,department,
		        is_jailbroken,is_rooted,is_encrypted,is_screen_lock,is_compliant,
		        compliance_issues,risk_score,risk_level,last_location,last_seen_at,
		        last_checkin_at,last_ip,carrier,tags,notes,created_by,created_at,updated_at
		 FROM mob_devices WHERE `+where+
			fmt.Sprintf(` ORDER BY risk_score DESC LIMIT $%d OFFSET $%d`, n, n+1),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var devices []model.MobDevice
	for rows.Next() {
		var d model.MobDevice
		if err := rows.Scan(&d.ID, &d.TenantID, &d.DeviceName, &d.DeviceType, &d.Platform,
			&d.OSVersion, &d.Model, &d.Manufacturer, &d.SerialNumber, &d.IMEI, &d.UDID,
			&d.EnrollmentStatus, &d.EnrollmentDate, &d.MDMProfileInstalled,
			&d.Ownership, &d.OwnerName, &d.OwnerID, &d.OwnerEmail, &d.Department,
			&d.IsJailbroken, &d.IsRooted, &d.IsEncrypted, &d.IsScreenLock, &d.IsCompliant,
			&d.ComplianceIssues, &d.RiskScore, &d.RiskLevel, &d.LastLocation,
			&d.LastSeenAt, &d.LastCheckinAt, &d.LastIP, &d.Carrier,
			&d.Tags, &d.Notes, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, 0, err
		}
		devices = append(devices, d)
	}
	return devices, total, nil
}

func (r *MobileRepository) UpdateDevice(ctx context.Context, tenantID, id uuid.UUID, req model.UpdateDeviceRequest) (*model.MobDevice, error) {
	sets := []string{"updated_at=NOW()", "last_checkin_at=NOW()"}
	args := []any{tenantID, id}
	n := 3

	if req.DeviceName != nil {
		sets = append(sets, fmt.Sprintf("device_name=$%d", n)); args = append(args, *req.DeviceName); n++
	}
	if req.OSVersion != nil {
		sets = append(sets, fmt.Sprintf("os_version=$%d", n)); args = append(args, *req.OSVersion); n++
	}
	if req.EnrollmentStatus != nil {
		sets = append(sets, fmt.Sprintf("enrollment_status=$%d", n)); args = append(args, *req.EnrollmentStatus); n++
	}
	if req.MDMProfileInstalled != nil {
		sets = append(sets, fmt.Sprintf("mdm_profile_installed=$%d", n)); args = append(args, *req.MDMProfileInstalled); n++
	}
	if req.IsJailbroken != nil {
		sets = append(sets, fmt.Sprintf("is_jailbroken=$%d", n)); args = append(args, *req.IsJailbroken); n++
	}
	if req.IsRooted != nil {
		sets = append(sets, fmt.Sprintf("is_rooted=$%d", n)); args = append(args, *req.IsRooted); n++
	}
	if req.IsEncrypted != nil {
		sets = append(sets, fmt.Sprintf("is_encrypted=$%d", n)); args = append(args, *req.IsEncrypted); n++
	}
	if req.IsScreenLock != nil {
		sets = append(sets, fmt.Sprintf("is_screen_lock=$%d", n)); args = append(args, *req.IsScreenLock); n++
	}
	if req.IsCompliant != nil {
		sets = append(sets, fmt.Sprintf("is_compliant=$%d", n)); args = append(args, *req.IsCompliant); n++
	}
	if req.ComplianceIssues != nil {
		sets = append(sets, fmt.Sprintf("compliance_issues=$%d", n)); args = append(args, req.ComplianceIssues); n++
	}
	if req.LastLocation != nil {
		sets = append(sets, fmt.Sprintf("last_location=$%d", n)); args = append(args, *req.LastLocation); n++
		sets = append(sets, fmt.Sprintf("last_seen_at=$%d", n)); args = append(args, time.Now().UTC()); n++
	}
	if req.LastIP != nil {
		sets = append(sets, fmt.Sprintf("last_ip=$%d", n)); args = append(args, *req.LastIP); n++
	}
	if req.Notes != nil {
		sets = append(sets, fmt.Sprintf("notes=$%d", n)); args = append(args, *req.Notes); n++
	}
	if req.Tags != nil {
		sets = append(sets, fmt.Sprintf("tags=$%d", n)); args = append(args, req.Tags); n++
	}

	var d model.MobDevice
	err := r.db.QueryRow(ctx,
		`UPDATE mob_devices SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND id=$2
		 RETURNING id,tenant_id,device_name,device_type,platform,os_version,model,manufacturer,
		           serial_number,imei,udid,enrollment_status,enrollment_date,mdm_profile_installed,
		           ownership,owner_name,owner_id,owner_email,department,
		           is_jailbroken,is_rooted,is_encrypted,is_screen_lock,is_compliant,
		           compliance_issues,risk_score,risk_level,last_location,last_seen_at,
		           last_checkin_at,last_ip,carrier,tags,notes,created_by,created_at,updated_at`,
		args...,
	).Scan(&d.ID, &d.TenantID, &d.DeviceName, &d.DeviceType, &d.Platform,
		&d.OSVersion, &d.Model, &d.Manufacturer, &d.SerialNumber, &d.IMEI, &d.UDID,
		&d.EnrollmentStatus, &d.EnrollmentDate, &d.MDMProfileInstalled,
		&d.Ownership, &d.OwnerName, &d.OwnerID, &d.OwnerEmail, &d.Department,
		&d.IsJailbroken, &d.IsRooted, &d.IsEncrypted, &d.IsScreenLock, &d.IsCompliant,
		&d.ComplianceIssues, &d.RiskScore, &d.RiskLevel, &d.LastLocation,
		&d.LastSeenAt, &d.LastCheckinAt, &d.LastIP, &d.Carrier,
		&d.Tags, &d.Notes, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt)
	return &d, err
}

func (r *MobileRepository) DeleteDevice(ctx context.Context, tenantID, deviceID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`DELETE FROM mob_devices WHERE tenant_id=$1 AND id=$2`, tenantID, deviceID)
	return err
}

// refreshDeviceRisk recomputes risk score after threat changes
func (r *MobileRepository) refreshDeviceRisk(ctx context.Context, tenantID, deviceID uuid.UUID) {
	var isJailbroken, isRooted, isEncrypted, isScreenLock bool
	var complianceIssues []string
	_ = r.db.QueryRow(ctx,
		`SELECT is_jailbroken,is_rooted,is_encrypted,is_screen_lock,compliance_issues
		 FROM mob_devices WHERE tenant_id=$1 AND id=$2`,
		tenantID, deviceID).Scan(&isJailbroken, &isRooted, &isEncrypted, &isScreenLock, &complianceIssues)
	var threatCount int
	_ = r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM mob_threats WHERE tenant_id=$1 AND device_id=$2 AND status NOT IN ('resolved','false_positive')`,
		tenantID, deviceID).Scan(&threatCount)
	score := deviceRiskScore(isJailbroken, isRooted, isEncrypted, isScreenLock, len(complianceIssues), threatCount)
	level := riskLevelFromScore(score)
	_, _ = r.db.Exec(ctx,
		`UPDATE mob_devices SET risk_score=$1, risk_level=$2, updated_at=NOW() WHERE tenant_id=$3 AND id=$4`,
		score, level, tenantID, deviceID)
}

// ─── Apps ─────────────────────────────────────────────────────────────────────

func (r *MobileRepository) CreateApp(ctx context.Context, tenantID uuid.UUID, req model.CreateAppRequest) (*model.MobApp, error) {
	perms := req.Permissions
	if perms == nil {
		perms = []string{}
	}
	tags := req.Tags
	if tags == nil {
		tags = []string{}
	}
	src := req.StoreSource
	if src == "" {
		src = "enterprise"
	}
	var a model.MobApp
	err := r.db.QueryRow(ctx,
		`INSERT INTO mob_apps
		 (tenant_id,app_name,bundle_id,version,platform,store_source,is_managed,permissions,developer,category,tags)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		 ON CONFLICT (tenant_id,bundle_id,version,platform) DO UPDATE
		   SET app_name=EXCLUDED.app_name, updated_at=NOW()
		 RETURNING id,tenant_id,app_name,bundle_id,version,platform,store_source,is_managed,
		           is_approved,risk_level,permissions,has_known_vulns,vuln_count,
		           is_blocklisted,blocklist_reason,developer,category,install_count,tags,created_at,updated_at`,
		tenantID, req.AppName, req.BundleID, req.Version, req.Platform,
		src, req.IsManaged, perms, req.Developer, req.Category, tags,
	).Scan(&a.ID, &a.TenantID, &a.AppName, &a.BundleID, &a.Version, &a.Platform,
		&a.StoreSource, &a.IsManaged, &a.IsApproved, &a.RiskLevel, &a.Permissions,
		&a.HasKnownVulns, &a.VulnCount, &a.IsBlocklisted, &a.BlocklistReason,
		&a.Developer, &a.Category, &a.InstallCount, &a.Tags, &a.CreatedAt, &a.UpdatedAt)
	return &a, err
}

func (r *MobileRepository) GetApp(ctx context.Context, tenantID, appID uuid.UUID) (*model.MobApp, error) {
	var a model.MobApp
	err := r.db.QueryRow(ctx,
		`SELECT id,tenant_id,app_name,bundle_id,version,platform,store_source,is_managed,
		        is_approved,risk_level,permissions,has_known_vulns,vuln_count,
		        is_blocklisted,blocklist_reason,developer,category,install_count,tags,created_at,updated_at
		 FROM mob_apps WHERE tenant_id=$1 AND id=$2`,
		tenantID, appID,
	).Scan(&a.ID, &a.TenantID, &a.AppName, &a.BundleID, &a.Version, &a.Platform,
		&a.StoreSource, &a.IsManaged, &a.IsApproved, &a.RiskLevel, &a.Permissions,
		&a.HasKnownVulns, &a.VulnCount, &a.IsBlocklisted, &a.BlocklistReason,
		&a.Developer, &a.Category, &a.InstallCount, &a.Tags, &a.CreatedAt, &a.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

func (r *MobileRepository) ListApps(ctx context.Context, tenantID uuid.UUID, f model.ListAppsFilter) ([]model.MobApp, int, error) {
	cond := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if f.Platform != "" {
		cond = append(cond, fmt.Sprintf("platform=$%d", n)); args = append(args, f.Platform); n++
	}
	if f.IsApproved != nil {
		cond = append(cond, fmt.Sprintf("is_approved=$%d", n)); args = append(args, *f.IsApproved); n++
	}
	if f.IsBlocklisted != nil {
		cond = append(cond, fmt.Sprintf("is_blocklisted=$%d", n)); args = append(args, *f.IsBlocklisted); n++
	}
	if f.HasVulns != nil {
		cond = append(cond, fmt.Sprintf("has_known_vulns=$%d", n)); args = append(args, *f.HasVulns); n++
	}
	where := strings.Join(cond, " AND ")
	var total int
	_ = r.db.QueryRow(ctx, `SELECT COUNT(*) FROM mob_apps WHERE `+where, args...).Scan(&total)

	limit := f.Limit
	if limit == 0 {
		limit = 50
	}
	args = append(args, limit, f.Offset)
	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,app_name,bundle_id,version,platform,store_source,is_managed,
		        is_approved,risk_level,permissions,has_known_vulns,vuln_count,
		        is_blocklisted,blocklist_reason,developer,category,install_count,tags,created_at,updated_at
		 FROM mob_apps WHERE `+where+
			fmt.Sprintf(` ORDER BY is_blocklisted DESC, vuln_count DESC, install_count DESC LIMIT $%d OFFSET $%d`, n, n+1),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var apps []model.MobApp
	for rows.Next() {
		var a model.MobApp
		if err := rows.Scan(&a.ID, &a.TenantID, &a.AppName, &a.BundleID, &a.Version, &a.Platform,
			&a.StoreSource, &a.IsManaged, &a.IsApproved, &a.RiskLevel, &a.Permissions,
			&a.HasKnownVulns, &a.VulnCount, &a.IsBlocklisted, &a.BlocklistReason,
			&a.Developer, &a.Category, &a.InstallCount, &a.Tags, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, 0, err
		}
		apps = append(apps, a)
	}
	return apps, total, nil
}

func (r *MobileRepository) UpdateApp(ctx context.Context, tenantID, id uuid.UUID, req model.UpdateAppRequest) (*model.MobApp, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{tenantID, id}
	n := 3

	if req.IsApproved != nil {
		sets = append(sets, fmt.Sprintf("is_approved=$%d", n)); args = append(args, *req.IsApproved); n++
	}
	if req.IsBlocklisted != nil {
		sets = append(sets, fmt.Sprintf("is_blocklisted=$%d", n)); args = append(args, *req.IsBlocklisted); n++
	}
	if req.BlocklistReason != nil {
		sets = append(sets, fmt.Sprintf("blocklist_reason=$%d", n)); args = append(args, *req.BlocklistReason); n++
	}
	if req.HasKnownVulns != nil {
		sets = append(sets, fmt.Sprintf("has_known_vulns=$%d", n)); args = append(args, *req.HasKnownVulns); n++
	}
	if req.VulnCount != nil {
		sets = append(sets, fmt.Sprintf("vuln_count=$%d", n)); args = append(args, *req.VulnCount); n++
	}
	if req.RiskLevel != nil {
		sets = append(sets, fmt.Sprintf("risk_level=$%d", n)); args = append(args, *req.RiskLevel); n++
	}
	if req.Tags != nil {
		sets = append(sets, fmt.Sprintf("tags=$%d", n)); args = append(args, req.Tags); n++
	}

	var a model.MobApp
	err := r.db.QueryRow(ctx,
		`UPDATE mob_apps SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND id=$2
		 RETURNING id,tenant_id,app_name,bundle_id,version,platform,store_source,is_managed,
		           is_approved,risk_level,permissions,has_known_vulns,vuln_count,
		           is_blocklisted,blocklist_reason,developer,category,install_count,tags,created_at,updated_at`,
		args...,
	).Scan(&a.ID, &a.TenantID, &a.AppName, &a.BundleID, &a.Version, &a.Platform,
		&a.StoreSource, &a.IsManaged, &a.IsApproved, &a.RiskLevel, &a.Permissions,
		&a.HasKnownVulns, &a.VulnCount, &a.IsBlocklisted, &a.BlocklistReason,
		&a.Developer, &a.Category, &a.InstallCount, &a.Tags, &a.CreatedAt, &a.UpdatedAt)
	return &a, err
}

// InstallApp links an app to a device and increments install_count
func (r *MobileRepository) InstallApp(ctx context.Context, tenantID, deviceID, appID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO mob_device_apps (device_id, app_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
		deviceID, appID)
	if err != nil {
		return err
	}
	_, _ = r.db.Exec(ctx,
		`UPDATE mob_apps SET install_count=install_count+1, updated_at=NOW() WHERE tenant_id=$1 AND id=$2`,
		tenantID, appID)
	return nil
}

func (r *MobileRepository) ListDeviceApps(ctx context.Context, tenantID, deviceID uuid.UUID) ([]model.MobApp, error) {
	rows, err := r.db.Query(ctx,
		`SELECT a.id,a.tenant_id,a.app_name,a.bundle_id,a.version,a.platform,a.store_source,a.is_managed,
		        a.is_approved,a.risk_level,a.permissions,a.has_known_vulns,a.vuln_count,
		        a.is_blocklisted,a.blocklist_reason,a.developer,a.category,a.install_count,a.tags,a.created_at,a.updated_at
		 FROM mob_apps a
		 JOIN mob_device_apps da ON da.app_id=a.id
		 WHERE a.tenant_id=$1 AND da.device_id=$2 AND da.is_active=true
		 ORDER BY a.app_name`,
		tenantID, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var apps []model.MobApp
	for rows.Next() {
		var a model.MobApp
		if err := rows.Scan(&a.ID, &a.TenantID, &a.AppName, &a.BundleID, &a.Version, &a.Platform,
			&a.StoreSource, &a.IsManaged, &a.IsApproved, &a.RiskLevel, &a.Permissions,
			&a.HasKnownVulns, &a.VulnCount, &a.IsBlocklisted, &a.BlocklistReason,
			&a.Developer, &a.Category, &a.InstallCount, &a.Tags, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		apps = append(apps, a)
	}
	return apps, nil
}

// ─── Policies ─────────────────────────────────────────────────────────────────

func (r *MobileRepository) CreatePolicy(ctx context.Context, tenantID uuid.UUID, req model.CreatePolicyRequest, createdBy *uuid.UUID) (*model.MobPolicy, error) {
	rules, _ := json.Marshal(req.Rules)
	platform := req.Platform
	if platform == "" {
		platform = "all"
	}
	action := req.Action
	if action == "" {
		action = "alert"
	}
	appliesTo := req.AppliesTo
	if appliesTo == "" {
		appliesTo = "all"
	}
	var p model.MobPolicy
	var rulesRaw []byte
	err := r.db.QueryRow(ctx,
		`INSERT INTO mob_policies
		 (tenant_id,name,description,policy_type,platform,rules,action,applies_to,department,created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 RETURNING id,tenant_id,name,description,policy_type,platform,rules,action,is_active,
		           applies_to,department,assigned_count,created_by,created_at,updated_at`,
		tenantID, req.Name, req.Description, req.PolicyType, platform, rules,
		action, appliesTo, req.Department, createdBy,
	).Scan(&p.ID, &p.TenantID, &p.Name, &p.Description, &p.PolicyType, &p.Platform,
		&rulesRaw, &p.Action, &p.IsActive, &p.AppliesTo, &p.Department,
		&p.AssignedCount, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(rulesRaw, &p.Rules)
	return &p, nil
}

func (r *MobileRepository) GetPolicy(ctx context.Context, tenantID, policyID uuid.UUID) (*model.MobPolicy, error) {
	var p model.MobPolicy
	var rulesRaw []byte
	err := r.db.QueryRow(ctx,
		`SELECT id,tenant_id,name,description,policy_type,platform,rules,action,is_active,
		        applies_to,department,assigned_count,created_by,created_at,updated_at
		 FROM mob_policies WHERE tenant_id=$1 AND id=$2`,
		tenantID, policyID,
	).Scan(&p.ID, &p.TenantID, &p.Name, &p.Description, &p.PolicyType, &p.Platform,
		&rulesRaw, &p.Action, &p.IsActive, &p.AppliesTo, &p.Department,
		&p.AssignedCount, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(rulesRaw, &p.Rules)
	return &p, nil
}

func (r *MobileRepository) ListPolicies(ctx context.Context, tenantID uuid.UUID) ([]model.MobPolicy, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,name,description,policy_type,platform,rules,action,is_active,
		        applies_to,department,assigned_count,created_by,created_at,updated_at
		 FROM mob_policies WHERE tenant_id=$1 ORDER BY policy_type,name`,
		tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var policies []model.MobPolicy
	for rows.Next() {
		var p model.MobPolicy
		var rulesRaw []byte
		if err := rows.Scan(&p.ID, &p.TenantID, &p.Name, &p.Description, &p.PolicyType, &p.Platform,
			&rulesRaw, &p.Action, &p.IsActive, &p.AppliesTo, &p.Department,
			&p.AssignedCount, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(rulesRaw, &p.Rules)
		policies = append(policies, p)
	}
	return policies, nil
}

func (r *MobileRepository) UpdatePolicy(ctx context.Context, tenantID, id uuid.UUID, req model.UpdatePolicyRequest) (*model.MobPolicy, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{tenantID, id}
	n := 3

	if req.Name != nil {
		sets = append(sets, fmt.Sprintf("name=$%d", n)); args = append(args, *req.Name); n++
	}
	if req.Description != nil {
		sets = append(sets, fmt.Sprintf("description=$%d", n)); args = append(args, *req.Description); n++
	}
	if req.Rules != nil {
		rules, _ := json.Marshal(req.Rules)
		sets = append(sets, fmt.Sprintf("rules=$%d", n)); args = append(args, rules); n++
	}
	if req.Action != nil {
		sets = append(sets, fmt.Sprintf("action=$%d", n)); args = append(args, *req.Action); n++
	}
	if req.IsActive != nil {
		sets = append(sets, fmt.Sprintf("is_active=$%d", n)); args = append(args, *req.IsActive); n++
	}
	if req.AppliesTo != nil {
		sets = append(sets, fmt.Sprintf("applies_to=$%d", n)); args = append(args, *req.AppliesTo); n++
	}

	var p model.MobPolicy
	var rulesRaw []byte
	err := r.db.QueryRow(ctx,
		`UPDATE mob_policies SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND id=$2
		 RETURNING id,tenant_id,name,description,policy_type,platform,rules,action,is_active,
		           applies_to,department,assigned_count,created_by,created_at,updated_at`,
		args...,
	).Scan(&p.ID, &p.TenantID, &p.Name, &p.Description, &p.PolicyType, &p.Platform,
		&rulesRaw, &p.Action, &p.IsActive, &p.AppliesTo, &p.Department,
		&p.AssignedCount, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(rulesRaw, &p.Rules)
	return &p, nil
}

func (r *MobileRepository) DeletePolicy(ctx context.Context, tenantID, policyID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`DELETE FROM mob_policies WHERE tenant_id=$1 AND id=$2`, tenantID, policyID)
	return err
}

// ─── Threats ──────────────────────────────────────────────────────────────────

func (r *MobileRepository) CreateThreat(ctx context.Context, tenantID uuid.UUID, req model.CreateThreatRequest) (*model.MobThreat, error) {
	tags := req.Tags
	if tags == nil {
		tags = []string{}
	}
	netDet, _ := json.Marshal(req.NetworkDetails)
	var t model.MobThreat
	var netRaw []byte
	err := r.db.QueryRow(ctx,
		`INSERT INTO mob_threats
		 (tenant_id,device_id,threat_type,severity,title,description,
		  threat_indicator,affected_app,network_details,detected_by,tags)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		 RETURNING id,tenant_id,device_id,threat_type,severity,status,title,description,
		           threat_indicator,affected_app,network_details,detected_by,detected_at,
		           auto_remediated,remediation,resolved_by,resolved_at,tags,created_at,updated_at`,
		tenantID, req.DeviceID, req.ThreatType, req.Severity, req.Title, req.Description,
		req.ThreatIndicator, req.AffectedApp, netDet, req.DetectedBy, tags,
	).Scan(&t.ID, &t.TenantID, &t.DeviceID, &t.ThreatType, &t.Severity, &t.Status,
		&t.Title, &t.Description, &t.ThreatIndicator, &t.AffectedApp, &netRaw,
		&t.DetectedBy, &t.DetectedAt, &t.AutoRemediated, &t.Remediation,
		&t.ResolvedBy, &t.ResolvedAt, &t.Tags, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(netRaw, &t.NetworkDetails)
	go r.refreshDeviceRisk(context.Background(), tenantID, req.DeviceID)
	return &t, nil
}

func (r *MobileRepository) GetThreat(ctx context.Context, tenantID, threatID uuid.UUID) (*model.MobThreat, error) {
	var t model.MobThreat
	var netRaw []byte
	err := r.db.QueryRow(ctx,
		`SELECT id,tenant_id,device_id,threat_type,severity,status,title,description,
		        threat_indicator,affected_app,network_details,detected_by,detected_at,
		        auto_remediated,remediation,resolved_by,resolved_at,tags,created_at,updated_at
		 FROM mob_threats WHERE tenant_id=$1 AND id=$2`,
		tenantID, threatID,
	).Scan(&t.ID, &t.TenantID, &t.DeviceID, &t.ThreatType, &t.Severity, &t.Status,
		&t.Title, &t.Description, &t.ThreatIndicator, &t.AffectedApp, &netRaw,
		&t.DetectedBy, &t.DetectedAt, &t.AutoRemediated, &t.Remediation,
		&t.ResolvedBy, &t.ResolvedAt, &t.Tags, &t.CreatedAt, &t.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(netRaw, &t.NetworkDetails)
	return &t, nil
}

func (r *MobileRepository) ListThreats(ctx context.Context, tenantID uuid.UUID, f model.ListThreatsFilter) ([]model.MobThreat, int, error) {
	cond := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if f.DeviceID != nil {
		cond = append(cond, fmt.Sprintf("device_id=$%d", n)); args = append(args, *f.DeviceID); n++
	}
	if f.ThreatType != "" {
		cond = append(cond, fmt.Sprintf("threat_type=$%d", n)); args = append(args, f.ThreatType); n++
	}
	if f.Severity != "" {
		cond = append(cond, fmt.Sprintf("severity=$%d", n)); args = append(args, f.Severity); n++
	}
	if f.Status != "" {
		cond = append(cond, fmt.Sprintf("status=$%d", n)); args = append(args, f.Status); n++
	}
	where := strings.Join(cond, " AND ")
	var total int
	_ = r.db.QueryRow(ctx, `SELECT COUNT(*) FROM mob_threats WHERE `+where, args...).Scan(&total)

	limit := f.Limit
	if limit == 0 {
		limit = 50
	}
	args = append(args, limit, f.Offset)
	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,device_id,threat_type,severity,status,title,description,
		        threat_indicator,affected_app,network_details,detected_by,detected_at,
		        auto_remediated,remediation,resolved_by,resolved_at,tags,created_at,updated_at
		 FROM mob_threats WHERE `+where+
			fmt.Sprintf(` ORDER BY detected_at DESC LIMIT $%d OFFSET $%d`, n, n+1),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var threats []model.MobThreat
	for rows.Next() {
		var t model.MobThreat
		var netRaw []byte
		if err := rows.Scan(&t.ID, &t.TenantID, &t.DeviceID, &t.ThreatType, &t.Severity, &t.Status,
			&t.Title, &t.Description, &t.ThreatIndicator, &t.AffectedApp, &netRaw,
			&t.DetectedBy, &t.DetectedAt, &t.AutoRemediated, &t.Remediation,
			&t.ResolvedBy, &t.ResolvedAt, &t.Tags, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal(netRaw, &t.NetworkDetails)
		threats = append(threats, t)
	}
	return threats, total, nil
}

func (r *MobileRepository) UpdateThreat(ctx context.Context, tenantID, id uuid.UUID, req model.UpdateThreatRequest) (*model.MobThreat, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{tenantID, id}
	n := 3

	if req.Status != nil {
		sets = append(sets, fmt.Sprintf("status=$%d", n)); args = append(args, *req.Status); n++
		if *req.Status == "resolved" || *req.Status == "false_positive" {
			sets = append(sets, fmt.Sprintf("resolved_at=COALESCE(resolved_at,$%d)", n))
			args = append(args, time.Now().UTC()); n++
		}
	}
	if req.Remediation != nil {
		sets = append(sets, fmt.Sprintf("remediation=$%d", n)); args = append(args, *req.Remediation); n++
	}
	if req.ResolvedBy != nil {
		sets = append(sets, fmt.Sprintf("resolved_by=$%d", n)); args = append(args, *req.ResolvedBy); n++
	}

	var t model.MobThreat
	var netRaw []byte
	err := r.db.QueryRow(ctx,
		`UPDATE mob_threats SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND id=$2
		 RETURNING id,tenant_id,device_id,threat_type,severity,status,title,description,
		           threat_indicator,affected_app,network_details,detected_by,detected_at,
		           auto_remediated,remediation,resolved_by,resolved_at,tags,created_at,updated_at`,
		args...,
	).Scan(&t.ID, &t.TenantID, &t.DeviceID, &t.ThreatType, &t.Severity, &t.Status,
		&t.Title, &t.Description, &t.ThreatIndicator, &t.AffectedApp, &netRaw,
		&t.DetectedBy, &t.DetectedAt, &t.AutoRemediated, &t.Remediation,
		&t.ResolvedBy, &t.ResolvedAt, &t.Tags, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(netRaw, &t.NetworkDetails)
	return &t, nil
}

// ─── Compliance ───────────────────────────────────────────────────────────────

func (r *MobileRepository) RunComplianceCheck(ctx context.Context, tenantID uuid.UUID, req model.RunComplianceRequest) (*model.MobComplianceCheck, error) {
	deviceID := req.DeviceID
	policyID := req.PolicyID

	// Fetch device state
	var isJailbroken, isRooted, isEncrypted, isScreenLock, mdmInstalled bool
	var compIssues []string
	err := r.db.QueryRow(ctx,
		`SELECT is_jailbroken,is_rooted,is_encrypted,is_screen_lock,mdm_profile_installed,compliance_issues
		 FROM mob_devices WHERE tenant_id=$1 AND id=$2`,
		tenantID, deviceID).Scan(&isJailbroken, &isRooted, &isEncrypted, &isScreenLock, &mdmInstalled, &compIssues)
	if err != nil {
		return nil, err
	}

	// Evaluate violations
	type violation struct {
		Rule        string `json:"rule"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
	}
	var violations []violation
	if isJailbroken {
		violations = append(violations, violation{"no_jailbreak", "Device is jailbroken", "critical"})
	}
	if isRooted {
		violations = append(violations, violation{"no_root", "Device is rooted", "critical"})
	}
	if !isEncrypted {
		violations = append(violations, violation{"encryption_required", "Device storage is not encrypted", "high"})
	}
	if !isScreenLock {
		violations = append(violations, violation{"screen_lock_required", "Screen lock is not enabled", "medium"})
	}
	if !mdmInstalled {
		violations = append(violations, violation{"mdm_required", "MDM profile not installed", "high"})
	}

	// Score: start 100, deduct per severity
	score := 100
	isCompliant := len(violations) == 0
	for _, v := range violations {
		switch v.Severity {
		case "critical":
			score -= 30
		case "high":
			score -= 20
		case "medium":
			score -= 10
		}
	}
	if score < 0 {
		score = 0
	}

	violationsJSON, _ := json.Marshal(violations)
	nextCheck := time.Now().UTC().Add(24 * time.Hour)

	var check model.MobComplianceCheck
	var violRaw []byte
	err = r.db.QueryRow(ctx,
		`INSERT INTO mob_compliance_checks
		 (tenant_id,device_id,policy_id,is_compliant,violations,compliance_score,next_check_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)
		 RETURNING id,tenant_id,device_id,policy_id,is_compliant,violations,compliance_score,action_taken,checked_at,next_check_at`,
		tenantID, deviceID, policyID, isCompliant, violationsJSON, score, nextCheck,
	).Scan(&check.ID, &check.TenantID, &check.DeviceID, &check.PolicyID,
		&check.IsCompliant, &violRaw, &check.ComplianceScore,
		&check.ActionTaken, &check.CheckedAt, &check.NextCheckAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(violRaw, &check.Violations)

	// Update device compliance status
	issues := make([]string, len(violations))
	for i, v := range violations {
		issues[i] = v.Rule
	}
	_, _ = r.db.Exec(ctx,
		`UPDATE mob_devices SET is_compliant=$1, compliance_issues=$2, updated_at=NOW() WHERE tenant_id=$3 AND id=$4`,
		isCompliant, issues, tenantID, deviceID)

	return &check, nil
}

func (r *MobileRepository) ListComplianceChecks(ctx context.Context, tenantID, deviceID uuid.UUID, limit int) ([]model.MobComplianceCheck, error) {
	if limit == 0 {
		limit = 20
	}
	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,device_id,policy_id,is_compliant,violations,compliance_score,action_taken,checked_at,next_check_at
		 FROM mob_compliance_checks WHERE tenant_id=$1 AND device_id=$2
		 ORDER BY checked_at DESC LIMIT $3`,
		tenantID, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var checks []model.MobComplianceCheck
	for rows.Next() {
		var c model.MobComplianceCheck
		var violRaw []byte
		if err := rows.Scan(&c.ID, &c.TenantID, &c.DeviceID, &c.PolicyID,
			&c.IsCompliant, &violRaw, &c.ComplianceScore,
			&c.ActionTaken, &c.CheckedAt, &c.NextCheckAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(violRaw, &c.Violations)
		checks = append(checks, c)
	}
	return checks, nil
}

// ─── Remote Actions ───────────────────────────────────────────────────────────

func (r *MobileRepository) CreateRemoteAction(ctx context.Context, tenantID uuid.UUID, req model.CreateRemoteActionRequest) (*model.MobRemoteAction, error) {
	payload, _ := json.Marshal(req.Payload)
	var a model.MobRemoteAction
	var payRaw []byte
	err := r.db.QueryRow(ctx,
		`INSERT INTO mob_remote_actions
		 (tenant_id,device_id,action_type,payload,message,requested_by,requested_by_id)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)
		 RETURNING id,tenant_id,device_id,action_type,status,payload,message,
		           requested_by,requested_by_id,sent_at,completed_at,failure_reason,created_at,updated_at`,
		tenantID, req.DeviceID, req.ActionType, payload, req.Message,
		req.RequestedBy, req.RequestedByID,
	).Scan(&a.ID, &a.TenantID, &a.DeviceID, &a.ActionType, &a.Status, &payRaw,
		&a.Message, &a.RequestedBy, &a.RequestedByID,
		&a.SentAt, &a.CompletedAt, &a.FailureReason, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(payRaw, &a.Payload)
	return &a, nil
}

func (r *MobileRepository) GetRemoteAction(ctx context.Context, tenantID, actionID uuid.UUID) (*model.MobRemoteAction, error) {
	var a model.MobRemoteAction
	var payRaw []byte
	err := r.db.QueryRow(ctx,
		`SELECT id,tenant_id,device_id,action_type,status,payload,message,
		        requested_by,requested_by_id,sent_at,completed_at,failure_reason,created_at,updated_at
		 FROM mob_remote_actions WHERE tenant_id=$1 AND id=$2`,
		tenantID, actionID,
	).Scan(&a.ID, &a.TenantID, &a.DeviceID, &a.ActionType, &a.Status, &payRaw,
		&a.Message, &a.RequestedBy, &a.RequestedByID,
		&a.SentAt, &a.CompletedAt, &a.FailureReason, &a.CreatedAt, &a.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(payRaw, &a.Payload)
	return &a, nil
}

func (r *MobileRepository) ListRemoteActions(ctx context.Context, tenantID, deviceID uuid.UUID) ([]model.MobRemoteAction, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,device_id,action_type,status,payload,message,
		        requested_by,requested_by_id,sent_at,completed_at,failure_reason,created_at,updated_at
		 FROM mob_remote_actions WHERE tenant_id=$1 AND device_id=$2
		 ORDER BY created_at DESC LIMIT 50`,
		tenantID, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var actions []model.MobRemoteAction
	for rows.Next() {
		var a model.MobRemoteAction
		var payRaw []byte
		if err := rows.Scan(&a.ID, &a.TenantID, &a.DeviceID, &a.ActionType, &a.Status, &payRaw,
			&a.Message, &a.RequestedBy, &a.RequestedByID,
			&a.SentAt, &a.CompletedAt, &a.FailureReason, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(payRaw, &a.Payload)
		actions = append(actions, a)
	}
	return actions, nil
}

func (r *MobileRepository) UpdateRemoteAction(ctx context.Context, tenantID, id uuid.UUID, req model.UpdateRemoteActionRequest) (*model.MobRemoteAction, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{tenantID, id}
	n := 3

	if req.Status != nil {
		sets = append(sets, fmt.Sprintf("status=$%d", n)); args = append(args, *req.Status); n++
		now := time.Now().UTC()
		switch *req.Status {
		case "sent":
			sets = append(sets, fmt.Sprintf("sent_at=COALESCE(sent_at,$%d)", n)); args = append(args, now); n++
		case "completed", "failed":
			sets = append(sets, fmt.Sprintf("completed_at=COALESCE(completed_at,$%d)", n)); args = append(args, now); n++
		}
	}
	if req.FailureReason != nil {
		sets = append(sets, fmt.Sprintf("failure_reason=$%d", n)); args = append(args, *req.FailureReason); n++
	}

	var a model.MobRemoteAction
	var payRaw []byte
	err := r.db.QueryRow(ctx,
		`UPDATE mob_remote_actions SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND id=$2
		 RETURNING id,tenant_id,device_id,action_type,status,payload,message,
		           requested_by,requested_by_id,sent_at,completed_at,failure_reason,created_at,updated_at`,
		args...,
	).Scan(&a.ID, &a.TenantID, &a.DeviceID, &a.ActionType, &a.Status, &payRaw,
		&a.Message, &a.RequestedBy, &a.RequestedByID,
		&a.SentAt, &a.CompletedAt, &a.FailureReason, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(payRaw, &a.Payload)
	return &a, nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (r *MobileRepository) GetStats(ctx context.Context, tenantID uuid.UUID) (*model.MobStats, error) {
	stats := &model.MobStats{
		DevicesByPlatform:  make(map[string]int),
		DevicesByOwnership: make(map[string]int),
		ThreatsBySeverity:  make(map[string]int),
		ThreatsByType:      make(map[string]int),
	}

	_ = r.db.QueryRow(ctx,
		`SELECT COUNT(*),
		        COUNT(*) FILTER (WHERE enrollment_status='enrolled'),
		        COUNT(*) FILTER (WHERE is_compliant=false),
		        COUNT(*) FILTER (WHERE is_jailbroken OR is_rooted),
		        COUNT(*) FILTER (WHERE risk_level IN ('critical','high'))
		 FROM mob_devices WHERE tenant_id=$1`, tenantID,
	).Scan(&stats.TotalDevices, &stats.EnrolledDevices, &stats.NonCompliantDevices,
		&stats.JailbrokenDevices, &stats.HighRiskDevices)

	_ = r.db.QueryRow(ctx,
		`SELECT COUNT(*), COUNT(*) FILTER (WHERE is_blocklisted), COUNT(*) FILTER (WHERE has_known_vulns)
		 FROM mob_apps WHERE tenant_id=$1`, tenantID,
	).Scan(&stats.TotalApps, &stats.BlocklistedApps, &stats.VulnerableApps)

	_ = r.db.QueryRow(ctx,
		`SELECT COUNT(*), COUNT(*) FILTER (WHERE severity='critical')
		 FROM mob_threats WHERE tenant_id=$1 AND status NOT IN ('resolved','false_positive')`, tenantID,
	).Scan(&stats.ActiveThreats, &stats.CriticalThreats)

	_ = r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM mob_remote_actions WHERE tenant_id=$1 AND status='pending'`, tenantID,
	).Scan(&stats.PendingActions)

	// By platform
	rows, _ := r.db.Query(ctx,
		`SELECT platform, COUNT(*) FROM mob_devices WHERE tenant_id=$1 GROUP BY platform`, tenantID)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var k string; var v int
			_ = rows.Scan(&k, &v)
			stats.DevicesByPlatform[k] = v
		}
	}

	// By ownership
	rows2, _ := r.db.Query(ctx,
		`SELECT ownership, COUNT(*) FROM mob_devices WHERE tenant_id=$1 GROUP BY ownership`, tenantID)
	if rows2 != nil {
		defer rows2.Close()
		for rows2.Next() {
			var k string; var v int
			_ = rows2.Scan(&k, &v)
			stats.DevicesByOwnership[k] = v
		}
	}

	// Threats by severity
	rows3, _ := r.db.Query(ctx,
		`SELECT severity, COUNT(*) FROM mob_threats WHERE tenant_id=$1 AND status NOT IN ('resolved','false_positive') GROUP BY severity`, tenantID)
	if rows3 != nil {
		defer rows3.Close()
		for rows3.Next() {
			var k string; var v int
			_ = rows3.Scan(&k, &v)
			stats.ThreatsBySeverity[k] = v
		}
	}

	// Threats by type
	rows4, _ := r.db.Query(ctx,
		`SELECT threat_type, COUNT(*) FROM mob_threats WHERE tenant_id=$1 AND status NOT IN ('resolved','false_positive') GROUP BY threat_type`, tenantID)
	if rows4 != nil {
		defer rows4.Close()
		for rows4.Next() {
			var k string; var v int
			_ = rows4.Scan(&k, &v)
			stats.ThreatsByType[k] = v
		}
	}

	// Top risky devices
	drows, _ := r.db.Query(ctx,
		`SELECT id,tenant_id,device_name,device_type,platform,os_version,model,manufacturer,
		        serial_number,imei,udid,enrollment_status,enrollment_date,mdm_profile_installed,
		        ownership,owner_name,owner_id,owner_email,department,
		        is_jailbroken,is_rooted,is_encrypted,is_screen_lock,is_compliant,
		        compliance_issues,risk_score,risk_level,last_location,last_seen_at,
		        last_checkin_at,last_ip,carrier,tags,notes,created_by,created_at,updated_at
		 FROM mob_devices WHERE tenant_id=$1 AND risk_level IN ('critical','high')
		 ORDER BY risk_score DESC LIMIT 5`, tenantID)
	if drows != nil {
		defer drows.Close()
		for drows.Next() {
			var d model.MobDevice
			if err := drows.Scan(&d.ID, &d.TenantID, &d.DeviceName, &d.DeviceType, &d.Platform,
				&d.OSVersion, &d.Model, &d.Manufacturer, &d.SerialNumber, &d.IMEI, &d.UDID,
				&d.EnrollmentStatus, &d.EnrollmentDate, &d.MDMProfileInstalled,
				&d.Ownership, &d.OwnerName, &d.OwnerID, &d.OwnerEmail, &d.Department,
				&d.IsJailbroken, &d.IsRooted, &d.IsEncrypted, &d.IsScreenLock, &d.IsCompliant,
				&d.ComplianceIssues, &d.RiskScore, &d.RiskLevel, &d.LastLocation,
				&d.LastSeenAt, &d.LastCheckinAt, &d.LastIP, &d.Carrier,
				&d.Tags, &d.Notes, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt); err == nil {
				stats.TopRiskyDevices = append(stats.TopRiskyDevices, d)
			}
		}
	}

	// Recent threats
	trows, _ := r.db.Query(ctx,
		`SELECT id,tenant_id,device_id,threat_type,severity,status,title,description,
		        threat_indicator,affected_app,network_details,detected_by,detected_at,
		        auto_remediated,remediation,resolved_by,resolved_at,tags,created_at,updated_at
		 FROM mob_threats WHERE tenant_id=$1 AND status NOT IN ('resolved','false_positive')
		 ORDER BY detected_at DESC LIMIT 5`, tenantID)
	if trows != nil {
		defer trows.Close()
		for trows.Next() {
			var t model.MobThreat
			var netRaw []byte
			if err := trows.Scan(&t.ID, &t.TenantID, &t.DeviceID, &t.ThreatType, &t.Severity, &t.Status,
				&t.Title, &t.Description, &t.ThreatIndicator, &t.AffectedApp, &netRaw,
				&t.DetectedBy, &t.DetectedAt, &t.AutoRemediated, &t.Remediation,
				&t.ResolvedBy, &t.ResolvedAt, &t.Tags, &t.CreatedAt, &t.UpdatedAt); err == nil {
				_ = json.Unmarshal(netRaw, &t.NetworkDetails)
				stats.RecentThreats = append(stats.RecentThreats, t)
			}
		}
	}

	return stats, nil
}
