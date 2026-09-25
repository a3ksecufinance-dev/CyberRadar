package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cyberradar/platform/services/vuln/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// VulnRepository manages vulnerabilities, findings, scans, and tickets in PostgreSQL.
type VulnRepository struct {
	db *pgxpool.Pool
}

// NewVulnRepository creates a VulnRepository.
func NewVulnRepository(db *pgxpool.Pool) *VulnRepository {
	return &VulnRepository{db: db}
}

// ─── Vulnerabilities ──────────────────────────────────────────────────────────

// UpsertVuln inserts or updates a vulnerability definition.
func (r *VulnRepository) UpsertVuln(ctx context.Context, tenantID uuid.UUID, req *model.CreateVulnRequest) (*model.Vulnerability, error) {
	id := uuid.New()
	sev := cvssToSeverity(req.CVSSScore)
	prods := req.AffectedProducts
	if prods == nil {
		prods = []string{}
	}
	refs := []string{}
	tags := req.Tags
	if tags == nil {
		tags = []string{}
	}

	v := &model.Vulnerability{
		ID: id, TenantID: tenantID, Title: req.Title,
		CVSSScore: req.CVSSScore, CVSSSeverity: sev,
	}

	if err := r.db.QueryRow(ctx, `
		INSERT INTO vulnerabilities
			(id, tenant_id, cve_id, title, description, cvss_score, cvss_vector, cvss_severity,
			 is_exploited, exploit_available, epss_score, cwe_id, cwe_name,
			 mitre_technique, affected_products, patch_available, patch_url, published_at, tags)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
		ON CONFLICT (tenant_id, cve_id) WHERE cve_id IS NOT NULL DO UPDATE SET
			cvss_score        = GREATEST(vulnerabilities.cvss_score, EXCLUDED.cvss_score),
			cvss_severity     = EXCLUDED.cvss_severity,
			is_exploited      = vulnerabilities.is_exploited OR EXCLUDED.is_exploited,
			exploit_available = vulnerabilities.exploit_available OR EXCLUDED.exploit_available,
			epss_score        = GREATEST(vulnerabilities.epss_score, EXCLUDED.epss_score),
			patch_available   = vulnerabilities.patch_available OR EXCLUDED.patch_available,
			updated_at        = NOW()
		RETURNING id, cvss_severity, created_at, updated_at`,
		id, tenantID, nvlS(req.CVEID), req.Title, nvlS(req.Description),
		req.CVSSScore, nvlS(req.CVSSVector), sev,
		req.IsExploited, req.ExploitAvailable, req.EPSSScore,
		nvlS(req.CWEID), nvlS(req.CWEName), nvlS(req.MitreTechnique),
		prods, req.PatchAvailable, nvlS(req.PatchURL), req.PublishedAt, tags,
	).Scan(&v.ID, &v.CVSSSeverity, &v.CreatedAt, &v.UpdatedAt); err != nil {
		return nil, fmt.Errorf("upsert vuln: %w", err)
	}
	v.AffectedProducts = prods
	v.References = refs
	v.Tags = tags
	return v, nil
}

// GetVuln returns a vulnerability by ID.
func (r *VulnRepository) GetVuln(ctx context.Context, tenantID, vulnID uuid.UUID) (*model.Vulnerability, error) {
	row := r.db.QueryRow(ctx, vulnSelect+` WHERE id = $1 AND tenant_id = $2`, vulnID, tenantID)
	return scanVuln(row)
}

// ListVulns returns vulnerability definitions matching the filter.
func (r *VulnRepository) ListVulns(ctx context.Context, f model.VulnFilter) ([]*model.Vulnerability, int, error) {
	where := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	n := 2

	if f.Severity != "" {
		where = append(where, fmt.Sprintf("cvss_severity = $%d", n))
		args = append(args, f.Severity)
		n++
	}
	if f.IsExploited != nil {
		where = append(where, fmt.Sprintf("is_exploited = $%d", n))
		args = append(args, *f.IsExploited)
		n++
	}
	if f.Search != "" {
		where = append(where, fmt.Sprintf("(cve_id ILIKE $%d OR title ILIKE $%d)", n, n))
		args = append(args, "%"+f.Search+"%")
		n++
	}

	wc := strings.Join(where, " AND ")
	limit := clampLimit(f.Limit, 50, 200)
	var total int
	r.db.QueryRow(ctx, fmt.Sprintf("SELECT COUNT(*) FROM vulnerabilities WHERE %s", wc), args...).Scan(&total) //nolint

	q := fmt.Sprintf(vulnSelect+` WHERE %s ORDER BY cvss_score DESC LIMIT $%d OFFSET $%d`, wc, n, n+1)
	args = append(args, limit, f.Offset)
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*model.Vulnerability
	for rows.Next() {
		v, err := scanVuln(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, v)
	}
	return out, total, nil
}

// ─── Asset Vulnerabilities (Findings) ────────────────────────────────────────

// UpsertFinding inserts or updates an asset-vulnerability finding and computes SLA.
func (r *VulnRepository) UpsertFinding(ctx context.Context, tenantID uuid.UUID, req *model.CreateFindingRequest, cvss float64, severity string) (*model.AssetVulnerability, error) {
	id := uuid.New()
	exposure := computeExposure(cvss, severity, false)
	sla := computeSLA(severity)
	evidence, _ := json.Marshal(req.Evidence)

	av := &model.AssetVulnerability{
		ID: id, TenantID: tenantID, AssetID: req.AssetID,
		VulnID: req.VulnID, ScanJobID: req.ScanJobID,
		Status: model.StatusOpen, ExposureScore: exposure,
		Port: req.Port, Protocol: req.Protocol, ServiceName: req.ServiceName,
	}
	slaTime := time.Now().UTC().Add(time.Duration(sla) * 24 * time.Hour)
	av.SLADueAt = &slaTime

	if err := r.db.QueryRow(ctx, `
		INSERT INTO asset_vulnerabilities
			(id, tenant_id, asset_id, vuln_id, scan_job_id, exposure_score,
			 port, protocol, service_name, evidence, sla_due_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (tenant_id, asset_id, vuln_id) DO UPDATE SET
			last_seen_at   = NOW(),
			scan_job_id    = COALESCE(EXCLUDED.scan_job_id, asset_vulnerabilities.scan_job_id),
			status         = CASE WHEN asset_vulnerabilities.status IN ('resolved','false_positive')
			                      THEN 'open' ELSE asset_vulnerabilities.status END,
			exposure_score = EXCLUDED.exposure_score,
			updated_at     = NOW()
		RETURNING id, status, first_seen_at, last_seen_at, sla_due_at, created_at, updated_at`,
		id, tenantID, req.AssetID, req.VulnID, req.ScanJobID,
		exposure, req.Port, nvlS(req.Protocol), nvlS(req.ServiceName), evidence, slaTime,
	).Scan(&av.ID, &av.Status, &av.FirstSeenAt, &av.LastSeenAt, &av.SLADueAt, &av.CreatedAt, &av.UpdatedAt); err != nil {
		return nil, fmt.Errorf("upsert finding: %w", err)
	}
	return av, nil
}

// ListFindings returns asset-vulnerability findings with optional join.
func (r *VulnRepository) ListFindings(ctx context.Context, f model.FindingFilter) ([]*model.AssetVulnerability, int, error) {
	where := []string{"av.tenant_id = $1"}
	args := []any{f.TenantID}
	n := 2

	if f.AssetID != nil {
		where = append(where, fmt.Sprintf("av.asset_id = $%d", n))
		args = append(args, *f.AssetID)
		n++
	}
	if f.VulnID != nil {
		where = append(where, fmt.Sprintf("av.vuln_id = $%d", n))
		args = append(args, *f.VulnID)
		n++
	}
	if f.Status != "" {
		where = append(where, fmt.Sprintf("av.status = $%d", n))
		args = append(args, f.Status)
		n++
	}
	if f.Severity != "" {
		where = append(where, fmt.Sprintf("v.cvss_severity = $%d", n))
		args = append(args, f.Severity)
		n++
	}
	if f.ScanID != nil {
		where = append(where, fmt.Sprintf("av.scan_job_id = $%d", n))
		args = append(args, *f.ScanID)
		n++
	}

	wc := strings.Join(where, " AND ")
	limit := clampLimit(f.Limit, 50, 500)

	var total int
	r.db.QueryRow(ctx, fmt.Sprintf(`
		SELECT COUNT(*) FROM asset_vulnerabilities av
		JOIN vulnerabilities v ON v.id = av.vuln_id WHERE %s`, wc), args...).Scan(&total) //nolint

	q := fmt.Sprintf(`
		SELECT av.id, av.tenant_id, av.asset_id, av.vuln_id, av.scan_job_id, av.status,
		       av.exposure_score, av.port, av.protocol, av.service_name,
		       av.first_seen_at, av.last_seen_at, av.resolved_at, av.sla_due_at,
		       av.remediation_ticket_id, av.assignee_id, av.notes, av.evidence,
		       av.created_at, av.updated_at,
		       v.id, v.cve_id, v.title, v.cvss_score, v.cvss_severity,
		       v.is_exploited, v.exploit_available, v.patch_available
		FROM asset_vulnerabilities av
		JOIN vulnerabilities v ON v.id = av.vuln_id
		WHERE %s
		ORDER BY av.exposure_score DESC, av.first_seen_at DESC
		LIMIT $%d OFFSET $%d`, wc, n, n+1)
	args = append(args, limit, f.Offset)

	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []*model.AssetVulnerability
	for rows.Next() {
		av := &model.AssetVulnerability{}
		vuln := &model.Vulnerability{}
		var (
			protocol, svcName, notes *string
			evRaw                    []byte
		)
		if err := rows.Scan(
			&av.ID, &av.TenantID, &av.AssetID, &av.VulnID, &av.ScanJobID, &av.Status,
			&av.ExposureScore, &av.Port, &protocol, &svcName,
			&av.FirstSeenAt, &av.LastSeenAt, &av.ResolvedAt, &av.SLADueAt,
			&av.RemediationTicketID, &av.AssigneeID, &notes, &evRaw,
			&av.CreatedAt, &av.UpdatedAt,
			&vuln.ID, &vuln.CVEID, &vuln.Title, &vuln.CVSSScore, &vuln.CVSSSeverity,
			&vuln.IsExploited, &vuln.ExploitAvailable, &vuln.PatchAvailable,
		); err != nil {
			return nil, 0, err
		}
		if protocol != nil {
			av.Protocol = *protocol
		}
		if svcName != nil {
			av.ServiceName = *svcName
		}
		if notes != nil {
			av.Notes = *notes
		}
		_ = json.Unmarshal(evRaw, &av.Evidence)
		av.Vulnerability = vuln
		out = append(out, av)
	}
	return out, total, nil
}

// UpdateFinding applies a partial update to a finding.
func (r *VulnRepository) UpdateFinding(ctx context.Context, tenantID, findingID uuid.UUID, req *model.UpdateFindingRequest) (*model.AssetVulnerability, error) {
	sets := []string{}
	args := []any{}
	n := 1
	set := func(col string, val any) {
		sets = append(sets, fmt.Sprintf("%s = $%d", col, n))
		args = append(args, val)
		n++
	}
	if req.Status != nil {
		set("status", *req.Status)
		if *req.Status == model.StatusResolved || *req.Status == model.StatusFalsePositive {
			set("resolved_at", time.Now().UTC())
		}
	}
	if req.AssigneeID != nil {
		set("assignee_id", *req.AssigneeID)
	}
	if req.RemediationTicketID != nil {
		set("remediation_ticket_id", *req.RemediationTicketID)
	}
	if req.Notes != nil {
		set("notes", *req.Notes)
	}
	if len(sets) == 0 {
		return r.getFinding(ctx, tenantID, findingID)
	}
	set("updated_at", time.Now().UTC())
	q := fmt.Sprintf(`UPDATE asset_vulnerabilities SET %s WHERE id = $%d AND tenant_id = $%d`,
		strings.Join(sets, ", "), n, n+1)
	args = append(args, findingID, tenantID)
	if _, err := r.db.Exec(ctx, q, args...); err != nil {
		return nil, fmt.Errorf("update finding: %w", err)
	}
	return r.getFinding(ctx, tenantID, findingID)
}

func (r *VulnRepository) getFinding(ctx context.Context, tenantID, findingID uuid.UUID) (*model.AssetVulnerability, error) {
	row := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, asset_id, vuln_id, scan_job_id, status, exposure_score,
		       port, protocol, service_name, first_seen_at, last_seen_at, resolved_at, sla_due_at,
		       remediation_ticket_id, assignee_id, notes, evidence, created_at, updated_at
		FROM asset_vulnerabilities WHERE id = $1 AND tenant_id = $2`, findingID, tenantID)
	av := &model.AssetVulnerability{}
	var protocol, svcName, notes *string
	var evRaw []byte
	err := row.Scan(
		&av.ID, &av.TenantID, &av.AssetID, &av.VulnID, &av.ScanJobID, &av.Status,
		&av.ExposureScore, &av.Port, &protocol, &svcName,
		&av.FirstSeenAt, &av.LastSeenAt, &av.ResolvedAt, &av.SLADueAt,
		&av.RemediationTicketID, &av.AssigneeID, &notes, &evRaw,
		&av.CreatedAt, &av.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if protocol != nil {
		av.Protocol = *protocol
	}
	if svcName != nil {
		av.ServiceName = *svcName
	}
	if notes != nil {
		av.Notes = *notes
	}
	_ = json.Unmarshal(evRaw, &av.Evidence)
	return av, nil
}

// AssetExposure computes the aggregate exposure score for one asset.
func (r *VulnRepository) AssetExposure(ctx context.Context, tenantID, assetID uuid.UUID) (*model.ExposureScore, error) {
	es := &model.ExposureScore{AssetID: assetID}
	r.db.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE av.status IN ('open','in_remediation')),
			COUNT(*) FILTER (WHERE v.cvss_severity='CRITICAL' AND av.status IN ('open','in_remediation')),
			COUNT(*) FILTER (WHERE v.cvss_severity='HIGH'     AND av.status IN ('open','in_remediation')),
			COUNT(*) FILTER (WHERE v.cvss_severity='MEDIUM'   AND av.status IN ('open','in_remediation')),
			COUNT(*) FILTER (WHERE v.cvss_severity='LOW'      AND av.status IN ('open','in_remediation')),
			COALESCE(AVG(v.cvss_score) FILTER (WHERE av.status IN ('open','in_remediation')), 0),
			COALESCE(MAX(v.cvss_score) FILTER (WHERE av.status IN ('open','in_remediation')), 0),
			COALESCE(AVG(av.exposure_score) FILTER (WHERE av.status IN ('open','in_remediation')), 0),
			COUNT(*) FILTER (WHERE av.sla_due_at < NOW() AND av.status IN ('open','in_remediation')),
			BOOL_OR(v.is_exploited AND av.status IN ('open','in_remediation'))
		FROM asset_vulnerabilities av
		JOIN vulnerabilities v ON v.id = av.vuln_id
		WHERE av.tenant_id = $1 AND av.asset_id = $2`,
		tenantID, assetID,
	).Scan(
		&es.TotalFindings, &es.OpenFindings,
		&es.CriticalCount, &es.HighCount, &es.MediumCount, &es.LowCount,
		&es.AvgCVSS, &es.MaxCVSS, &es.ExposureScore,
		&es.SLABreached, &es.HasKEV,
	) //nolint
	return es, nil
}

// ─── Scan Jobs ────────────────────────────────────────────────────────────────

func (r *VulnRepository) CreateScanJob(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreateScanJobRequest) (*model.ScanJob, error) {
	id := uuid.New()
	targets, _ := json.Marshal(req.Targets)
	job := &model.ScanJob{
		ID: id, TenantID: tenantID, Name: req.Name,
		ScanType: req.ScanType, Status: "pending",
		TriggeredBy: callerID, ScheduledAt: req.ScheduledAt,
	}
	if req.Targets == nil {
		job.Targets = map[string]any{}
	} else {
		job.Targets = req.Targets
	}
	if err := r.db.QueryRow(ctx, `
		INSERT INTO vuln_scan_jobs (id, tenant_id, name, scan_type, targets, triggered_by, scheduled_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING created_at, updated_at`,
		id, tenantID, req.Name, req.ScanType, targets, callerID, req.ScheduledAt,
	).Scan(&job.CreatedAt, &job.UpdatedAt); err != nil {
		return nil, fmt.Errorf("create scan job: %w", err)
	}
	return job, nil
}

func (r *VulnRepository) ListScanJobs(ctx context.Context, tenantID uuid.UUID, status string, limit int) ([]*model.ScanJob, error) {
	where := "tenant_id = $1"
	args := []any{tenantID}
	if status != "" {
		where += " AND status = $2"
		args = append(args, status)
	}
	rows, err := r.db.Query(ctx, fmt.Sprintf(`
		SELECT id, tenant_id, name, scan_type, targets, status, triggered_by,
		       scheduled_at, started_at, completed_at,
		       total_assets, scanned_assets, total_findings, new_findings, resolved_findings,
		       critical_count, high_count, medium_count, low_count, error_message,
		       created_at, updated_at
		FROM vuln_scan_jobs WHERE %s ORDER BY created_at DESC LIMIT $%d`, where, len(args)+1),
		append(args, clampLimit(limit, 20, 100))...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.ScanJob
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, job)
	}
	return out, nil
}

func (r *VulnRepository) UpdateScanJobStatus(ctx context.Context, jobID uuid.UUID, status string, summary *model.ScanJob) error {
	if summary == nil {
		_, err := r.db.Exec(ctx,
			`UPDATE vuln_scan_jobs SET status=$1, updated_at=NOW() WHERE id=$2`, status, jobID)
		return err
	}
	_, err := r.db.Exec(ctx, `
		UPDATE vuln_scan_jobs SET
			status=$1, completed_at=$2,
			total_assets=$3, scanned_assets=$4,
			total_findings=$5, new_findings=$6, resolved_findings=$7,
			critical_count=$8, high_count=$9, medium_count=$10, low_count=$11,
			updated_at=NOW()
		WHERE id=$12`,
		status, summary.CompletedAt,
		summary.TotalAssets, summary.ScannedAssets,
		summary.TotalFindings, summary.NewFindings, summary.ResolvedFindings,
		summary.CriticalCount, summary.HighCount, summary.MediumCount, summary.LowCount,
		jobID,
	)
	return err
}

// ─── Remediation Tickets ──────────────────────────────────────────────────────

func (r *VulnRepository) CreateTicket(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreateTicketRequest) (*model.RemediationTicket, error) {
	id := uuid.New()
	prio := req.Priority
	if prio == 0 {
		prio = 2
	}
	tags := req.Tags
	if tags == nil {
		tags = []string{}
	}
	t := &model.RemediationTicket{
		ID: id, TenantID: tenantID, Title: req.Title,
		Description: req.Description, Status: "open", Priority: prio,
		AssigneeID: req.AssigneeID, CreatedBy: callerID,
		SLADueAt: req.SLADueAt, ExternalID: req.ExternalID, ExternalURL: req.ExternalURL, Tags: tags,
	}
	if err := r.db.QueryRow(ctx, `
		INSERT INTO remediation_tickets
			(id, tenant_id, title, description, priority, assignee_id, created_by, sla_due_at, external_id, external_url, tags)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING created_at, updated_at`,
		id, tenantID, req.Title, nvlS(req.Description), prio,
		req.AssigneeID, callerID, req.SLADueAt,
		nvlS(req.ExternalID), nvlS(req.ExternalURL), tags,
	).Scan(&t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, fmt.Errorf("create ticket: %w", err)
	}
	return t, nil
}

func (r *VulnRepository) ListTickets(ctx context.Context, tenantID uuid.UUID, status string, limit, offset int) ([]*model.RemediationTicket, int, error) {
	where := []string{"tenant_id = $1"}
	args := []any{tenantID}
	n := 2
	if status != "" {
		where = append(where, fmt.Sprintf("status = $%d", n))
		args = append(args, status)
		n++
	}
	wc := strings.Join(where, " AND ")
	var total int
	r.db.QueryRow(ctx, fmt.Sprintf("SELECT COUNT(*) FROM remediation_tickets WHERE %s", wc), args...).Scan(&total) //nolint

	q := fmt.Sprintf(`
		SELECT id, tenant_id, title, description, status, priority, assignee_id, created_by,
		       finding_count, affected_asset_count, sla_due_at, resolved_at,
		       external_id, external_url, tags, created_at, updated_at
		FROM remediation_tickets WHERE %s
		ORDER BY priority DESC, created_at DESC
		LIMIT $%d OFFSET $%d`, wc, n, n+1)
	args = append(args, clampLimit(limit, 50, 200), offset)

	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*model.RemediationTicket
	for rows.Next() {
		t, err := scanTicket(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, t)
	}
	return out, total, nil
}

func (r *VulnRepository) UpdateTicket(ctx context.Context, tenantID, ticketID uuid.UUID, req *model.UpdateTicketRequest) (*model.RemediationTicket, error) {
	sets := []string{}
	args := []any{}
	n := 1
	set := func(col string, val any) {
		sets = append(sets, fmt.Sprintf("%s = $%d", col, n))
		args = append(args, val)
		n++
	}
	if req.Status != nil {
		set("status", *req.Status)
		if *req.Status == "resolved" {
			set("resolved_at", time.Now().UTC())
		}
	}
	if req.AssigneeID != nil {
		set("assignee_id", *req.AssigneeID)
	}
	if req.Priority != nil {
		set("priority", *req.Priority)
	}
	if req.SLADueAt != nil {
		set("sla_due_at", *req.SLADueAt)
	}
	if req.ExternalID != nil {
		set("external_id", *req.ExternalID)
	}
	if req.ExternalURL != nil {
		set("external_url", *req.ExternalURL)
	}
	if len(sets) == 0 {
		return r.getTicket(ctx, tenantID, ticketID)
	}
	set("updated_at", time.Now().UTC())
	q := fmt.Sprintf(`UPDATE remediation_tickets SET %s WHERE id = $%d AND tenant_id = $%d`,
		strings.Join(sets, ", "), n, n+1)
	args = append(args, ticketID, tenantID)
	if _, err := r.db.Exec(ctx, q, args...); err != nil {
		return nil, fmt.Errorf("update ticket: %w", err)
	}
	return r.getTicket(ctx, tenantID, ticketID)
}

func (r *VulnRepository) getTicket(ctx context.Context, tenantID, ticketID uuid.UUID) (*model.RemediationTicket, error) {
	row := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, title, description, status, priority, assignee_id, created_by,
		       finding_count, affected_asset_count, sla_due_at, resolved_at,
		       external_id, external_url, tags, created_at, updated_at
		FROM remediation_tickets WHERE id = $1 AND tenant_id = $2`, ticketID, tenantID)
	t, err := scanTicket(row)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (r *VulnRepository) Stats(ctx context.Context, tenantID uuid.UUID) (*model.VulnStats, error) {
	s := &model.VulnStats{
		BySeverity: make(map[string]int),
		ByStatus:   make(map[string]int),
	}

	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM vulnerabilities WHERE tenant_id=$1`, tenantID).Scan(&s.TotalVulns)                                                                                                                             //nolint
	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM asset_vulnerabilities WHERE tenant_id=$1`, tenantID).Scan(&s.TotalFindings)                                                                                                                    //nolint
	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM asset_vulnerabilities WHERE tenant_id=$1 AND status IN ('open','in_remediation')`, tenantID).Scan(&s.OpenFindings)                                                                             //nolint
	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM asset_vulnerabilities av JOIN vulnerabilities v ON v.id=av.vuln_id WHERE av.tenant_id=$1 AND av.sla_due_at < NOW() AND av.status IN ('open','in_remediation')`, tenantID).Scan(&s.SLABreached) //nolint
	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM asset_vulnerabilities av JOIN vulnerabilities v ON v.id=av.vuln_id WHERE av.tenant_id=$1 AND v.is_exploited=true AND av.status IN ('open','in_remediation')`, tenantID).Scan(&s.KEVFindings)   //nolint
	r.db.QueryRow(ctx, `SELECT COALESCE(AVG(v.cvss_score),0) FROM asset_vulnerabilities av JOIN vulnerabilities v ON v.id=av.vuln_id WHERE av.tenant_id=$1 AND av.status IN ('open','in_remediation')`, tenantID).Scan(&s.AvgCVSS)          //nolint

	rows, _ := r.db.Query(ctx, `SELECT v.cvss_severity, COUNT(*) FROM asset_vulnerabilities av JOIN vulnerabilities v ON v.id=av.vuln_id WHERE av.tenant_id=$1 AND av.status IN ('open','in_remediation') GROUP BY v.cvss_severity`, tenantID)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var sev string
			var cnt int
			if rows.Scan(&sev, &cnt) == nil {
				s.BySeverity[sev] = cnt
			}
		}
	}
	srows, _ := r.db.Query(ctx, `SELECT status, COUNT(*) FROM asset_vulnerabilities WHERE tenant_id=$1 GROUP BY status`, tenantID)
	if srows != nil {
		defer srows.Close()
		for srows.Next() {
			var st string
			var cnt int
			if srows.Scan(&st, &cnt) == nil {
				s.ByStatus[st] = cnt
			}
		}
	}

	// Top 10 most exposed assets
	arows, _ := r.db.Query(ctx, `
		SELECT av.asset_id,
		       COUNT(*) as total,
		       COUNT(*) FILTER (WHERE av.status IN ('open','in_remediation')) as open_cnt,
		       COUNT(*) FILTER (WHERE v.cvss_severity='CRITICAL') as crit,
		       COALESCE(AVG(v.cvss_score),0), COALESCE(MAX(v.cvss_score),0),
		       COALESCE(AVG(av.exposure_score),0),
		       COUNT(*) FILTER (WHERE av.sla_due_at < NOW() AND av.status IN ('open','in_remediation')),
		       BOOL_OR(v.is_exploited AND av.status IN ('open','in_remediation'))
		FROM asset_vulnerabilities av
		JOIN vulnerabilities v ON v.id = av.vuln_id
		WHERE av.tenant_id = $1
		GROUP BY av.asset_id
		ORDER BY COALESCE(AVG(av.exposure_score),0) DESC
		LIMIT 10`, tenantID)
	if arows != nil {
		defer arows.Close()
		for arows.Next() {
			es := &model.ExposureScore{}
			if arows.Scan(&es.AssetID, &es.TotalFindings, &es.OpenFindings, &es.CriticalCount,
				&es.AvgCVSS, &es.MaxCVSS, &es.ExposureScore, &es.SLABreached, &es.HasKEV) == nil {
				s.TopVulnerableAssets = append(s.TopVulnerableAssets, es)
			}
		}
	}

	scans, _ := r.ListScanJobs(ctx, tenantID, "", 5)
	s.RecentScans = scans
	return s, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

type scannable interface {
	Scan(dest ...any) error
}

const vulnSelect = `
	SELECT id, tenant_id, cve_id, title, description, cvss_score, cvss_vector, cvss_severity,
	       is_exploited, exploit_available, epss_score, cwe_id, cwe_name, mitre_technique,
	       affected_products, patch_available, patch_url, published_at, modified_at,
	       nvd_url, reference_urls, tags, created_at, updated_at
	FROM vulnerabilities`

func scanVuln(row scannable) (*model.Vulnerability, error) {
	v := &model.Vulnerability{}
	var cveID, desc, vec, cweID, cweName, mitreTech, patchURL, nvdURL *string
	var publishedAt, modifiedAt *time.Time
	err := row.Scan(
		&v.ID, &v.TenantID, &cveID, &v.Title, &desc, &v.CVSSScore, &vec, &v.CVSSSeverity,
		&v.IsExploited, &v.ExploitAvailable, &v.EPSSScore, &cweID, &cweName, &mitreTech,
		&v.AffectedProducts, &v.PatchAvailable, &patchURL, &publishedAt, &modifiedAt,
		&nvdURL, &v.References, &v.Tags, &v.CreatedAt, &v.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan vuln: %w", err)
	}
	for _, p := range []*string{cveID, desc, vec, cweID, cweName, mitreTech, patchURL, nvdURL} {
		_ = p // already applied below
	}
	if cveID != nil {
		v.CVEID = *cveID
	}
	if desc != nil {
		v.Description = *desc
	}
	if vec != nil {
		v.CVSSVector = *vec
	}
	if cweID != nil {
		v.CWEID = *cweID
	}
	if cweName != nil {
		v.CWEName = *cweName
	}
	if mitreTech != nil {
		v.MitreTechnique = *mitreTech
	}
	if patchURL != nil {
		v.PatchURL = *patchURL
	}
	if nvdURL != nil {
		v.NVDURL = *nvdURL
	}
	v.PublishedAt = publishedAt
	v.ModifiedAt = modifiedAt
	if v.AffectedProducts == nil {
		v.AffectedProducts = []string{}
	}
	if v.References == nil {
		v.References = []string{}
	}
	if v.Tags == nil {
		v.Tags = []string{}
	}
	return v, nil
}

func scanJob(row scannable) (*model.ScanJob, error) {
	job := &model.ScanJob{}
	var errMsg *string
	var targetsRaw []byte
	err := row.Scan(
		&job.ID, &job.TenantID, &job.Name, &job.ScanType, &targetsRaw, &job.Status,
		&job.TriggeredBy, &job.ScheduledAt, &job.StartedAt, &job.CompletedAt,
		&job.TotalAssets, &job.ScannedAssets, &job.TotalFindings, &job.NewFindings, &job.ResolvedFindings,
		&job.CriticalCount, &job.HighCount, &job.MediumCount, &job.LowCount,
		&errMsg, &job.CreatedAt, &job.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if errMsg != nil {
		job.ErrorMessage = *errMsg
	}
	_ = json.Unmarshal(targetsRaw, &job.Targets)
	if job.Targets == nil {
		job.Targets = map[string]any{}
	}
	return job, nil
}

func scanTicket(row scannable) (*model.RemediationTicket, error) {
	t := &model.RemediationTicket{}
	var desc, extID, extURL *string
	err := row.Scan(
		&t.ID, &t.TenantID, &t.Title, &desc, &t.Status, &t.Priority,
		&t.AssigneeID, &t.CreatedBy,
		&t.FindingCount, &t.AffectedAssets,
		&t.SLADueAt, &t.ResolvedAt, &extID, &extURL, &t.Tags,
		&t.CreatedAt, &t.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan ticket: %w", err)
	}
	if desc != nil {
		t.Description = *desc
	}
	if extID != nil {
		t.ExternalID = *extID
	}
	if extURL != nil {
		t.ExternalURL = *extURL
	}
	if t.Tags == nil {
		t.Tags = []string{}
	}
	return t, nil
}

func cvssToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return model.SeverityCritical
	case score >= 7.0:
		return model.SeverityHigh
	case score >= 4.0:
		return model.SeverityMedium
	case score > 0:
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

// computeExposure calculates an exposure score 0-10 from CVSS and exploitability.
func computeExposure(cvss float64, severity string, isExploited bool) float64 {
	base := cvss // 0-10 from CVSS
	if isExploited {
		base = min10(base + 1.5) // KEV boost
	}
	switch severity {
	case model.SeverityCritical:
		base = min10(base * 1.1)
	case model.SeverityHigh:
		base = min10(base * 1.05)
	}
	return base
}

func computeSLA(severity string) int {
	if days, ok := model.SLADays[severity]; ok {
		return days
	}
	return 90
}

func min10(v float64) float64 {
	if v > 10 {
		return 10
	}
	return v
}

func clampLimit(v, def, max int) int {
	if v <= 0 {
		return def
	}
	if v > max {
		return max
	}
	return v
}

func nvlS(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
