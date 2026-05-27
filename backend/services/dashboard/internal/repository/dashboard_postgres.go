package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cyberradar/platform/services/dashboard/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DashboardRepository handles dashboard/widget/report persistence in PostgreSQL.
type DashboardRepository struct {
	db *pgxpool.Pool
}

// NewDashboardRepository creates a DashboardRepository.
func NewDashboardRepository(db *pgxpool.Pool) *DashboardRepository {
	return &DashboardRepository{db: db}
}

// ─── Dashboards ───────────────────────────────────────────────────────────────

const dashSelect = `id, tenant_id, name, COALESCE(description,''), layout, columns,
    is_default, is_public, COALESCE(tags,'{}'), created_by, created_at, updated_at`

func (r *DashboardRepository) CreateDashboard(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreateDashboardRequest) (*model.Dashboard, error) {
	cols := req.Columns
	if cols == 0 {
		cols = 12
	}
	layout := req.Layout
	if layout == "" {
		layout = "grid"
	}
	tags := req.Tags
	if tags == nil {
		tags = []string{}
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// Unset previous default if this one becomes default
	if req.IsDefault {
		_, err = tx.Exec(ctx,
			`UPDATE dashboards SET is_default=FALSE, updated_at=NOW() WHERE tenant_id=$1 AND is_default=TRUE`,
			tenantID)
		if err != nil {
			return nil, err
		}
	}

	d, err := scanDashboard(tx.QueryRow(ctx, `
		INSERT INTO dashboards (tenant_id, name, description, layout, columns, is_default, is_public, tags, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING `+dashSelect,
		tenantID, req.Name, req.Description, layout, cols,
		req.IsDefault, req.IsPublic, tags, callerID))
	if err != nil {
		return nil, err
	}
	return d, tx.Commit(ctx)
}

func (r *DashboardRepository) GetDashboard(ctx context.Context, tenantID, dashID uuid.UUID) (*model.Dashboard, error) {
	d, err := scanDashboard(r.db.QueryRow(ctx,
		`SELECT `+dashSelect+` FROM dashboards WHERE id=$1 AND tenant_id=$2`,
		dashID, tenantID))
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	widgets, err := r.listWidgets(ctx, tenantID, dashID)
	if err != nil {
		return nil, err
	}
	d.Widgets = widgets
	return d, nil
}

func (r *DashboardRepository) UpdateDashboard(ctx context.Context, tenantID, dashID uuid.UUID, req *model.UpdateDashboardRequest) (*model.Dashboard, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	setClauses := []string{"updated_at = NOW()"}
	args := []any{dashID, tenantID}
	idx := 3

	if req.Name != nil {
		setClauses = append(setClauses, fmt.Sprintf("name = $%d", idx))
		args = append(args, *req.Name)
		idx++
	}
	if req.Description != nil {
		setClauses = append(setClauses, fmt.Sprintf("description = $%d", idx))
		args = append(args, *req.Description)
		idx++
	}
	if req.IsPublic != nil {
		setClauses = append(setClauses, fmt.Sprintf("is_public = $%d", idx))
		args = append(args, *req.IsPublic)
		idx++
	}
	if req.IsDefault != nil && *req.IsDefault {
		// Unset other defaults first
		_, _ = tx.Exec(ctx,
			`UPDATE dashboards SET is_default=FALSE, updated_at=NOW() WHERE tenant_id=$1 AND is_default=TRUE AND id<>$2`,
			tenantID, dashID)
		setClauses = append(setClauses, fmt.Sprintf("is_default = $%d", idx))
		args = append(args, *req.IsDefault)
		idx++
	}
	if req.Tags != nil {
		setClauses = append(setClauses, fmt.Sprintf("tags = $%d", idx))
		args = append(args, req.Tags)
		idx++
	}

	q := fmt.Sprintf(`UPDATE dashboards SET %s WHERE id=$1 AND tenant_id=$2 RETURNING %s`,
		strings.Join(setClauses, ", "), dashSelect)
	d, err := scanDashboard(tx.QueryRow(ctx, q, args...))
	if err != nil {
		return nil, err
	}
	return d, tx.Commit(ctx)
}

func (r *DashboardRepository) DeleteDashboard(ctx context.Context, tenantID, dashID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`DELETE FROM dashboards WHERE id=$1 AND tenant_id=$2`, dashID, tenantID)
	return err
}

func (r *DashboardRepository) ListDashboards(ctx context.Context, tenantID uuid.UUID) ([]*model.Dashboard, error) {
	rows, err := r.db.Query(ctx,
		`SELECT `+dashSelect+` FROM dashboards WHERE tenant_id=$1 ORDER BY is_default DESC, updated_at DESC`,
		tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var dashboards []*model.Dashboard
	for rows.Next() {
		d, err := scanDashboard(rows)
		if err != nil {
			return nil, err
		}
		dashboards = append(dashboards, d)
	}
	return dashboards, rows.Err()
}

// ─── Widgets ──────────────────────────────────────────────────────────────────

const widgetSelect = `id, dashboard_id, tenant_id, widget_type, title,
    pos_x, pos_y, width, height, data_source, metric_key, config, refresh_sec, created_at, updated_at`

func (r *DashboardRepository) AddWidget(ctx context.Context, tenantID, dashID uuid.UUID, req *model.CreateWidgetRequest) (*model.Widget, error) {
	cfg, _ := json.Marshal(req.Config)
	refresh := req.RefreshSec
	if refresh == 0 {
		refresh = 60
	}
	return scanWidget(r.db.QueryRow(ctx, `
		INSERT INTO dashboard_widgets
		    (dashboard_id, tenant_id, widget_type, title, pos_x, pos_y, width, height,
		     data_source, metric_key, config, refresh_sec)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING `+widgetSelect,
		dashID, tenantID, req.WidgetType, req.Title,
		req.PosX, req.PosY, req.Width, req.Height,
		req.DataSource, req.MetricKey, cfg, refresh))
}

func (r *DashboardRepository) UpdateWidget(ctx context.Context, tenantID, widgetID uuid.UUID, req *model.UpdateWidgetRequest) (*model.Widget, error) {
	setClauses := []string{"updated_at = NOW()"}
	args := []any{widgetID, tenantID}
	idx := 3

	if req.Title != nil {
		setClauses = append(setClauses, fmt.Sprintf("title = $%d", idx))
		args = append(args, *req.Title)
		idx++
	}
	if req.PosX != nil {
		setClauses = append(setClauses, fmt.Sprintf("pos_x = $%d", idx))
		args = append(args, *req.PosX)
		idx++
	}
	if req.PosY != nil {
		setClauses = append(setClauses, fmt.Sprintf("pos_y = $%d", idx))
		args = append(args, *req.PosY)
		idx++
	}
	if req.Width != nil {
		setClauses = append(setClauses, fmt.Sprintf("width = $%d", idx))
		args = append(args, *req.Width)
		idx++
	}
	if req.Height != nil {
		setClauses = append(setClauses, fmt.Sprintf("height = $%d", idx))
		args = append(args, *req.Height)
		idx++
	}
	if req.Config != nil {
		cfg, _ := json.Marshal(req.Config)
		setClauses = append(setClauses, fmt.Sprintf("config = config || $%d", idx))
		args = append(args, cfg)
		idx++
	}
	if req.RefreshSec != nil {
		setClauses = append(setClauses, fmt.Sprintf("refresh_sec = $%d", idx))
		args = append(args, *req.RefreshSec)
		idx++
	}

	q := fmt.Sprintf(`UPDATE dashboard_widgets SET %s WHERE id=$1 AND tenant_id=$2 RETURNING %s`,
		strings.Join(setClauses, ", "), widgetSelect)
	return scanWidget(r.db.QueryRow(ctx, q, args...))
}

func (r *DashboardRepository) DeleteWidget(ctx context.Context, tenantID, widgetID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`DELETE FROM dashboard_widgets WHERE id=$1 AND tenant_id=$2`, widgetID, tenantID)
	return err
}

func (r *DashboardRepository) listWidgets(ctx context.Context, tenantID, dashID uuid.UUID) ([]model.Widget, error) {
	rows, err := r.db.Query(ctx,
		`SELECT `+widgetSelect+` FROM dashboard_widgets WHERE dashboard_id=$1 AND tenant_id=$2 ORDER BY pos_y, pos_x`,
		dashID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var widgets []model.Widget
	for rows.Next() {
		w, err := scanWidget(rows)
		if err != nil {
			return nil, err
		}
		widgets = append(widgets, *w)
	}
	return widgets, rows.Err()
}

// ─── Reports ──────────────────────────────────────────────────────────────────

const reportSelect = `id, tenant_id, name, COALESCE(description,''), report_type,
    COALESCE(schedule,''), last_payload, last_run_at, next_run_at, status, format,
    COALESCE(recipients,'{}'), created_by, created_at, updated_at`

func (r *DashboardRepository) CreateReport(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreateReportRequest) (*model.Report, error) {
	format := req.Format
	if format == "" {
		format = "json"
	}
	recipients := req.Recipients
	if recipients == nil {
		recipients = []string{}
	}
	return scanReport(r.db.QueryRow(ctx, `
		INSERT INTO dashboard_reports (tenant_id, name, description, report_type, schedule, format, recipients, created_by)
		VALUES ($1,$2,$3,$4,NULLIF($5,''),$6,$7,$8)
		RETURNING `+reportSelect,
		tenantID, req.Name, req.Description, req.ReportType,
		req.Schedule, format, recipients, callerID))
}

func (r *DashboardRepository) GetReport(ctx context.Context, tenantID, reportID uuid.UUID) (*model.Report, error) {
	rpt, err := scanReport(r.db.QueryRow(ctx,
		`SELECT `+reportSelect+` FROM dashboard_reports WHERE id=$1 AND tenant_id=$2`,
		reportID, tenantID))
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return rpt, err
}

func (r *DashboardRepository) ListReports(ctx context.Context, tenantID uuid.UUID) ([]*model.Report, error) {
	rows, err := r.db.Query(ctx,
		`SELECT `+reportSelect+` FROM dashboard_reports WHERE tenant_id=$1 ORDER BY created_at DESC`,
		tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var reports []*model.Report
	for rows.Next() {
		rpt, err := scanReport(rows)
		if err != nil {
			return nil, err
		}
		reports = append(reports, rpt)
	}
	return reports, rows.Err()
}

func (r *DashboardRepository) SaveReportPayload(ctx context.Context, tenantID, reportID uuid.UUID, payload map[string]any, status string) error {
	pJSON, _ := json.Marshal(payload)
	now := time.Now().UTC()
	_, err := r.db.Exec(ctx, `
		UPDATE dashboard_reports
		SET last_payload=$1, last_run_at=$2, status=$3, updated_at=NOW()
		WHERE id=$4 AND tenant_id=$5`,
		pJSON, now, status, reportID, tenantID)
	return err
}

func (r *DashboardRepository) DeleteReport(ctx context.Context, tenantID, reportID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`DELETE FROM dashboard_reports WHERE id=$1 AND tenant_id=$2`, reportID, tenantID)
	return err
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

type scannable interface {
	Scan(...any) error
}

func scanDashboard(row scannable) (*model.Dashboard, error) {
	var d model.Dashboard
	err := row.Scan(
		&d.ID, &d.TenantID, &d.Name, &d.Description, &d.Layout, &d.Columns,
		&d.IsDefault, &d.IsPublic, &d.Tags, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if d.Tags == nil {
		d.Tags = []string{}
	}
	return &d, nil
}

func scanWidget(row scannable) (*model.Widget, error) {
	var w model.Widget
	var cfgRaw []byte
	err := row.Scan(
		&w.ID, &w.DashboardID, &w.TenantID, &w.WidgetType, &w.Title,
		&w.PosX, &w.PosY, &w.Width, &w.Height,
		&w.DataSource, &w.MetricKey, &cfgRaw, &w.RefreshSec,
		&w.CreatedAt, &w.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(cfgRaw, &w.Config)
	return &w, nil
}

func scanReport(row scannable) (*model.Report, error) {
	var rpt model.Report
	var payloadRaw []byte
	err := row.Scan(
		&rpt.ID, &rpt.TenantID, &rpt.Name, &rpt.Description, &rpt.ReportType,
		&rpt.Schedule, &payloadRaw, &rpt.LastRunAt, &rpt.NextRunAt, &rpt.Status,
		&rpt.Format, &rpt.Recipients, &rpt.CreatedBy, &rpt.CreatedAt, &rpt.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if len(payloadRaw) > 0 {
		_ = json.Unmarshal(payloadRaw, &rpt.LastPayload)
	}
	if rpt.Recipients == nil {
		rpt.Recipients = []string{}
	}
	return &rpt, nil
}
