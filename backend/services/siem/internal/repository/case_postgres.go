package repository

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cyberradar/platform/services/siem/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CaseRepository handles case management in PostgreSQL.
type CaseRepository struct {
	db *pgxpool.Pool
}

// NewCaseRepository creates a CaseRepository.
func NewCaseRepository(db *pgxpool.Pool) *CaseRepository {
	return &CaseRepository{db: db}
}

// CreateCase opens a new case.
func (r *CaseRepository) CreateCase(ctx context.Context, tenantID uuid.UUID, createdBy *uuid.UUID, req *model.CreateCaseRequest) (*model.Case, error) {
	id := uuid.New()
	prio := req.Priority
	if prio == 0 {
		prio = 2
	}
	const q = `
		INSERT INTO cases
			(id, tenant_id, title, description, severity, priority,
			 assignee_id, created_by, mitre_tactic, mitre_technique, due_at, tags)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING id, status, opened_at, created_at, updated_at`

	c := &model.Case{
		ID:             id,
		TenantID:       tenantID,
		Title:          req.Title,
		Description:    req.Description,
		Severity:       req.Severity,
		Priority:       prio,
		AssigneeID:     req.AssigneeID,
		CreatedBy:      createdBy,
		MitreTactic:    req.MitreTactic,
		MitreTechnique: req.MitreTechnique,
		DueAt:          req.DueAt,
		Tags:           req.Tags,
	}
	if c.Tags == nil {
		c.Tags = []string{}
	}

	if err := r.db.QueryRow(ctx, q,
		id, tenantID, req.Title, nvl(req.Description), req.Severity, prio,
		req.AssigneeID, createdBy, nvl(req.MitreTactic), nvl(req.MitreTechnique), req.DueAt, c.Tags,
	).Scan(&c.ID, &c.Status, &c.OpenedAt, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, fmt.Errorf("create case: %w", err)
	}
	return c, nil
}

// GetCase returns a case by ID.
func (r *CaseRepository) GetCase(ctx context.Context, tenantID, caseID uuid.UUID) (*model.Case, error) {
	const q = `
		SELECT id, tenant_id, title, description, severity, status, priority,
		       assignee_id, created_by, mitre_tactic, mitre_technique,
		       opened_at, due_at, resolved_at, closed_at,
		       alert_count, mttr_seconds, tags, created_at, updated_at
		FROM cases WHERE id = $1 AND tenant_id = $2`
	row := r.db.QueryRow(ctx, q, caseID, tenantID)
	return scanCase(row)
}

// ListCases returns cases matching the filter.
func (r *CaseRepository) ListCases(ctx context.Context, f model.CaseFilter) ([]*model.Case, int, error) {
	where := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	n := 2

	if f.Status != "" {
		where = append(where, fmt.Sprintf("status = $%d", n))
		args = append(args, f.Status)
		n++
	}
	if f.Severity != "" {
		where = append(where, fmt.Sprintf("severity = $%d", n))
		args = append(args, f.Severity)
		n++
	}
	if f.AssigneeID != nil {
		where = append(where, fmt.Sprintf("assignee_id = $%d", n))
		args = append(args, *f.AssigneeID)
		n++
	}

	wc := strings.Join(where, " AND ")
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	var total int
	if err := r.db.QueryRow(ctx, fmt.Sprintf("SELECT COUNT(*) FROM cases WHERE %s", wc), args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	dataQ := fmt.Sprintf(`
		SELECT id, tenant_id, title, description, severity, status, priority,
		       assignee_id, created_by, mitre_tactic, mitre_technique,
		       opened_at, due_at, resolved_at, closed_at,
		       alert_count, mttr_seconds, tags, created_at, updated_at
		FROM cases WHERE %s
		ORDER BY priority DESC, opened_at DESC
		LIMIT $%d OFFSET $%d`, wc, n, n+1)
	args = append(args, limit, f.Offset)

	rows, err := r.db.Query(ctx, dataQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []*model.Case
	for rows.Next() {
		c, err := scanCase(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, nil
}

// UpdateCase applies a partial update.
func (r *CaseRepository) UpdateCase(ctx context.Context, tenantID, caseID uuid.UUID, req *model.UpdateCaseRequest) (*model.Case, error) {
	sets := []string{}
	args := []any{}
	n := 1

	set := func(col string, val any) {
		sets = append(sets, fmt.Sprintf("%s = $%d", col, n))
		args = append(args, val)
		n++
	}

	if req.Title != nil {
		set("title", *req.Title)
	}
	if req.Description != nil {
		set("description", *req.Description)
	}
	if req.Severity != nil {
		set("severity", *req.Severity)
	}
	if req.Status != nil {
		set("status", *req.Status)
		switch *req.Status {
		case model.CaseResolved:
			now := time.Now().UTC()
			set("resolved_at", now)
		case model.CaseClosed, model.CaseFalsePositive:
			now := time.Now().UTC()
			set("closed_at", now)
		}
	}
	if req.Priority != nil {
		set("priority", *req.Priority)
	}
	if req.AssigneeID != nil {
		set("assignee_id", *req.AssigneeID)
	}
	if req.DueAt != nil {
		set("due_at", *req.DueAt)
	}
	if req.Tags != nil {
		set("tags", req.Tags)
	}

	if len(sets) == 0 {
		return r.GetCase(ctx, tenantID, caseID)
	}

	q := fmt.Sprintf(`UPDATE cases SET %s WHERE id = $%d AND tenant_id = $%d`,
		strings.Join(sets, ", "), n, n+1)
	args = append(args, caseID, tenantID)

	if _, err := r.db.Exec(ctx, q, args...); err != nil {
		return nil, fmt.Errorf("update case: %w", err)
	}
	return r.GetCase(ctx, tenantID, caseID)
}

// LinkAlert links an alert to a case and increments alert_count.
func (r *CaseRepository) LinkAlert(ctx context.Context, tenantID, caseID, alertID uuid.UUID) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		`UPDATE alert_metadata SET case_id = $1 WHERE alert_id = $2 AND tenant_id = $3`,
		caseID, alertID, tenantID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`UPDATE cases SET alert_count = alert_count + 1 WHERE id = $1 AND tenant_id = $2`,
		caseID, tenantID)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AddComment appends a comment to the case timeline.
func (r *CaseRepository) AddComment(ctx context.Context, tenantID, caseID uuid.UUID, authorID *uuid.UUID, req *model.AddCommentRequest) (*model.CaseComment, error) {
	id := uuid.New()
	const q = `
		INSERT INTO case_comments (id, tenant_id, case_id, author_id, comment, is_internal)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id, created_at`

	c := &model.CaseComment{
		ID:         id,
		TenantID:   tenantID,
		CaseID:     caseID,
		AuthorID:   authorID,
		Comment:    req.Comment,
		IsInternal: req.IsInternal,
	}
	if err := r.db.QueryRow(ctx, q, id, tenantID, caseID, authorID, req.Comment, req.IsInternal).
		Scan(&c.ID, &c.CreatedAt); err != nil {
		return nil, fmt.Errorf("add comment: %w", err)
	}
	return c, nil
}

// ListComments returns all comments for a case.
func (r *CaseRepository) ListComments(ctx context.Context, tenantID, caseID uuid.UUID) ([]*model.CaseComment, error) {
	const q = `
		SELECT id, tenant_id, case_id, author_id, comment, is_internal, created_at
		FROM case_comments WHERE tenant_id = $1 AND case_id = $2 ORDER BY created_at`
	rows, err := r.db.Query(ctx, q, tenantID, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.CaseComment
	for rows.Next() {
		c := &model.CaseComment{}
		if err := rows.Scan(&c.ID, &c.TenantID, &c.CaseID, &c.AuthorID, &c.Comment, &c.IsInternal, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// AddObservable links an IOC observable to a case.
func (r *CaseRepository) AddObservable(ctx context.Context, tenantID, caseID uuid.UUID, addedBy *uuid.UUID, req *model.AddObservableRequest) (*model.Observable, error) {
	id := uuid.New()
	const q = `
		INSERT INTO case_observables (id, tenant_id, case_id, obs_type, value, tlp, is_ioc, notes, added_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id, created_at`
	obs := &model.Observable{
		ID: id, TenantID: tenantID, CaseID: caseID,
		Type: req.Type, Value: req.Value, TLP: req.TLP,
		IsIOC: req.IsIOC, Notes: req.Notes, AddedBy: addedBy,
	}
	if err := r.db.QueryRow(ctx, q,
		id, tenantID, caseID, req.Type, req.Value, req.TLP, req.IsIOC, nvl(req.Notes), addedBy,
	).Scan(&obs.ID, &obs.CreatedAt); err != nil {
		return nil, fmt.Errorf("add observable: %w", err)
	}
	return obs, nil
}

// UpsertAlertMetadata creates or updates alert metadata status.
func (r *CaseRepository) UpsertAlertMetadata(ctx context.Context, tenantID, alertID uuid.UUID, ruleID *uuid.UUID) error {
	const q = `
		INSERT INTO alert_metadata (alert_id, tenant_id, rule_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (alert_id) DO NOTHING`
	_, err := r.db.Exec(ctx, q, alertID, tenantID, ruleID)
	return err
}

// UpdateAlertMetadata updates alert status/assignment.
func (r *CaseRepository) UpdateAlertMetadata(ctx context.Context, tenantID, alertID uuid.UUID, req *model.UpdateAlertRequest) (*model.AlertMetadata, error) {
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
	}
	if req.AssigneeID != nil {
		set("assignee_id", *req.AssigneeID)
	}
	if req.Notes != nil {
		set("notes", *req.Notes)
	}

	if len(sets) == 0 {
		return r.GetAlertMetadata(ctx, tenantID, alertID)
	}

	q := fmt.Sprintf(`UPDATE alert_metadata SET %s WHERE alert_id = $%d AND tenant_id = $%d`,
		strings.Join(sets, ", "), n, n+1)
	args = append(args, alertID, tenantID)
	if _, err := r.db.Exec(ctx, q, args...); err != nil {
		return nil, err
	}
	return r.GetAlertMetadata(ctx, tenantID, alertID)
}

// GetAlertMetadata returns alert metadata.
func (r *CaseRepository) GetAlertMetadata(ctx context.Context, tenantID, alertID uuid.UUID) (*model.AlertMetadata, error) {
	const q = `
		SELECT alert_id, tenant_id, rule_id, status, assignee_id, case_id, notes, created_at, updated_at
		FROM alert_metadata WHERE alert_id = $1 AND tenant_id = $2`
	m := &model.AlertMetadata{}
	var notes *string
	if err := r.db.QueryRow(ctx, q, alertID, tenantID).
		Scan(&m.AlertID, &m.TenantID, &m.RuleID, &m.Status, &m.AssigneeID, &m.CaseID, &notes, &m.CreatedAt, &m.UpdatedAt); err == pgx.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if notes != nil {
		m.Notes = *notes
	}
	return m, nil
}

func scanCase(row scannable) (*model.Case, error) {
	c := &model.Case{}
	var (
		desc, tactic, technique *string
	)
	err := row.Scan(
		&c.ID, &c.TenantID, &c.Title, &desc, &c.Severity, &c.Status, &c.Priority,
		&c.AssigneeID, &c.CreatedBy, &tactic, &technique,
		&c.OpenedAt, &c.DueAt, &c.ResolvedAt, &c.ClosedAt,
		&c.AlertCount, &c.MTTRSeconds, &c.Tags, &c.CreatedAt, &c.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan case: %w", err)
	}
	if desc != nil {
		c.Description = *desc
	}
	if tactic != nil {
		c.MitreTactic = *tactic
	}
	if technique != nil {
		c.MitreTechnique = *technique
	}
	if c.Tags == nil {
		c.Tags = []string{}
	}
	return c, nil
}
