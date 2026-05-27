package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cyberradar/platform/services/soar/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SOARRepository handles all SOAR persistence.
type SOARRepository struct {
	db *pgxpool.Pool
}

// NewSOARRepository creates a SOARRepository.
func NewSOARRepository(db *pgxpool.Pool) *SOARRepository {
	return &SOARRepository{db: db}
}

// ─── Incidents ────────────────────────────────────────────────────────────────

const incidentSelect = `
    id, tenant_id, title, COALESCE(description,''), severity, status,
    COALESCE(source_service,''), source_event_id, assignee_id,
    COALESCE(mitre_tactics,'{}'), COALESCE(mitre_techniques,'{}'),
    COALESCE(affected_assets,'{}'), COALESCE(ioc_ids,'{}'),
    COALESCE(tags,'{}'), properties, sla_due_at, contained_at,
    resolved_at, closed_at, created_by, created_at, updated_at`

func (r *SOARRepository) CreateIncident(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreateIncidentRequest) (*model.Incident, error) {
	props, _ := json.Marshal(req.Properties)
	slaH := model.IncidentSLAHours[req.Severity]
	slaAt := time.Now().UTC().Add(time.Duration(slaH) * time.Hour)

	tactics := req.MitreTactics
	if tactics == nil {
		tactics = []string{}
	}
	techniques := req.MitreTechniques
	if techniques == nil {
		techniques = []string{}
	}
	assets := req.AffectedAssets
	if assets == nil {
		assets = []uuid.UUID{}
	}
	iocs := req.IOCIDs
	if iocs == nil {
		iocs = []uuid.UUID{}
	}
	tags := req.Tags
	if tags == nil {
		tags = []string{}
	}

	row := r.db.QueryRow(ctx, `
		INSERT INTO soar_incidents
		    (tenant_id, title, description, severity, source_service, source_event_id,
		     assignee_id, mitre_tactics, mitre_techniques, affected_assets, ioc_ids,
		     tags, properties, sla_due_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		RETURNING `+incidentSelect,
		tenantID, req.Title, req.Description, req.Severity,
		nvlS(req.SourceService), req.SourceEventID, req.AssigneeID,
		tactics, techniques, assets, iocs, tags, props, slaAt, callerID)
	return scanIncident(row)
}

func (r *SOARRepository) GetIncident(ctx context.Context, tenantID, incidentID uuid.UUID) (*model.Incident, error) {
	row := r.db.QueryRow(ctx,
		`SELECT `+incidentSelect+` FROM soar_incidents WHERE id=$1 AND tenant_id=$2`,
		incidentID, tenantID)
	inc, err := scanIncident(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return inc, err
}

func (r *SOARRepository) UpdateIncident(ctx context.Context, tenantID, incidentID uuid.UUID, req *model.UpdateIncidentRequest, actorID *uuid.UUID) (*model.Incident, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	setClauses := []string{"updated_at = NOW()"}
	args := []any{incidentID, tenantID}
	idx := 3
	details := map[string]any{}

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
	if req.Severity != nil {
		setClauses = append(setClauses, fmt.Sprintf("severity = $%d", idx))
		args = append(args, *req.Severity)
		// Recompute SLA
		slaH := model.IncidentSLAHours[*req.Severity]
		slaAt := time.Now().UTC().Add(time.Duration(slaH) * time.Hour)
		setClauses = append(setClauses, fmt.Sprintf("sla_due_at = $%d", idx+1))
		args = append(args, slaAt)
		idx += 2
	}
	if req.Status != nil {
		setClauses = append(setClauses, fmt.Sprintf("status = $%d", idx))
		args = append(args, *req.Status)
		details["old_status_changed_to"] = *req.Status
		now := time.Now().UTC()
		switch *req.Status {
		case model.IncidentStatusContained:
			setClauses = append(setClauses, fmt.Sprintf("contained_at = COALESCE(contained_at, $%d)", idx+1))
			args = append(args, now)
			idx += 2
		case model.IncidentStatusResolved:
			setClauses = append(setClauses, fmt.Sprintf("resolved_at = COALESCE(resolved_at, $%d)", idx+1))
			args = append(args, now)
			idx += 2
		case model.IncidentStatusClosed:
			setClauses = append(setClauses, fmt.Sprintf("closed_at = COALESCE(closed_at, $%d)", idx+1))
			args = append(args, now)
			idx += 2
		default:
			idx++
		}
	}
	if req.AssigneeID != nil {
		setClauses = append(setClauses, fmt.Sprintf("assignee_id = $%d", idx))
		args = append(args, *req.AssigneeID)
		details["assignee_id"] = req.AssigneeID.String()
		idx++
	}
	if req.Tags != nil {
		setClauses = append(setClauses, fmt.Sprintf("tags = $%d", idx))
		args = append(args, req.Tags)
		idx++
	}
	if req.Properties != nil {
		props, _ := json.Marshal(req.Properties)
		setClauses = append(setClauses, fmt.Sprintf("properties = properties || $%d", idx))
		args = append(args, props)
		idx++
	}

	q := fmt.Sprintf(`UPDATE soar_incidents SET %s WHERE id=$1 AND tenant_id=$2 RETURNING %s`,
		strings.Join(setClauses, ", "), incidentSelect)
	inc, err := scanIncident(tx.QueryRow(ctx, q, args...))
	if err != nil {
		return nil, err
	}

	// Append timeline event
	eventType := "UPDATED"
	if req.Status != nil {
		eventType = "STATUS_CHANGED"
	}
	if req.Note != "" {
		eventType = "NOTE_ADDED"
		details["note"] = req.Note
	}
	detJSON, _ := json.Marshal(details)
	_, err = tx.Exec(ctx, `
		INSERT INTO soar_incident_events (tenant_id, incident_id, event_type, actor_id, actor_type, details)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		tenantID, incidentID, eventType, actorID,
		map[bool]string{true: "user", false: "system"}[actorID != nil], detJSON)
	if err != nil {
		return nil, err
	}

	return inc, tx.Commit(ctx)
}

func (r *SOARRepository) ListIncidents(ctx context.Context, f model.IncidentFilter) ([]*model.Incident, int, error) {
	where := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	idx := 2

	if f.Status != "" {
		where = append(where, fmt.Sprintf("status = $%d", idx))
		args = append(args, f.Status)
		idx++
	}
	if f.Severity != "" {
		where = append(where, fmt.Sprintf("severity = $%d", idx))
		args = append(args, f.Severity)
		idx++
	}
	if f.Assignee != nil {
		where = append(where, fmt.Sprintf("assignee_id = $%d", idx))
		args = append(args, *f.Assignee)
		idx++
	}
	if f.Source != "" {
		where = append(where, fmt.Sprintf("source_service = $%d", idx))
		args = append(args, f.Source)
		idx++
	}
	if f.SLABreach {
		where = append(where, "sla_due_at < NOW() AND status NOT IN ('resolved','closed')")
	}

	whereStr := strings.Join(where, " AND ")
	var total int
	if err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM soar_incidents WHERE `+whereStr, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	args = append(args, limit, f.Offset)
	rows, err := r.db.Query(ctx,
		`SELECT `+incidentSelect+` FROM soar_incidents WHERE `+whereStr+
			` ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END, created_at DESC`+
			fmt.Sprintf(` LIMIT $%d OFFSET $%d`, idx, idx+1),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var incidents []*model.Incident
	for rows.Next() {
		inc, err := scanIncident(rows)
		if err != nil {
			return nil, 0, err
		}
		incidents = append(incidents, inc)
	}
	return incidents, total, rows.Err()
}

func (r *SOARRepository) ListIncidentEvents(ctx context.Context, tenantID, incidentID uuid.UUID) ([]*model.IncidentEvent, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, incident_id, event_type, actor_id, actor_type, details, created_at
		FROM soar_incident_events WHERE incident_id=$1 AND tenant_id=$2 ORDER BY created_at ASC`,
		incidentID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*model.IncidentEvent
	for rows.Next() {
		var e model.IncidentEvent
		var detRaw []byte
		if err := rows.Scan(&e.ID, &e.TenantID, &e.IncidentID, &e.EventType,
			&e.ActorID, &e.ActorType, &detRaw, &e.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(detRaw, &e.Details)
		events = append(events, &e)
	}
	return events, rows.Err()
}

func (r *SOARRepository) AddIncidentEvent(ctx context.Context, tenantID, incidentID uuid.UUID, eventType string, actorID *uuid.UUID, actorType string, details map[string]any) error {
	detJSON, _ := json.Marshal(details)
	_, err := r.db.Exec(ctx, `
		INSERT INTO soar_incident_events (tenant_id, incident_id, event_type, actor_id, actor_type, details)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		tenantID, incidentID, eventType, actorID, actorType, detJSON)
	return err
}

// ─── Playbooks ────────────────────────────────────────────────────────────────

func (r *SOARRepository) CreatePlaybook(ctx context.Context, tenantID uuid.UUID, callerID *uuid.UUID, req *model.CreatePlaybookRequest) (*model.Playbook, error) {
	conds, _ := json.Marshal(req.TriggerConditions)

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var pb model.Playbook
	var condsRaw []byte
	err = tx.QueryRow(ctx, `
		INSERT INTO soar_playbooks (tenant_id, name, description, trigger_type, trigger_conditions, is_active, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id, tenant_id, name, COALESCE(description,''), trigger_type, trigger_conditions,
		          is_active, run_count, success_count, failure_count, last_run_at, created_by, created_at, updated_at`,
		tenantID, req.Name, req.Description, req.TriggerType, conds, req.IsActive, callerID,
	).Scan(&pb.ID, &pb.TenantID, &pb.Name, &pb.Description, &pb.TriggerType, &condsRaw,
		&pb.IsActive, &pb.RunCount, &pb.SuccessCount, &pb.FailureCount, &pb.LastRunAt, &pb.CreatedBy, &pb.CreatedAt, &pb.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(condsRaw, &pb.TriggerConditions)

	// Insert steps
	for i, s := range req.Steps {
		order := i + 1
		onFail := s.OnFailure
		if onFail == "" {
			onFail = "abort"
		}
		timeout := s.TimeoutSec
		if timeout == 0 {
			timeout = 30
		}
		params, _ := json.Marshal(s.ActionParams)
		var step model.PlaybookStep
		var paramsRaw []byte
		err = tx.QueryRow(ctx, `
			INSERT INTO soar_playbook_steps (playbook_id, step_order, name, action_type, action_params, on_failure, retry_count, timeout_sec)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			RETURNING id, playbook_id, step_order, name, action_type, action_params, on_failure, retry_count, timeout_sec`,
			pb.ID, order, s.Name, s.ActionType, params, onFail, s.RetryCount, timeout,
		).Scan(&step.ID, &step.PlaybookID, &step.StepOrder, &step.Name, &step.ActionType,
			&paramsRaw, &step.OnFailure, &step.RetryCount, &step.TimeoutSec)
		if err != nil {
			return nil, err
		}
		_ = json.Unmarshal(paramsRaw, &step.ActionParams)
		pb.Steps = append(pb.Steps, step)
	}

	return &pb, tx.Commit(ctx)
}

func (r *SOARRepository) GetPlaybook(ctx context.Context, tenantID, playbookID uuid.UUID) (*model.Playbook, error) {
	var pb model.Playbook
	var condsRaw []byte
	err := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, name, COALESCE(description,''), trigger_type, trigger_conditions,
		       is_active, run_count, success_count, failure_count, last_run_at, created_by, created_at, updated_at
		FROM soar_playbooks WHERE id=$1 AND tenant_id=$2`, playbookID, tenantID,
	).Scan(&pb.ID, &pb.TenantID, &pb.Name, &pb.Description, &pb.TriggerType, &condsRaw,
		&pb.IsActive, &pb.RunCount, &pb.SuccessCount, &pb.FailureCount, &pb.LastRunAt, &pb.CreatedBy, &pb.CreatedAt, &pb.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(condsRaw, &pb.TriggerConditions)

	steps, err := r.getSteps(ctx, playbookID)
	if err != nil {
		return nil, err
	}
	pb.Steps = steps
	return &pb, nil
}

func (r *SOARRepository) ListPlaybooks(ctx context.Context, tenantID uuid.UUID, activeOnly bool) ([]*model.Playbook, error) {
	q := `SELECT id, tenant_id, name, COALESCE(description,''), trigger_type, trigger_conditions,
	             is_active, run_count, success_count, failure_count, last_run_at, created_by, created_at, updated_at
	      FROM soar_playbooks WHERE tenant_id=$1`
	if activeOnly {
		q += " AND is_active = TRUE"
	}
	q += " ORDER BY created_at DESC"

	rows, err := r.db.Query(ctx, q, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var playbooks []*model.Playbook
	for rows.Next() {
		var pb model.Playbook
		var condsRaw []byte
		if err := rows.Scan(&pb.ID, &pb.TenantID, &pb.Name, &pb.Description, &pb.TriggerType, &condsRaw,
			&pb.IsActive, &pb.RunCount, &pb.SuccessCount, &pb.FailureCount, &pb.LastRunAt, &pb.CreatedBy, &pb.CreatedAt, &pb.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(condsRaw, &pb.TriggerConditions)
		playbooks = append(playbooks, &pb)
	}
	return playbooks, rows.Err()
}

func (r *SOARRepository) SetPlaybookActive(ctx context.Context, tenantID, playbookID uuid.UUID, active bool) error {
	_, err := r.db.Exec(ctx,
		`UPDATE soar_playbooks SET is_active=$1, updated_at=NOW() WHERE id=$2 AND tenant_id=$3`,
		active, playbookID, tenantID)
	return err
}

func (r *SOARRepository) getSteps(ctx context.Context, playbookID uuid.UUID) ([]model.PlaybookStep, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, playbook_id, step_order, name, action_type, action_params, on_failure, retry_count, timeout_sec
		FROM soar_playbook_steps WHERE playbook_id=$1 ORDER BY step_order`, playbookID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var steps []model.PlaybookStep
	for rows.Next() {
		var s model.PlaybookStep
		var paramsRaw []byte
		if err := rows.Scan(&s.ID, &s.PlaybookID, &s.StepOrder, &s.Name, &s.ActionType,
			&paramsRaw, &s.OnFailure, &s.RetryCount, &s.TimeoutSec); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(paramsRaw, &s.ActionParams)
		steps = append(steps, s)
	}
	return steps, rows.Err()
}

// FindMatchingPlaybooks returns active playbooks whose trigger_type and conditions match.
func (r *SOARRepository) FindMatchingPlaybooks(ctx context.Context, tenantID uuid.UUID, triggerType, severity, sourceService string) ([]*model.Playbook, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id FROM soar_playbooks
		WHERE tenant_id=$1 AND is_active=TRUE AND trigger_type=$2
		  AND (
		      trigger_conditions->>'severity' IS NULL
		      OR trigger_conditions->'severity' ? $3
		  )
		  AND (
		      trigger_conditions->>'source_service' IS NULL
		      OR trigger_conditions->>'source_service' = $4
		  )`,
		tenantID, triggerType, severity, sourceService)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var playbooks []*model.Playbook
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		pb, err := r.GetPlaybook(ctx, tenantID, id)
		if err != nil || pb == nil {
			continue
		}
		playbooks = append(playbooks, pb)
	}
	return playbooks, rows.Err()
}

// ─── Executions ───────────────────────────────────────────────────────────────

func (r *SOARRepository) CreateExecution(ctx context.Context, tenantID, playbookID uuid.UUID, incidentID *uuid.UUID, triggerEvent map[string]any, triggeredBy *uuid.UUID, stepsTotal int) (*model.Execution, error) {
	evJSON, _ := json.Marshal(triggerEvent)
	now := time.Now().UTC()
	var exec model.Execution
	var evRaw []byte
	err := r.db.QueryRow(ctx, `
		INSERT INTO soar_executions
		    (tenant_id, playbook_id, incident_id, trigger_event, status, steps_total, triggered_by, started_at)
		VALUES ($1,$2,$3,$4,'running',$5,$6,$7)
		RETURNING id, tenant_id, playbook_id, incident_id, trigger_event, status,
		          steps_total, steps_completed, steps_failed, result_summary,
		          COALESCE(error_message,''), triggered_by, started_at, completed_at, created_at`,
		tenantID, playbookID, incidentID, evJSON, stepsTotal, triggeredBy, now,
	).Scan(&exec.ID, &exec.TenantID, &exec.PlaybookID, &exec.IncidentID, &evRaw, &exec.Status,
		&exec.StepsTotal, &exec.StepsCompleted, &exec.StepsFailed, &evRaw,
		&exec.ErrorMessage, &exec.TriggeredBy, &exec.StartedAt, &exec.CompletedAt, &exec.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(evRaw, &exec.TriggerEvent)

	// Update playbook stats
	_, _ = r.db.Exec(ctx,
		`UPDATE soar_playbooks SET run_count=run_count+1, last_run_at=NOW(), updated_at=NOW() WHERE id=$1`,
		playbookID)
	return &exec, nil
}

func (r *SOARRepository) CreateExecutionStep(ctx context.Context, execID, stepID uuid.UUID, stepOrder int, actionType string) (*model.ExecutionStep, error) {
	var s model.ExecutionStep
	err := r.db.QueryRow(ctx, `
		INSERT INTO soar_execution_steps (execution_id, step_id, step_order, action_type, status)
		VALUES ($1,$2,$3,$4,'pending')
		RETURNING id, execution_id, step_id, step_order, action_type, status, output, COALESCE(error_message,''), attempts, started_at, completed_at`,
		execID, stepID, stepOrder, actionType,
	).Scan(&s.ID, &s.ExecutionID, &s.StepID, &s.StepOrder, &s.ActionType, &s.Status,
		new([]byte), &s.ErrorMessage, &s.Attempts, &s.StartedAt, &s.CompletedAt)
	return &s, err
}

func (r *SOARRepository) UpdateExecutionStep(ctx context.Context, stepID uuid.UUID, status string, output map[string]any, errMsg string) error {
	outJSON, _ := json.Marshal(output)
	now := time.Now().UTC()
	_, err := r.db.Exec(ctx, `
		UPDATE soar_execution_steps
		SET status=$1, output=$2, error_message=NULLIF($3,''), attempts=attempts+1,
		    started_at=COALESCE(started_at,$4), completed_at=$4
		WHERE id=$5`,
		status, outJSON, errMsg, now, stepID)
	return err
}

func (r *SOARRepository) CompleteExecution(ctx context.Context, execID uuid.UUID, status string, completed, failed int, summary map[string]any, errMsg string) error {
	sumJSON, _ := json.Marshal(summary)
	now := time.Now().UTC()
	_, err := r.db.Exec(ctx, `
		UPDATE soar_executions
		SET status=$1, steps_completed=$2, steps_failed=$3, result_summary=$4,
		    error_message=NULLIF($5,''), completed_at=$6
		WHERE id=$7`,
		status, completed, failed, sumJSON, errMsg, now, execID)
	if err != nil {
		return err
	}
	// Update playbook counters
	col := "success_count"
	if status == "failed" {
		col = "failure_count"
	}
	_, _ = r.db.Exec(ctx,
		`UPDATE soar_playbooks SET `+col+`=`+col+`+1, updated_at=NOW() WHERE id=(SELECT playbook_id FROM soar_executions WHERE id=$1)`,
		execID)
	return nil
}

func (r *SOARRepository) GetExecution(ctx context.Context, tenantID, execID uuid.UUID) (*model.Execution, error) {
	var exec model.Execution
	var evRaw, sumRaw []byte
	err := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, playbook_id, incident_id, trigger_event, status,
		       steps_total, steps_completed, steps_failed, result_summary,
		       COALESCE(error_message,''), triggered_by, started_at, completed_at, created_at
		FROM soar_executions WHERE id=$1 AND tenant_id=$2`, execID, tenantID,
	).Scan(&exec.ID, &exec.TenantID, &exec.PlaybookID, &exec.IncidentID, &evRaw, &exec.Status,
		&exec.StepsTotal, &exec.StepsCompleted, &exec.StepsFailed, &sumRaw,
		&exec.ErrorMessage, &exec.TriggeredBy, &exec.StartedAt, &exec.CompletedAt, &exec.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(evRaw, &exec.TriggerEvent)
	_ = json.Unmarshal(sumRaw, &exec.ResultSummary)

	// Load step results
	rows, err := r.db.Query(ctx, `
		SELECT id, execution_id, step_id, step_order, action_type, status,
		       output, COALESCE(error_message,''), attempts, started_at, completed_at
		FROM soar_execution_steps WHERE execution_id=$1 ORDER BY step_order`, execID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var s model.ExecutionStep
		var outRaw []byte
		if err := rows.Scan(&s.ID, &s.ExecutionID, &s.StepID, &s.StepOrder, &s.ActionType, &s.Status,
			&outRaw, &s.ErrorMessage, &s.Attempts, &s.StartedAt, &s.CompletedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(outRaw, &s.Output)
		exec.Steps = append(exec.Steps, s)
	}
	return &exec, rows.Err()
}

func (r *SOARRepository) ListExecutions(ctx context.Context, f model.ExecutionFilter) ([]*model.Execution, int, error) {
	where := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	idx := 2

	if f.PlaybookID != nil {
		where = append(where, fmt.Sprintf("playbook_id = $%d", idx))
		args = append(args, *f.PlaybookID)
		idx++
	}
	if f.IncidentID != nil {
		where = append(where, fmt.Sprintf("incident_id = $%d", idx))
		args = append(args, *f.IncidentID)
		idx++
	}
	if f.Status != "" {
		where = append(where, fmt.Sprintf("status = $%d", idx))
		args = append(args, f.Status)
		idx++
	}

	whereStr := strings.Join(where, " AND ")
	var total int
	if err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM soar_executions WHERE `+whereStr, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	args = append(args, limit, f.Offset)
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, playbook_id, incident_id, trigger_event, status,
		       steps_total, steps_completed, steps_failed, result_summary,
		       COALESCE(error_message,''), triggered_by, started_at, completed_at, created_at
		FROM soar_executions WHERE `+whereStr+
		fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, idx, idx+1),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var executions []*model.Execution
	for rows.Next() {
		var exec model.Execution
		var evRaw, sumRaw []byte
		if err := rows.Scan(&exec.ID, &exec.TenantID, &exec.PlaybookID, &exec.IncidentID, &evRaw, &exec.Status,
			&exec.StepsTotal, &exec.StepsCompleted, &exec.StepsFailed, &sumRaw,
			&exec.ErrorMessage, &exec.TriggeredBy, &exec.StartedAt, &exec.CompletedAt, &exec.CreatedAt); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal(evRaw, &exec.TriggerEvent)
		_ = json.Unmarshal(sumRaw, &exec.ResultSummary)
		executions = append(executions, &exec)
	}
	return executions, total, rows.Err()
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (r *SOARRepository) Stats(ctx context.Context, tenantID uuid.UUID) (*model.SOARStats, error) {
	s := &model.SOARStats{}
	today := time.Now().UTC().Truncate(24 * time.Hour)

	r.db.QueryRow(ctx, `
		SELECT
		    COUNT(*) FILTER (WHERE status NOT IN ('resolved','closed')),
		    COUNT(*) FILTER (WHERE severity='CRITICAL' AND status NOT IN ('resolved','closed')),
		    COUNT(*) FILTER (WHERE status='in_progress'),
		    COUNT(*) FILTER (WHERE resolved_at >= $2),
		    COUNT(*) FILTER (WHERE sla_due_at < NOW() AND status NOT IN ('resolved','closed'))
		FROM soar_incidents WHERE tenant_id=$1`,
		tenantID, today,
	).Scan(&s.OpenIncidents, &s.CriticalIncidents, &s.InProgressIncidents, &s.ResolvedToday, &s.SLABreached)

	r.db.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE is_active)
		FROM soar_playbooks WHERE tenant_id=$1`, tenantID,
	).Scan(&s.TotalPlaybooks, &s.ActivePlaybooks)

	r.db.QueryRow(ctx, `
		SELECT
		    COUNT(*),
		    COUNT(*) FILTER (WHERE status='completed'),
		    COUNT(*) FILTER (WHERE status='failed')
		FROM soar_executions WHERE tenant_id=$1 AND created_at >= $2`,
		tenantID, today,
	).Scan(&s.ExecutionsToday, &s.ExecutionSuccess, &s.ExecutionFailed)

	// MTTC and MTTR in hours
	r.db.QueryRow(ctx, `
		SELECT
		    COALESCE(AVG(EXTRACT(EPOCH FROM (contained_at - created_at))/3600) FILTER (WHERE contained_at IS NOT NULL), 0),
		    COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))/3600) FILTER (WHERE resolved_at IS NOT NULL), 0)
		FROM soar_incidents WHERE tenant_id=$1`, tenantID,
	).Scan(&s.MeanTimeToContain, &s.MeanTimeToResolve)

	return s, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

type scannable interface {
	Scan(...any) error
}

func scanIncident(row scannable) (*model.Incident, error) {
	var inc model.Incident
	var propsRaw []byte
	err := row.Scan(
		&inc.ID, &inc.TenantID, &inc.Title, &inc.Description, &inc.Severity, &inc.Status,
		&inc.SourceService, &inc.SourceEventID, &inc.AssigneeID,
		&inc.MitreTactics, &inc.MitreTechniques, &inc.AffectedAssets, &inc.IOCIDs,
		&inc.Tags, &propsRaw, &inc.SLADueAt, &inc.ContainedAt,
		&inc.ResolvedAt, &inc.ClosedAt, &inc.CreatedBy, &inc.CreatedAt, &inc.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(propsRaw, &inc.Properties)
	if inc.MitreTactics == nil {
		inc.MitreTactics = []string{}
	}
	if inc.MitreTechniques == nil {
		inc.MitreTechniques = []string{}
	}
	if inc.AffectedAssets == nil {
		inc.AffectedAssets = []uuid.UUID{}
	}
	if inc.IOCIDs == nil {
		inc.IOCIDs = []uuid.UUID{}
	}
	if inc.Tags == nil {
		inc.Tags = []string{}
	}
	return &inc, nil
}

func nvlS(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
