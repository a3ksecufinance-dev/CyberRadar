package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cyberradar/platform/services/ir/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type IRRepository struct {
	db *pgxpool.Pool
}

func NewIRRepository(pool *pgxpool.Pool) *IRRepository {
	return &IRRepository{db: pool}
}

// ─── Incident number generation ───────────────────────────────────────────────

func (r *IRRepository) nextIncidentNumber(ctx context.Context, tenantID uuid.UUID) (string, error) {
	year := time.Now().UTC().Year()
	prefix := fmt.Sprintf("INC-%d-", year)
	var maxNum int
	err := r.db.QueryRow(ctx,
		`SELECT COALESCE(MAX(CAST(SUBSTRING(incident_number FROM '\d+$') AS INTEGER)), 0)
		 FROM ir_incidents WHERE tenant_id=$1 AND incident_number LIKE $2`,
		tenantID, prefix+"%",
	).Scan(&maxNum)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%05d", prefix, maxNum+1), nil
}

// ─── Playbooks ────────────────────────────────────────────────────────────────

func (r *IRRepository) CreatePlaybook(ctx context.Context, tenantID uuid.UUID, req *model.CreatePlaybookRequest, createdBy *uuid.UUID) (*model.IRPlaybook, error) {
	tasks, _ := json.Marshal(req.Tasks)
	sev := req.Severity
	if sev == "" {
		sev = "high"
	}
	var pb model.IRPlaybook
	var tasksRaw []byte
	err := r.db.QueryRow(ctx,
		`INSERT INTO ir_playbooks
		 (tenant_id,name,description,incident_type,severity,tasks,estimated_hours,created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		 RETURNING id,tenant_id,name,description,incident_type,severity,tasks,
		           estimated_hours,is_active,version,created_by,created_at,updated_at`,
		tenantID, req.Name, req.Description, req.IncidentType, sev,
		tasks, req.EstimatedHours, createdBy,
	).Scan(&pb.ID, &pb.TenantID, &pb.Name, &pb.Description, &pb.IncidentType, &pb.Severity,
		&tasksRaw, &pb.EstimatedHours, &pb.IsActive, &pb.Version, &pb.CreatedBy,
		&pb.CreatedAt, &pb.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(tasksRaw, &pb.Tasks)
	return &pb, nil
}

func (r *IRRepository) GetPlaybook(ctx context.Context, tenantID, id uuid.UUID) (*model.IRPlaybook, error) {
	var pb model.IRPlaybook
	var tasksRaw []byte
	err := r.db.QueryRow(ctx,
		`SELECT id,tenant_id,name,description,incident_type,severity,tasks,
		        estimated_hours,is_active,version,created_by,created_at,updated_at
		 FROM ir_playbooks WHERE tenant_id=$1 AND id=$2`,
		tenantID, id,
	).Scan(&pb.ID, &pb.TenantID, &pb.Name, &pb.Description, &pb.IncidentType, &pb.Severity,
		&tasksRaw, &pb.EstimatedHours, &pb.IsActive, &pb.Version, &pb.CreatedBy,
		&pb.CreatedAt, &pb.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	_ = json.Unmarshal(tasksRaw, &pb.Tasks)
	return &pb, nil
}

func (r *IRRepository) ListPlaybooks(ctx context.Context, tenantID uuid.UUID, incidentType string) ([]model.IRPlaybook, error) {
	cond := []string{"tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if incidentType != "" {
		cond = append(cond, fmt.Sprintf("incident_type=$%d", n))
		args = append(args, incidentType)
		n++
	}
	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,name,description,incident_type,severity,tasks,
		        estimated_hours,is_active,version,created_by,created_at,updated_at
		 FROM ir_playbooks WHERE `+strings.Join(cond, " AND ")+
			` ORDER BY incident_type,name`,
		args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pbs []model.IRPlaybook
	for rows.Next() {
		var pb model.IRPlaybook
		var tasksRaw []byte
		if err := rows.Scan(&pb.ID, &pb.TenantID, &pb.Name, &pb.Description, &pb.IncidentType, &pb.Severity,
			&tasksRaw, &pb.EstimatedHours, &pb.IsActive, &pb.Version, &pb.CreatedBy,
			&pb.CreatedAt, &pb.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(tasksRaw, &pb.Tasks)
		pbs = append(pbs, pb)
	}
	return pbs, nil
}

func (r *IRRepository) UpdatePlaybook(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdatePlaybookRequest) (*model.IRPlaybook, error) {
	sets := []string{"updated_at=NOW()", "version=version+1"}
	args := []any{tenantID, id}
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
	if req.Severity != nil {
		sets = append(sets, fmt.Sprintf("severity=$%d", n))
		args = append(args, *req.Severity)
		n++
	}
	if req.Tasks != nil {
		tasks, _ := json.Marshal(req.Tasks)
		sets = append(sets, fmt.Sprintf("tasks=$%d", n))
		args = append(args, tasks)
		n++
	}
	if req.EstimatedHours != nil {
		sets = append(sets, fmt.Sprintf("estimated_hours=$%d", n))
		args = append(args, *req.EstimatedHours)
		n++
	}
	if req.IsActive != nil {
		sets = append(sets, fmt.Sprintf("is_active=$%d", n))
		args = append(args, *req.IsActive)
		n++
	}
	var pb model.IRPlaybook
	var tasksRaw []byte
	err := r.db.QueryRow(ctx,
		`UPDATE ir_playbooks SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND id=$2
		 RETURNING id,tenant_id,name,description,incident_type,severity,tasks,
		           estimated_hours,is_active,version,created_by,created_at,updated_at`,
		args...,
	).Scan(&pb.ID, &pb.TenantID, &pb.Name, &pb.Description, &pb.IncidentType, &pb.Severity,
		&tasksRaw, &pb.EstimatedHours, &pb.IsActive, &pb.Version, &pb.CreatedBy,
		&pb.CreatedAt, &pb.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(tasksRaw, &pb.Tasks)
	return &pb, nil
}

// ─── Incidents ────────────────────────────────────────────────────────────────

func (r *IRRepository) CreateIncident(ctx context.Context, tenantID uuid.UUID, req *model.CreateIncidentRequest, createdBy *uuid.UUID) (*model.IRIncident, error) {
	number, err := r.nextIncidentNumber(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	prio := req.Priority
	if prio == 0 {
		prio = 2
	}
	detectedAt := time.Now().UTC()
	if req.DetectedAt != nil {
		detectedAt = *req.DetectedAt
	}
	iocs, _ := json.Marshal([]any{})
	tags := req.Tags
	if tags == nil {
		tags = []string{}
	}
	affected := req.AffectedSystems
	if affected == nil {
		affected = []string{}
	}
	affUsers := req.AffectedUsers
	if affUsers == nil {
		affUsers = []string{}
	}
	affData := req.AffectedData
	if affData == nil {
		affData = []string{}
	}
	var inc model.IRIncident
	var iocsRaw []byte
	err = r.db.QueryRow(ctx,
		`INSERT INTO ir_incidents
		 (tenant_id,incident_number,title,description,incident_type,severity,priority,
		  source,source_ref,affected_systems,affected_users,affected_data,
		  attack_vector,iocs,mitre_tactics,mitre_techniques,team_members,
		  playbook_id,detected_at,tags,created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
		 RETURNING id,tenant_id,incident_number,title,COALESCE(description,'') AS description,incident_type,severity,status,priority,
		           COALESCE(source,'') AS source,COALESCE(source_ref,'') AS source_ref,affected_systems,affected_users,affected_data,
		           is_contained,data_exfiltrated,COALESCE(estimated_impact,'') AS estimated_impact,COALESCE(attack_vector,'') AS attack_vector,iocs,
		           mitre_tactics,mitre_techniques,lead_id,COALESCE(lead_name,'') AS lead_name,team_members,
		           playbook_id,detected_at,reported_at,contained_at,eradicated_at,
		           recovered_at,closed_at,mttd_minutes,mttr_minutes,
		           requires_notification,notification_sent_at,tags,created_by,created_at,updated_at`,
		tenantID, number, req.Title, req.Description, req.IncidentType, req.Severity, prio,
		req.Source, req.SourceRef, affected, affUsers, affData,
		req.AttackVector, iocs, []string{}, []string{}, []string{},
		req.PlaybookID, detectedAt, tags, createdBy,
	).Scan(
		&inc.ID, &inc.TenantID, &inc.IncidentNumber, &inc.Title, &inc.Description,
		&inc.IncidentType, &inc.Severity, &inc.Status, &inc.Priority,
		&inc.Source, &inc.SourceRef, &inc.AffectedSystems, &inc.AffectedUsers, &inc.AffectedData,
		&inc.IsContained, &inc.DataExfiltrated, &inc.EstimatedImpact, &inc.AttackVector, &iocsRaw,
		&inc.MITRETactics, &inc.MITRETechniques, &inc.LeadID, &inc.LeadName, &inc.TeamMembers,
		&inc.PlaybookID, &inc.DetectedAt, &inc.ReportedAt, &inc.ContainedAt, &inc.EradicatedAt,
		&inc.RecoveredAt, &inc.ClosedAt, &inc.MTTDMinutes, &inc.MTTRMinutes,
		&inc.RequiresNotification, &inc.NotificationSentAt, &inc.Tags,
		&inc.CreatedBy, &inc.CreatedAt, &inc.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(iocsRaw, &inc.IOCs)
	return &inc, nil
}

func (r *IRRepository) GetIncident(ctx context.Context, tenantID, id uuid.UUID) (*model.IRIncident, error) {
	var inc model.IRIncident
	var iocsRaw []byte
	err := r.db.QueryRow(ctx,
		`SELECT i.id,i.tenant_id,i.incident_number,i.title,COALESCE(i.description,'') AS description,i.incident_type,
		        i.severity,i.status,i.priority,COALESCE(i.source,'') AS source,COALESCE(i.source_ref,'') AS source_ref,
		        i.affected_systems,i.affected_users,i.affected_data,
		        i.is_contained,i.data_exfiltrated,COALESCE(i.estimated_impact,'') AS estimated_impact,COALESCE(i.attack_vector,'') AS attack_vector,i.iocs,
		        i.mitre_tactics,i.mitre_techniques,i.lead_id,COALESCE(i.lead_name,'') AS lead_name,i.team_members,
		        i.playbook_id,i.detected_at,i.reported_at,i.contained_at,i.eradicated_at,
		        i.recovered_at,i.closed_at,i.mttd_minutes,i.mttr_minutes,
		        i.requires_notification,i.notification_sent_at,i.tags,i.created_by,i.created_at,i.updated_at,
		        COUNT(DISTINCT t.id) FILTER (WHERE t.id IS NOT NULL) AS task_count,
		        COUNT(DISTINCT tl.id) FILTER (WHERE tl.id IS NOT NULL) AS timeline_count,
		        COUNT(DISTINCT e.id) FILTER (WHERE e.id IS NOT NULL) AS evidence_count
		 FROM ir_incidents i
		 LEFT JOIN ir_tasks t ON t.incident_id=i.id
		 LEFT JOIN ir_timeline tl ON tl.incident_id=i.id
		 LEFT JOIN ir_evidence e ON e.incident_id=i.id
		 WHERE i.tenant_id=$1 AND i.id=$2
		 GROUP BY i.id`,
		tenantID, id,
	).Scan(
		&inc.ID, &inc.TenantID, &inc.IncidentNumber, &inc.Title, &inc.Description,
		&inc.IncidentType, &inc.Severity, &inc.Status, &inc.Priority,
		&inc.Source, &inc.SourceRef, &inc.AffectedSystems, &inc.AffectedUsers, &inc.AffectedData,
		&inc.IsContained, &inc.DataExfiltrated, &inc.EstimatedImpact, &inc.AttackVector, &iocsRaw,
		&inc.MITRETactics, &inc.MITRETechniques, &inc.LeadID, &inc.LeadName, &inc.TeamMembers,
		&inc.PlaybookID, &inc.DetectedAt, &inc.ReportedAt, &inc.ContainedAt, &inc.EradicatedAt,
		&inc.RecoveredAt, &inc.ClosedAt, &inc.MTTDMinutes, &inc.MTTRMinutes,
		&inc.RequiresNotification, &inc.NotificationSentAt, &inc.Tags,
		&inc.CreatedBy, &inc.CreatedAt, &inc.UpdatedAt,
		&inc.TaskCount, &inc.TimelineCount, &inc.EvidenceCount,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	_ = json.Unmarshal(iocsRaw, &inc.IOCs)
	return &inc, nil
}

func (r *IRRepository) ListIncidents(ctx context.Context, tenantID uuid.UUID, f model.ListIncidentsFilter) ([]model.IRIncident, int, error) {
	cond := []string{"i.tenant_id=$1"}
	args := []any{tenantID}
	n := 2
	if f.Status != "" {
		cond = append(cond, fmt.Sprintf("i.status=$%d", n))
		args = append(args, f.Status)
		n++
	}
	if f.Severity != "" {
		cond = append(cond, fmt.Sprintf("i.severity=$%d", n))
		args = append(args, f.Severity)
		n++
	}
	if f.IncidentType != "" {
		cond = append(cond, fmt.Sprintf("i.incident_type=$%d", n))
		args = append(args, f.IncidentType)
		n++
	}
	where := strings.Join(cond, " AND ")
	var total int
	_ = r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM ir_incidents i WHERE `+where, args...).Scan(&total)

	limit := f.Limit
	if limit == 0 {
		limit = 50
	}
	args = append(args, limit, f.Offset)
	rows, err := r.db.Query(ctx,
		`SELECT i.id,i.tenant_id,i.incident_number,i.title,COALESCE(i.description,'') AS description,i.incident_type,
		        i.severity,i.status,i.priority,COALESCE(i.source,'') AS source,COALESCE(i.source_ref,'') AS source_ref,
		        i.affected_systems,i.affected_users,i.affected_data,
		        i.is_contained,i.data_exfiltrated,COALESCE(i.estimated_impact,'') AS estimated_impact,COALESCE(i.attack_vector,'') AS attack_vector,i.iocs,
		        i.mitre_tactics,i.mitre_techniques,i.lead_id,COALESCE(i.lead_name,'') AS lead_name,i.team_members,
		        i.playbook_id,i.detected_at,i.reported_at,i.contained_at,i.eradicated_at,
		        i.recovered_at,i.closed_at,i.mttd_minutes,i.mttr_minutes,
		        i.requires_notification,i.notification_sent_at,i.tags,i.created_by,i.created_at,i.updated_at
		 FROM ir_incidents i WHERE `+where+
			fmt.Sprintf(` ORDER BY i.detected_at DESC LIMIT $%d OFFSET $%d`, n, n+1),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var incs []model.IRIncident
	for rows.Next() {
		var inc model.IRIncident
		var iocsRaw []byte
		if err := rows.Scan(
			&inc.ID, &inc.TenantID, &inc.IncidentNumber, &inc.Title, &inc.Description,
			&inc.IncidentType, &inc.Severity, &inc.Status, &inc.Priority,
			&inc.Source, &inc.SourceRef, &inc.AffectedSystems, &inc.AffectedUsers, &inc.AffectedData,
			&inc.IsContained, &inc.DataExfiltrated, &inc.EstimatedImpact, &inc.AttackVector, &iocsRaw,
			&inc.MITRETactics, &inc.MITRETechniques, &inc.LeadID, &inc.LeadName, &inc.TeamMembers,
			&inc.PlaybookID, &inc.DetectedAt, &inc.ReportedAt, &inc.ContainedAt, &inc.EradicatedAt,
			&inc.RecoveredAt, &inc.ClosedAt, &inc.MTTDMinutes, &inc.MTTRMinutes,
			&inc.RequiresNotification, &inc.NotificationSentAt, &inc.Tags,
			&inc.CreatedBy, &inc.CreatedAt, &inc.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal(iocsRaw, &inc.IOCs)
		incs = append(incs, inc)
	}
	return incs, total, nil
}

func (r *IRRepository) UpdateIncident(ctx context.Context, tenantID, id uuid.UUID, req *model.UpdateIncidentRequest) (*model.IRIncident, error) {
	// Fetch current incident for MTTD/MTTR computation
	curr, err := r.GetIncident(ctx, tenantID, id)
	if err != nil || curr == nil {
		return nil, err
	}

	sets := []string{"updated_at=NOW()"}
	args := []any{tenantID, id}
	n := 3

	addStr := func(col string, val *string) {
		if val != nil {
			sets = append(sets, fmt.Sprintf("%s=$%d", col, n))
			args = append(args, *val)
			n++
		}
	}
	addBool := func(col string, val *bool) {
		if val != nil {
			sets = append(sets, fmt.Sprintf("%s=$%d", col, n))
			args = append(args, *val)
			n++
		}
	}
	addInt := func(col string, val *int) {
		if val != nil {
			sets = append(sets, fmt.Sprintf("%s=$%d", col, n))
			args = append(args, *val)
			n++
		}
	}

	addStr("title", req.Title)
	addStr("description", req.Description)
	addStr("severity", req.Severity)
	addStr("estimated_impact", req.EstimatedImpact)
	addStr("attack_vector", req.AttackVector)
	addStr("lead_name", req.LeadName)
	addBool("is_contained", req.IsContained)
	addBool("data_exfiltrated", req.DataExfiltrated)
	addBool("requires_notification", req.RequiresNotification)
	addInt("priority", req.Priority)

	if req.LeadID != nil {
		sets = append(sets, fmt.Sprintf("lead_id=$%d", n))
		args = append(args, *req.LeadID)
		n++
	}
	if req.IOCs != nil {
		iocs, _ := json.Marshal(req.IOCs)
		sets = append(sets, fmt.Sprintf("iocs=$%d", n))
		args = append(args, iocs)
		n++
	}
	if req.MITRETactics != nil {
		sets = append(sets, fmt.Sprintf("mitre_tactics=$%d", n))
		args = append(args, req.MITRETactics)
		n++
	}
	if req.MITRETechniques != nil {
		sets = append(sets, fmt.Sprintf("mitre_techniques=$%d", n))
		args = append(args, req.MITRETechniques)
		n++
	}
	if req.TeamMembers != nil {
		sets = append(sets, fmt.Sprintf("team_members=$%d", n))
		args = append(args, req.TeamMembers)
		n++
	}
	if req.AffectedSystems != nil {
		sets = append(sets, fmt.Sprintf("affected_systems=$%d", n))
		args = append(args, req.AffectedSystems)
		n++
	}
	if req.AffectedUsers != nil {
		sets = append(sets, fmt.Sprintf("affected_users=$%d", n))
		args = append(args, req.AffectedUsers)
		n++
	}
	if req.Tags != nil {
		sets = append(sets, fmt.Sprintf("tags=$%d", n))
		args = append(args, req.Tags)
		n++
	}

	// Status transitions with timestamps
	if req.Status != nil {
		sets = append(sets, fmt.Sprintf("status=$%d", n))
		args = append(args, *req.Status)
		n++
		now := time.Now().UTC()
		switch *req.Status {
		case "contained":
			if curr.ContainedAt == nil {
				sets = append(sets, fmt.Sprintf("contained_at=$%d", n))
				args = append(args, now)
				n++
			}
		case "eradicated":
			if curr.EradicatedAt == nil {
				sets = append(sets, fmt.Sprintf("eradicated_at=$%d", n))
				args = append(args, now)
				n++
			}
		case "recovered":
			if curr.RecoveredAt == nil {
				sets = append(sets, fmt.Sprintf("recovered_at=$%d", n))
				args = append(args, now)
				n++
				// Compute MTTR: from detected_at to now
				mttr := int(now.Sub(curr.DetectedAt).Minutes())
				sets = append(sets, fmt.Sprintf("mttr_minutes=$%d", n))
				args = append(args, mttr)
				n++
			}
		case "closed", "false_positive":
			if curr.ClosedAt == nil {
				sets = append(sets, fmt.Sprintf("closed_at=$%d", n))
				args = append(args, now)
				n++
			}
		}
	}

	var inc model.IRIncident
	var iocsRaw []byte
	err = r.db.QueryRow(ctx,
		`UPDATE ir_incidents SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND id=$2
		 RETURNING id,tenant_id,incident_number,title,COALESCE(description,'') AS description,incident_type,
		           severity,status,priority,COALESCE(source,'') AS source,COALESCE(source_ref,'') AS source_ref,
		           affected_systems,affected_users,affected_data,
		           is_contained,data_exfiltrated,COALESCE(estimated_impact,'') AS estimated_impact,COALESCE(attack_vector,'') AS attack_vector,iocs,
		           mitre_tactics,mitre_techniques,lead_id,COALESCE(lead_name,'') AS lead_name,team_members,
		           playbook_id,detected_at,reported_at,contained_at,eradicated_at,
		           recovered_at,closed_at,mttd_minutes,mttr_minutes,
		           requires_notification,notification_sent_at,tags,created_by,created_at,updated_at`,
		args...,
	).Scan(
		&inc.ID, &inc.TenantID, &inc.IncidentNumber, &inc.Title, &inc.Description,
		&inc.IncidentType, &inc.Severity, &inc.Status, &inc.Priority,
		&inc.Source, &inc.SourceRef, &inc.AffectedSystems, &inc.AffectedUsers, &inc.AffectedData,
		&inc.IsContained, &inc.DataExfiltrated, &inc.EstimatedImpact, &inc.AttackVector, &iocsRaw,
		&inc.MITRETactics, &inc.MITRETechniques, &inc.LeadID, &inc.LeadName, &inc.TeamMembers,
		&inc.PlaybookID, &inc.DetectedAt, &inc.ReportedAt, &inc.ContainedAt, &inc.EradicatedAt,
		&inc.RecoveredAt, &inc.ClosedAt, &inc.MTTDMinutes, &inc.MTTRMinutes,
		&inc.RequiresNotification, &inc.NotificationSentAt, &inc.Tags,
		&inc.CreatedBy, &inc.CreatedAt, &inc.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(iocsRaw, &inc.IOCs)
	return &inc, nil
}

// ─── Timeline ─────────────────────────────────────────────────────────────────

func (r *IRRepository) AddTimelineEvent(ctx context.Context, tenantID, incidentID uuid.UUID, req *model.CreateTimelineEventRequest, createdBy *uuid.UUID) (*model.IRTimeline, error) {
	actorType := req.ActorType
	if actorType == "" {
		actorType = "analyst"
	}
	iocs := req.IOCs
	if iocs == nil {
		iocs = []string{}
	}
	var ev model.IRTimeline
	err := r.db.QueryRow(ctx,
		`INSERT INTO ir_timeline
		 (tenant_id,incident_id,event_time,event_type,title,description,actor,actor_type,
		  source_system,iocs,is_verified,created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		 RETURNING id,tenant_id,incident_id,event_time,event_type,title,description,
		           actor,actor_type,source_system,iocs,evidence_refs,is_verified,created_by,created_at`,
		tenantID, incidentID, req.EventTime, req.EventType, req.Title, req.Description,
		req.Actor, actorType, req.SourceSystem, iocs, req.IsVerified, createdBy,
	).Scan(&ev.ID, &ev.TenantID, &ev.IncidentID, &ev.EventTime, &ev.EventType,
		&ev.Title, &ev.Description, &ev.Actor, &ev.ActorType, &ev.SourceSystem,
		&ev.IOCs, &ev.EvidenceRefs, &ev.IsVerified, &ev.CreatedBy, &ev.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &ev, nil
}

func (r *IRRepository) GetTimeline(ctx context.Context, tenantID, incidentID uuid.UUID) ([]model.IRTimeline, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,incident_id,event_time,event_type,title,description,
		        actor,actor_type,source_system,iocs,evidence_refs,is_verified,created_by,created_at
		 FROM ir_timeline WHERE tenant_id=$1 AND incident_id=$2
		 ORDER BY event_time ASC`,
		tenantID, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var evs []model.IRTimeline
	for rows.Next() {
		var ev model.IRTimeline
		if err := rows.Scan(&ev.ID, &ev.TenantID, &ev.IncidentID, &ev.EventTime, &ev.EventType,
			&ev.Title, &ev.Description, &ev.Actor, &ev.ActorType, &ev.SourceSystem,
			&ev.IOCs, &ev.EvidenceRefs, &ev.IsVerified, &ev.CreatedBy, &ev.CreatedAt); err != nil {
			return nil, err
		}
		evs = append(evs, ev)
	}
	return evs, nil
}

// ─── Tasks ────────────────────────────────────────────────────────────────────

func (r *IRRepository) CreateTask(ctx context.Context, tenantID, incidentID uuid.UUID, req *model.CreateTaskRequest, createdBy *uuid.UUID) (*model.IRTask, error) {
	taskType := req.TaskType
	if taskType == "" {
		taskType = "action"
	}
	phase := req.Phase
	if phase == "" {
		phase = "investigation"
	}
	prio := req.Priority
	if prio == 0 {
		prio = 2
	}
	var t model.IRTask
	err := r.db.QueryRow(ctx,
		`INSERT INTO ir_tasks
		 (tenant_id,incident_id,title,description,task_type,phase,priority,
		  assigned_to,assigned_id,due_at,order_idx,created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		 RETURNING id,tenant_id,incident_id,title,description,task_type,phase,status,priority,
		           assigned_to,assigned_id,due_at,started_at,completed_at,completion_note,
		           order_idx,created_by,created_at,updated_at`,
		tenantID, incidentID, req.Title, req.Description, taskType, phase, prio,
		req.AssignedTo, req.AssignedID, req.DueAt, req.OrderIdx, createdBy,
	).Scan(&t.ID, &t.TenantID, &t.IncidentID, &t.Title, &t.Description,
		&t.TaskType, &t.Phase, &t.Status, &t.Priority,
		&t.AssignedTo, &t.AssignedID, &t.DueAt, &t.StartedAt, &t.CompletedAt, &t.CompletionNote,
		&t.OrderIdx, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *IRRepository) ListTasks(ctx context.Context, tenantID, incidentID uuid.UUID) ([]model.IRTask, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,incident_id,title,description,task_type,phase,status,priority,
		        assigned_to,assigned_id,due_at,started_at,completed_at,completion_note,
		        order_idx,created_by,created_at,updated_at
		 FROM ir_tasks WHERE tenant_id=$1 AND incident_id=$2
		 ORDER BY order_idx ASC, created_at ASC`,
		tenantID, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tasks []model.IRTask
	for rows.Next() {
		var t model.IRTask
		if err := rows.Scan(&t.ID, &t.TenantID, &t.IncidentID, &t.Title, &t.Description,
			&t.TaskType, &t.Phase, &t.Status, &t.Priority,
			&t.AssignedTo, &t.AssignedID, &t.DueAt, &t.StartedAt, &t.CompletedAt, &t.CompletionNote,
			&t.OrderIdx, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		tasks = append(tasks, t)
	}
	return tasks, nil
}

func (r *IRRepository) UpdateTask(ctx context.Context, tenantID, incidentID, taskID uuid.UUID, req *model.UpdateTaskRequest) (*model.IRTask, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{tenantID, incidentID, taskID}
	n := 4

	if req.Status != nil {
		sets = append(sets, fmt.Sprintf("status=$%d", n))
		args = append(args, *req.Status)
		n++
		now := time.Now().UTC()
		switch *req.Status {
		case "in_progress":
			sets = append(sets, fmt.Sprintf("started_at=COALESCE(started_at,$%d)", n))
			args = append(args, now)
			n++
		case "completed", "skipped":
			sets = append(sets, fmt.Sprintf("completed_at=COALESCE(completed_at,$%d)", n))
			args = append(args, now)
			n++
		}
	}
	if req.AssignedTo != nil {
		sets = append(sets, fmt.Sprintf("assigned_to=$%d", n))
		args = append(args, *req.AssignedTo)
		n++
	}
	if req.AssignedID != nil {
		sets = append(sets, fmt.Sprintf("assigned_id=$%d", n))
		args = append(args, *req.AssignedID)
		n++
	}
	if req.DueAt != nil {
		sets = append(sets, fmt.Sprintf("due_at=$%d", n))
		args = append(args, *req.DueAt)
		n++
	}
	if req.CompletionNote != nil {
		sets = append(sets, fmt.Sprintf("completion_note=$%d", n))
		args = append(args, *req.CompletionNote)
		n++
	}
	if req.Priority != nil {
		sets = append(sets, fmt.Sprintf("priority=$%d", n))
		args = append(args, *req.Priority)
		n++
	}

	var t model.IRTask
	err := r.db.QueryRow(ctx,
		`UPDATE ir_tasks SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND incident_id=$2 AND id=$3
		 RETURNING id,tenant_id,incident_id,title,description,task_type,phase,status,priority,
		           assigned_to,assigned_id,due_at,started_at,completed_at,completion_note,
		           order_idx,created_by,created_at,updated_at`,
		args...,
	).Scan(&t.ID, &t.TenantID, &t.IncidentID, &t.Title, &t.Description,
		&t.TaskType, &t.Phase, &t.Status, &t.Priority,
		&t.AssignedTo, &t.AssignedID, &t.DueAt, &t.StartedAt, &t.CompletedAt, &t.CompletionNote,
		&t.OrderIdx, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// InstantiatePlaybookTasks creates ir_tasks from a playbook's task templates
func (r *IRRepository) InstantiatePlaybookTasks(ctx context.Context, tenantID, incidentID, playbookID uuid.UUID, createdBy *uuid.UUID) error {
	pb, err := r.GetPlaybook(ctx, tenantID, playbookID)
	if err != nil || pb == nil {
		return err
	}
	for i, rawTask := range pb.Tasks {
		t, ok := rawTask.(map[string]any)
		if !ok {
			continue
		}
		title, _ := t["title"].(string)
		if title == "" {
			continue
		}
		desc, _ := t["description"].(string)
		taskType, _ := t["task_type"].(string)
		if taskType == "" {
			taskType = "action"
		}
		phase, _ := t["phase"].(string)
		if phase == "" {
			phase = "investigation"
		}
		_, err := r.db.Exec(ctx,
			`INSERT INTO ir_tasks
			 (tenant_id,incident_id,title,description,task_type,phase,order_idx,created_by)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			tenantID, incidentID, title, desc, taskType, phase, i, createdBy)
		if err != nil {
			return err
		}
	}
	return nil
}

// ─── Evidence ─────────────────────────────────────────────────────────────────

func (r *IRRepository) CreateEvidence(ctx context.Context, tenantID, incidentID uuid.UUID, req *model.CreateEvidenceRequest, createdBy *uuid.UUID) (*model.IREvidence, error) {
	tags := req.Tags
	if tags == nil {
		tags = []string{}
	}
	meta, _ := json.Marshal(req.Metadata)
	var ev model.IREvidence
	var metaRaw []byte
	err := r.db.QueryRow(ctx,
		`INSERT INTO ir_evidence
		 (tenant_id,incident_id,name,description,evidence_type,file_name,file_size,
		  file_hash_md5,file_hash_sha256,storage_path,collected_by,collection_method,
		  is_sensitive,tags,metadata)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		 RETURNING id,tenant_id,incident_id,name,description,evidence_type,
		           file_name,file_size,file_hash_md5,file_hash_sha256,storage_path,
		           collected_by,collected_at,collection_method,status,
		           analysis_notes,analyzed_by,analyzed_at,is_sensitive,tags,metadata,
		           created_at,updated_at`,
		tenantID, incidentID, req.Name, req.Description, req.EvidenceType,
		req.FileName, req.FileSize, req.FileHashMD5, req.FileHashSHA256, req.StoragePath,
		req.CollectedBy, req.CollectionMethod, req.IsSensitive, tags, meta,
	).Scan(&ev.ID, &ev.TenantID, &ev.IncidentID, &ev.Name, &ev.Description, &ev.EvidenceType,
		&ev.FileName, &ev.FileSize, &ev.FileHashMD5, &ev.FileHashSHA256, &ev.StoragePath,
		&ev.CollectedBy, &ev.CollectedAt, &ev.CollectionMethod, &ev.Status,
		&ev.AnalysisNotes, &ev.AnalyzedBy, &ev.AnalyzedAt, &ev.IsSensitive, &ev.Tags,
		&metaRaw, &ev.CreatedAt, &ev.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(metaRaw, &ev.Metadata)
	return &ev, nil
}

func (r *IRRepository) ListEvidence(ctx context.Context, tenantID, incidentID uuid.UUID) ([]model.IREvidence, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id,tenant_id,incident_id,name,description,evidence_type,
		        file_name,file_size,file_hash_md5,file_hash_sha256,storage_path,
		        collected_by,collected_at,collection_method,status,
		        analysis_notes,analyzed_by,analyzed_at,is_sensitive,tags,metadata,
		        created_at,updated_at
		 FROM ir_evidence WHERE tenant_id=$1 AND incident_id=$2
		 ORDER BY collected_at DESC`,
		tenantID, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var evs []model.IREvidence
	for rows.Next() {
		var ev model.IREvidence
		var metaRaw []byte
		if err := rows.Scan(&ev.ID, &ev.TenantID, &ev.IncidentID, &ev.Name, &ev.Description, &ev.EvidenceType,
			&ev.FileName, &ev.FileSize, &ev.FileHashMD5, &ev.FileHashSHA256, &ev.StoragePath,
			&ev.CollectedBy, &ev.CollectedAt, &ev.CollectionMethod, &ev.Status,
			&ev.AnalysisNotes, &ev.AnalyzedBy, &ev.AnalyzedAt, &ev.IsSensitive, &ev.Tags,
			&metaRaw, &ev.CreatedAt, &ev.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(metaRaw, &ev.Metadata)
		evs = append(evs, ev)
	}
	return evs, nil
}

func (r *IRRepository) UpdateEvidence(ctx context.Context, tenantID, incidentID, evidenceID uuid.UUID, req *model.UpdateEvidenceRequest) (*model.IREvidence, error) {
	sets := []string{"updated_at=NOW()"}
	args := []any{tenantID, incidentID, evidenceID}
	n := 4

	if req.Status != nil {
		sets = append(sets, fmt.Sprintf("status=$%d", n))
		args = append(args, *req.Status)
		n++
		if *req.Status == "analyzed" {
			sets = append(sets, fmt.Sprintf("analyzed_at=COALESCE(analyzed_at,$%d)", n))
			args = append(args, time.Now().UTC())
			n++
		}
	}
	if req.AnalysisNotes != nil {
		sets = append(sets, fmt.Sprintf("analysis_notes=$%d", n))
		args = append(args, *req.AnalysisNotes)
		n++
	}
	if req.AnalyzedBy != nil {
		sets = append(sets, fmt.Sprintf("analyzed_by=$%d", n))
		args = append(args, *req.AnalyzedBy)
		n++
	}

	var ev model.IREvidence
	var metaRaw []byte
	err := r.db.QueryRow(ctx,
		`UPDATE ir_evidence SET `+strings.Join(sets, ",")+
			` WHERE tenant_id=$1 AND incident_id=$2 AND id=$3
		 RETURNING id,tenant_id,incident_id,name,description,evidence_type,
		           file_name,file_size,file_hash_md5,file_hash_sha256,storage_path,
		           collected_by,collected_at,collection_method,status,
		           analysis_notes,analyzed_by,analyzed_at,is_sensitive,tags,metadata,
		           created_at,updated_at`,
		args...,
	).Scan(&ev.ID, &ev.TenantID, &ev.IncidentID, &ev.Name, &ev.Description, &ev.EvidenceType,
		&ev.FileName, &ev.FileSize, &ev.FileHashMD5, &ev.FileHashSHA256, &ev.StoragePath,
		&ev.CollectedBy, &ev.CollectedAt, &ev.CollectionMethod, &ev.Status,
		&ev.AnalysisNotes, &ev.AnalyzedBy, &ev.AnalyzedAt, &ev.IsSensitive, &ev.Tags,
		&metaRaw, &ev.CreatedAt, &ev.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(metaRaw, &ev.Metadata)
	return &ev, nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (r *IRRepository) GetStats(ctx context.Context, tenantID uuid.UUID) (*model.IRStats, error) {
	stats := &model.IRStats{
		ByStatus:   make(map[string]int),
		BySeverity: make(map[string]int),
		ByType:     make(map[string]int),
	}

	_ = r.db.QueryRow(ctx,
		`SELECT COUNT(*),
		        COUNT(*) FILTER (WHERE status NOT IN ('closed','false_positive')),
		        COUNT(*) FILTER (WHERE severity='critical' AND status NOT IN ('closed','false_positive')),
		        COALESCE(AVG(mttd_minutes) FILTER (WHERE mttd_minutes IS NOT NULL), 0),
		        COALESCE(AVG(mttr_minutes) FILTER (WHERE mttr_minutes IS NOT NULL), 0),
		        COUNT(*) FILTER (WHERE requires_notification AND notification_sent_at IS NULL)
		 FROM ir_incidents WHERE tenant_id=$1`, tenantID,
	).Scan(&stats.TotalIncidents, &stats.OpenIncidents, &stats.CriticalIncidents,
		&stats.AvgMTTDMinutes, &stats.AvgMTTRMinutes, &stats.RequireNotification)

	// By status
	rows, _ := r.db.Query(ctx,
		`SELECT status, COUNT(*) FROM ir_incidents WHERE tenant_id=$1 GROUP BY status`, tenantID)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var k string
			var v int
			_ = rows.Scan(&k, &v)
			stats.ByStatus[k] = v
		}
	}

	// By severity
	rows2, _ := r.db.Query(ctx,
		`SELECT severity, COUNT(*) FROM ir_incidents WHERE tenant_id=$1 GROUP BY severity`, tenantID)
	if rows2 != nil {
		defer rows2.Close()
		for rows2.Next() {
			var k string
			var v int
			_ = rows2.Scan(&k, &v)
			stats.BySeverity[k] = v
		}
	}

	// By type
	rows3, _ := r.db.Query(ctx,
		`SELECT incident_type, COUNT(*) FROM ir_incidents WHERE tenant_id=$1 GROUP BY incident_type`, tenantID)
	if rows3 != nil {
		defer rows3.Close()
		for rows3.Next() {
			var k string
			var v int
			_ = rows3.Scan(&k, &v)
			stats.ByType[k] = v
		}
	}

	// Counts
	_ = r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM ir_playbooks WHERE tenant_id=$1 AND is_active=true`, tenantID,
	).Scan(&stats.TotalPlaybooks)

	_ = r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM ir_evidence e
		 JOIN ir_incidents i ON i.id=e.incident_id WHERE e.tenant_id=$1`, tenantID,
	).Scan(&stats.TotalEvidence)

	// Recent incidents (last 5 open)
	recentRows, _ := r.db.Query(ctx,
		`SELECT id,tenant_id,incident_number,title,COALESCE(description,'') AS description,incident_type,
		        severity,status,priority,COALESCE(source,'') AS source,COALESCE(source_ref,'') AS source_ref,
		        affected_systems,affected_users,affected_data,
		        is_contained,data_exfiltrated,COALESCE(estimated_impact,'') AS estimated_impact,COALESCE(attack_vector,'') AS attack_vector,iocs,
		        mitre_tactics,mitre_techniques,lead_id,COALESCE(lead_name,'') AS lead_name,team_members,
		        playbook_id,detected_at,reported_at,contained_at,eradicated_at,
		        recovered_at,closed_at,mttd_minutes,mttr_minutes,
		        requires_notification,notification_sent_at,tags,created_by,created_at,updated_at
		 FROM ir_incidents WHERE tenant_id=$1 AND status NOT IN ('closed','false_positive')
		 ORDER BY detected_at DESC LIMIT 5`, tenantID)
	if recentRows != nil {
		defer recentRows.Close()
		for recentRows.Next() {
			var inc model.IRIncident
			var iocsRaw []byte
			if err := recentRows.Scan(
				&inc.ID, &inc.TenantID, &inc.IncidentNumber, &inc.Title, &inc.Description,
				&inc.IncidentType, &inc.Severity, &inc.Status, &inc.Priority,
				&inc.Source, &inc.SourceRef, &inc.AffectedSystems, &inc.AffectedUsers, &inc.AffectedData,
				&inc.IsContained, &inc.DataExfiltrated, &inc.EstimatedImpact, &inc.AttackVector, &iocsRaw,
				&inc.MITRETactics, &inc.MITRETechniques, &inc.LeadID, &inc.LeadName, &inc.TeamMembers,
				&inc.PlaybookID, &inc.DetectedAt, &inc.ReportedAt, &inc.ContainedAt, &inc.EradicatedAt,
				&inc.RecoveredAt, &inc.ClosedAt, &inc.MTTDMinutes, &inc.MTTRMinutes,
				&inc.RequiresNotification, &inc.NotificationSentAt, &inc.Tags,
				&inc.CreatedBy, &inc.CreatedAt, &inc.UpdatedAt,
			); err == nil {
				_ = json.Unmarshal(iocsRaw, &inc.IOCs)
				stats.RecentIncidents = append(stats.RecentIncidents, inc)
			}
		}
	}

	return stats, nil
}
