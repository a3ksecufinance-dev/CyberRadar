package repository

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/cyberradar/platform/services/audit/internal/model"
	"github.com/google/uuid"
)

// AuditRepository writes and reads audit logs from ClickHouse.
// SECURITY: Write is the only mutating operation — no UPDATE, no DELETE.
type AuditRepository struct {
	conn driver.Conn
}

// NewAuditRepository creates an AuditRepository.
func NewAuditRepository(conn driver.Conn) *AuditRepository {
	return &AuditRepository{conn: conn}
}

// Write inserts an audit event. This operation is irreversible.
func (r *AuditRepository) Write(ctx context.Context, event *model.AuditEvent) error {
	if event.ID == uuid.Nil {
		event.ID = uuid.New()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Compute integrity checksum
	event.Checksum = computeChecksum(event)

	batch, err := r.conn.PrepareBatch(ctx,
		`INSERT INTO crp_audit.audit_logs (
			id, tenant_id, timestamp,
			actor_id, actor_type, actor_email,
			action, resource_type, resource_id,
			ip_address, user_agent, session_id, request_id,
			result, details, checksum
		)`)
	if err != nil {
		return fmt.Errorf("prepare audit batch: %w", err)
	}

	err = batch.Append(
		event.ID,
		event.TenantID,
		event.Timestamp,
		event.ActorID,
		event.ActorType,
		event.ActorEmail,
		event.Action,
		event.ResourceType,
		event.ResourceID,
		event.IPAddress,
		event.UserAgent,
		event.SessionID,
		event.RequestID,
		event.Result,
		event.Details,
		event.Checksum,
	)
	if err != nil {
		return fmt.Errorf("append audit event: %w", err)
	}

	return batch.Send()
}

// WriteBatch inserts multiple audit events atomically.
func (r *AuditRepository) WriteBatch(ctx context.Context, events []*model.AuditEvent) error {
	batch, err := r.conn.PrepareBatch(ctx,
		`INSERT INTO crp_audit.audit_logs (
			id, tenant_id, timestamp,
			actor_id, actor_type, actor_email,
			action, resource_type, resource_id,
			ip_address, user_agent, session_id, request_id,
			result, details, checksum
		)`)
	if err != nil {
		return fmt.Errorf("prepare audit batch: %w", err)
	}

	for _, event := range events {
		if event.ID == uuid.Nil {
			event.ID = uuid.New()
		}
		if event.Timestamp.IsZero() {
			event.Timestamp = time.Now().UTC()
		}
		event.Checksum = computeChecksum(event)

		if err := batch.Append(
			event.ID, event.TenantID, event.Timestamp,
			event.ActorID, event.ActorType, event.ActorEmail,
			event.Action, event.ResourceType, event.ResourceID,
			event.IPAddress, event.UserAgent, event.SessionID, event.RequestID,
			event.Result, event.Details, event.Checksum,
		); err != nil {
			return fmt.Errorf("append event %s: %w", event.ID, err)
		}
	}

	return batch.Send()
}

// Search queries audit logs with filters. Read-only.
func (r *AuditRepository) Search(ctx context.Context, f *model.AuditEventFilter) ([]*model.AuditEvent, int64, error) {
	where := "tenant_id = {tenant_id:String}"
	args := map[string]any{"tenant_id": f.TenantID}

	if f.ActorID != "" {
		where += " AND actor_id = {actor_id:String}"
		args["actor_id"] = f.ActorID
	}
	if f.Action != "" {
		where += " AND action = {action:String}"
		args["action"] = f.Action
	}
	if f.ResourceType != "" {
		where += " AND resource_type = {resource_type:String}"
		args["resource_type"] = f.ResourceType
	}
	if f.ResourceID != "" {
		where += " AND resource_id = {resource_id:String}"
		args["resource_id"] = f.ResourceID
	}
	if f.Result != "" {
		where += " AND result = {result:String}"
		args["result"] = f.Result
	}
	if f.From != nil {
		where += " AND timestamp >= {from:DateTime64(3)}"
		args["from"] = *f.From
	}
	if f.To != nil {
		where += " AND timestamp <= {to:DateTime64(3)}"
		args["to"] = *f.To
	}

	// Count — ClickHouse is fast enough for count with the partition key set
	var total uint64
	countQ := fmt.Sprintf("SELECT COUNT(*) FROM crp_audit.audit_logs WHERE %s", where)
	if err := r.conn.QueryRow(ctx, countQ, args).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count audit events: %w", err)
	}

	offset := (f.Page - 1) * f.Limit
	listQ := fmt.Sprintf(`
		SELECT id, tenant_id, timestamp,
		       actor_id, actor_type, actor_email,
		       action, resource_type, resource_id,
		       ip_address, user_agent, session_id, request_id,
		       result, details, checksum
		FROM crp_audit.audit_logs
		WHERE %s
		ORDER BY timestamp DESC
		LIMIT %d OFFSET %d`, where, f.Limit, offset)

	rows, err := r.conn.Query(ctx, listQ, args)
	if err != nil {
		return nil, 0, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()

	var events []*model.AuditEvent
	for rows.Next() {
		var e model.AuditEvent
		var actorType, result string
		if err := rows.Scan(
			&e.ID, &e.TenantID, &e.Timestamp,
			&e.ActorID, &actorType, &e.ActorEmail,
			&e.Action, &e.ResourceType, &e.ResourceID,
			&e.IPAddress, &e.UserAgent, &e.SessionID, &e.RequestID,
			&result, &e.Details, &e.Checksum,
		); err != nil {
			return nil, 0, fmt.Errorf("scan audit event: %w", err)
		}
		e.ActorType = actorType
		e.Result = result
		events = append(events, &e)
	}

	return events, int64(total), rows.Err()
}

// computeChecksum creates a SHA-256 checksum over the canonical audit fields.
// This allows forensic verification that a log entry has not been tampered with.
func computeChecksum(e *model.AuditEvent) string {
	canonical := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s",
		e.TenantID,
		e.Timestamp.UTC().Format(time.RFC3339Nano),
		e.ActorID,
		e.ActorType,
		e.Action,
		e.ResourceType,
		e.ResourceID,
		e.Result,
	)
	h := sha256.Sum256([]byte(canonical))
	return fmt.Sprintf("%x", h)
}
