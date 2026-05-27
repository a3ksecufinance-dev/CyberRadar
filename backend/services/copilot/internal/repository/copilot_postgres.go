package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cyberradar/platform/services/copilot/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CopilotRepository handles copilot persistence.
type CopilotRepository struct {
	db *pgxpool.Pool
}

// NewCopilotRepository creates a CopilotRepository.
func NewCopilotRepository(db *pgxpool.Pool) *CopilotRepository {
	return &CopilotRepository{db: db}
}

// ─── Sessions ─────────────────────────────────────────────────────────────────

const sessionSelect = `id, tenant_id, user_id, COALESCE(title,''), context,
    is_active, message_count, last_message_at, created_at, updated_at`

func (r *CopilotRepository) CreateSession(ctx context.Context, tenantID, userID uuid.UUID, req *model.CreateSessionRequest) (*model.Session, error) {
	ctxJSON, _ := json.Marshal(req.Context)
	return scanSession(r.db.QueryRow(ctx, `
		INSERT INTO copilot_sessions (tenant_id, user_id, context)
		VALUES ($1,$2,$3)
		RETURNING `+sessionSelect,
		tenantID, userID, ctxJSON))
}

func (r *CopilotRepository) GetSession(ctx context.Context, tenantID, sessionID uuid.UUID) (*model.Session, error) {
	s, err := scanSession(r.db.QueryRow(ctx,
		`SELECT `+sessionSelect+` FROM copilot_sessions WHERE id=$1 AND tenant_id=$2`,
		sessionID, tenantID))
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return s, err
}

func (r *CopilotRepository) UpdateSessionTitle(ctx context.Context, sessionID uuid.UUID, title string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE copilot_sessions SET title=$1, updated_at=NOW() WHERE id=$2`,
		title, sessionID)
	return err
}

func (r *CopilotRepository) TouchSession(ctx context.Context, sessionID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		UPDATE copilot_sessions
		SET message_count=message_count+1, last_message_at=NOW(), updated_at=NOW()
		WHERE id=$1`, sessionID)
	return err
}

func (r *CopilotRepository) CloseSession(ctx context.Context, tenantID, sessionID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE copilot_sessions SET is_active=FALSE, updated_at=NOW() WHERE id=$1 AND tenant_id=$2`,
		sessionID, tenantID)
	return err
}

func (r *CopilotRepository) ListSessions(ctx context.Context, f model.SessionFilter) ([]*model.Session, int, error) {
	where := []string{"tenant_id=$1", "user_id=$2"}
	args := []any{f.TenantID, f.UserID}
	idx := 3

	if f.Active != nil {
		where = append(where, fmt.Sprintf("is_active=$%d", idx))
		args = append(args, *f.Active)
		idx++
	}

	whereStr := strings.Join(where, " AND ")
	var total int
	if err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM copilot_sessions WHERE `+whereStr, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 20
	}
	args = append(args, limit, f.Offset)
	rows, err := r.db.Query(ctx,
		`SELECT `+sessionSelect+` FROM copilot_sessions WHERE `+whereStr+
			fmt.Sprintf(` ORDER BY updated_at DESC LIMIT $%d OFFSET $%d`, idx, idx+1),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var sessions []*model.Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, 0, err
		}
		sessions = append(sessions, s)
	}
	return sessions, total, rows.Err()
}

// ─── Messages ─────────────────────────────────────────────────────────────────

func (r *CopilotRepository) SaveMessage(ctx context.Context, msg *model.Message) (*model.Message, error) {
	toolInput, _ := json.Marshal(msg.ToolInput)
	toolOutput, _ := json.Marshal(msg.ToolOutput)
	toolName := msg.ToolName

	var tiRaw, toRaw []byte
	err := r.db.QueryRow(ctx, `
		INSERT INTO copilot_messages
		    (session_id, tenant_id, role, content, tool_name, tool_input, tool_output,
		     input_tokens, output_tokens, latency_ms)
		VALUES ($1,$2,$3,$4,NULLIF($5,''),$6,$7,$8,$9,$10)
		RETURNING id, session_id, tenant_id, role, content,
		          COALESCE(tool_name,''), tool_input, tool_output,
		          input_tokens, output_tokens, latency_ms, created_at`,
		msg.SessionID, msg.TenantID, msg.Role, msg.Content,
		toolName, toolInput, toolOutput,
		msg.InputTokens, msg.OutputTokens, msg.LatencyMS,
	).Scan(&msg.ID, &msg.SessionID, &msg.TenantID, &msg.Role, &msg.Content,
		&msg.ToolName, &tiRaw, &toRaw,
		&msg.InputTokens, &msg.OutputTokens, &msg.LatencyMS, &msg.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(tiRaw, &msg.ToolInput)
	_ = json.Unmarshal(toRaw, &msg.ToolOutput)
	return msg, nil
}

// GetHistory returns the last N messages of a session in chronological order.
func (r *CopilotRepository) GetHistory(ctx context.Context, tenantID, sessionID uuid.UUID, limit int) ([]*model.Message, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := r.db.Query(ctx, `
		SELECT id, session_id, tenant_id, role, content,
		       COALESCE(tool_name,''), tool_input, tool_output,
		       input_tokens, output_tokens, latency_ms, created_at
		FROM copilot_messages
		WHERE session_id=$1 AND tenant_id=$2
		ORDER BY created_at DESC
		LIMIT $3`,
		sessionID, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var msgs []*model.Message
	for rows.Next() {
		var m model.Message
		var tiRaw, toRaw []byte
		if err := rows.Scan(&m.ID, &m.SessionID, &m.TenantID, &m.Role, &m.Content,
			&m.ToolName, &tiRaw, &toRaw,
			&m.InputTokens, &m.OutputTokens, &m.LatencyMS, &m.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(tiRaw, &m.ToolInput)
		_ = json.Unmarshal(toRaw, &m.ToolOutput)
		msgs = append(msgs, &m)
	}
	// Reverse to chronological order
	for i, j := 0, len(msgs)-1; i < j; i, j = i+1, j-1 {
		msgs[i], msgs[j] = msgs[j], msgs[i]
	}
	return msgs, rows.Err()
}

// ─── Hunt Jobs ────────────────────────────────────────────────────────────────

const jobSelect = `id, tenant_id, user_id, session_id, hunt_type, query, status,
    COALESCE(result_summary,''), result_payload, COALESCE(error_message,''),
    input_tokens, output_tokens, started_at, completed_at, created_at`

func (r *CopilotRepository) CreateHuntJob(ctx context.Context, tenantID, userID uuid.UUID, req *model.CreateHuntJobRequest) (*model.HuntJob, error) {
	return scanJob(r.db.QueryRow(ctx, `
		INSERT INTO copilot_hunt_jobs (tenant_id, user_id, session_id, hunt_type, query)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING `+jobSelect,
		tenantID, userID, req.SessionID, req.HuntType, req.Query))
}

func (r *CopilotRepository) GetHuntJob(ctx context.Context, tenantID, jobID uuid.UUID) (*model.HuntJob, error) {
	j, err := scanJob(r.db.QueryRow(ctx,
		`SELECT `+jobSelect+` FROM copilot_hunt_jobs WHERE id=$1 AND tenant_id=$2`,
		jobID, tenantID))
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return j, err
}

func (r *CopilotRepository) UpdateHuntJob(ctx context.Context, jobID uuid.UUID, status, summary, errMsg string, payload map[string]any, inputTok, outputTok int) error {
	payJSON, _ := json.Marshal(payload)
	now := time.Now().UTC()
	var startedAt *time.Time
	if status == "running" {
		startedAt = &now
	}
	var completedAt *time.Time
	if status == "completed" || status == "failed" {
		completedAt = &now
	}
	_, err := r.db.Exec(ctx, `
		UPDATE copilot_hunt_jobs
		SET status=$1, result_summary=NULLIF($2,''), result_payload=$3,
		    error_message=NULLIF($4,''), input_tokens=$5, output_tokens=$6,
		    started_at=COALESCE(started_at,$7), completed_at=$8
		WHERE id=$9`,
		status, summary, payJSON, errMsg, inputTok, outputTok,
		startedAt, completedAt, jobID)
	return err
}

func (r *CopilotRepository) ListHuntJobs(ctx context.Context, tenantID, userID uuid.UUID, limit, offset int) ([]*model.HuntJob, int, error) {
	var total int
	r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM copilot_hunt_jobs WHERE tenant_id=$1 AND user_id=$2`,
		tenantID, userID).Scan(&total)

	if limit <= 0 {
		limit = 20
	}
	rows, err := r.db.Query(ctx,
		`SELECT `+jobSelect+` FROM copilot_hunt_jobs WHERE tenant_id=$1 AND user_id=$2 ORDER BY created_at DESC LIMIT $3 OFFSET $4`,
		tenantID, userID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var jobs []*model.HuntJob
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, 0, err
		}
		jobs = append(jobs, j)
	}
	return jobs, total, rows.Err()
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (r *CopilotRepository) Stats(ctx context.Context, tenantID uuid.UUID) (*model.CopilotStats, error) {
	s := &model.CopilotStats{}
	r.db.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE is_active)
		FROM copilot_sessions WHERE tenant_id=$1`, tenantID,
	).Scan(&s.TotalSessions, &s.ActiveSessions)

	r.db.QueryRow(ctx, `
		SELECT COUNT(*), COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0)
		FROM copilot_messages WHERE tenant_id=$1`, tenantID,
	).Scan(&s.TotalMessages, &s.TotalInputTokens, &s.TotalOutputTokens)

	r.db.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE status='pending')
		FROM copilot_hunt_jobs WHERE tenant_id=$1`, tenantID,
	).Scan(&s.TotalHuntJobs, &s.PendingJobs)

	return s, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

type scannable interface {
	Scan(...any) error
}

func scanSession(row scannable) (*model.Session, error) {
	var s model.Session
	var ctxRaw []byte
	err := row.Scan(
		&s.ID, &s.TenantID, &s.UserID, &s.Title, &ctxRaw,
		&s.IsActive, &s.MessageCount, &s.LastMessageAt, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(ctxRaw, &s.Context)
	return &s, nil
}

func scanJob(row scannable) (*model.HuntJob, error) {
	var j model.HuntJob
	var payRaw []byte
	err := row.Scan(
		&j.ID, &j.TenantID, &j.UserID, &j.SessionID, &j.HuntType, &j.Query, &j.Status,
		&j.ResultSummary, &payRaw, &j.ErrorMessage,
		&j.InputTokens, &j.OutputTokens, &j.StartedAt, &j.CompletedAt, &j.CreatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(payRaw, &j.ResultPayload)
	return &j, nil
}
