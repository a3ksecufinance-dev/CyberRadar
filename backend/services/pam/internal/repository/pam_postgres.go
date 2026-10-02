package repository

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cyberradar/platform/services/pam/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PAMRepository handles all PAM-related DB operations.
type PAMRepository struct {
	db *pgxpool.Pool
}

// NewPAMRepository creates a PAMRepository.
func NewPAMRepository(db *pgxpool.Pool) *PAMRepository {
	return &PAMRepository{db: db}
}

// ─── Privileged Accounts ──────────────────────────────────────────────────────

// CreateAccount registers a new privileged account.
func (r *PAMRepository) CreateAccount(ctx context.Context, tenantID uuid.UUID, req *model.CreateAccountRequest) (*model.PrivilegedAccount, error) {
	id := uuid.New()
	rotDays := req.RotationPolicyDays
	if rotDays == 0 {
		rotDays = 30
	}
	maxMin := req.MaxSessionMinutes
	if maxMin == 0 {
		maxMin = 60
	}

	const q = `
		INSERT INTO privileged_accounts (
			id, tenant_id, account_name, account_type,
			target_asset_id, target_asset_hostname, target_protocol,
			credential_ref, rotation_policy_days,
			requires_approval, max_session_minutes, allowed_roles
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING id, created_at, updated_at`

	var createdAt, updatedAt time.Time
	if err := r.db.QueryRow(ctx, q,
		id, tenantID, req.AccountName, req.AccountType,
		req.TargetAssetID, nvl(req.TargetAssetHostname), req.TargetProtocol,
		nvl(req.CredentialRef), rotDays,
		req.RequiresApproval, maxMin, req.AllowedRoles,
	).Scan(&id, &createdAt, &updatedAt); err != nil {
		return nil, fmt.Errorf("create privileged account: %w", err)
	}
	return r.GetAccount(ctx, tenantID, id)
}

// GetAccount fetches a privileged account by ID.
func (r *PAMRepository) GetAccount(ctx context.Context, tenantID, id uuid.UUID) (*model.PrivilegedAccount, error) {
	const q = `
		SELECT id, tenant_id, account_name, account_type,
		       target_asset_id, target_asset_hostname, target_protocol,
		       credential_stored, credential_ref,
		       last_rotated_at, rotation_policy_days, auto_rotate,
		       requires_approval, max_session_minutes, allowed_roles,
		       is_active, last_used_at, use_count, created_at, updated_at
		FROM privileged_accounts
		WHERE id = $1 AND tenant_id = $2`

	row := r.db.QueryRow(ctx, q, id, tenantID)
	return scanAccount(row)
}

// ListAccounts returns all active privileged accounts for a tenant.
func (r *PAMRepository) ListAccounts(ctx context.Context, tenantID uuid.UUID) ([]*model.PrivilegedAccount, error) {
	const q = `
		SELECT id, tenant_id, account_name, account_type,
		       target_asset_id, target_asset_hostname, target_protocol,
		       credential_stored, credential_ref,
		       last_rotated_at, rotation_policy_days, auto_rotate,
		       requires_approval, max_session_minutes, allowed_roles,
		       is_active, last_used_at, use_count, created_at, updated_at
		FROM privileged_accounts
		WHERE tenant_id = $1 AND is_active = true
		ORDER BY account_name`

	rows, err := r.db.Query(ctx, q, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*model.PrivilegedAccount
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// ─── Access Requests ──────────────────────────────────────────────────────────

// CreateRequest creates a JIT access request.
func (r *PAMRepository) CreateRequest(ctx context.Context, tenantID, requesterID uuid.UUID, req *model.CreateRequestRequest) (*model.AccessRequest, error) {
	id := uuid.New()
	const q = `
		INSERT INTO pam_access_requests
			(id, tenant_id, requester_id, privileged_account_id, target_asset_id,
			 reason, ticket_ref, requested_duration_min)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id, status, expires_at, created_at`

	ar := &model.AccessRequest{
		ID:                   id,
		TenantID:             tenantID,
		RequesterID:          requesterID,
		PrivilegedAccountID:  req.PrivilegedAccountID,
		TargetAssetID:        req.TargetAssetID,
		Reason:               req.Reason,
		TicketRef:            req.TicketRef,
		RequestedDurationMin: req.RequestedDurationMin,
	}

	if err := r.db.QueryRow(ctx, q,
		id, tenantID, requesterID, req.PrivilegedAccountID, req.TargetAssetID,
		req.Reason, nvl(req.TicketRef), req.RequestedDurationMin,
	).Scan(&ar.ID, &ar.Status, &ar.ExpiresAt, &ar.CreatedAt); err != nil {
		return nil, fmt.Errorf("create access request: %w", err)
	}
	return ar, nil
}

// GetRequest fetches an access request by ID.
func (r *PAMRepository) GetRequest(ctx context.Context, tenantID, requestID uuid.UUID) (*model.AccessRequest, error) {
	const q = `
		SELECT id, tenant_id, requester_id, privileged_account_id, target_asset_id,
		       reason, ticket_ref, requested_duration_min,
		       status, approver_id, approval_note,
		       valid_from, valid_until, expires_at, created_at, resolved_at
		FROM pam_access_requests
		WHERE id = $1 AND tenant_id = $2`

	row := r.db.QueryRow(ctx, q, requestID, tenantID)
	return scanRequest(row)
}

// ListRequests returns requests matching the filter.
func (r *PAMRepository) ListRequests(ctx context.Context, f model.AccessRequestFilter) ([]*model.AccessRequest, int, error) {
	where := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	n := 2

	if f.Status != "" {
		where = append(where, fmt.Sprintf("status = $%d", n))
		args = append(args, f.Status)
		n++
	}
	if f.RequesterID != nil {
		where = append(where, fmt.Sprintf("requester_id = $%d", n))
		args = append(args, *f.RequesterID)
		n++
	}

	wc := strings.Join(where, " AND ")
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	var total int
	if err := r.db.QueryRow(ctx, fmt.Sprintf("SELECT COUNT(*) FROM pam_access_requests WHERE %s", wc), args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	dataQ := fmt.Sprintf(`
		SELECT id, tenant_id, requester_id, privileged_account_id, target_asset_id,
		       reason, ticket_ref, requested_duration_min,
		       status, approver_id, approval_note,
		       valid_from, valid_until, expires_at, created_at, resolved_at
		FROM pam_access_requests WHERE %s
		ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, wc, n, n+1)
	args = append(args, limit, f.Offset)

	rows, err := r.db.Query(ctx, dataQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []*model.AccessRequest
	for rows.Next() {
		ar, err := scanRequest(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, ar)
	}
	return out, total, nil
}

// ResolveRequest approves or rejects a request.
func (r *PAMRepository) ResolveRequest(ctx context.Context, tenantID, requestID, approverID uuid.UUID, approved bool, note string) error {
	status := model.RequestRejected
	var validFrom, validUntil *time.Time
	if approved {
		status = model.RequestApproved
		now := time.Now().UTC()
		validFrom = &now
	}

	const q = `
		UPDATE pam_access_requests
		SET status = $1, approver_id = $2, approval_note = $3,
		    valid_from = $4, valid_until = $5,
		    resolved_at = NOW()
		WHERE id = $6 AND tenant_id = $7 AND status = 'pending'`

	// valid_until set when session is opened (we know duration then)
	tag, err := r.db.Exec(ctx, q, status, approverID, nvl(note), validFrom, validUntil, requestID, tenantID)
	if err != nil {
		return fmt.Errorf("resolve request: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ─── Privileged Sessions ──────────────────────────────────────────────────────

// OpenSession creates and returns a new privileged session.
func (r *PAMRepository) OpenSession(ctx context.Context, tenantID, userID uuid.UUID, req *model.OpenSessionRequest, expiresAt time.Time) (*model.PrivilegedSession, error) {
	id := uuid.New()
	const q = `
		INSERT INTO pam_sessions
			(id, tenant_id, request_id, user_id, privileged_account_id,
			 expires_at, client_ip, mfa_verified)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id, status, started_at`

	s := &model.PrivilegedSession{
		ID:                  id,
		TenantID:            tenantID,
		RequestID:           &req.RequestID,
		UserID:              userID,
		PrivilegedAccountID: &req.PrivilegedAccountID,
		ExpiresAt:           expiresAt,
		ClientIP:            req.ClientIP,
		MFAVerified:         req.MFAVerified,
		Status:              model.SessionActive,
		RiskFlags:           []string{},
	}

	if err := r.db.QueryRow(ctx, q,
		id, tenantID, req.RequestID, userID, req.PrivilegedAccountID,
		expiresAt, nvl(req.ClientIP), req.MFAVerified,
	).Scan(&s.ID, &s.Status, &s.StartedAt); err != nil {
		return nil, fmt.Errorf("open session: %w", err)
	}

	// Increment account use_count
	_, _ = r.db.Exec(ctx,
		`UPDATE privileged_accounts SET use_count = use_count + 1, last_used_at = NOW() WHERE id = $1`,
		req.PrivilegedAccountID)

	return s, nil
}

// GetSession returns a session by ID.
func (r *PAMRepository) GetSession(ctx context.Context, tenantID, sessionID uuid.UUID) (*model.PrivilegedSession, error) {
	const q = `
		SELECT id, tenant_id, request_id, user_id, privileged_account_id, target_asset_id,
		       protocol, status, started_at, expires_at, terminated_at,
		       client_ip, mfa_verified, commands_count, bytes_transferred,
		       risk_score, risk_flags, recording_ref
		FROM pam_sessions
		WHERE id = $1 AND tenant_id = $2`
	row := r.db.QueryRow(ctx, q, sessionID, tenantID)
	return scanSession(row)
}

// ListSessions returns sessions matching the filter.
func (r *PAMRepository) ListSessions(ctx context.Context, f model.SessionFilter) ([]*model.PrivilegedSession, int, error) {
	where := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	n := 2

	if f.Status != "" {
		where = append(where, fmt.Sprintf("status = $%d", n))
		args = append(args, f.Status)
		n++
	}
	if f.UserID != nil {
		where = append(where, fmt.Sprintf("user_id = $%d", n))
		args = append(args, *f.UserID)
		n++
	}

	wc := strings.Join(where, " AND ")
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	var total int
	if err := r.db.QueryRow(ctx, fmt.Sprintf("SELECT COUNT(*) FROM pam_sessions WHERE %s", wc), args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	dataQ := fmt.Sprintf(`
		SELECT id, tenant_id, request_id, user_id, privileged_account_id, target_asset_id,
		       protocol, status, started_at, expires_at, terminated_at,
		       client_ip, mfa_verified, commands_count, bytes_transferred,
		       risk_score, risk_flags, recording_ref
		FROM pam_sessions WHERE %s
		ORDER BY started_at DESC LIMIT $%d OFFSET $%d`, wc, n, n+1)
	args = append(args, limit, f.Offset)

	rows, err := r.db.Query(ctx, dataQ, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []*model.PrivilegedSession
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, s)
	}
	return out, total, nil
}

// TerminateSession ends a session.
func (r *PAMRepository) TerminateSession(ctx context.Context, tenantID, sessionID uuid.UUID, status model.SessionStatus) error {
	const q = `
		UPDATE pam_sessions
		SET status = $1, terminated_at = NOW()
		WHERE id = $2 AND tenant_id = $3 AND status = 'active'`
	tag, err := r.db.Exec(ctx, q, status, sessionID, tenantID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// RecordEvent appends a session event.
func (r *PAMRepository) RecordEvent(ctx context.Context, tenantID, sessionID uuid.UUID, req *model.RecordEventRequest) (*model.SessionEvent, error) {
	id := uuid.New()
	const q = `
		INSERT INTO pam_session_events (id, tenant_id, session_id, event_type, content)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING id, timestamp`

	e := &model.SessionEvent{
		ID:        id,
		TenantID:  tenantID,
		SessionID: sessionID,
		EventType: req.EventType,
		Content:   req.Content,
	}
	if err := r.db.QueryRow(ctx, q, id, tenantID, sessionID, req.EventType, nvl(req.Content)).Scan(&e.ID, &e.Timestamp); err != nil {
		return nil, fmt.Errorf("record session event: %w", err)
	}

	// Increment commands_count
	if req.EventType == "command" {
		_, _ = r.db.Exec(ctx,
			`UPDATE pam_sessions SET commands_count = commands_count + 1 WHERE id = $1`, sessionID)
	}
	return e, nil
}

// ListSessionEvents returns all events for a session.
func (r *PAMRepository) ListSessionEvents(ctx context.Context, tenantID, sessionID uuid.UUID) ([]*model.SessionEvent, error) {
	const q = `
		SELECT id, tenant_id, session_id, timestamp, event_type, content, risk_flag, risk_reason
		FROM pam_session_events
		WHERE tenant_id = $1 AND session_id = $2
		ORDER BY timestamp`

	rows, err := r.db.Query(ctx, q, tenantID, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*model.SessionEvent
	for rows.Next() {
		e := &model.SessionEvent{}
		var content, riskReason *string
		if err := rows.Scan(&e.ID, &e.TenantID, &e.SessionID, &e.Timestamp,
			&e.EventType, &content, &e.RiskFlag, &riskReason); err != nil {
			return nil, err
		}
		if content != nil {
			e.Content = *content
		}
		if riskReason != nil {
			e.RiskReason = *riskReason
		}
		out = append(out, e)
	}
	return out, nil
}

// ─── Identity Risk ────────────────────────────────────────────────────────────

// UpsertRiskProfile creates or updates an identity risk profile.
func (r *PAMRepository) UpsertRiskProfile(ctx context.Context, p *model.IdentityRiskProfile) error {
	const q = `
		INSERT INTO identity_risk_profiles (
			id, tenant_id, identity_id,
			risk_score, failed_login_score, anomalous_hours_score,
			geo_anomaly_score, privilege_abuse_score, data_exfil_score, lateral_movement_score,
			normal_login_hours, normal_countries, normal_ip_prefixes,
			avg_daily_events, baseline_ready,
			last_anomaly_at, anomaly_count_7d, anomaly_count_30d,
			last_login_at, last_login_ip, last_login_country,
			events_today, events_7d, priv_sessions_30d
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
			$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24
		)
		ON CONFLICT (tenant_id, identity_id) DO UPDATE SET
			risk_score              = EXCLUDED.risk_score,
			failed_login_score      = EXCLUDED.failed_login_score,
			anomalous_hours_score   = EXCLUDED.anomalous_hours_score,
			geo_anomaly_score       = EXCLUDED.geo_anomaly_score,
			privilege_abuse_score   = EXCLUDED.privilege_abuse_score,
			data_exfil_score        = EXCLUDED.data_exfil_score,
			lateral_movement_score  = EXCLUDED.lateral_movement_score,
			normal_login_hours      = EXCLUDED.normal_login_hours,
			normal_countries        = EXCLUDED.normal_countries,
			normal_ip_prefixes      = EXCLUDED.normal_ip_prefixes,
			avg_daily_events        = EXCLUDED.avg_daily_events,
			baseline_ready          = EXCLUDED.baseline_ready,
			last_anomaly_at         = EXCLUDED.last_anomaly_at,
			anomaly_count_7d        = EXCLUDED.anomaly_count_7d,
			anomaly_count_30d       = EXCLUDED.anomaly_count_30d,
			last_login_at           = EXCLUDED.last_login_at,
			last_login_ip           = EXCLUDED.last_login_ip,
			last_login_country      = EXCLUDED.last_login_country,
			events_today            = EXCLUDED.events_today,
			events_7d               = EXCLUDED.events_7d,
			priv_sessions_30d       = EXCLUDED.priv_sessions_30d,
			updated_at              = NOW()`

	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	_, err := r.db.Exec(ctx, q,
		p.ID, p.TenantID, p.IdentityID,
		p.RiskScore, p.FailedLoginScore, p.AnomalousHoursScore,
		p.GeoAnomalyScore, p.PrivilegeAbuseScore, p.DataExfilScore, p.LateralMovementScore,
		p.NormalLoginHours, p.NormalCountries, p.NormalIPPrefixes,
		p.AvgDailyEvents, p.BaselineReady,
		p.LastAnomalyAt, p.AnomalyCount7d, p.AnomalyCount30d,
		p.LastLoginAt, nvl(p.LastLoginIP), nvl(p.LastLoginCountry),
		p.EventsToday, p.Events7d, p.PrivSessions30d,
	)
	return err
}

// ActivityWindows holds an identity's activity over the windows the risk
// profile reports. Every figure is derived from identity_activity_daily, so
// each is true to its name rather than a lifetime total.
type ActivityWindows struct {
	EventsToday     int
	Events7d        int
	Anomalies7d     int
	Anomalies30d    int
	PrivSessions30d int
}

// RecordActivity adds one day's worth of counts for an identity.
//
// The increment happens in the database, not in Go: the profile row used to be
// read, incremented in memory and written back whole, so two replicas handling
// events for the same identity silently lost one another's counts.
func (r *PAMRepository) RecordActivity(ctx context.Context, tenantID, identityID uuid.UUID, day time.Time, events, anomalies, privSessions int) error {
	const q = `
		INSERT INTO identity_activity_daily (tenant_id, identity_id, day, events, anomalies, priv_sessions)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id, identity_id, day) DO UPDATE SET
			events        = identity_activity_daily.events        + EXCLUDED.events,
			anomalies     = identity_activity_daily.anomalies     + EXCLUDED.anomalies,
			priv_sessions = identity_activity_daily.priv_sessions + EXCLUDED.priv_sessions`

	_, err := r.db.Exec(ctx, q, tenantID, identityID, day.UTC(), events, anomalies, privSessions)
	if err != nil {
		return fmt.Errorf("record identity activity: %w", err)
	}
	return nil
}

// ReadActivityWindows sums an identity's recent activity per window.
//
// The windows are inclusive of today and count back whole UTC days, so "7
// days" means today plus the six before it.
func (r *PAMRepository) ReadActivityWindows(ctx context.Context, tenantID, identityID uuid.UUID, now time.Time) (ActivityWindows, error) {
	today := now.UTC().Truncate(24 * time.Hour)

	const q = `
		SELECT
			COALESCE(SUM(events)        FILTER (WHERE day  = $3), 0),
			COALESCE(SUM(events)        FILTER (WHERE day >= $4), 0),
			COALESCE(SUM(anomalies)     FILTER (WHERE day >= $4), 0),
			COALESCE(SUM(anomalies)     FILTER (WHERE day >= $5), 0),
			COALESCE(SUM(priv_sessions) FILTER (WHERE day >= $5), 0)
		FROM identity_activity_daily
		WHERE tenant_id = $1 AND identity_id = $2 AND day >= $5`

	var w ActivityWindows
	err := r.db.QueryRow(ctx, q,
		tenantID, identityID,
		today,
		today.AddDate(0, 0, -6),  // 7-day window, today included
		today.AddDate(0, 0, -29), // 30-day window, today included
	).Scan(&w.EventsToday, &w.Events7d, &w.Anomalies7d, &w.Anomalies30d, &w.PrivSessions30d)
	if err != nil {
		return ActivityWindows{}, fmt.Errorf("read identity activity windows: %w", err)
	}
	return w, nil
}

// PurgeActivityBefore drops rows past the widest window any figure uses.
// Without it the table grows one row per identity per day for ever.
func (r *PAMRepository) PurgeActivityBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := r.db.Exec(ctx,
		`DELETE FROM identity_activity_daily WHERE day < $1`, cutoff.UTC().Truncate(24*time.Hour))
	if err != nil {
		return 0, fmt.Errorf("purge identity activity: %w", err)
	}
	return tag.RowsAffected(), nil
}

// GetRiskProfile returns the risk profile for an identity.
func (r *PAMRepository) GetRiskProfile(ctx context.Context, tenantID, identityID uuid.UUID) (*model.IdentityRiskProfile, error) {
	const q = `
		SELECT id, tenant_id, identity_id,
		       risk_score, failed_login_score, anomalous_hours_score,
		       geo_anomaly_score, privilege_abuse_score, data_exfil_score, lateral_movement_score,
		       normal_login_hours, normal_countries, normal_ip_prefixes,
		       avg_daily_events, baseline_ready,
		       last_anomaly_at, anomaly_count_7d, anomaly_count_30d,
		       last_login_at, last_login_ip, last_login_country,
		       events_today, events_7d, priv_sessions_30d, updated_at
		FROM identity_risk_profiles
		WHERE tenant_id = $1 AND identity_id = $2`

	row := r.db.QueryRow(ctx, q, tenantID, identityID)
	return scanRiskProfile(row)
}

// ListHighRisk returns identities with risk_score >= threshold.
func (r *PAMRepository) ListHighRisk(ctx context.Context, tenantID uuid.UUID, threshold float64, limit int) ([]*model.IdentityRiskProfile, error) {
	const q = `
		SELECT id, tenant_id, identity_id,
		       risk_score, failed_login_score, anomalous_hours_score,
		       geo_anomaly_score, privilege_abuse_score, data_exfil_score, lateral_movement_score,
		       normal_login_hours, normal_countries, normal_ip_prefixes,
		       avg_daily_events, baseline_ready,
		       last_anomaly_at, anomaly_count_7d, anomaly_count_30d,
		       last_login_at, last_login_ip, last_login_country,
		       events_today, events_7d, priv_sessions_30d, updated_at
		FROM identity_risk_profiles
		WHERE tenant_id = $1 AND risk_score >= $2
		ORDER BY risk_score DESC
		LIMIT $3`

	rows, err := r.db.Query(ctx, q, tenantID, threshold, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*model.IdentityRiskProfile
	for rows.Next() {
		p, err := scanRiskProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// ─── Scanners ─────────────────────────────────────────────────────────────────

type scannable interface {
	Scan(dest ...any) error
}

func scanAccount(row scannable) (*model.PrivilegedAccount, error) {
	a := &model.PrivilegedAccount{}
	var hostname, credRef *string
	if err := row.Scan(
		&a.ID, &a.TenantID, &a.AccountName, &a.AccountType,
		&a.TargetAssetID, &hostname, &a.TargetProtocol,
		&a.CredentialStored, &credRef,
		&a.LastRotatedAt, &a.RotationPolicyDays, &a.AutoRotate,
		&a.RequiresApproval, &a.MaxSessionMinutes, &a.AllowedRoles,
		&a.IsActive, &a.LastUsedAt, &a.UseCount, &a.CreatedAt, &a.UpdatedAt,
	); err == pgx.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("scan account: %w", err)
	}
	if hostname != nil {
		a.TargetAssetHostname = *hostname
	}
	if credRef != nil {
		a.CredentialRef = *credRef
	}
	if a.AllowedRoles == nil {
		a.AllowedRoles = []string{}
	}
	return a, nil
}

func scanRequest(row scannable) (*model.AccessRequest, error) {
	ar := &model.AccessRequest{}
	var ticketRef, approvalNote *string
	if err := row.Scan(
		&ar.ID, &ar.TenantID, &ar.RequesterID,
		&ar.PrivilegedAccountID, &ar.TargetAssetID,
		&ar.Reason, &ticketRef, &ar.RequestedDurationMin,
		&ar.Status, &ar.ApproverID, &approvalNote,
		&ar.ValidFrom, &ar.ValidUntil, &ar.ExpiresAt, &ar.CreatedAt, &ar.ResolvedAt,
	); err == pgx.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("scan request: %w", err)
	}
	if ticketRef != nil {
		ar.TicketRef = *ticketRef
	}
	if approvalNote != nil {
		ar.ApprovalNote = *approvalNote
	}
	return ar, nil
}

func scanSession(row scannable) (*model.PrivilegedSession, error) {
	s := &model.PrivilegedSession{}
	var clientIP, recordingRef *string
	var proto *model.Protocol
	if err := row.Scan(
		&s.ID, &s.TenantID, &s.RequestID, &s.UserID,
		&s.PrivilegedAccountID, &s.TargetAssetID,
		&proto, &s.Status,
		&s.StartedAt, &s.ExpiresAt, &s.TerminatedAt,
		&clientIP, &s.MFAVerified, &s.CommandsCount, &s.BytesTransferred,
		&s.RiskScore, &s.RiskFlags, &recordingRef,
	); err == pgx.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("scan session: %w", err)
	}
	if clientIP != nil {
		s.ClientIP = *clientIP
	}
	if recordingRef != nil {
		s.RecordingRef = *recordingRef
	}
	if proto != nil {
		s.Protocol = *proto
	}
	if s.RiskFlags == nil {
		s.RiskFlags = []string{}
	}
	return s, nil
}

func scanRiskProfile(row scannable) (*model.IdentityRiskProfile, error) {
	p := &model.IdentityRiskProfile{}
	var lastLoginIP, lastLoginCountry *string
	if err := row.Scan(
		&p.ID, &p.TenantID, &p.IdentityID,
		&p.RiskScore, &p.FailedLoginScore, &p.AnomalousHoursScore,
		&p.GeoAnomalyScore, &p.PrivilegeAbuseScore, &p.DataExfilScore, &p.LateralMovementScore,
		&p.NormalLoginHours, &p.NormalCountries, &p.NormalIPPrefixes,
		&p.AvgDailyEvents, &p.BaselineReady,
		&p.LastAnomalyAt, &p.AnomalyCount7d, &p.AnomalyCount30d,
		&p.LastLoginAt, &lastLoginIP, &lastLoginCountry,
		&p.EventsToday, &p.Events7d, &p.PrivSessions30d, &p.UpdatedAt,
	); err == pgx.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("scan risk profile: %w", err)
	}
	if lastLoginIP != nil {
		p.LastLoginIP = *lastLoginIP
	}
	if lastLoginCountry != nil {
		p.LastLoginCountry = *lastLoginCountry
	}
	if p.NormalLoginHours == nil {
		p.NormalLoginHours = []int{}
	}
	if p.NormalCountries == nil {
		p.NormalCountries = []string{}
	}
	if p.NormalIPPrefixes == nil {
		p.NormalIPPrefixes = []string{}
	}
	return p, nil
}

func nvl(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
