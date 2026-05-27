package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cyberradar/platform/services/ueba/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ProfileRepository manages entity behavior profiles and anomaly records in PostgreSQL.
type ProfileRepository struct {
	db *pgxpool.Pool
}

// NewProfileRepository creates a ProfileRepository.
func NewProfileRepository(db *pgxpool.Pool) *ProfileRepository {
	return &ProfileRepository{db: db}
}

// ─── Entity Profiles ──────────────────────────────────────────────────────────

// GetOrCreate loads an existing profile or inserts a blank one.
func (r *ProfileRepository) GetOrCreate(ctx context.Context, tenantID, entityID uuid.UUID, entityType string) (*model.EntityProfile, error) {
	id := uuid.New()
	_, err := r.db.Exec(ctx, `
		INSERT INTO ueba_profiles (id, tenant_id, entity_id, entity_type)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id, entity_id) DO NOTHING`,
		id, tenantID, entityID, entityType,
	)
	if err != nil {
		return nil, fmt.Errorf("upsert profile: %w", err)
	}
	return r.get(ctx, tenantID, entityID)
}

func (r *ProfileRepository) get(ctx context.Context, tenantID, entityID uuid.UUID) (*model.EntityProfile, error) {
	row := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, entity_id, entity_type,
		       normal_hours, normal_countries, normal_ip_prefixes, normal_event_types,
		       risk_score, login_score, access_score, data_score, peer_score, temporal_score,
		       event_count, anomaly_count, last_seen_at, baseline_ready, peer_group_id,
		       created_at, updated_at
		FROM ueba_profiles WHERE tenant_id = $1 AND entity_id = $2`,
		tenantID, entityID,
	)
	return scanProfile(row)
}

// GetByEntityID returns a profile by entity UUID.
func (r *ProfileRepository) GetByEntityID(ctx context.Context, tenantID, entityID uuid.UUID) (*model.EntityProfile, error) {
	p, err := r.get(ctx, tenantID, entityID)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// Update persists all mutable fields of a profile.
func (r *ProfileRepository) Update(ctx context.Context, p *model.EntityProfile) error {
	_, err := r.db.Exec(ctx, `
		UPDATE ueba_profiles SET
			normal_hours        = $1,
			normal_countries    = $2,
			normal_ip_prefixes  = $3,
			normal_event_types  = $4,
			risk_score          = $5,
			login_score         = $6,
			access_score        = $7,
			data_score          = $8,
			peer_score          = $9,
			temporal_score      = $10,
			event_count         = $11,
			anomaly_count       = $12,
			last_seen_at        = $13,
			baseline_ready      = $14,
			updated_at          = NOW()
		WHERE id = $15 AND tenant_id = $16`,
		p.NormalHours, p.NormalCountries, p.NormalIPPrefixes, p.NormalEventTypes,
		p.RiskScore, p.LoginScore, p.AccessScore, p.DataScore, p.PeerScore, p.TemporalScore,
		p.EventCount, p.AnomalyCount, p.LastSeenAt, p.BaselineReady,
		p.ID, p.TenantID,
	)
	return err
}

// ListProfiles returns profiles matching the filter.
func (r *ProfileRepository) ListProfiles(ctx context.Context, f model.ProfileFilter) ([]*model.EntityProfile, int, error) {
	where := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	n := 2

	if f.EntityType != "" {
		where = append(where, fmt.Sprintf("entity_type = $%d", n))
		args = append(args, f.EntityType)
		n++
	}
	if f.MinRisk > 0 {
		where = append(where, fmt.Sprintf("risk_score >= $%d", n))
		args = append(args, f.MinRisk)
		n++
	}
	if f.BaselineReady != nil {
		where = append(where, fmt.Sprintf("baseline_ready = $%d", n))
		args = append(args, *f.BaselineReady)
		n++
	}

	wc := strings.Join(where, " AND ")
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	var total int
	if err := r.db.QueryRow(ctx, fmt.Sprintf("SELECT COUNT(*) FROM ueba_profiles WHERE %s", wc), args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	q := fmt.Sprintf(`
		SELECT id, tenant_id, entity_id, entity_type,
		       normal_hours, normal_countries, normal_ip_prefixes, normal_event_types,
		       risk_score, login_score, access_score, data_score, peer_score, temporal_score,
		       event_count, anomaly_count, last_seen_at, baseline_ready, peer_group_id,
		       created_at, updated_at
		FROM ueba_profiles WHERE %s
		ORDER BY risk_score DESC
		LIMIT $%d OFFSET $%d`, wc, n, n+1)
	args = append(args, limit, f.Offset)

	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []*model.EntityProfile
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, p)
	}
	return out, total, nil
}

// ─── Anomalies ────────────────────────────────────────────────────────────────

// InsertAnomaly stores a new anomaly record.
func (r *ProfileRepository) InsertAnomaly(ctx context.Context, a *model.Anomaly) error {
	details, _ := json.Marshal(a.Details)
	_, err := r.db.Exec(ctx, `
		INSERT INTO ueba_anomalies
			(id, tenant_id, entity_id, entity_type, anomaly_type, severity, score,
			 baseline_val, observed_val, details, source_event_id, status, detected_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		a.ID, a.TenantID, a.EntityID, a.EntityType, a.AnomalyType, a.Severity, a.Score,
		nvls(a.BaselineVal), nvls(a.ObservedVal), details, a.SourceEventID,
		a.Status, a.DetectedAt,
	)
	return err
}

// ListAnomalies returns anomaly records matching the filter.
func (r *ProfileRepository) ListAnomalies(ctx context.Context, f model.AnomalyFilter) ([]*model.Anomaly, int, error) {
	where := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	n := 2

	if f.EntityID != nil {
		where = append(where, fmt.Sprintf("entity_id = $%d", n))
		args = append(args, *f.EntityID)
		n++
	}
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
	if f.AnomalyType != "" {
		where = append(where, fmt.Sprintf("anomaly_type = $%d", n))
		args = append(args, f.AnomalyType)
		n++
	}
	if f.From != nil {
		where = append(where, fmt.Sprintf("detected_at >= $%d", n))
		args = append(args, *f.From)
		n++
	}
	if f.To != nil {
		where = append(where, fmt.Sprintf("detected_at <= $%d", n))
		args = append(args, *f.To)
		n++
	}

	wc := strings.Join(where, " AND ")
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	var total int
	if err := r.db.QueryRow(ctx, fmt.Sprintf("SELECT COUNT(*) FROM ueba_anomalies WHERE %s", wc), args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	q := fmt.Sprintf(`
		SELECT id, tenant_id, entity_id, entity_type, anomaly_type, severity, score,
		       baseline_val, observed_val, details, source_event_id,
		       status, assignee_id, notes, detected_at, resolved_at, created_at, updated_at
		FROM ueba_anomalies WHERE %s
		ORDER BY detected_at DESC
		LIMIT $%d OFFSET $%d`, wc, n, n+1)
	args = append(args, limit, f.Offset)

	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []*model.Anomaly
	for rows.Next() {
		a, err := scanAnomaly(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, nil
}

// UpdateAnomaly applies a partial update to an anomaly record.
func (r *ProfileRepository) UpdateAnomaly(ctx context.Context, tenantID, anomalyID uuid.UUID, req *model.UpdateAnomalyRequest) (*model.Anomaly, error) {
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
		if *req.Status == model.AnomalyStatusResolved || *req.Status == model.AnomalyStatusFalsePositive {
			now := time.Now().UTC()
			set("resolved_at", now)
		}
	}
	if req.AssigneeID != nil {
		set("assignee_id", *req.AssigneeID)
	}
	if req.Notes != nil {
		set("notes", *req.Notes)
	}

	if len(sets) == 0 {
		return r.getAnomaly(ctx, tenantID, anomalyID)
	}
	set("updated_at", time.Now().UTC())

	q := fmt.Sprintf(`UPDATE ueba_anomalies SET %s WHERE id = $%d AND tenant_id = $%d`,
		strings.Join(sets, ", "), n, n+1)
	args = append(args, anomalyID, tenantID)

	if _, err := r.db.Exec(ctx, q, args...); err != nil {
		return nil, fmt.Errorf("update anomaly: %w", err)
	}
	return r.getAnomaly(ctx, tenantID, anomalyID)
}

func (r *ProfileRepository) getAnomaly(ctx context.Context, tenantID, anomalyID uuid.UUID) (*model.Anomaly, error) {
	row := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, entity_id, entity_type, anomaly_type, severity, score,
		       baseline_val, observed_val, details, source_event_id,
		       status, assignee_id, notes, detected_at, resolved_at, created_at, updated_at
		FROM ueba_anomalies WHERE id = $1 AND tenant_id = $2`, anomalyID, tenantID)
	return scanAnomaly(row)
}

// AnomalyStats returns counts for the stats dashboard.
func (r *ProfileRepository) AnomalyStats(ctx context.Context, tenantID uuid.UUID) (open, last24h, last7d, highRisk int, bySeverity map[string]int, err error) {
	bySeverity = make(map[string]int)

	r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM ueba_anomalies WHERE tenant_id=$1 AND status='open'`, tenantID,
	).Scan(&open) //nolint:errcheck

	r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM ueba_anomalies WHERE tenant_id=$1 AND detected_at >= NOW()-INTERVAL '24 hours'`, tenantID,
	).Scan(&last24h) //nolint:errcheck

	r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM ueba_anomalies WHERE tenant_id=$1 AND detected_at >= NOW()-INTERVAL '7 days'`, tenantID,
	).Scan(&last7d) //nolint:errcheck

	r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM ueba_profiles WHERE tenant_id=$1 AND risk_score >= 7.0`, tenantID,
	).Scan(&highRisk) //nolint:errcheck

	rows, qErr := r.db.Query(ctx,
		`SELECT severity, COUNT(*) FROM ueba_anomalies WHERE tenant_id=$1 AND status='open' GROUP BY severity`, tenantID)
	if qErr == nil {
		defer rows.Close()
		for rows.Next() {
			var sev string
			var cnt int
			if rows.Scan(&sev, &cnt) == nil {
				bySeverity[sev] = cnt
			}
		}
	}
	return
}

// ─── Peer Groups ──────────────────────────────────────────────────────────────

// CreatePeerGroup creates a new peer group.
func (r *ProfileRepository) CreatePeerGroup(ctx context.Context, tenantID uuid.UUID, req *model.CreatePeerGroupRequest) (*model.PeerGroup, error) {
	id := uuid.New()
	criteria, _ := json.Marshal(req.Criteria)
	pg := &model.PeerGroup{
		ID:          id,
		TenantID:    tenantID,
		Name:        req.Name,
		Description: req.Description,
		Criteria:    req.Criteria,
	}
	if err := r.db.QueryRow(ctx, `
		INSERT INTO ueba_peer_groups (id, tenant_id, name, description, criteria)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING created_at, updated_at`,
		id, tenantID, req.Name, nvls(req.Description), criteria,
	).Scan(&pg.CreatedAt, &pg.UpdatedAt); err != nil {
		return nil, fmt.Errorf("create peer group: %w", err)
	}
	return pg, nil
}

// ListPeerGroups returns all peer groups for a tenant.
func (r *ProfileRepository) ListPeerGroups(ctx context.Context, tenantID uuid.UUID) ([]*model.PeerGroup, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, name, description, criteria, avg_risk_score, member_count, created_at, updated_at
		FROM ueba_peer_groups WHERE tenant_id = $1 ORDER BY name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*model.PeerGroup
	for rows.Next() {
		pg := &model.PeerGroup{}
		var criteriaRaw []byte
		var desc *string
		if err := rows.Scan(&pg.ID, &pg.TenantID, &pg.Name, &desc, &criteriaRaw,
			&pg.AvgRiskScore, &pg.MemberCount, &pg.CreatedAt, &pg.UpdatedAt); err != nil {
			return nil, err
		}
		if desc != nil {
			pg.Description = *desc
		}
		_ = json.Unmarshal(criteriaRaw, &pg.Criteria)
		out = append(out, pg)
	}
	return out, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

type scannable interface {
	Scan(dest ...any) error
}

func scanProfile(row scannable) (*model.EntityProfile, error) {
	p := &model.EntityProfile{}
	err := row.Scan(
		&p.ID, &p.TenantID, &p.EntityID, &p.EntityType,
		&p.NormalHours, &p.NormalCountries, &p.NormalIPPrefixes, &p.NormalEventTypes,
		&p.RiskScore, &p.LoginScore, &p.AccessScore, &p.DataScore, &p.PeerScore, &p.TemporalScore,
		&p.EventCount, &p.AnomalyCount, &p.LastSeenAt, &p.BaselineReady, &p.PeerGroupID,
		&p.CreatedAt, &p.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan profile: %w", err)
	}
	if p.NormalHours == nil {
		p.NormalHours = []int32{}
	}
	if p.NormalCountries == nil {
		p.NormalCountries = []string{}
	}
	if p.NormalIPPrefixes == nil {
		p.NormalIPPrefixes = []string{}
	}
	if p.NormalEventTypes == nil {
		p.NormalEventTypes = []string{}
	}
	return p, nil
}

func scanAnomaly(row scannable) (*model.Anomaly, error) {
	a := &model.Anomaly{}
	var (
		detailsRaw          []byte
		baselineVal, obsVal *string
		notes               *string
	)
	err := row.Scan(
		&a.ID, &a.TenantID, &a.EntityID, &a.EntityType,
		&a.AnomalyType, &a.Severity, &a.Score,
		&baselineVal, &obsVal, &detailsRaw, &a.SourceEventID,
		&a.Status, &a.AssigneeID, &notes,
		&a.DetectedAt, &a.ResolvedAt, &a.CreatedAt, &a.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan anomaly: %w", err)
	}
	if baselineVal != nil {
		a.BaselineVal = *baselineVal
	}
	if obsVal != nil {
		a.ObservedVal = *obsVal
	}
	if notes != nil {
		a.Notes = *notes
	}
	_ = json.Unmarshal(detailsRaw, &a.Details)
	return a, nil
}

func nvls(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
