package repository

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cyberradar/platform/services/ti/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// IOCRepository manages feeds, IOCs, threat actors, and hit records in PostgreSQL.
type IOCRepository struct {
	db *pgxpool.Pool
}

// NewIOCRepository creates an IOCRepository.
func NewIOCRepository(db *pgxpool.Pool) *IOCRepository {
	return &IOCRepository{db: db}
}

// ─── Feeds ────────────────────────────────────────────────────────────────────

func (r *IOCRepository) CreateFeed(ctx context.Context, tenantID uuid.UUID, req *model.CreateFeedRequest) (*model.Feed, error) {
	id := uuid.New()
	interval := req.PollIntervalS
	if interval <= 0 {
		interval = 3600
	}
	conf := req.Confidence
	if conf == 0 {
		conf = 50
	}
	f := &model.Feed{
		ID: id, TenantID: tenantID, Name: req.Name, FeedType: req.FeedType,
		PollIntervalS: interval, TLP: req.TLP, Confidence: conf,
		URL: req.URL, ApiKeyRef: req.ApiKeyRef, CollectionID: req.CollectionID,
		Description: req.Description, Enabled: true,
	}
	if err := r.db.QueryRow(ctx, `
		INSERT INTO ti_feeds
			(id, tenant_id, name, description, feed_type, url, api_key_ref, collection_id,
			 poll_interval_s, tlp, confidence)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING enabled, created_at, updated_at`,
		id, tenantID, req.Name, nvlS(req.Description), req.FeedType,
		nvlS(req.URL), nvlS(req.ApiKeyRef), nvlS(req.CollectionID),
		interval, req.TLP, conf,
	).Scan(&f.Enabled, &f.CreatedAt, &f.UpdatedAt); err != nil {
		return nil, fmt.Errorf("create feed: %w", err)
	}
	return f, nil
}

func (r *IOCRepository) GetFeed(ctx context.Context, tenantID, feedID uuid.UUID) (*model.Feed, error) {
	row := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, name, description, feed_type, url, api_key_ref, collection_id,
		       poll_interval_s, enabled, tlp, confidence,
		       last_polled_at, last_ioc_count, error_count, last_error, created_at, updated_at
		FROM ti_feeds WHERE id = $1 AND tenant_id = $2`, feedID, tenantID)
	return scanFeed(row)
}

func (r *IOCRepository) ListFeeds(ctx context.Context, tenantID uuid.UUID) ([]*model.Feed, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, name, description, feed_type, url, api_key_ref, collection_id,
		       poll_interval_s, enabled, tlp, confidence,
		       last_polled_at, last_ioc_count, error_count, last_error, created_at, updated_at
		FROM ti_feeds WHERE tenant_id = $1 ORDER BY name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Feed
	for rows.Next() {
		f, err := scanFeed(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

func (r *IOCRepository) UpdateFeed(ctx context.Context, tenantID, feedID uuid.UUID, req *model.UpdateFeedRequest) (*model.Feed, error) {
	sets := []string{}
	args := []any{}
	n := 1
	set := func(col string, val any) {
		sets = append(sets, fmt.Sprintf("%s = $%d", col, n))
		args = append(args, val)
		n++
	}
	if req.Enabled != nil {
		set("enabled", *req.Enabled)
	}
	if req.PollIntervalS != nil {
		set("poll_interval_s", *req.PollIntervalS)
	}
	if req.Confidence != nil {
		set("confidence", *req.Confidence)
	}
	if req.Description != nil {
		set("description", *req.Description)
	}
	if len(sets) == 0 {
		return r.GetFeed(ctx, tenantID, feedID)
	}
	set("updated_at", time.Now().UTC())
	q := fmt.Sprintf(`UPDATE ti_feeds SET %s WHERE id = $%d AND tenant_id = $%d`,
		strings.Join(sets, ", "), n, n+1)
	args = append(args, feedID, tenantID)
	if _, err := r.db.Exec(ctx, q, args...); err != nil {
		return nil, fmt.Errorf("update feed: %w", err)
	}
	return r.GetFeed(ctx, tenantID, feedID)
}

func (r *IOCRepository) DeleteFeed(ctx context.Context, tenantID, feedID uuid.UUID) error {
	res, err := r.db.Exec(ctx, `DELETE FROM ti_feeds WHERE id = $1 AND tenant_id = $2`, feedID, tenantID)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// MarkFeedPolled updates last_polled_at and ioc count after a successful poll.
func (r *IOCRepository) MarkFeedPolled(ctx context.Context, feedID uuid.UUID, count int) error {
	_, err := r.db.Exec(ctx,
		`UPDATE ti_feeds SET last_polled_at = NOW(), last_ioc_count = $1, error_count = 0, last_error = NULL, updated_at = NOW() WHERE id = $2`,
		count, feedID)
	return err
}

// MarkFeedError records a polling failure.
func (r *IOCRepository) MarkFeedError(ctx context.Context, feedID uuid.UUID, errMsg string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE ti_feeds SET error_count = error_count + 1, last_error = $1, updated_at = NOW() WHERE id = $2`,
		errMsg, feedID)
	return err
}

// ─── IOCs ─────────────────────────────────────────────────────────────────────

// UpsertIOC inserts or updates an IOC by (tenant_id, ioc_type, normalized).
func (r *IOCRepository) UpsertIOC(ctx context.Context, tenantID uuid.UUID, req *model.CreateIOCRequest) (*model.IOC, error) {
	id := uuid.New()
	norm := normalizeValue(req.IOCType, req.Value)
	sev := req.Severity
	if sev == "" {
		sev = "MEDIUM"
	}
	tags := req.Tags
	if tags == nil {
		tags = []string{}
	}

	ioc := &model.IOC{
		ID: id, TenantID: tenantID, FeedID: req.FeedID,
		IOCType: req.IOCType, Value: req.Value, Normalized: norm,
		TLP: req.TLP, Confidence: req.Confidence, Severity: sev,
		IsActive: true, ValidFrom: time.Now().UTC(),
		MitreTactic: req.MitreTactic, MitreTechnique: req.MitreTechnique,
		ThreatActor: req.ThreatActor, MalwareFamily: req.MalwareFamily, Campaign: req.Campaign,
		ValidUntil: req.ValidUntil, ExternalID: req.ExternalID, StixID: req.StixID,
		Tags: tags, Description: req.Description,
	}

	if err := r.db.QueryRow(ctx, `
		INSERT INTO ti_iocs
			(id, tenant_id, feed_id, ioc_type, value, normalized, tlp, confidence, severity,
			 mitre_tactic, mitre_technique, threat_actor, malware_family, campaign,
			 valid_until, external_id, stix_id, tags, description)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
		ON CONFLICT (tenant_id, ioc_type, normalized) DO UPDATE SET
			confidence      = GREATEST(ti_iocs.confidence, EXCLUDED.confidence),
			severity        = EXCLUDED.severity,
			is_active       = true,
			threat_actor    = COALESCE(EXCLUDED.threat_actor, ti_iocs.threat_actor),
			malware_family  = COALESCE(EXCLUDED.malware_family, ti_iocs.malware_family),
			campaign        = COALESCE(EXCLUDED.campaign, ti_iocs.campaign),
			valid_until     = EXCLUDED.valid_until,
			updated_at      = NOW()
		RETURNING id, is_active, valid_from, created_at, updated_at`,
		id, tenantID, req.FeedID, req.IOCType, req.Value, norm,
		req.TLP, req.Confidence, sev,
		nvlS(req.MitreTactic), nvlS(req.MitreTechnique),
		nvlS(req.ThreatActor), nvlS(req.MalwareFamily), nvlS(req.Campaign),
		req.ValidUntil, nvlS(req.ExternalID), nvlS(req.StixID),
		tags, nvlS(req.Description),
	).Scan(&ioc.ID, &ioc.IsActive, &ioc.ValidFrom, &ioc.CreatedAt, &ioc.UpdatedAt); err != nil {
		return nil, fmt.Errorf("upsert ioc: %w", err)
	}
	return ioc, nil
}

// Lookup finds an active IOC by type and value. Returns nil if not found.
func (r *IOCRepository) Lookup(ctx context.Context, tenantID uuid.UUID, iocType, value string) (*model.IOC, error) {
	norm := normalizeValue(iocType, value)
	row := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, feed_id, ioc_type, value, normalized, tlp, confidence, severity,
		       is_active, mitre_tactic, mitre_technique, threat_actor, malware_family, campaign,
		       valid_from, valid_until, hit_count, last_hit_at, external_id, stix_id,
		       tags, description, created_at, updated_at
		FROM ti_iocs
		WHERE tenant_id = $1 AND ioc_type = $2 AND normalized = $3
		  AND is_active = true
		  AND (valid_until IS NULL OR valid_until > NOW())`,
		tenantID, iocType, norm)
	ioc, err := scanIOC(row)
	if err != nil {
		return nil, err
	}
	return ioc, nil
}

// ListIOCs returns IOCs matching the filter.
func (r *IOCRepository) ListIOCs(ctx context.Context, f model.IOCFilter) ([]*model.IOC, int, error) {
	where := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	n := 2

	if f.IOCType != "" {
		where = append(where, fmt.Sprintf("ioc_type = $%d", n))
		args = append(args, f.IOCType)
		n++
	}
	if f.Severity != "" {
		where = append(where, fmt.Sprintf("severity = $%d", n))
		args = append(args, f.Severity)
		n++
	}
	if f.FeedID != nil {
		where = append(where, fmt.Sprintf("feed_id = $%d", n))
		args = append(args, *f.FeedID)
		n++
	}
	if f.IsActive != nil {
		where = append(where, fmt.Sprintf("is_active = $%d", n))
		args = append(args, *f.IsActive)
		n++
	}
	if f.Search != "" {
		where = append(where, fmt.Sprintf("(value ILIKE $%d OR description ILIKE $%d)", n, n))
		args = append(args, "%"+f.Search+"%")
		n++
	}

	wc := strings.Join(where, " AND ")
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	var total int
	if err := r.db.QueryRow(ctx, fmt.Sprintf("SELECT COUNT(*) FROM ti_iocs WHERE %s", wc), args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	q := fmt.Sprintf(`
		SELECT id, tenant_id, feed_id, ioc_type, value, normalized, tlp, confidence, severity,
		       is_active, mitre_tactic, mitre_technique, threat_actor, malware_family, campaign,
		       valid_from, valid_until, hit_count, last_hit_at, external_id, stix_id,
		       tags, description, created_at, updated_at
		FROM ti_iocs WHERE %s
		ORDER BY hit_count DESC, created_at DESC
		LIMIT $%d OFFSET $%d`, wc, n, n+1)
	args = append(args, limit, f.Offset)

	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []*model.IOC
	for rows.Next() {
		ioc, err := scanIOC(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, ioc)
	}
	return out, total, nil
}

// DeactivateExpired marks IOCs past their valid_until date as inactive.
func (r *IOCRepository) DeactivateExpired(ctx context.Context) (int64, error) {
	res, err := r.db.Exec(ctx,
		`UPDATE ti_iocs SET is_active = false, updated_at = NOW()
		 WHERE is_active = true AND valid_until IS NOT NULL AND valid_until <= NOW()`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected(), nil
}

// RecordHit increments hit_count and updates last_hit_at for an IOC.
func (r *IOCRepository) RecordHit(ctx context.Context, tenantID, iocID uuid.UUID, hit *model.IOCHit) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		`UPDATE ti_iocs SET hit_count = hit_count + 1, last_hit_at = NOW() WHERE id = $1 AND tenant_id = $2`,
		iocID, tenantID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO ti_ioc_hits (id, tenant_id, ioc_id, source_event_id, alert_id, matched_value, matched_field, severity, auto_blocked)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		hit.ID, tenantID, iocID, hit.SourceEventID, hit.AlertID,
		hit.MatchedValue, hit.MatchedField, hit.Severity, hit.AutoBlocked,
	)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ListHits returns recent IOC hit records.
func (r *IOCRepository) ListHits(ctx context.Context, tenantID uuid.UUID, limit int) ([]*model.IOCHit, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, ioc_id, source_event_id, alert_id, matched_value, matched_field, severity, auto_blocked, hit_at
		FROM ti_ioc_hits WHERE tenant_id = $1
		ORDER BY hit_at DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.IOCHit
	for rows.Next() {
		h := &model.IOCHit{}
		if err := rows.Scan(&h.ID, &h.TenantID, &h.IOCID, &h.SourceEventID, &h.AlertID,
			&h.MatchedValue, &h.MatchedField, &h.Severity, &h.AutoBlocked, &h.HitAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, nil
}

// ─── Threat Actors ────────────────────────────────────────────────────────────

func (r *IOCRepository) CreateThreatActor(ctx context.Context, tenantID uuid.UUID, req *model.CreateThreatActorRequest) (*model.ThreatActor, error) {
	id := uuid.New()
	soph := req.Sophistication
	if soph == "" {
		soph = "medium"
	}
	aliases := req.Aliases
	if aliases == nil {
		aliases = []string{}
	}
	groups := req.MitreGroups
	if groups == nil {
		groups = []string{}
	}
	ttps := req.TTPs
	if ttps == nil {
		ttps = []string{}
	}
	tags := req.Tags
	if tags == nil {
		tags = []string{}
	}

	ta := &model.ThreatActor{
		ID: id, TenantID: tenantID, Name: req.Name, Aliases: aliases,
		Description: req.Description, Motivation: req.Motivation, Sophistication: soph,
		OriginCountry: req.OriginCountry, MitreGroups: groups, TTPs: ttps,
		TargetsCBS: req.TargetsCBS, TargetsSWIFT: req.TargetsSWIFT, TargetsATM: req.TargetsATM,
		StixID: req.StixID, Tags: tags,
	}
	if err := r.db.QueryRow(ctx, `
		INSERT INTO ti_threat_actors
			(id, tenant_id, name, aliases, description, motivation, sophistication,
			 origin_country, mitre_groups, ttps, targets_cbs, targets_swift, targets_atm, stix_id, tags)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		RETURNING created_at, updated_at`,
		id, tenantID, req.Name, aliases, nvlS(req.Description),
		nvlS(req.Motivation), soph, nvlS(req.OriginCountry),
		groups, ttps, req.TargetsCBS, req.TargetsSWIFT, req.TargetsATM,
		nvlS(req.StixID), tags,
	).Scan(&ta.CreatedAt, &ta.UpdatedAt); err != nil {
		return nil, fmt.Errorf("create threat actor: %w", err)
	}
	return ta, nil
}

func (r *IOCRepository) ListThreatActors(ctx context.Context, tenantID uuid.UUID, bankingOnly bool) ([]*model.ThreatActor, error) {
	q := `SELECT id, tenant_id, name, aliases, description, motivation, sophistication,
		         origin_country, first_seen, last_seen, mitre_groups, ttps,
		         targets_cbs, targets_swift, targets_atm, stix_id, tags, created_at, updated_at
		  FROM ti_threat_actors WHERE tenant_id = $1`
	if bankingOnly {
		q += ` AND (targets_cbs = true OR targets_swift = true OR targets_atm = true)`
	}
	q += ` ORDER BY name`

	rows, err := r.db.Query(ctx, q, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.ThreatActor
	for rows.Next() {
		ta := &model.ThreatActor{}
		var desc, mot, orig, stix *string
		if err := rows.Scan(
			&ta.ID, &ta.TenantID, &ta.Name, &ta.Aliases, &desc, &mot, &ta.Sophistication,
			&orig, &ta.FirstSeen, &ta.LastSeen, &ta.MitreGroups, &ta.TTPs,
			&ta.TargetsCBS, &ta.TargetsSWIFT, &ta.TargetsATM, &stix, &ta.Tags,
			&ta.CreatedAt, &ta.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if desc != nil {
			ta.Description = *desc
		}
		if mot != nil {
			ta.Motivation = *mot
		}
		if orig != nil {
			ta.OriginCountry = *orig
		}
		if stix != nil {
			ta.StixID = *stix
		}
		if ta.Aliases == nil {
			ta.Aliases = []string{}
		}
		if ta.MitreGroups == nil {
			ta.MitreGroups = []string{}
		}
		if ta.TTPs == nil {
			ta.TTPs = []string{}
		}
		if ta.Tags == nil {
			ta.Tags = []string{}
		}
		out = append(out, ta)
	}
	return out, nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (r *IOCRepository) Stats(ctx context.Context, tenantID uuid.UUID) (*model.TIStats, error) {
	s := &model.TIStats{
		ByType:     make(map[string]int),
		BySeverity: make(map[string]int),
	}

	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM ti_iocs WHERE tenant_id=$1`, tenantID).Scan(&s.TotalIOCs)                                                                                //nolint
	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM ti_iocs WHERE tenant_id=$1 AND is_active=true`, tenantID).Scan(&s.ActiveIOCs)                                                            //nolint
	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM ti_feeds WHERE tenant_id=$1`, tenantID).Scan(&s.TotalFeeds)                                                                              //nolint
	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM ti_feeds WHERE tenant_id=$1 AND enabled=true`, tenantID).Scan(&s.EnabledFeeds)                                                           //nolint
	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM ti_ioc_hits WHERE tenant_id=$1 AND hit_at >= NOW()-INTERVAL '24 hours'`, tenantID).Scan(&s.HitsLast24h)                                  //nolint
	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM ti_ioc_hits WHERE tenant_id=$1 AND hit_at >= NOW()-INTERVAL '7 days'`, tenantID).Scan(&s.HitsLast7d)                                     //nolint
	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM ti_threat_actors WHERE tenant_id=$1`, tenantID).Scan(&s.ThreatActors)                                                                    //nolint
	r.db.QueryRow(ctx, `SELECT COUNT(*) FROM ti_threat_actors WHERE tenant_id=$1 AND (targets_cbs=true OR targets_swift=true OR targets_atm=true)`, tenantID).Scan(&s.BankingThreats) //nolint

	rows, _ := r.db.Query(ctx, `SELECT ioc_type, COUNT(*) FROM ti_iocs WHERE tenant_id=$1 AND is_active=true GROUP BY ioc_type`, tenantID)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var typ string
			var cnt int
			if rows.Scan(&typ, &cnt) == nil {
				s.ByType[typ] = cnt
			}
		}
	}

	srows, _ := r.db.Query(ctx, `SELECT severity, COUNT(*) FROM ti_iocs WHERE tenant_id=$1 AND is_active=true GROUP BY severity`, tenantID)
	if srows != nil {
		defer srows.Close()
		for srows.Next() {
			var sev string
			var cnt int
			if srows.Scan(&sev, &cnt) == nil {
				s.BySeverity[sev] = cnt
			}
		}
	}

	// Top 10 most-hit IOCs
	topRows, _ := r.db.Query(ctx, `
		SELECT id, tenant_id, feed_id, ioc_type, value, normalized, tlp, confidence, severity,
		       is_active, mitre_tactic, mitre_technique, threat_actor, malware_family, campaign,
		       valid_from, valid_until, hit_count, last_hit_at, external_id, stix_id,
		       tags, description, created_at, updated_at
		FROM ti_iocs WHERE tenant_id=$1 AND is_active=true ORDER BY hit_count DESC LIMIT 10`, tenantID)
	if topRows != nil {
		defer topRows.Close()
		for topRows.Next() {
			ioc, err := scanIOC(topRows)
			if err == nil {
				s.TopIOCs = append(s.TopIOCs, ioc)
			}
		}
	}

	return s, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

type scannable interface {
	Scan(dest ...any) error
}

func scanFeed(row scannable) (*model.Feed, error) {
	f := &model.Feed{}
	var desc, url, apiRef, collID, lastErr *string
	err := row.Scan(
		&f.ID, &f.TenantID, &f.Name, &desc, &f.FeedType, &url, &apiRef, &collID,
		&f.PollIntervalS, &f.Enabled, &f.TLP, &f.Confidence,
		&f.LastPolledAt, &f.LastIOCCount, &f.ErrorCount, &lastErr,
		&f.CreatedAt, &f.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan feed: %w", err)
	}
	if desc != nil {
		f.Description = *desc
	}
	if url != nil {
		f.URL = *url
	}
	if apiRef != nil {
		f.ApiKeyRef = *apiRef
	}
	if collID != nil {
		f.CollectionID = *collID
	}
	if lastErr != nil {
		f.LastError = *lastErr
	}
	return f, nil
}

func scanIOC(row scannable) (*model.IOC, error) {
	ioc := &model.IOC{}
	var (
		tactic, technique, actor, malware, campaign *string
		extID, stixID, desc                         *string
	)
	err := row.Scan(
		&ioc.ID, &ioc.TenantID, &ioc.FeedID, &ioc.IOCType, &ioc.Value, &ioc.Normalized,
		&ioc.TLP, &ioc.Confidence, &ioc.Severity, &ioc.IsActive,
		&tactic, &technique, &actor, &malware, &campaign,
		&ioc.ValidFrom, &ioc.ValidUntil, &ioc.HitCount, &ioc.LastHitAt,
		&extID, &stixID, &ioc.Tags, &desc,
		&ioc.CreatedAt, &ioc.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan ioc: %w", err)
	}
	if tactic != nil {
		ioc.MitreTactic = *tactic
	}
	if technique != nil {
		ioc.MitreTechnique = *technique
	}
	if actor != nil {
		ioc.ThreatActor = *actor
	}
	if malware != nil {
		ioc.MalwareFamily = *malware
	}
	if campaign != nil {
		ioc.Campaign = *campaign
	}
	if extID != nil {
		ioc.ExternalID = *extID
	}
	if stixID != nil {
		ioc.StixID = *stixID
	}
	if desc != nil {
		ioc.Description = *desc
	}
	if ioc.Tags == nil {
		ioc.Tags = []string{}
	}
	return ioc, nil
}

// normalizeValue canonicalizes an IOC value for dedup matching.
func normalizeValue(iocType, value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	// Strip http(s):// scheme for URLs when storing normalized form
	if iocType == model.IOCTypeDomain || iocType == model.IOCTypeURL {
		v = strings.TrimPrefix(v, "http://")
		v = strings.TrimPrefix(v, "https://")
		v = strings.TrimRight(v, "/")
	}
	return v
}

func nvlS(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
