package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/cyberradar/platform/services/ueba/internal/model"
	"github.com/google/uuid"
)

// BehaviorRepository stores behavioral time-series in ClickHouse.
type BehaviorRepository struct {
	db driver.Conn
}

// NewBehaviorRepository creates a BehaviorRepository.
func NewBehaviorRepository(db driver.Conn) *BehaviorRepository {
	return &BehaviorRepository{db: db}
}

// InsertEvent writes one behavioral event to ClickHouse.
func (r *BehaviorRepository) InsertEvent(ctx context.Context, be *model.BehaviorEvent) error {
	attrs, _ := json.Marshal(be.Attributes)
	return r.db.Exec(ctx, `
		INSERT INTO crp_ueba.behavior_events
			(event_id, tenant_id, entity_id, entity_type, event_type, source_type,
			 action, outcome, ip_source, geo_country, risk_score,
			 hour_of_day, day_of_week, attributes, event_time)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		be.EventID, be.TenantID, be.EntityID, be.EntityType, be.EventType, be.SourceType,
		be.Action, be.Outcome, be.IPSource, be.GeoCountry, be.RiskScore,
		be.HourOfDay, be.DayOfWeek, string(attrs), be.EventTime,
	)
}

// InsertAnomaly mirrors an anomaly event to ClickHouse for fast range queries.
func (r *BehaviorRepository) InsertAnomaly(ctx context.Context, a *model.Anomaly) error {
	details, _ := json.Marshal(a.Details)
	srcID := uuid.Nil
	if a.SourceEventID != nil {
		srcID = *a.SourceEventID
	}
	return r.db.Exec(ctx, `
		INSERT INTO crp_ueba.anomaly_events
			(anomaly_id, tenant_id, entity_id, entity_type, anomaly_type, severity,
			 score, baseline_val, observed_val, details, source_event_id, detected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.TenantID.String(), a.EntityID.String(), a.EntityType,
		a.AnomalyType, a.Severity, float32(a.Score),
		a.BaselineVal, a.ObservedVal, string(details), srcID, a.DetectedAt,
	)
}

// Timeline returns recent behavior events for an entity (descending).
func (r *BehaviorRepository) Timeline(ctx context.Context, tenantID, entityID string, from time.Time, limit int) ([]*model.BehaviorEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := r.db.Query(ctx, `
		SELECT event_id, tenant_id, entity_id, entity_type, event_type, source_type,
		       action, outcome, ip_source, geo_country, risk_score,
		       hour_of_day, day_of_week, attributes, event_time
		FROM crp_ueba.behavior_events
		WHERE tenant_id = {tenant:String}
		  AND entity_id = {entity:String}
		  AND event_time >= {from:DateTime64(3,'UTC')}
		ORDER BY event_time DESC
		LIMIT {limit:UInt32}`,
		map[string]any{
			"tenant": tenantID,
			"entity": entityID,
			"from":   from,
			"limit":  uint32(limit),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("timeline query: %w", err)
	}
	defer rows.Close()

	var out []*model.BehaviorEvent
	for rows.Next() {
		be := &model.BehaviorEvent{}
		var attrsRaw string
		if err := rows.Scan(
			&be.EventID, &be.TenantID, &be.EntityID, &be.EntityType,
			&be.EventType, &be.SourceType, &be.Action, &be.Outcome,
			&be.IPSource, &be.GeoCountry, &be.RiskScore,
			&be.HourOfDay, &be.DayOfWeek, &attrsRaw, &be.EventTime,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(attrsRaw), &be.Attributes)
		out = append(out, be)
	}
	return out, nil
}

// AnomalyCountByType returns anomaly counts grouped by type for the last N days.
func (r *BehaviorRepository) AnomalyCountByType(ctx context.Context, tenantID string, days int) (map[string]int, error) {
	cutoff := time.Now().UTC().AddDate(0, 0, -days)
	rows, err := r.db.Query(ctx, `
		SELECT anomaly_type, count() AS cnt
		FROM crp_ueba.anomaly_events
		WHERE tenant_id = {tenant:String}
		  AND detected_at >= {cutoff:DateTime64(3,'UTC')}
		GROUP BY anomaly_type`,
		map[string]any{"tenant": tenantID, "cutoff": cutoff},
	)
	if err != nil {
		return nil, fmt.Errorf("anomaly_count_by_type: %w", err)
	}
	defer rows.Close()

	out := make(map[string]int)
	for rows.Next() {
		var typ string
		var cnt uint64
		if err := rows.Scan(&typ, &cnt); err != nil {
			return nil, err
		}
		out[typ] = int(cnt)
	}
	return out, nil
}
