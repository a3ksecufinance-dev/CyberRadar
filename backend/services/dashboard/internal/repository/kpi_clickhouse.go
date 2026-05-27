package repository

import (
	"context"
	"time"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/cyberradar/platform/services/dashboard/internal/model"
	"github.com/google/uuid"
)

// KPIRepository reads/writes platform KPI snapshots in ClickHouse.
type KPIRepository struct {
	ch driver.Conn
}

// NewKPIRepository creates a KPIRepository.
func NewKPIRepository(ch driver.Conn) *KPIRepository {
	return &KPIRepository{ch: ch}
}

// InsertSnapshot persists a single KPI snapshot.
func (r *KPIRepository) InsertSnapshot(ctx context.Context, s model.KPISnapshot) error {
	labels := s.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	return r.ch.Exec(ctx, `
		INSERT INTO crp_dash.kpi_snapshots
		    (tenant_id, domain, metric_key, metric_value, labels, snapped_at)
		VALUES (?,?,?,?,?,?)`,
		s.TenantID, s.Domain, s.MetricKey, s.MetricValue, labels, s.SnappedAt)
}

// InsertSnapshotBatch persists multiple KPI snapshots in one batch.
func (r *KPIRepository) InsertSnapshotBatch(ctx context.Context, snapshots []model.KPISnapshot) error {
	if len(snapshots) == 0 {
		return nil
	}
	batch, err := r.ch.PrepareBatch(ctx, `
		INSERT INTO crp_dash.kpi_snapshots
		    (tenant_id, domain, metric_key, metric_value, labels, snapped_at)`)
	if err != nil {
		return err
	}
	for _, s := range snapshots {
		labels := s.Labels
		if labels == nil {
			labels = map[string]string{}
		}
		if err := batch.Append(s.TenantID, s.Domain, s.MetricKey, s.MetricValue, labels, s.SnappedAt); err != nil {
			return err
		}
	}
	return batch.Send()
}

// QueryTimeSeries returns KPI data points for a given domain/metric over a time range.
// interval: "1m", "5m", "1h", "1d"
func (r *KPIRepository) QueryTimeSeries(ctx context.Context, q model.KPIQueryRequest) ([]model.KPIPoint, error) {
	chInterval := intervalToClickHouse(q.Interval)

	rows, err := r.ch.Query(ctx, `
		SELECT
		    toStartOfInterval(snapped_at, INTERVAL `+chInterval+`) AS ts,
		    avg(metric_value) AS val
		FROM crp_dash.kpi_snapshots
		WHERE tenant_id={tenant:UUID}
		  AND domain={domain:String}
		  AND metric_key={metric_key:String}
		  AND snapped_at BETWEEN {since:DateTime} AND {until:DateTime}
		GROUP BY ts
		ORDER BY ts`,
		clickhouse.Named("tenant", q.TenantID),
		clickhouse.Named("domain", q.Domain),
		clickhouse.Named("metric_key", q.MetricKey),
		clickhouse.Named("since", q.Since),
		clickhouse.Named("until", q.Until),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []model.KPIPoint
	for rows.Next() {
		var p model.KPIPoint
		if err := rows.Scan(&p.Timestamp, &p.Value); err != nil {
			return nil, err
		}
		points = append(points, p)
	}
	return points, rows.Err()
}

// LatestSnapshots returns the most recent value for every metric of a domain.
func (r *KPIRepository) LatestSnapshots(ctx context.Context, tenantID uuid.UUID, domain string) (map[string]float64, error) {
	rows, err := r.ch.Query(ctx, `
		SELECT metric_key, argMax(metric_value, snapped_at)
		FROM crp_dash.kpi_snapshots
		WHERE tenant_id={tenant:UUID} AND domain={domain:String}
		  AND snapped_at >= now() - INTERVAL 1 HOUR
		GROUP BY metric_key`,
		clickhouse.Named("tenant", tenantID),
		clickhouse.Named("domain", domain),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	m := make(map[string]float64)
	for rows.Next() {
		var key string
		var val float64
		if err := rows.Scan(&key, &val); err != nil {
			return nil, err
		}
		m[key] = val
	}
	return m, rows.Err()
}

// RiskTimeline returns entity risk score history.
func (r *KPIRepository) RiskTimeline(ctx context.Context, tenantID uuid.UUID, entityType, entityID string, since time.Time) ([]model.KPIPoint, error) {
	eid, _ := uuid.Parse(entityID)
	rows, err := r.ch.Query(ctx, `
		SELECT hour, risk_score FROM crp_dash.risk_timeline
		WHERE tenant_id={tenant:UUID}
		  AND entity_type={entity_type:String}
		  AND entity_id={entity_id:UUID}
		  AND hour >= {since:DateTime}
		ORDER BY hour`,
		clickhouse.Named("tenant", tenantID),
		clickhouse.Named("entity_type", entityType),
		clickhouse.Named("entity_id", eid),
		clickhouse.Named("since", since),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []model.KPIPoint
	for rows.Next() {
		var p model.KPIPoint
		if err := rows.Scan(&p.Timestamp, &p.Value); err != nil {
			return nil, err
		}
		points = append(points, p)
	}
	return points, rows.Err()
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func intervalToClickHouse(interval string) string {
	switch interval {
	case "5m":
		return "5 MINUTE"
	case "1h":
		return "1 HOUR"
	case "1d":
		return "1 DAY"
	default: // 1m
		return "1 MINUTE"
	}
}
