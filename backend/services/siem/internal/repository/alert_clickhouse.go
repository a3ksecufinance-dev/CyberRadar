package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/cyberradar/platform/services/siem/internal/model"
	"github.com/google/uuid"
)

// AlertRepository stores and queries alerts in ClickHouse.
type AlertRepository struct {
	conn clickhouse.Conn
}

// NewAlertRepository creates an AlertRepository.
func NewAlertRepository(conn clickhouse.Conn) *AlertRepository {
	return &AlertRepository{conn: conn}
}

// Insert writes a new alert to ClickHouse.
func (r *AlertRepository) Insert(ctx context.Context, a *model.Alert) error {
	return r.conn.Exec(ctx, `
		INSERT INTO crp_siem.alerts (
			alert_id, tenant_id, rule_id, rule_name,
			severity, category, mitre_tactic, mitre_technique,
			entity_type, entity_value,
			source_event_id, user_id, ip_source, ip_destination,
			title, description, raw_evidence,
			dedup_key, dedup_window_s,
			event_time, event_count, risk_score
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.AlertID, a.TenantID, a.RuleID, a.RuleName,
		string(a.Severity), a.Category, a.MitreTactic, a.MitreTechnique,
		a.EntityType, a.EntityValue,
		a.SourceEventID, a.UserID, a.IPSource, a.IPDestination,
		a.Title, a.Description, a.RawEvidence,
		a.DedupKey, uint32(300),
		a.EventTime, a.EventCount, a.RiskScore,
	)
}

// IsDuplicate checks if an alert with the same dedup_key fired within the dedup window.
func (r *AlertRepository) IsDuplicate(ctx context.Context, tenantID, dedupKey string, windowSeconds int) (bool, error) {
	cutoff := time.Now().UTC().Add(-time.Duration(windowSeconds) * time.Second)
	var count uint64
	err := r.conn.QueryRow(ctx, `
		SELECT COUNT(*) FROM crp_siem.alerts
		WHERE tenant_id = {tenant:String}
		  AND dedup_key  = {key:String}
		  AND detected_at >= {cutoff:DateTime64(3,'UTC')}`,
		clickhouse.Named("tenant", tenantID),
		clickhouse.Named("key", dedupKey),
		clickhouse.Named("cutoff", cutoff),
	).Scan(&count)
	return count > 0, err
}

// List returns alerts matching the filter.
func (r *AlertRepository) List(ctx context.Context, f model.AlertFilter) ([]*model.Alert, int, error) {
	where := []string{"tenant_id = {tenant:String}"}
	params := []any{clickhouse.Named("tenant", f.TenantID.String())}

	if f.Severity != "" {
		where = append(where, "severity = {sev:String}")
		params = append(params, clickhouse.Named("sev", f.Severity))
	}
	if f.RuleID != "" {
		where = append(where, "rule_id = {rule:String}")
		params = append(params, clickhouse.Named("rule", f.RuleID))
	}
	if f.EntityType != "" {
		where = append(where, "entity_type = {etype:String}")
		params = append(params, clickhouse.Named("etype", f.EntityType))
	}
	if f.From != nil {
		where = append(where, "detected_at >= {from:DateTime64(3,'UTC')}")
		params = append(params, clickhouse.Named("from", *f.From))
	}
	if f.To != nil {
		where = append(where, "detected_at <= {to:DateTime64(3,'UTC')}")
		params = append(params, clickhouse.Named("to", *f.To))
	}

	wc := ""
	for i, w := range where {
		if i == 0 {
			wc = "WHERE " + w
		} else {
			wc += " AND " + w
		}
	}

	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	// Count
	var total uint64
	if err := r.conn.QueryRow(ctx,
		fmt.Sprintf("SELECT COUNT(*) FROM crp_siem.alerts %s", wc),
		params...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("alert count: %w", err)
	}

	// Data
	rows, err := r.conn.Query(ctx, fmt.Sprintf(`
		SELECT alert_id, tenant_id, rule_id, rule_name,
		       severity, category, mitre_tactic, mitre_technique,
		       entity_type, entity_value,
		       source_event_id, user_id, ip_source, ip_destination,
		       title, description, raw_evidence,
		       dedup_key, event_time, detected_at, event_count, risk_score
		FROM crp_siem.alerts %s
		ORDER BY severity DESC, detected_at DESC
		LIMIT %d OFFSET %d`, wc, limit, f.Offset), params...)
	if err != nil {
		return nil, 0, fmt.Errorf("alert list: %w", err)
	}
	defer rows.Close()

	var alerts []*model.Alert
	for rows.Next() {
		a := &model.Alert{}
		var sev string
		if err := rows.Scan(
			&a.AlertID, &a.TenantID, &a.RuleID, &a.RuleName,
			&sev, &a.Category, &a.MitreTactic, &a.MitreTechnique,
			&a.EntityType, &a.EntityValue,
			&a.SourceEventID, &a.UserID, &a.IPSource, &a.IPDestination,
			&a.Title, &a.Description, &a.RawEvidence,
			&a.DedupKey, &a.EventTime, &a.DetectedAt, &a.EventCount, &a.RiskScore,
		); err != nil {
			return nil, 0, err
		}
		a.Severity = model.Severity(sev)
		alerts = append(alerts, a)
	}

	return alerts, int(total), nil
}

// Stats returns aggregated alert statistics.
func (r *AlertRepository) Stats(ctx context.Context, tenantID uuid.UUID) (*model.AlertStats, error) {
	stats := &model.AlertStats{
		BySeverity: make(map[string]int),
		ByCategory: make(map[string]int),
	}

	// Total and 24h/7d counts
	row := r.conn.QueryRow(ctx, `
		SELECT
			COUNT(*),
			countIf(detected_at >= now() - INTERVAL 1 DAY),
			countIf(detected_at >= now() - INTERVAL 7 DAY)
		FROM crp_siem.alerts
		WHERE tenant_id = {t:String}`,
		clickhouse.Named("t", tenantID.String()))
	if err := row.Scan(&stats.Total, &stats.FiredLast24h, &stats.FiredLast7d); err != nil {
		return nil, err
	}

	// By severity
	rows, err := r.conn.Query(ctx, `
		SELECT severity, COUNT(*) FROM crp_siem.alerts
		WHERE tenant_id = {t:String}
		GROUP BY severity`, clickhouse.Named("t", tenantID.String()))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var cnt uint64
		if err := rows.Scan(&sev, &cnt); err != nil {
			return nil, err
		}
		stats.BySeverity[sev] = int(cnt)
	}

	// By category
	rows2, err := r.conn.Query(ctx, `
		SELECT category, COUNT(*) FROM crp_siem.alerts
		WHERE tenant_id = {t:String}
		GROUP BY category ORDER BY COUNT(*) DESC LIMIT 10`,
		clickhouse.Named("t", tenantID.String()))
	if err != nil {
		return nil, err
	}
	defer rows2.Close()
	for rows2.Next() {
		var cat string
		var cnt uint64
		if err := rows2.Scan(&cat, &cnt); err != nil {
			return nil, err
		}
		stats.ByCategory[cat] = int(cnt)
	}

	// Top rules
	rows3, err := r.conn.Query(ctx, `
		SELECT rule_id, rule_name, COUNT(*) as cnt
		FROM crp_siem.alerts WHERE tenant_id = {t:String}
		GROUP BY rule_id, rule_name ORDER BY cnt DESC LIMIT 5`,
		clickhouse.Named("t", tenantID.String()))
	if err != nil {
		return nil, err
	}
	defer rows3.Close()
	for rows3.Next() {
		var rs model.RuleStat
		var cnt uint64
		if err := rows3.Scan(&rs.RuleID, &rs.RuleName, &cnt); err != nil {
			return nil, err
		}
		rs.Count = int(cnt)
		stats.TopRules = append(stats.TopRules, rs)
	}

	return stats, nil
}

// evidenceJSON serialises an event to a compact JSON string for raw_evidence.
func evidenceJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
