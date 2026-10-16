package service

import (
	"context"

	"github.com/google/uuid"

	"github.com/cyberradar/platform/internal/pkg/kpi"
)

// ─── KPI reporting ────────────────────────────────────────────────────────────
//
// What this domain owes the platform dashboard. PlatformOverview reads these
// keys back and builds the security score from them; nothing published them
// before, so the whole overview answered zero.
//
// The risk_score formula below is a STARTING POINT, not a calibrated model.
// It is monotone (more of anything bad raises it), bounded at 100, and written
// out so it can be argued with. Weighting one severity against another is a
// risk-appetite decision that belongs to the institution deploying this, in
// the same way the permission matrix does — review it before anyone reads the
// number as a measurement.
//
// SIEM: an open critical alert is the loudest thing this domain can say, so it
// dominates. Ten open criticals saturate the score.
func (s *SIEMService) KPISamples(ctx context.Context, tenantID uuid.UUID) ([]kpi.Sample, error) {
	stats, err := s.GetAlertStats(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// ClickHouse stores severity as Enum8('LOW','MEDIUM','HIGH','CRITICAL'),
	// so these buckets are upper case here and lower case in Postgres domains.
	critical := stats.BySeverity["CRITICAL"]
	high := stats.BySeverity["HIGH"]
	medium := stats.BySeverity["MEDIUM"]

	return []kpi.Sample{
		{MetricKey: "open_alerts", Value: float64(stats.Open)},
		{MetricKey: "critical_alerts", Value: float64(critical)},
		{MetricKey: "risk_score", Value: capped(10*critical + 4*high + medium)},
	}, nil
}

// capped bounds a weighted count to the 0–100 range the dashboard expects.
func capped(n int) float64 {
	if n > 100 {
		return 100
	}
	if n < 0 {
		return 0
	}
	return float64(n)
}
