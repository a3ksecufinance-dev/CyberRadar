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
// UEBA: a single entity whose behaviour has drifted far enough to be flagged
// high-risk matters more than a handful of individual anomalies.
func (s *UEBAService) KPISamples(ctx context.Context, tenantID uuid.UUID) ([]kpi.Sample, error) {
	stats, err := s.GetStats(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return []kpi.Sample{
		{MetricKey: "active_anomalies", Value: float64(stats.OpenAnomalies)},
		{MetricKey: "high_risk_entities", Value: float64(stats.HighRiskEntities)},
		{MetricKey: "risk_score", Value: capped(8*stats.HighRiskEntities + 2*stats.OpenAnomalies)},
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
