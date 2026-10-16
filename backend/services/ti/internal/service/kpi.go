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
// Threat intel: holding indicators is not itself risk — a hit is. The size of
// the feed does not move the score; matches against it do.
func (s *TIService) KPISamples(ctx context.Context, tenantID uuid.UUID) ([]kpi.Sample, error) {
	stats, err := s.GetStats(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return []kpi.Sample{
		{MetricKey: "active_iocs", Value: float64(stats.ActiveIOCs)},
		{MetricKey: "ioc_hits_today", Value: float64(stats.HitsLast24h)},
		{MetricKey: "risk_score", Value: capped(10 * stats.HitsLast24h)},
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
