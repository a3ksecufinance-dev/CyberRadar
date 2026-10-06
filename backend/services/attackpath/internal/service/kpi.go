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
// Attack paths: a path that both starts on the internet and carries an exploit
// step is the one an attacker can actually walk today, so it weighs most.
func (s *AttackPathService) KPISamples(ctx context.Context, tenantID uuid.UUID) ([]kpi.Sample, error) {
	stats, err := s.GetStats(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Choke points are not in the stats rollup; they are computed on demand.
	// The limit bounds the work, and the overview only shows how many there
	// are — a tenant with more than this many has bigger problems than the
	// count's precision.
	const chokePointLimit = 100
	chokePoints, err := s.GetChokePoints(ctx, tenantID, nil, chokePointLimit)
	if err != nil {
		return nil, err
	}

	return []kpi.Sample{
		{MetricKey: "total_paths", Value: float64(stats.TotalPaths)},
		{MetricKey: "choke_points", Value: float64(len(chokePoints))},
		{MetricKey: "risk_score", Value: capped(10*stats.HighRiskPaths + 2*stats.PathsWithExploit)},
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
