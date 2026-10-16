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
// Vulnerabilities: a finding past its remediation SLA counts for more than an
// equally severe one still inside it — the breach is the part that is nobody's
// plan any more.
func (s *VulnService) KPISamples(ctx context.Context, tenantID uuid.UUID) ([]kpi.Sample, error) {
	stats, err := s.GetStats(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	critical := stats.BySeverity["critical"]
	high := stats.BySeverity["high"]

	return []kpi.Sample{
		{MetricKey: "critical_vulns", Value: float64(critical)},
		{MetricKey: "sla_breached", Value: float64(stats.SLABreached)},
		{MetricKey: "risk_score", Value: capped(5*critical + 2*high + 3*stats.SLABreached)},
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
