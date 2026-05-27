package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/cyberradar/platform/internal/pkg/event"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/services/pam/internal/model"
	"github.com/cyberradar/platform/services/pam/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// RiskEngine consumes enriched events and maintains identity risk profiles.
type RiskEngine struct {
	repo     *repository.PAMRepository
	consumer *pkgkafka.Consumer
	logger   zerolog.Logger
}

// NewRiskEngine creates a RiskEngine.
func NewRiskEngine(repo *repository.PAMRepository, consumer *pkgkafka.Consumer, logger zerolog.Logger) *RiskEngine {
	return &RiskEngine{repo: repo, consumer: consumer, logger: logger}
}

// Run starts the Kafka consumer. Blocks until ctx is cancelled.
func (e *RiskEngine) Run(ctx context.Context) error {
	e.logger.Info().Msg("risk_engine_started")
	return e.consumer.Run(ctx, e.handle)
}

// handle processes one enriched event and updates the relevant identity risk profile.
func (e *RiskEngine) handle(ctx context.Context, msg pkgkafka.Message) error {
	var ev event.NormalizedEvent
	if err := json.Unmarshal(msg.Value, &ev); err != nil {
		return nil
	}
	if ev.UserID == nil || *ev.UserID == "" {
		return nil // no identity context to enrich
	}

	tenantID, err := uuid.Parse(ev.TenantID)
	if err != nil {
		return nil
	}
	identityID, err := uuid.Parse(*ev.UserID)
	if err != nil {
		return nil
	}

	// Load or create profile
	profile, err := e.repo.GetRiskProfile(ctx, tenantID, identityID)
	if err != nil {
		e.logger.Error().Err(err).Msg("risk_profile_load_error")
		return nil
	}
	if profile == nil {
		profile = &model.IdentityRiskProfile{
			TenantID:         tenantID,
			IdentityID:       identityID,
			NormalLoginHours: []int{},
			NormalCountries:  []string{},
			NormalIPPrefixes: []string{},
		}
	}

	// Update activity counters
	profile.Events7d++
	profile.EventsToday++

	// Update last login context for IAM events
	if ev.Category == event.CategoryIAM {
		now := ev.Timestamp
		profile.LastLoginAt = &now
		if ev.IPSource != nil {
			profile.LastLoginIP = *ev.IPSource
		}
		if ev.GeoCountry != nil {
			profile.LastLoginCountry = *ev.GeoCountry
		}
	}

	// Run anomaly detectors
	anomalies := e.detectAnomalies(profile, &ev)
	if len(anomalies) > 0 {
		now := time.Now().UTC()
		profile.LastAnomalyAt = &now
		profile.AnomalyCount7d++
		profile.AnomalyCount30d++
	}

	// Recompute dimensional scores
	e.recomputeScores(profile, &ev)

	// Persist
	if err := e.repo.UpsertRiskProfile(ctx, profile); err != nil {
		e.logger.Error().Err(err).
			Str("identity_id", identityID.String()).
			Msg("risk_profile_upsert_error")
	}

	return nil
}

// detectAnomalies returns a list of anomaly descriptions for an event.
func (e *RiskEngine) detectAnomalies(p *model.IdentityRiskProfile, ev *event.NormalizedEvent) []string {
	var anomalies []string

	// Off-hours login
	if p.BaselineReady && ev.Category == event.CategoryIAM && ev.Outcome == event.OutcomeSuccess {
		hour := ev.Timestamp.UTC().Hour()
		if !contains(p.NormalLoginHours, hour) {
			anomalies = append(anomalies, fmt.Sprintf("off_hours_login: hour %d not in baseline", hour))
		}
	}

	// New country
	if p.BaselineReady && ev.GeoCountry != nil && *ev.GeoCountry != "" && *ev.GeoCountry != "PRIVATE" {
		if !containsStr(p.NormalCountries, *ev.GeoCountry) {
			anomalies = append(anomalies, fmt.Sprintf("new_country: %s not in baseline", *ev.GeoCountry))
		}
	}

	// New IP prefix (/24)
	if p.BaselineReady && ev.IPSource != nil {
		prefix := ipPrefix(*ev.IPSource)
		if prefix != "" && !containsStr(p.NormalIPPrefixes, prefix) && !isPrivatePrefix(prefix) {
			anomalies = append(anomalies, fmt.Sprintf("new_ip_prefix: %s not in baseline", prefix))
		}
	}

	// Brute force (high failed_login_score already accounts for this via event score)
	if ev.Category == event.CategoryIAM && ev.Outcome == event.OutcomeFailure {
		if p.FailedLoginScore >= 3.0 {
			anomalies = append(anomalies, "brute_force_pattern: repeated authentication failures")
		}
	}

	// Exfiltration indicator
	if ev.MitreTactic != nil && *ev.MitreTactic == "TA0010" {
		anomalies = append(anomalies, "exfiltration_tactic_detected")
	}

	// Lateral movement
	if ev.MitreTactic != nil && *ev.MitreTactic == "TA0008" {
		anomalies = append(anomalies, "lateral_movement_tactic_detected")
	}

	return anomalies
}

// recomputeScores updates dimensional risk scores based on the incoming event.
func (e *RiskEngine) recomputeScores(p *model.IdentityRiskProfile, ev *event.NormalizedEvent) {
	// Failed login score: accumulate, decay over time
	if ev.Category == event.CategoryIAM && ev.Outcome == event.OutcomeFailure {
		p.FailedLoginScore = min(p.FailedLoginScore+1.0, 5.0)
	} else if ev.Category == event.CategoryIAM && ev.Outcome == event.OutcomeSuccess {
		// Partial decay on successful login
		p.FailedLoginScore = max(0, p.FailedLoginScore-0.5)
	}

	// Anomalous hours
	if p.BaselineReady && ev.Category == event.CategoryIAM {
		hour := ev.Timestamp.UTC().Hour()
		if !contains(p.NormalLoginHours, hour) {
			p.AnomalousHoursScore = min(p.AnomalousHoursScore+0.5, 3.0)
		} else {
			p.AnomalousHoursScore = max(0, p.AnomalousHoursScore-0.1)
		}
	}

	// Geo anomaly
	if p.BaselineReady && ev.GeoCountry != nil && *ev.GeoCountry != "" && *ev.GeoCountry != "PRIVATE" {
		if !containsStr(p.NormalCountries, *ev.GeoCountry) {
			p.GeoAnomalyScore = min(p.GeoAnomalyScore+1.5, 4.0)
		}
	}

	// Data exfil
	if ev.MitreTactic != nil && *ev.MitreTactic == "TA0010" {
		p.DataExfilScore = min(p.DataExfilScore+2.0, 5.0)
	}

	// Lateral movement
	if ev.MitreTactic != nil && *ev.MitreTactic == "TA0008" {
		p.LateralMovementScore = min(p.LateralMovementScore+1.5, 4.0)
	}

	// Recompute total (weighted average, cap 10)
	total := p.FailedLoginScore*0.25 +
		p.AnomalousHoursScore*0.15 +
		p.GeoAnomalyScore*0.20 +
		p.PrivilegeAbuseScore*0.20 +
		p.DataExfilScore*0.10 +
		p.LateralMovementScore*0.10

	if total > 10.0 {
		total = 10.0
	}
	p.RiskScore = total

	// Update baseline with new data (rolling window — simple append unique)
	if ev.Category == event.CategoryIAM && ev.Outcome == event.OutcomeSuccess {
		hour := ev.Timestamp.UTC().Hour()
		if !contains(p.NormalLoginHours, hour) && len(p.NormalLoginHours) < 24 {
			p.NormalLoginHours = append(p.NormalLoginHours, hour)
		}
		if ev.GeoCountry != nil && *ev.GeoCountry != "" && !containsStr(p.NormalCountries, *ev.GeoCountry) {
			p.NormalCountries = append(p.NormalCountries, *ev.GeoCountry)
		}
		if ev.IPSource != nil {
			pfx := ipPrefix(*ev.IPSource)
			if pfx != "" && !containsStr(p.NormalIPPrefixes, pfx) && len(p.NormalIPPrefixes) < 20 {
				p.NormalIPPrefixes = append(p.NormalIPPrefixes, pfx)
			}
		}
		// Mark baseline ready after 10 successful logins
		if len(p.NormalLoginHours) >= 3 {
			p.BaselineReady = true
		}
	}
}

// ComputeBreakdown produces a human-readable risk breakdown for an identity.
func ComputeBreakdown(p *model.IdentityRiskProfile) *model.RiskBreakdown {
	rb := &model.RiskBreakdown{
		IdentityID: p.IdentityID,
		TotalScore: p.RiskScore,
		RiskLevel:  p.RiskLevel(),
	}

	addFactor := func(dim string, score float64, reason string) {
		if score > 0 {
			rb.Factors = append(rb.Factors, model.RiskFactor{
				Dimension: dim,
				Score:     score,
				Reason:    reason,
			})
		}
	}

	addFactor("failed_logins", p.FailedLoginScore, fmt.Sprintf("%.1f failed login score (recent auth failures)", p.FailedLoginScore))
	addFactor("anomalous_hours", p.AnomalousHoursScore, "Login activity outside established baseline hours")
	addFactor("geo_anomaly", p.GeoAnomalyScore, "Authentication from new or unusual geographic location")
	addFactor("privilege_abuse", p.PrivilegeAbuseScore, "Unusual privileged access patterns")
	addFactor("data_exfiltration", p.DataExfilScore, "Potential data exfiltration behavior detected")
	addFactor("lateral_movement", p.LateralMovementScore, "Lateral movement tactics observed in events")

	if p.AnomalyCount7d > 0 {
		rb.Anomalies = append(rb.Anomalies, fmt.Sprintf("%d anomalies in the last 7 days", p.AnomalyCount7d))
	}
	if p.AnomalyCount30d > 3 {
		rb.Anomalies = append(rb.Anomalies, fmt.Sprintf("%d anomalies in the last 30 days (persistent risk)", p.AnomalyCount30d))
	}

	// Recommendations
	if p.FailedLoginScore >= 3 {
		rb.Recommended = append(rb.Recommended, "Force password reset and review auth logs")
	}
	if p.GeoAnomalyScore >= 2 {
		rb.Recommended = append(rb.Recommended, "Verify recent login locations with the user")
	}
	if p.DataExfilScore >= 2 {
		rb.Recommended = append(rb.Recommended, "Review data transfer logs and DLP alerts immediately")
	}
	if p.PrivilegeAbuseScore >= 2 {
		rb.Recommended = append(rb.Recommended, "Audit privileged session recordings")
	}
	if p.RiskScore >= 7 {
		rb.Recommended = append(rb.Recommended, "Consider account suspension pending investigation")
	}

	return rb
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func ipPrefix(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	if parsed.To4() != nil {
		_, net, err := net.ParseCIDR(ip + "/24")
		if err != nil {
			return ""
		}
		return net.String()
	}
	return ""
}

func isPrivatePrefix(prefix string) bool {
	private := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}
	_, pnet, _ := net.ParseCIDR(prefix)
	if pnet == nil {
		return false
	}
	for _, p := range private {
		_, priv, _ := net.ParseCIDR(p)
		if priv != nil && priv.Contains(pnet.IP) {
			return true
		}
	}
	return false
}

func contains(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
