package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cyberradar/platform/internal/pkg/cache"
	"github.com/cyberradar/platform/internal/pkg/event"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/services/ueba/internal/model"
	"github.com/cyberradar/platform/services/ueba/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

const (
	// topicUEBA is the output topic for detected UEBA anomalies.
	topicUEBA = "crp.events.ueba"

	// Baseline thresholds
	minHoursForBaseline     = 3 // distinct hours before baseline is considered ready
	minCountriesForBaseline = 1

	// Velocity: >N events per entity within 1 minute triggers VELOCITY_SPIKE
	velocityThreshold = 80
	velocityWindow    = 60 * time.Second

	// Brute-force: >N auth failures per entity within 5 minutes
	bruteForceThreshold = 5
	bruteForceWindow    = 5 * time.Minute
)

// BehaviorEngine consumes crp.events.enriched and performs UEBA.
type BehaviorEngine struct {
	profileRepo  *repository.ProfileRepository
	behaviorRepo *repository.BehaviorRepository
	consumer     *pkgkafka.Consumer
	publisher    *pkgkafka.Producer
	logger       zerolog.Logger

	// velocity and failures count across every replica of this service. They
	// used to be maps in this process, so an attacker spreading four failed
	// logins over each of two replicas stayed under a five-failure threshold
	// that a single counter would have tripped.
	velocity *cache.Window
	failures *cache.Window
}

// NewBehaviorEngine creates a BehaviorEngine.
func NewBehaviorEngine(
	profileRepo *repository.ProfileRepository,
	behaviorRepo *repository.BehaviorRepository,
	consumer *pkgkafka.Consumer,
	publisher *pkgkafka.Producer,
	velocity *cache.Window,
	failures *cache.Window,
	logger zerolog.Logger,
) *BehaviorEngine {
	return &BehaviorEngine{
		profileRepo:  profileRepo,
		behaviorRepo: behaviorRepo,
		consumer:     consumer,
		publisher:    publisher,
		logger:       logger,
		velocity:     velocity,
		failures:     failures,
	}
}

// Run starts the Kafka consumer. Blocks until ctx is cancelled.
func (e *BehaviorEngine) Run(ctx context.Context) error {
	e.logger.Info().Msg("ueba_engine_started")
	return e.consumer.Run(ctx, e.handle)
}

// handle processes one enriched event.
func (e *BehaviorEngine) handle(ctx context.Context, msg pkgkafka.Message) error {
	var ev event.NormalizedEvent
	if err := json.Unmarshal(msg.Value, &ev); err != nil {
		return nil
	}

	entityIDStr, entityType := entityFrom(&ev)
	if entityIDStr == "" {
		return nil // skip events without an identifiable entity
	}

	tid, err := uuid.Parse(ev.TenantID)
	if err != nil {
		return nil
	}
	eid, err := uuid.Parse(entityIDStr)
	if err != nil {
		return nil // entity IDs must be UUIDs in this platform
	}

	// Load or create profile
	profile, err := e.profileRepo.GetOrCreate(ctx, tid, eid, entityType)
	if err != nil || profile == nil {
		e.logger.Error().Err(err).Str("entity_id", entityIDStr).Msg("profile_load_error")
		return nil
	}

	// Write behavioral event to ClickHouse time-series
	be := behaviorEventFrom(&ev, entityIDStr, entityType)
	if err := e.behaviorRepo.InsertEvent(ctx, be); err != nil {
		e.logger.Error().Err(err).Msg("behavior_event_insert_error")
	}

	// Track velocity and failure counters (always — before baseline check)
	counterKey := ev.TenantID + "|" + entityIDStr
	vel := e.velocityCount(ctx, counterKey)
	var failCnt int
	if ev.Outcome == "failure" {
		failCnt = e.failureCount(ctx, counterKey)
	}

	// Detect anomalies
	anomalies := e.detectAnomalies(profile, &ev, eid, tid, vel, failCnt)

	// Update baseline before scoring
	updateBaseline(profile, &ev)

	// Recompute risk scores
	recomputeScores(profile, anomalies)

	// Persist profile
	if err := e.profileRepo.Update(ctx, profile); err != nil {
		e.logger.Error().Err(err).Str("entity_id", entityIDStr).Msg("profile_update_error")
	}

	// Store and publish anomalies
	for _, a := range anomalies {
		if err := e.profileRepo.InsertAnomaly(ctx, a); err != nil {
			e.logger.Error().Err(err).Str("anomaly_type", a.AnomalyType).Msg("anomaly_insert_error")
			continue
		}
		_ = e.behaviorRepo.InsertAnomaly(ctx, a)
		_ = e.publisher.Publish(ctx, ev.TenantID, a)
		e.logger.Warn().
			Str("entity_id", a.EntityID.String()).
			Str("anomaly_type", a.AnomalyType).
			Str("severity", a.Severity).
			Float64("score", a.Score).
			Msg("ueba_anomaly_detected")
	}

	return nil
}

// detectAnomalies evaluates all behavioral rules and returns the set that fired.
func (e *BehaviorEngine) detectAnomalies(
	p *model.EntityProfile,
	ev *event.NormalizedEvent,
	entityID uuid.UUID,
	tenantID uuid.UUID,
	velocityCount, failureCount int,
) []*model.Anomaly {
	now := time.Now().UTC()
	hour := int32(now.Hour())
	srcEventID := ev.EventID

	newAnomaly := func(atype, severity string, score float64, baseline, observed string) *model.Anomaly {
		return &model.Anomaly{
			ID:            uuid.New(),
			TenantID:      tenantID,
			EntityID:      entityID,
			EntityType:    p.EntityType,
			AnomalyType:   atype,
			Severity:      severity,
			Score:         score,
			BaselineVal:   baseline,
			ObservedVal:   observed,
			SourceEventID: &srcEventID,
			Status:        model.AnomalyStatusOpen,
			DetectedAt:    now,
		}
	}

	var anomalies []*model.Anomaly

	// ── Baseline-dependent detections ─────────────────────────────────────────
	if p.BaselineReady {
		// OFF_HOURS_ACCESS
		if !containsInt32(p.NormalHours, hour) {
			anomalies = append(anomalies, newAnomaly(
				model.AnomalyOffHoursAccess, model.SeverityMedium, 3.5,
				fmt.Sprintf("normal_hours=%v", p.NormalHours),
				fmt.Sprintf("hour=%d", hour),
			))
		}

		// NEW_COUNTRY
		if ev.GeoCountry != nil && *ev.GeoCountry != "" && *ev.GeoCountry != "PRIVATE" {
			if !containsStr(p.NormalCountries, *ev.GeoCountry) {
				anomalies = append(anomalies, newAnomaly(
					model.AnomalyNewCountry, model.SeverityHigh, 6.5,
					fmt.Sprintf("countries=%v", p.NormalCountries),
					*ev.GeoCountry,
				))
			}
		}

		// NEW_IP_PREFIX (/24)
		if ev.IPSource != nil && *ev.IPSource != "" {
			prefix := ipCIDR24(*ev.IPSource)
			if !containsStr(p.NormalIPPrefixes, prefix) {
				anomalies = append(anomalies, newAnomaly(
					model.AnomalyNewIPPrefix, model.SeverityLow, 2.0,
					fmt.Sprintf("prefixes=%v", p.NormalIPPrefixes),
					prefix,
				))
			}
		}
	}

	// ── Always-on detections ──────────────────────────────────────────────────

	// VELOCITY_SPIKE
	if velocityCount >= velocityThreshold {
		anomalies = append(anomalies, newAnomaly(
			model.AnomalyVelocitySpike, model.SeverityHigh, 5.0,
			fmt.Sprintf("threshold=%d/min", velocityThreshold),
			fmt.Sprintf("%d events/min", velocityCount),
		))
	}

	// BRUTE_FORCE
	if failureCount >= bruteForceThreshold {
		anomalies = append(anomalies, newAnomaly(
			model.AnomalyBruteForce, model.SeverityHigh, 6.0,
			fmt.Sprintf("threshold=%d failures/5min", bruteForceThreshold),
			fmt.Sprintf("%d failures/5min", failureCount),
		))
	}

	// MITRE ATT&CK tactic-based detections
	if ev.MitreTactic != nil {
		switch *ev.MitreTactic {
		case "TA0004": // Privilege Escalation
			anomalies = append(anomalies, newAnomaly(
				model.AnomalyPrivEscalation, model.SeverityHigh, 7.0,
				"no_priv_esc_expected",
				fmt.Sprintf("tactic=%s technique=%v", *ev.MitreTactic, ev.MitreTechnique),
			))
		case "TA0008": // Lateral Movement
			anomalies = append(anomalies, newAnomaly(
				model.AnomalyLateralMovement, model.SeverityCritical, 8.5,
				"no_lateral_movement_expected",
				fmt.Sprintf("tactic=%s", *ev.MitreTactic),
			))
		case "TA0010": // Exfiltration
			anomalies = append(anomalies, newAnomaly(
				model.AnomalyDataExfiltration, model.SeverityCritical, 9.0,
				"no_exfiltration_expected",
				fmt.Sprintf("tactic=%s", *ev.MitreTactic),
			))
		}
	}

	return anomalies
}

// ─── Baseline and scoring ─────────────────────────────────────────────────────

// updateBaseline appends new observations to the entity's normal sets.
func updateBaseline(p *model.EntityProfile, ev *event.NormalizedEvent) {
	now := time.Now().UTC()
	hour := int32(now.Hour())

	if !containsInt32(p.NormalHours, hour) {
		p.NormalHours = append(p.NormalHours, hour)
	}
	if ev.GeoCountry != nil && *ev.GeoCountry != "" {
		if !containsStr(p.NormalCountries, *ev.GeoCountry) {
			p.NormalCountries = append(p.NormalCountries, *ev.GeoCountry)
		}
	}
	if ev.IPSource != nil && *ev.IPSource != "" {
		prefix := ipCIDR24(*ev.IPSource)
		if !containsStr(p.NormalIPPrefixes, prefix) {
			p.NormalIPPrefixes = append(p.NormalIPPrefixes, prefix)
		}
	}
	evType := string(ev.Category)
	if !containsStr(p.NormalEventTypes, evType) {
		p.NormalEventTypes = append(p.NormalEventTypes, evType)
	}

	p.EventCount++
	p.LastSeenAt = &now

	if !p.BaselineReady &&
		len(p.NormalHours) >= minHoursForBaseline &&
		len(p.NormalCountries) >= minCountriesForBaseline {
		p.BaselineReady = true
	}
}

// recomputeScores adjusts dimensional scores based on new anomalies and applies decay.
func recomputeScores(p *model.EntityProfile, anomalies []*model.Anomaly) {
	if len(anomalies) == 0 {
		// Gradual decay when no anomalies detected
		p.LoginScore = cap10(p.LoginScore - 0.05)
		p.AccessScore = cap10(p.AccessScore - 0.05)
		p.DataScore = cap10(p.DataScore - 0.05)
		p.TemporalScore = cap10(p.TemporalScore - 0.03)
	} else {
		for _, a := range anomalies {
			switch a.AnomalyType {
			case model.AnomalyBruteForce, model.AnomalyNewCountry, model.AnomalyNewIPPrefix:
				p.LoginScore = cap10(p.LoginScore + a.Score*0.4)
			case model.AnomalyPrivEscalation, model.AnomalyLateralMovement:
				p.AccessScore = cap10(p.AccessScore + a.Score*0.5)
			case model.AnomalyDataExfiltration:
				p.DataScore = cap10(p.DataScore + a.Score*0.5)
			case model.AnomalyOffHoursAccess, model.AnomalyVelocitySpike:
				p.TemporalScore = cap10(p.TemporalScore + a.Score*0.3)
			}
			p.AnomalyCount++
		}
	}

	// Weighted aggregate: login 25%, access 25%, data 25%, temporal 15%, peer 10%
	p.RiskScore = cap10(
		0.25*p.LoginScore +
			0.25*p.AccessScore +
			0.25*p.DataScore +
			0.15*p.TemporalScore +
			0.10*p.PeerScore,
	)
}

// ─── Sliding window counters ──────────────────────────────────────────────────

// A degraded count — one that covers this replica only — is reported by the
// window itself, as a throttled log and crp_sliding_window_fallback_total, so
// neither of these repeats it per event.

func (e *BehaviorEngine) velocityCount(ctx context.Context, key string) int {
	n, _ := e.velocity.Count(ctx, key, velocityWindow)
	return n
}

func (e *BehaviorEngine) failureCount(ctx context.Context, key string) int {
	n, _ := e.failures.Count(ctx, key, bruteForceWindow)
	return n
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func entityFrom(ev *event.NormalizedEvent) (id, entityType string) {
	if ev.UserID != nil && *ev.UserID != "" {
		return *ev.UserID, model.EntityTypeUser
	}
	if ev.AssetID != nil && *ev.AssetID != "" {
		return *ev.AssetID, model.EntityTypeAsset
	}
	return "", ""
}

func behaviorEventFrom(ev *event.NormalizedEvent, entityID, entityType string) *model.BehaviorEvent {
	be := &model.BehaviorEvent{
		EventID:    ev.EventID,
		TenantID:   ev.TenantID,
		EntityID:   entityID,
		EntityType: entityType,
		EventType:  string(ev.Category),
		SourceType: ev.SourceType,
		Action:     ev.Action,
		Outcome:    string(ev.Outcome),
		RiskScore:  float32(ev.RiskScore),
		HourOfDay:  uint8(ev.Timestamp.UTC().Hour()),
		DayOfWeek:  uint8(ev.Timestamp.UTC().Weekday()),
		EventTime:  ev.Timestamp,
		Attributes: map[string]any{
			"threat_score": ev.ThreatScore,
			"cbs_impact":   ev.CBSImpact,
			"swift_impact": ev.SWIFTImpact,
			"mitre_tactic": ev.MitreTactic,
		},
	}
	if ev.IPSource != nil {
		be.IPSource = *ev.IPSource
	}
	if ev.GeoCountry != nil {
		be.GeoCountry = *ev.GeoCountry
	}
	return be
}

func ipCIDR24(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) >= 3 {
		return strings.Join(parts[:3], ".") + ".0/24"
	}
	return ip + "/32"
}

func containsInt32(s []int32, v int32) bool {
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

func cap10(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 10 {
		return 10
	}
	return v
}
