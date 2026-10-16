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

// topicUEBA is the output topic for detected UEBA anomalies.
const topicUEBA = "crp.events.ueba"

// The thresholds that used to live here as constants — eighty events a minute,
// five failures in five, three distinct hours before a baseline is trusted — are
// now the tenant's, read through repository.PolicyCache. What they were is kept
// as model.DefaultBehaviourPolicy(), which is both the standard profile the
// platform ships and what this engine falls back to when no policy can be read:
// detecting on slightly wrong thresholds beats not detecting at all.

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

	// policies are the thresholds in force, per tenant. This engine consumes
	// every tenant's events in one process, so they are served from a snapshot
	// rather than read per event — a query on this path is not a slow design,
	// it is an impossible one.
	policies *repository.PolicyCache
}

// NewBehaviorEngine creates a BehaviorEngine.
func NewBehaviorEngine(
	profileRepo *repository.ProfileRepository,
	behaviorRepo *repository.BehaviorRepository,
	consumer *pkgkafka.Consumer,
	publisher *pkgkafka.Producer,
	velocity *cache.Window,
	failures *cache.Window,
	policies *repository.PolicyCache,
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
		policies:     policies,
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

	entityIDStr, entityName, entityType := entityFrom(&ev)
	if entityIDStr == "" {
		return nil // skip events without an identifiable entity
	}

	tid, err := uuid.Parse(ev.TenantID)
	if err != nil {
		return nil
	}
	eid, err := uuid.Parse(entityIDStr)
	if err != nil {
		// entityFrom derives a UUID from anything that is not one, so reaching
		// here means the source handed us a user_id that looks like a UUID and
		// is not. Worth a line rather than a silent drop: a whole source going
		// unprofiled used to look exactly like this.
		e.logger.Warn().Str("entity", entityIDStr).Msg("ueba_entity_id_not_a_uuid")
		return nil
	}

	// Load or create profile
	profile, err := e.profileRepo.GetOrCreate(ctx, tid, eid, entityType, entityName)
	if err != nil || profile == nil {
		e.logger.Error().Err(err).Str("entity_id", entityIDStr).Msg("profile_load_error")
		return nil
	}

	// Write behavioral event to ClickHouse time-series
	be := behaviorEventFrom(&ev, entityIDStr, entityType)
	if err := e.behaviorRepo.InsertEvent(ctx, be); err != nil {
		e.logger.Error().Err(err).Msg("behavior_event_insert_error")
	}

	// The thresholds this tenant is detected against. Resolved once per event
	// and passed down, so every decision below — the counters, the anomalies and
	// the baseline — is taken against the same version of the policy even if a
	// refresh lands mid-event.
	policy := e.policies.For(tid)

	// Track velocity and failure counters (always — before baseline check)
	counterKey := ev.TenantID + "|" + entityIDStr
	vel := e.velocityCount(ctx, counterKey, policy)
	var failCnt int
	if ev.Outcome == "failure" {
		failCnt = e.failureCount(ctx, counterKey, policy)
	}

	// Detect anomalies
	anomalies := e.detectAnomalies(profile, &ev, eid, tid, vel, failCnt, policy)

	// Update baseline before scoring
	updateBaseline(profile, &ev, policy)

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
	policy *model.BehaviourPolicy,
) []*model.Anomaly {
	now := time.Now().UTC()
	hour := int32(now.Hour())
	srcEventID := ev.EventID

	var anomalies []*model.Anomaly

	// raise takes the severity and the score from the tenant's policy rather
	// than from a literal, and drops the anomaly entirely when they have turned
	// that signal off.
	//
	// Switching one off is a legitimate decision — an institution running three
	// shifts has no use for an off-hours alert that fires every night — and
	// honouring it here is what stops them doing it downstream in a mail rule,
	// where nobody can see that they did.
	raise := func(atype, baseline, observed string) {
		sig := policy.Signal(atype)
		if !sig.Enabled {
			return
		}
		anomalies = append(anomalies, &model.Anomaly{
			ID:            uuid.New(),
			TenantID:      tenantID,
			EntityID:      entityID,
			EntityType:    p.EntityType,
			AnomalyType:   atype,
			Severity:      sig.Severity,
			Score:         sig.Score,
			BaselineVal:   baseline,
			ObservedVal:   observed,
			SourceEventID: &srcEventID,
			Status:        model.AnomalyStatusOpen,
			DetectedAt:    now,
		})
	}

	// ── Baseline-dependent detections ─────────────────────────────────────────
	if p.BaselineReady {
		// OFF_HOURS_ACCESS
		if !containsInt32(p.NormalHours, hour) {
			raise(model.AnomalyOffHoursAccess,
				fmt.Sprintf("normal_hours=%v", p.NormalHours),
				fmt.Sprintf("hour=%d", hour))
		}

		// NEW_COUNTRY
		if ev.GeoCountry != nil && *ev.GeoCountry != "" && *ev.GeoCountry != "PRIVATE" {
			if !containsStr(p.NormalCountries, *ev.GeoCountry) {
				raise(model.AnomalyNewCountry,
					fmt.Sprintf("countries=%v", p.NormalCountries),
					*ev.GeoCountry)
			}
		}

		// NEW_IP_PREFIX (/24)
		if ev.IPSource != nil && *ev.IPSource != "" {
			prefix := ipCIDR24(*ev.IPSource)
			if !containsStr(p.NormalIPPrefixes, prefix) {
				raise(model.AnomalyNewIPPrefix,
					fmt.Sprintf("prefixes=%v", p.NormalIPPrefixes),
					prefix)
			}
		}
	}

	// ── Always-on detections ──────────────────────────────────────────────────

	// VELOCITY_SPIKE. The baseline and the observation both name the window the
	// tenant set, because "80/min" on an alert raised under a five-minute window
	// is a number an analyst cannot reconcile with anything.
	if velocityCount >= policy.VelocityThreshold {
		raise(model.AnomalyVelocitySpike,
			fmt.Sprintf("threshold=%d/%ds", policy.VelocityThreshold, policy.VelocityWindowS),
			fmt.Sprintf("%d events/%ds", velocityCount, policy.VelocityWindowS))
	}

	// BRUTE_FORCE
	if failureCount >= policy.BruteForceThreshold {
		raise(model.AnomalyBruteForce,
			fmt.Sprintf("threshold=%d failures/%ds", policy.BruteForceThreshold, policy.BruteForceWindowS),
			fmt.Sprintf("%d failures/%ds", failureCount, policy.BruteForceWindowS))
	}

	// MITRE ATT&CK tactic-based detections
	if ev.MitreTactic != nil {
		switch *ev.MitreTactic {
		case "TA0004": // Privilege Escalation
			raise(model.AnomalyPrivEscalation, "no_priv_esc_expected",
				fmt.Sprintf("tactic=%s technique=%v", *ev.MitreTactic, ev.MitreTechnique))
		case "TA0008": // Lateral Movement
			raise(model.AnomalyLateralMovement, "no_lateral_movement_expected",
				fmt.Sprintf("tactic=%s", *ev.MitreTactic))
		case "TA0010": // Exfiltration
			raise(model.AnomalyDataExfiltration, "no_exfiltration_expected",
				fmt.Sprintf("tactic=%s", *ev.MitreTactic))
		}
	}

	return anomalies
}

// ─── Baseline and scoring ─────────────────────────────────────────────────────

// updateBaseline appends new observations to the entity's normal sets.
func updateBaseline(p *model.EntityProfile, ev *event.NormalizedEvent, policy *model.BehaviourPolicy) {
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
		len(p.NormalHours) >= policy.MinHoursForBaseline &&
		len(p.NormalCountries) >= policy.MinCountriesForBaseline {
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

func (e *BehaviorEngine) velocityCount(ctx context.Context, key string, p *model.BehaviourPolicy) int {
	n, _ := e.velocity.Count(ctx, key, p.VelocityWindow)
	return n
}

func (e *BehaviorEngine) failureCount(ctx context.Context, key string, p *model.BehaviourPolicy) int {
	n, _ := e.failures.Count(ctx, key, p.BruteForceWindow)
	return n
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// entityNamespace scopes every derived entity identifier. Fixed, because the
// identifier has to be the same on every replica and across restarts — an
// entity whose id changed would get a fresh baseline each time and never be
// anomalous.
var entityNamespace = uuid.MustParse("6f6a2c1e-9b4e-5d3a-8c17-0d2f4b9a7e31")

// entityFrom is who this event is about.
//
// It used to read user_id and asset_id and nothing else. A log line carries a
// username, not a UUID — the SIEM parsers fill user_name and leave user_id
// empty — so every event was discarded one step after it arrived, and
// ueba_profiles had zero rows on a platform that had ingested thousands of
// events. The behavioural engine had never built a single baseline.
//
// Where the source gives a UUID it is used as is. Where it gives a name, the
// identifier is derived from it: the same name in the same tenant always yields
// the same UUID, on every replica and after every restart, without a lookup on
// the hot path. It is scoped by tenant, so one customer's "admin" is never
// another's, and lower-cased, because a source that writes "M.Durand" on Monday
// and "m.durand" on Tuesday is describing one person.
func entityFrom(ev *event.NormalizedEvent) (id, name, entityType string) {
	derive := func(kind, raw string) string {
		key := ev.TenantID + "|" + kind + "|" + strings.ToLower(strings.TrimSpace(raw))
		return uuid.NewSHA1(entityNamespace, []byte(key)).String()
	}

	// A user first: behaviour is a property of people before it is of machines,
	// and an event that names both is about what the person did.
	if ev.UserID != nil && *ev.UserID != "" {
		userName := *ev.UserID
		if ev.UserName != nil && *ev.UserName != "" {
			userName = *ev.UserName
		}
		if _, err := uuid.Parse(*ev.UserID); err == nil {
			return *ev.UserID, userName, model.EntityTypeUser
		}
		// A user_id that is not a UUID is still an identity; it is just one
		// this platform did not mint. Deriving beats discarding.
		return derive(model.EntityTypeUser, *ev.UserID), userName, model.EntityTypeUser
	}
	if ev.UserName != nil && *ev.UserName != "" {
		return derive(model.EntityTypeUser, *ev.UserName), *ev.UserName, model.EntityTypeUser
	}

	if ev.AssetID != nil && *ev.AssetID != "" {
		assetName := *ev.AssetID
		if ev.AssetHostname != nil && *ev.AssetHostname != "" {
			assetName = *ev.AssetHostname
		}
		if _, err := uuid.Parse(*ev.AssetID); err == nil {
			return *ev.AssetID, assetName, model.EntityTypeAsset
		}
		return derive(model.EntityTypeAsset, *ev.AssetID), assetName, model.EntityTypeAsset
	}
	if ev.AssetHostname != nil && *ev.AssetHostname != "" {
		return derive(model.EntityTypeAsset, *ev.AssetHostname), *ev.AssetHostname, model.EntityTypeAsset
	}

	return "", "", ""
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
