package service

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cyberradar/platform/internal/pkg/event"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/cyberradar/platform/services/siem/internal/model"
	"github.com/cyberradar/platform/services/siem/internal/repository"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// ruleCache stores active rules per tenant, refreshed periodically.
type ruleCache struct {
	mu    sync.RWMutex
	rules map[string][]*model.DetectionRule // tenant_id → rules
}

// RuleEngine consumes enriched events and evaluates detection rules.
type RuleEngine struct {
	ruleRepo  *repository.RuleRepository
	alertRepo *repository.AlertRepository
	caseRepo  *repository.CaseRepository
	consumer  *pkgkafka.Consumer
	publisher *pkgkafka.Producer // publishes fired alerts to crp.events.alerts
	logger    zerolog.Logger
	cache     ruleCache

	// In-memory threshold counters: key = dedup_key → []event_time
	threshMu      sync.Mutex
	threshCounters map[string][]time.Time
}

// NewRuleEngine creates a RuleEngine.
func NewRuleEngine(
	ruleRepo *repository.RuleRepository,
	alertRepo *repository.AlertRepository,
	caseRepo *repository.CaseRepository,
	consumer *pkgkafka.Consumer,
	publisher *pkgkafka.Producer,
	logger zerolog.Logger,
) *RuleEngine {
	return &RuleEngine{
		ruleRepo:       ruleRepo,
		alertRepo:      alertRepo,
		caseRepo:       caseRepo,
		consumer:       consumer,
		publisher:      publisher,
		logger:         logger,
		cache:          ruleCache{rules: make(map[string][]*model.DetectionRule)},
		threshCounters: make(map[string][]time.Time),
	}
}

// Run starts the event consumer. Blocks until ctx is cancelled.
func (e *RuleEngine) Run(ctx context.Context) error {
	e.logger.Info().Msg("rule_engine_started")
	// Refresh rule cache every 60s
	go e.refreshCacheLoop(ctx)
	return e.consumer.Run(ctx, e.handle)
}

// handle evaluates one event against all active rules for its tenant.
func (e *RuleEngine) handle(ctx context.Context, msg pkgkafka.Message) error {
	var ev event.NormalizedEvent
	if err := json.Unmarshal(msg.Value, &ev); err != nil {
		return nil
	}

	rules := e.getRules(ctx, ev.TenantID)
	for _, rule := range rules {
		if e.evaluate(rule, &ev) {
			e.fire(ctx, rule, &ev)
		}
	}
	return nil
}

// evaluate checks whether an event satisfies a rule's conditions.
func (e *RuleEngine) evaluate(rule *model.DetectionRule, ev *event.NormalizedEvent) bool {
	// 1. All field_matches must pass
	for _, fm := range rule.Conditions.FieldMatches {
		if !matchField(fm, ev) {
			return false
		}
	}

	// 2. Threshold check (if configured)
	if t := rule.Conditions.Threshold; t != nil && t.Count > 1 {
		return e.thresholdMet(rule, ev, t)
	}

	return true
}

// matchField tests a single FieldMatch against an event.
func matchField(fm model.FieldMatch, ev *event.NormalizedEvent) bool {
	actual := getField(ev, fm.Field)
	switch fm.Op {
	case model.OpEq:
		return strings.EqualFold(actual, fm.Value)
	case model.OpNeq:
		return !strings.EqualFold(actual, fm.Value)
	case model.OpContains:
		return strings.Contains(strings.ToLower(actual), strings.ToLower(fm.Value))
	case model.OpGt:
		a, _ := strconv.ParseFloat(actual, 64)
		b, _ := strconv.ParseFloat(fm.Value, 64)
		return a > b
	case model.OpGte:
		a, _ := strconv.ParseFloat(actual, 64)
		b, _ := strconv.ParseFloat(fm.Value, 64)
		return a >= b
	case model.OpExists:
		return actual != ""
	default:
		return strings.EqualFold(actual, fm.Value)
	}
}

// getField extracts a named field from a NormalizedEvent.
func getField(ev *event.NormalizedEvent, field string) string {
	switch field {
	case "category":
		return string(ev.Category)
	case "severity":
		return string(ev.Severity)
	case "outcome":
		return string(ev.Outcome)
	case "action":
		return ev.Action
	case "source_type":
		return ev.SourceType
	case "mitre_tactic":
		if ev.MitreTactic != nil {
			return *ev.MitreTactic
		}
	case "mitre_technique":
		if ev.MitreTechnique != nil {
			return *ev.MitreTechnique
		}
	case "user_id":
		if ev.UserID != nil {
			return *ev.UserID
		}
	case "user_name":
		if ev.UserName != nil {
			return *ev.UserName
		}
	case "ip_source":
		if ev.IPSource != nil {
			return *ev.IPSource
		}
	case "ip_destination":
		if ev.IPDestination != nil {
			return *ev.IPDestination
		}
	case "geo_country":
		if ev.GeoCountry != nil {
			return *ev.GeoCountry
		}
	case "risk_score":
		return fmt.Sprintf("%.2f", ev.RiskScore)
	case "threat_score":
		return fmt.Sprintf("%.2f", ev.ThreatScore)
	case "cbs_impact":
		return fmt.Sprintf("%d", ev.CBSImpact)
	case "swift_impact":
		return fmt.Sprintf("%d", ev.SWIFTImpact)
	// Synthetic anomaly fields (populated by PAM risk engine via event enrichment)
	case "geo_anomaly":
		// if GeoCountry is set and non-private — approximation
		if ev.GeoCountry != nil && *ev.GeoCountry != "" && *ev.GeoCountry != "PRIVATE" {
			return "true"
		}
	case "anomalous_hours":
		// flag set when risk_score > threshold from off-hours activity
		if ev.RiskScore >= 5.0 {
			return "true"
		}
	}
	return ""
}

// thresholdMet uses in-memory sliding window counters.
func (e *RuleEngine) thresholdMet(rule *model.DetectionRule, ev *event.NormalizedEvent, t *model.ThresholdCondition) bool {
	// Build group key from group_by fields
	parts := []string{rule.ID.String()}
	for _, gf := range t.GroupBy {
		parts = append(parts, getField(ev, gf))
	}
	groupKey := strings.Join(parts, "|")

	window := time.Duration(t.WindowSeconds) * time.Second
	now := time.Now().UTC()
	cutoff := now.Add(-window)

	e.threshMu.Lock()
	defer e.threshMu.Unlock()

	times := e.threshCounters[groupKey]
	// Expire old entries
	fresh := times[:0]
	for _, ts := range times {
		if ts.After(cutoff) {
			fresh = append(fresh, ts)
		}
	}
	fresh = append(fresh, now)
	e.threshCounters[groupKey] = fresh

	return len(fresh) >= t.Count
}

// fire creates an alert for a rule match.
func (e *RuleEngine) fire(ctx context.Context, rule *model.DetectionRule, ev *event.NormalizedEvent) {
	entityType, entityValue := entityFrom(ev)
	dedupKey := dedupHash(rule.ID.String(), entityValue, ev.TenantID)

	// Deduplication check
	isDup, err := e.alertRepo.IsDuplicate(ctx, ev.TenantID, dedupKey, rule.DedupWindowS)
	if err != nil {
		e.logger.Error().Err(err).Msg("dedup_check_error")
	}
	if isDup {
		return
	}

	alertID := uuid.New()
	title := fmt.Sprintf("[%s] %s — %s", rule.Severity, rule.Name, entityValue)

	rawEvidence, _ := json.Marshal(ev)
	ruleIDStr := rule.ID.String()

	a := &model.Alert{
		AlertID:        alertID,
		TenantID:       ev.TenantID,
		RuleID:         ruleIDStr,
		RuleName:       rule.Name,
		Severity:       rule.Severity,
		Category:       rule.Category,
		MitreTactic:    rule.MitreTactic,
		MitreTechnique: rule.MitreTechnique,
		EntityType:     entityType,
		EntityValue:    entityValue,
		SourceEventID:  ev.EventID.String(),
		Title:          title,
		Description:    rule.Description,
		RawEvidence:    string(rawEvidence),
		DedupKey:       dedupKey,
		EventTime:      ev.Timestamp,
		DetectedAt:     time.Now().UTC(),
		EventCount:     1,
		RiskScore:      float32(ev.RiskScore),
	}
	if ev.UserID != nil {
		a.UserID = *ev.UserID
	}
	if ev.IPSource != nil {
		a.IPSource = *ev.IPSource
	}
	if ev.IPDestination != nil {
		a.IPDestination = *ev.IPDestination
	}

	if err := e.alertRepo.Insert(ctx, a); err != nil {
		e.logger.Error().Err(err).Str("rule", rule.Name).Msg("alert_insert_error")
		return
	}

	// Upsert metadata in PostgreSQL
	_ = e.caseRepo.UpsertAlertMetadata(ctx, uuid.MustParse(ev.TenantID), alertID, &rule.ID)

	// Increment rule counter
	go e.ruleRepo.IncrementAlertCount(context.Background(), uuid.MustParse(ev.TenantID), rule.ID)

	// Publish to crp.events.alerts topic
	_ = e.publisher.Publish(ctx, ev.TenantID, a)

	e.logger.Warn().
		Str("alert_id", alertID.String()).
		Str("rule", rule.Name).
		Str("severity", string(rule.Severity)).
		Str("entity", entityValue).
		Str("tenant_id", ev.TenantID).
		Msg("alert_fired")
}

// ─── Rule cache ───────────────────────────────────────────────────────────────

func (e *RuleEngine) getRules(ctx context.Context, tenantID string) []*model.DetectionRule {
	e.cache.mu.RLock()
	rules, ok := e.cache.rules[tenantID]
	e.cache.mu.RUnlock()
	if ok {
		return rules
	}

	// Cache miss: load from DB
	tid, err := uuid.Parse(tenantID)
	if err != nil {
		return nil
	}
	rules, err = e.ruleRepo.ListEnabled(ctx, tid)
	if err != nil {
		e.logger.Error().Err(err).Str("tenant_id", tenantID).Msg("rule_cache_load_error")
		return nil
	}

	e.cache.mu.Lock()
	e.cache.rules[tenantID] = rules
	e.cache.mu.Unlock()
	return rules
}

func (e *RuleEngine) refreshCacheLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.cache.mu.Lock()
			// Invalidate — will reload on next event per tenant
			e.cache.rules = make(map[string][]*model.DetectionRule)
			e.cache.mu.Unlock()
			e.logger.Debug().Msg("rule_cache_invalidated")
		}
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func entityFrom(ev *event.NormalizedEvent) (entityType, entityValue string) {
	if ev.UserID != nil && *ev.UserID != "" {
		return "user", *ev.UserID
	}
	if ev.AssetID != nil && *ev.AssetID != "" {
		return "asset", *ev.AssetID
	}
	if ev.IPSource != nil && *ev.IPSource != "" {
		return "ip", *ev.IPSource
	}
	return "source", ev.Source
}

func dedupHash(ruleID, entityValue, tenantID string) string {
	h := sha256.Sum256([]byte(ruleID + "|" + entityValue + "|" + tenantID))
	return fmt.Sprintf("%x", h[:8])
}
