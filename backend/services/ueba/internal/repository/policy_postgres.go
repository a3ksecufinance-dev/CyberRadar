package repository

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/cyberradar/platform/services/ueba/internal/model"
)

// PolicyCache serves the behavioural thresholds in force, per tenant, fast
// enough to consult on every event.
//
// The same answer as the indicator index: the engine is one consumer handling
// every tenant's events, so a query per event is not a slow design, it is an
// impossible one. The thresholds change when somebody decides they should, which
// is to say rarely, so a snapshot refreshed on a timer is both correct enough
// and the only shape that works at throughput.
type PolicyCache struct {
	db       *pgxpool.Pool
	logger   zerolog.Logger
	interval time.Duration

	snapshot atomic.Pointer[map[uuid.UUID]*model.BehaviourPolicy]
}

// DefaultPolicyInterval is how often the thresholds are re-read. A change to a
// detection threshold is not an emergency; a minute of staleness is cheaper than
// a read on the hot path.
const DefaultPolicyInterval = time.Minute

// NewPolicyCache creates a PolicyCache.
func NewPolicyCache(db *pgxpool.Pool, logger zerolog.Logger) *PolicyCache {
	return &PolicyCache{db: db, logger: logger, interval: DefaultPolicyInterval}
}

// For is the policy in force for this tenant.
//
// A tenant the snapshot has never heard of — created since the last refresh —
// gets the platform's own values rather than nothing. A behaviour engine that
// stopped detecting because a tenant was new would be worse than one a minute
// behind.
func (c *PolicyCache) For(tenantID uuid.UUID) *model.BehaviourPolicy {
	snap := c.snapshot.Load()
	if snap == nil {
		return model.DefaultBehaviourPolicy()
	}
	if p, ok := (*snap)[tenantID]; ok {
		return p
	}
	return model.DefaultBehaviourPolicy()
}

// Start loads once and then refreshes until ctx is done.
//
// The first load is fatal: starting an engine that silently detects on default
// thresholds, while a customer's console shows the ones they chose, is the kind
// of divergence nobody finds for months.
func (c *PolicyCache) Start(ctx context.Context) error {
	if err := c.refresh(ctx); err != nil {
		return fmt.Errorf("load behaviour policies: %w", err)
	}
	go func() {
		t := time.NewTicker(c.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := c.refresh(ctx); err != nil {
					// Keep serving the snapshot we have. A failed refresh is a
					// reason to say so, not to stop detecting.
					c.logger.Error().Err(err).Msg("behaviour_policy_refresh_failed")
				}
			}
		}
	}()
	return nil
}

func (c *PolicyCache) refresh(ctx context.Context) error {
	rows, err := c.db.Query(ctx, `
		SELECT tenant_id, code, version, chosen,
		       min_hours_for_baseline, min_countries_for_baseline,
		       velocity_threshold, velocity_window_s,
		       brute_force_threshold, brute_force_window_s,
		       off_hours_enabled, off_hours_severity, off_hours_score,
		       new_country_enabled, new_country_severity, new_country_score,
		       new_ip_prefix_enabled, new_ip_prefix_severity, new_ip_prefix_score,
		       velocity_enabled, velocity_severity, velocity_score,
		       brute_force_enabled, brute_force_severity, brute_force_score,
		       priv_escalation_enabled, priv_escalation_severity, priv_escalation_score,
		       lateral_movement_enabled, lateral_movement_severity, lateral_movement_score,
		       data_exfiltration_enabled, data_exfiltration_severity, data_exfiltration_score
		FROM tenant_behaviour_policy`)
	if err != nil {
		return fmt.Errorf("read behaviour policies: %w", err)
	}
	defer rows.Close()

	next := map[uuid.UUID]*model.BehaviourPolicy{}
	for rows.Next() {
		var (
			tenantID                                    uuid.UUID
			p                                           model.BehaviourPolicy
			offHours, newCountry, newIPPrefix, velocity model.Signal
			bruteForce, privEsc, lateral, exfil         model.Signal
		)
		if err := rows.Scan(&tenantID, &p.Code, &p.Version, &p.Chosen,
			&p.MinHoursForBaseline, &p.MinCountriesForBaseline,
			&p.VelocityThreshold, &p.VelocityWindowS,
			&p.BruteForceThreshold, &p.BruteForceWindowS,
			&offHours.Enabled, &offHours.Severity, &offHours.Score,
			&newCountry.Enabled, &newCountry.Severity, &newCountry.Score,
			&newIPPrefix.Enabled, &newIPPrefix.Severity, &newIPPrefix.Score,
			&velocity.Enabled, &velocity.Severity, &velocity.Score,
			&bruteForce.Enabled, &bruteForce.Severity, &bruteForce.Score,
			&privEsc.Enabled, &privEsc.Severity, &privEsc.Score,
			&lateral.Enabled, &lateral.Severity, &lateral.Score,
			&exfil.Enabled, &exfil.Severity, &exfil.Score,
		); err != nil {
			return fmt.Errorf("scan behaviour policy: %w", err)
		}
		p.VelocityWindow = time.Duration(p.VelocityWindowS) * time.Second
		p.BruteForceWindow = time.Duration(p.BruteForceWindowS) * time.Second
		p.Signals = map[string]model.Signal{
			model.AnomalyOffHoursAccess:   offHours,
			model.AnomalyNewCountry:       newCountry,
			model.AnomalyNewIPPrefix:      newIPPrefix,
			model.AnomalyVelocitySpike:    velocity,
			model.AnomalyBruteForce:       bruteForce,
			model.AnomalyPrivEscalation:   privEsc,
			model.AnomalyLateralMovement:  lateral,
			model.AnomalyDataExfiltration: exfil,
		}
		next[tenantID] = &p
	}
	if err := rows.Err(); err != nil {
		return err
	}

	c.snapshot.Store(&next)
	c.logger.Debug().Int("tenants", len(next)).Msg("behaviour_policies_loaded")
	return nil
}
