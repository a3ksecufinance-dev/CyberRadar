package model

import "time"

// Signal is what one anomaly type is worth to this institution: whether it
// fires at all, how loud it is, and what it adds to the entity's score.
type Signal struct {
	Enabled  bool    `json:"enabled"`
	Severity string  `json:"severity"`
	Score    float64 `json:"score"`
}

// BehaviourPolicy is what this institution considers anomalous.
//
// These were Go constants with a comment above them. Eighty events a minute,
// five failures in five, three distinct hours before a baseline is trusted —
// none of them are facts about human behaviour. They are what one institution
// decided was worth waking someone for, and a bank running three shifts across
// four time zones does not have the same answer as a regional one whose branches
// close at five.
//
// A fixed threshold is not merely sometimes wrong; it is wrong invisibly. A
// detection that fires every night at the same institution stops being a
// detection and becomes a filter rule somebody wrote in their mail client.
type BehaviourPolicy struct {
	Code    string `json:"code"`
	Version int    `json:"version"`
	// Chosen is false when the tenant is running on the platform's values.
	Chosen bool `json:"chosen"`

	// How much history makes a baseline worth detecting against. An entity seen
	// three times is not a pattern.
	MinHoursForBaseline     int `json:"min_hours_for_baseline"`
	MinCountriesForBaseline int `json:"min_countries_for_baseline"`

	VelocityThreshold int           `json:"velocity_threshold"`
	VelocityWindow    time.Duration `json:"-"`
	VelocityWindowS   int           `json:"velocity_window_s"`

	BruteForceThreshold int           `json:"brute_force_threshold"`
	BruteForceWindow    time.Duration `json:"-"`
	BruteForceWindowS   int           `json:"brute_force_window_s"`

	// Signals, by anomaly type. A type absent from the map is one the policy
	// says nothing about, which the engine treats as off rather than guessing.
	Signals map[string]Signal `json:"signals"`
}

// Signal is the setting for one anomaly type.
//
// A type the policy says nothing about comes back disabled rather than with a
// default severity invented here. The alternative — a missing row quietly
// becoming a HIGH — is how a configuration mistake turns into a pager at 3am.
func (p *BehaviourPolicy) Signal(anomalyType string) Signal {
	if p == nil {
		return Signal{}
	}
	return p.Signals[anomalyType]
}

// DefaultBehaviourPolicy is exactly what the engine applied before any of this
// was configurable, and what it falls back to when no policy can be read.
//
// A behaviour engine that stopped detecting because a database was briefly
// unreachable would be worse than one using slightly wrong thresholds.
func DefaultBehaviourPolicy() *BehaviourPolicy {
	return &BehaviourPolicy{
		Code:                    "balanced",
		Version:                 1,
		MinHoursForBaseline:     3,
		MinCountriesForBaseline: 1,
		VelocityThreshold:       80,
		VelocityWindow:          60 * time.Second,
		VelocityWindowS:         60,
		BruteForceThreshold:     5,
		BruteForceWindow:        5 * time.Minute,
		BruteForceWindowS:       300,
		Signals: map[string]Signal{
			AnomalyOffHoursAccess:   {Enabled: true, Severity: SeverityMedium, Score: 3.5},
			AnomalyNewCountry:       {Enabled: true, Severity: SeverityHigh, Score: 6.5},
			AnomalyNewIPPrefix:      {Enabled: true, Severity: SeverityLow, Score: 2.0},
			AnomalyVelocitySpike:    {Enabled: true, Severity: SeverityHigh, Score: 5.0},
			AnomalyBruteForce:       {Enabled: true, Severity: SeverityHigh, Score: 6.0},
			AnomalyPrivEscalation:   {Enabled: true, Severity: SeverityHigh, Score: 7.0},
			AnomalyLateralMovement:  {Enabled: true, Severity: SeverityCritical, Score: 8.5},
			AnomalyDataExfiltration: {Enabled: true, Severity: SeverityCritical, Score: 9.0},
		},
	}
}
