package model

import (
	"time"

	"github.com/google/uuid"
)

// IdentityRiskProfile holds the composite risk state for an identity.
type IdentityRiskProfile struct {
	ID         uuid.UUID `json:"id"`
	TenantID   uuid.UUID `json:"tenant_id"`
	IdentityID uuid.UUID `json:"identity_id"`

	// Composite score 0–10
	RiskScore float64 `json:"risk_score"`

	// Dimensional scores
	FailedLoginScore     float64 `json:"failed_login_score"`
	AnomalousHoursScore  float64 `json:"anomalous_hours_score"`
	GeoAnomalyScore      float64 `json:"geo_anomaly_score"`
	PrivilegeAbuseScore  float64 `json:"privilege_abuse_score"`
	DataExfilScore       float64 `json:"data_exfil_score"`
	LateralMovementScore float64 `json:"lateral_movement_score"`

	// Behavioral baseline
	NormalLoginHours []int    `json:"normal_login_hours"`
	NormalCountries  []string `json:"normal_countries"`
	NormalIPPrefixes []string `json:"normal_ip_prefixes"`
	AvgDailyEvents   float64  `json:"avg_daily_events"`
	BaselineReady    bool     `json:"baseline_ready"`

	// Anomaly counters
	LastAnomalyAt   *time.Time `json:"last_anomaly_at,omitempty"`
	AnomalyCount7d  int        `json:"anomaly_count_7d"`
	AnomalyCount30d int        `json:"anomaly_count_30d"`

	// Recent activity
	LastLoginAt      *time.Time `json:"last_login_at,omitempty"`
	LastLoginIP      string     `json:"last_login_ip,omitempty"`
	LastLoginCountry string     `json:"last_login_country,omitempty"`
	EventsToday      int        `json:"events_today"`
	Events7d         int        `json:"events_7d"`
	PrivSessions30d  int        `json:"priv_sessions_30d"`

	UpdatedAt time.Time `json:"updated_at"`
}

// RiskLevel derives a categorical level from a score.
func (r *IdentityRiskProfile) RiskLevel() string {
	switch {
	case r.RiskScore >= 8.0:
		return "critical"
	case r.RiskScore >= 6.0:
		return "high"
	case r.RiskScore >= 4.0:
		return "medium"
	default:
		return "low"
	}
}

// RiskFactor is a single contributor to a risk score with human-readable detail.
type RiskFactor struct {
	Dimension string  `json:"dimension"`
	Score     float64 `json:"score"`
	Reason    string  `json:"reason"`
}

// RiskBreakdown is the detailed risk explanation for an identity.
type RiskBreakdown struct {
	IdentityID  uuid.UUID    `json:"identity_id"`
	TotalScore  float64      `json:"total_score"`
	RiskLevel   string       `json:"risk_level"`
	Factors     []RiskFactor `json:"factors"`
	Anomalies   []string     `json:"anomalies,omitempty"`
	Recommended []string     `json:"recommended_actions,omitempty"`
}

// AnomalyEvent is raised when the risk engine detects a behavioral anomaly.
type AnomalyEvent struct {
	TenantID   string    `json:"tenant_id"`
	IdentityID string    `json:"identity_id"`
	Type       string    `json:"type"` // impossible_travel, off_hours, new_country, brute_force, etc.
	Detail     string    `json:"detail"`
	Score      float64   `json:"score"`
	DetectedAt time.Time `json:"detected_at"`
}
