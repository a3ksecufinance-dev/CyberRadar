package model

import (
	"time"

	"github.com/google/uuid"
)

// Severity levels shared across SIEM objects.
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// FieldOp is a comparison operator for rule conditions.
type FieldOp string

const (
	OpEq       FieldOp = "eq"
	OpNeq      FieldOp = "neq"
	OpGt       FieldOp = "gt"
	OpGte      FieldOp = "gte"
	OpLt       FieldOp = "lt"
	OpLte      FieldOp = "lte"
	OpContains FieldOp = "contains"
	OpIn       FieldOp = "in"
	OpExists   FieldOp = "exists"
)

// FieldMatch is a single field-level condition.
type FieldMatch struct {
	Field string  `json:"field"`
	Op    FieldOp `json:"op"`
	Value string  `json:"value"`
}

// ThresholdCondition fires when count >= N events within window_seconds.
type ThresholdCondition struct {
	Count         int      `json:"count"`
	WindowSeconds int      `json:"window_seconds"`
	GroupBy       []string `json:"group_by"` // e.g. ["user_name", "ip_source"]
}

// RuleConditions is the full condition set for a detection rule.
type RuleConditions struct {
	FieldMatches []FieldMatch        `json:"field_matches,omitempty"`
	Threshold    *ThresholdCondition `json:"threshold,omitempty"`
}

// RuleAction defines what to do when a rule fires.
type RuleAction struct {
	Type    string         `json:"type"` // notify, create_case, block_ip, disable_user
	Params  map[string]any `json:"params,omitempty"`
}

// DetectionRule is a SIEM detection rule.
type DetectionRule struct {
	ID               uuid.UUID      `json:"id"`
	TenantID         uuid.UUID      `json:"tenant_id"`
	Name             string         `json:"name"`
	Description      string         `json:"description,omitempty"`
	Category         string         `json:"category,omitempty"`
	Severity         Severity       `json:"severity"`
	Conditions       RuleConditions `json:"conditions"`
	MitreTactic      string         `json:"mitre_tactic,omitempty"`
	MitreTechnique   string         `json:"mitre_technique,omitempty"`
	Actions          []RuleAction   `json:"actions"`
	DedupWindowS     int            `json:"dedup_window_s"`
	Enabled          bool           `json:"enabled"`
	IsSystem         bool           `json:"is_system"`
	FalsePositiveRate float64       `json:"false_positive_rate"`
	AlertsTotal      int            `json:"alerts_total"`
	LastFiredAt      *time.Time     `json:"last_fired_at,omitempty"`
	CreatedBy        *uuid.UUID     `json:"created_by,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

// CreateRuleRequest creates a new detection rule.
type CreateRuleRequest struct {
	Name           string         `json:"name"        validate:"required,min=3,max=255"`
	Description    string         `json:"description"`
	Category       string         `json:"category"`
	Severity       Severity       `json:"severity"    validate:"required,oneof=LOW MEDIUM HIGH CRITICAL"`
	Conditions     RuleConditions `json:"conditions"  validate:"required"`
	MitreTactic    string         `json:"mitre_tactic"`
	MitreTechnique string         `json:"mitre_technique"`
	Actions        []RuleAction   `json:"actions"`
	DedupWindowS   int            `json:"dedup_window_s"`
}

// UpdateRuleRequest allows partial rule updates.
type UpdateRuleRequest struct {
	Name           *string         `json:"name"`
	Description    *string         `json:"description"`
	Severity       *Severity       `json:"severity"`
	Conditions     *RuleConditions `json:"conditions"`
	MitreTactic    *string         `json:"mitre_tactic"`
	MitreTechnique *string         `json:"mitre_technique"`
	Actions        []RuleAction    `json:"actions"`
	DedupWindowS   *int            `json:"dedup_window_s"`
	Enabled        *bool           `json:"enabled"`
}
