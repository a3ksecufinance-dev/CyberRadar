package model

import (
	"time"

	"github.com/google/uuid"
)

// Channel is a notification delivery channel.
type Channel string

const (
	ChannelEmail   Channel = "email"
	ChannelSMS     Channel = "sms"
	ChannelSlack   Channel = "slack"
	ChannelTeams   Channel = "teams"
	ChannelWebhook Channel = "webhook"
	ChannelPush    Channel = "push"
)

// Severity levels that can trigger notifications.
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// NotificationRule defines when and how to send notifications.
type NotificationRule struct {
	ID          uuid.UUID       `json:"id"`
	TenantID    uuid.UUID       `json:"tenant_id"`
	Name        string          `json:"name"`
	Enabled     bool            `json:"enabled"`
	Conditions  RuleConditions  `json:"conditions"`
	Channels    []ChannelConfig `json:"channels"`
	TemplateID  string          `json:"template_id,omitempty"`
	Priority    int             `json:"priority"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// RuleConditions are the trigger criteria for a notification rule.
type RuleConditions struct {
	EventTypes    []string   `json:"event_types,omitempty"`
	Severities    []Severity `json:"severities,omitempty"`
	ResourceTypes []string   `json:"resource_types,omitempty"`
	MinRiskScore  float64    `json:"min_risk_score,omitempty"`
}

// ChannelConfig holds configuration for a notification channel.
type ChannelConfig struct {
	Type    Channel        `json:"type"`
	Config  map[string]any `json:"config"` // email: to/cc; slack: webhook_url; webhook: url
}

// NotificationEvent is a notification to be sent.
type NotificationEvent struct {
	ID           uuid.UUID `json:"id"`
	TenantID     uuid.UUID `json:"tenant_id"`
	RuleID       uuid.UUID `json:"rule_id"`
	Title        string    `json:"title"`
	Body         string    `json:"body"`
	Severity     Severity  `json:"severity"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	Channels     []Channel `json:"channels"`
	SentAt       time.Time `json:"sent_at"`
	Status       string    `json:"status"` // pending, sent, failed
}

// SendNotificationRequest is the payload for sending a notification.
type SendNotificationRequest struct {
	TenantID     string         `json:"tenant_id"     validate:"required"`
	Title        string         `json:"title"         validate:"required"`
	Body         string         `json:"body"          validate:"required"`
	Severity     Severity       `json:"severity"      validate:"required"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	Channels     []ChannelConfig `json:"channels"     validate:"required,min=1"`
}

// CreateRuleRequest is the payload to create a notification rule.
type CreateRuleRequest struct {
	Name       string         `json:"name"       validate:"required,min=2,max=255"`
	Conditions RuleConditions `json:"conditions"`
	Channels   []ChannelConfig `json:"channels"  validate:"required,min=1"`
	Priority   int            `json:"priority"`
}
