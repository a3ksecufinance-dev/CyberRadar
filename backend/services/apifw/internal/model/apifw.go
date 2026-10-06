package model

import (
	"time"

	"github.com/google/uuid"
)

// ── Scopes ────────────────────────────────────────────────────────────────────
const (
	ScopeRead    = "read"
	ScopeWrite   = "write"
	ScopeAdmin   = "admin"
	ScopeWebhook = "webhook"
)

// ── Webhook event types ───────────────────────────────────────────────────────
const (
	EventAlertCreated    = "alert.created"
	EventIncidentCreated = "incident.created"
	EventIOCMatched      = "ioc.matched"
	EventAnomalyDetected = "anomaly.detected"
	EventVulnFound       = "vuln.found"
)

// ─── Core models ──────────────────────────────────────────────────────────────

// APIKey represents an external API key. KeyHash is never exposed; PlainKey is
// set only at creation / rotation time and is not persisted.
type APIKey struct {
	ID           uuid.UUID  `json:"id"`
	TenantID     uuid.UUID  `json:"tenant_id"`
	Name         string     `json:"name"`
	KeyPrefix    string     `json:"key_prefix"` // e.g. "crp_a1b2..." — safe to show
	Description  string     `json:"description,omitempty"`
	Scopes       []string   `json:"scopes"`
	RateLimitRPM int        `json:"rate_limit_rpm"`
	RateLimitRPD int        `json:"rate_limit_rpd"`
	IsActive     bool       `json:"is_active"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	CreatedBy    *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`

	// Populated only at creation / rotation — NEVER stored, never in DB reads.
	PlainKey string `json:"plain_key,omitempty"`
}

// APIKeyUsage records a single request made with an API key.
type APIKeyUsage struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	KeyID       uuid.UUID `json:"key_id"`
	Endpoint    string    `json:"endpoint"`
	Method      string    `json:"method"`
	StatusCode  int       `json:"status_code"`
	LatencyMS   int       `json:"latency_ms"`
	IPAddress   string    `json:"ip_address,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	RequestedAt time.Time `json:"requested_at"`
}

// Webhook defines an outbound HTTP callback for platform events.
type Webhook struct {
	ID              uuid.UUID  `json:"id"`
	TenantID        uuid.UUID  `json:"tenant_id"`
	Name            string     `json:"name"`
	URL             string     `json:"url"`
	Events          []string   `json:"events"`
	IsActive        bool       `json:"is_active"`
	FailureCount    int        `json:"failure_count"`
	LastTriggeredAt *time.Time `json:"last_triggered_at,omitempty"`
	LastStatusCode  *int       `json:"last_status_code,omitempty"`
	CreatedBy       *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	// Secret is never returned in API responses.
}

// WebhookDelivery is the result of one delivery attempt.
type WebhookDelivery struct {
	ID             uuid.UUID      `json:"id"`
	TenantID       uuid.UUID      `json:"tenant_id"`
	WebhookID      uuid.UUID      `json:"webhook_id"`
	EventType      string         `json:"event_type"`
	Payload        map[string]any `json:"payload,omitempty"`
	ResponseStatus *int           `json:"response_status,omitempty"`
	ResponseBody   string         `json:"response_body,omitempty"`
	Attempt        int            `json:"attempt"`
	Success        bool           `json:"success"`
	DeliveredAt    *time.Time     `json:"delivered_at,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
}

// APIFWStats is the platform-wide API usage summary.
type APIFWStats struct {
	ActiveKeys          int            `json:"active_keys"`
	TotalRequestsToday  int            `json:"total_requests_today"`
	ActiveWebhooks      int            `json:"active_webhooks"`
	DeliverySuccessRate float64        `json:"delivery_success_rate"` // 0–100
	TopEndpoints        []EndpointStat `json:"top_endpoints"`
}

// EndpointStat aggregates usage for a single endpoint.
type EndpointStat struct {
	Endpoint   string  `json:"endpoint"`
	Method     string  `json:"method"`
	Count      int     `json:"count"`
	AvgLatency float64 `json:"avg_latency_ms"`
	ErrorRate  float64 `json:"error_rate"` // percent 4xx+5xx
}

// ── Request / filter models ───────────────────────────────────────────────────

type CreateAPIKeyRequest struct {
	Name         string     `json:"name"          validate:"required,min=2,max=200"`
	Description  string     `json:"description"`
	Scopes       []string   `json:"scopes"        validate:"required,min=1,dive,oneof=read write admin webhook"`
	RateLimitRPM int        `json:"rate_limit_rpm" validate:"omitempty,min=1,max=6000"`
	RateLimitRPD int        `json:"rate_limit_rpd" validate:"omitempty,min=1,max=10000000"`
	ExpiresAt    *time.Time `json:"expires_at"`
}

type UpdateAPIKeyRequest struct {
	Name         *string    `json:"name"          validate:"omitempty,min=2,max=200"`
	Description  *string    `json:"description"`
	Scopes       []string   `json:"scopes"        validate:"omitempty,dive,oneof=read write admin webhook"`
	RateLimitRPM *int       `json:"rate_limit_rpm" validate:"omitempty,min=1,max=6000"`
	RateLimitRPD *int       `json:"rate_limit_rpd" validate:"omitempty,min=1,max=10000000"`
	ExpiresAt    *time.Time `json:"expires_at"`
}

type CreateWebhookRequest struct {
	Name   string   `json:"name"   validate:"required,min=2,max=200"`
	URL    string   `json:"url"    validate:"required,url"`
	Secret string   `json:"secret"`
	Events []string `json:"events" validate:"required,min=1,dive,oneof=alert.created incident.created ioc.matched anomaly.detected vuln.found"`
}

type UpdateWebhookRequest struct {
	Name   *string  `json:"name"   validate:"omitempty,min=2,max=200"`
	URL    *string  `json:"url"    validate:"omitempty,url"`
	Secret *string  `json:"secret"`
	Events []string `json:"events" validate:"omitempty,dive,oneof=alert.created incident.created ioc.matched anomaly.detected vuln.found"`
}

type APIKeyFilter struct {
	TenantID uuid.UUID
	IsActive *bool
	Limit    int
	Offset   int
}

type WebhookFilter struct {
	TenantID uuid.UUID
	IsActive *bool
	Limit    int
	Offset   int
}
