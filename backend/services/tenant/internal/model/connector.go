package model

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	apierrors "github.com/cyberradar/platform/internal/pkg/errors"
)

// Connector is a declared source of telemetry.
//
// It lives here, beside RemediationPolicy and RiskProfile, because it is the
// same kind of thing: per-tenant configuration somebody set up and will change
// again. What the connector has actually *done* is not here and is not copied
// here — the collector answers that from the events themselves, so the two can
// never disagree.
type Connector struct {
	ID       uuid.UUID `json:"id"`
	TenantID uuid.UUID `json:"tenant_id"`

	Name       string `json:"name"`
	SourceType string `json:"source_type"`
	Format     string `json:"format"`

	// Config is the connector's own settings, stored and returned without
	// being interpreted. Parsing it here would make every new connector type
	// a change to this service.
	Config json.RawMessage `json:"config"`

	// Enabled is what the operator wants, not what is happening: it says this
	// source should be collected, never that it is sending.
	Enabled bool `json:"enabled"`

	// SilentAfter is how quiet this source may go before anyone should worry.
	// A property of the connector rather than a constant, because a firewall
	// and a quarterly compliance feed are silent on unrelated scales.
	SilentAfter time.Duration `json:"-"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// MarshalJSON renders SilentAfter as seconds, the unit the API speaks.
func (c Connector) MarshalJSON() ([]byte, error) {
	type alias Connector
	return json.Marshal(struct {
		alias
		SilentAfterSeconds int `json:"silent_after_seconds"`
	}{alias(c), int(c.SilentAfter.Seconds())})
}

// Known formats and the shape of a source type. Kept deliberately short: the
// list exists to catch a typo at registration, not to be a taxonomy the
// platform must agree with before a customer can collect anything.
var knownFormats = map[string]bool{
	"json": true, "cef": true, "syslog": true, "leef": true,
	"winevent": true, "netflow": true,
}

// CreateConnectorRequest is what registering a connector takes.
type CreateConnectorRequest struct {
	Name        string          `json:"name"`
	SourceType  string          `json:"source_type"`
	Format      string          `json:"format"`
	Config      json.RawMessage `json:"config"`
	Enabled     *bool           `json:"enabled"`
	SilentAfter int             `json:"silent_after_seconds"`
}

// Validate refuses what the database would refuse, and says why in words an
// operator can act on rather than as a constraint violation.
//
// Every refusal is a KindBadInput, because httperr classifies by kind and an
// unclassified error becomes a 500. A caller who mistypes a format is making
// a mistake, and answering "an internal error occurred" tells them to call
// support about a typo they could have fixed themselves. That exact failure
// was here, and the live API is what showed it.
func (r *CreateConnectorRequest) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return apierrors.BadInput("name is required: it is what an operator types when this source goes quiet")
	}
	if strings.TrimSpace(r.SourceType) == "" {
		return apierrors.BadInput("source_type is required")
	}
	if r.Format == "" {
		r.Format = "json"
	}
	if !knownFormats[r.Format] {
		return apierrors.BadInput(fmt.Sprintf("format %q is not one this platform parses", r.Format))
	}
	if r.SilentAfter < 0 {
		return apierrors.BadInput("silent_after_seconds cannot be negative")
	}
	if len(r.Config) > 0 && !json.Valid(r.Config) {
		return apierrors.BadInput("config is not valid JSON")
	}
	return nil
}

// UpdateConnectorRequest changes a registered connector. Every field is
// optional: a caller that only disables a connector must not have to resend
// its configuration, which is how configuration gets silently reverted.
type UpdateConnectorRequest struct {
	Name        *string          `json:"name"`
	SourceType  *string          `json:"source_type"`
	Format      *string          `json:"format"`
	Config      *json.RawMessage `json:"config"`
	Enabled     *bool            `json:"enabled"`
	SilentAfter *int             `json:"silent_after_seconds"`
}

func (r *UpdateConnectorRequest) Validate() error {
	if r.Name != nil && strings.TrimSpace(*r.Name) == "" {
		return apierrors.BadInput("name cannot be emptied")
	}
	if r.SourceType != nil && strings.TrimSpace(*r.SourceType) == "" {
		return apierrors.BadInput("source_type cannot be emptied")
	}
	if r.Format != nil && !knownFormats[*r.Format] {
		return apierrors.BadInput(fmt.Sprintf("format %q is not one this platform parses", *r.Format))
	}
	if r.SilentAfter != nil && *r.SilentAfter <= 0 {
		return apierrors.BadInput("silent_after_seconds must be positive")
	}
	if r.Config != nil && len(*r.Config) > 0 && !json.Valid(*r.Config) {
		return apierrors.BadInput("config is not valid JSON")
	}
	return nil
}
