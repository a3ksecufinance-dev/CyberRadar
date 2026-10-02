package model

import "github.com/cyberradar/platform/internal/pkg/event"

// IngestRequest is the HTTP payload for bulk event ingestion.
type IngestRequest struct {
	ConnectorID string       `json:"connector_id" validate:"required,uuid4"`
	Source      string       `json:"source"       validate:"required"`
	SourceType  string       `json:"source_type"  validate:"required"`
	Format      event.Format `json:"format"       validate:"required,oneof=json cef syslog leef winevent netflow clf"`
	Events      []string     `json:"events"       validate:"required,min=1,max=1000"`
}

// IngestResponse summarizes the result of a bulk ingestion.
type IngestResponse struct {
	Received  int      `json:"received"`
	Published int      `json:"published"`
	Failed    int      `json:"failed"`
	Errors    []string `json:"errors,omitempty"`
}

// ConnectorHeartbeat is sent by agents to report liveness.
type ConnectorHeartbeat struct {
	ConnectorID  string `json:"connector_id"   validate:"required,uuid4"`
	Source       string `json:"source"         validate:"required"`
	SourceType   string `json:"source_type"    validate:"required"`
	EventsQueued int64  `json:"events_queued"`
	Version      string `json:"version"`
}
