package normalizer

import (
	"fmt"
	"time"

	"github.com/cyberradar/platform/internal/pkg/event"
	"github.com/google/uuid"
)

// Normalize converts a raw event string to a NormalizedEvent based on its format.
func Normalize(raw event.RawEvent) (*event.NormalizedEvent, error) {
	switch raw.Format {
	case event.FormatJSON:
		return fromJSON(raw)
	case event.FormatCEF:
		return fromCEF(raw)
	case event.FormatSyslog:
		return fromSyslog(raw)
	case event.FormatLEEF:
		return fromLEEF(raw)
	case event.FormatWinEvent:
		return fromWinEvent(raw)
	case event.FormatCLF:
		return fromCLF(raw)
	default:
		return nil, fmt.Errorf("unsupported format: %s", raw.Format)
	}
}

// base returns a NormalizedEvent pre-populated with lineage fields.
func base(raw event.RawEvent) *event.NormalizedEvent {
	return &event.NormalizedEvent{
		EventID:       uuid.New(),
		TenantID:      raw.TenantID,
		Timestamp:     raw.ReceivedAt,
		IngestedAt:    time.Now().UTC(),
		SchemaVersion: 1,
		ConnectorID:   raw.ConnectorID,
		Source:        raw.Source,
		SourceType:    raw.SourceType,
		RawEventID:    raw.ID.String(),
		RawEvent:      raw.Raw,
		Category:      event.CategoryOther,
		Severity:      event.SeverityLow,
		Outcome:       event.OutcomeUnknown,
		IOCMatched:    []string{},
	}
}

// ptr helpers for optional string/uint16 fields.
func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
