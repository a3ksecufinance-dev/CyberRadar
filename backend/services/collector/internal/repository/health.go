// Package repository holds the collector's reads and writes against
// ClickHouse: which sources exist, and when each last said anything.
package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/cyberradar/platform/services/collector/internal/model"
)

// HealthRepository answers "which of my sources went quiet".
//
// A silent source is the blind spot a SOC cares about most: a firewall that
// stopped sending at two in the morning is not a missing chart, it is six
// hours of unexamined traffic. The platform already held every fact needed to
// answer it — each event carries its connector and its source — and nothing
// ever asked.
type HealthRepository struct {
	conn clickhouse.Conn
}

func NewHealthRepository(conn clickhouse.Conn) *HealthRepository {
	return &HealthRepository{conn: conn}
}

// RecordHeartbeat stores a connector's liveness report.
//
// crp_fabric.connectors is a ReplacingMergeTree keyed on (tenant_id, id) and
// versioned by last_seen_at, so an insert carrying a newer timestamp replaces
// the row rather than accumulating one per beat.
//
// events_total and events_failed are deliberately left at whatever the
// connector reports and are not maintained as running counters here. A
// counter kept in two places drifts, and this one has no need to exist: the
// events themselves are in crp_audit.cyber_events with their connector, so
// the true count is a GROUP BY away and cannot disagree with reality.
func (r *HealthRepository) RecordHeartbeat(ctx context.Context, tenantID string, hb *model.ConnectorHeartbeat) error {
	const q = `
		INSERT INTO crp_fabric.connectors
			(id, tenant_id, name, source_type, format, status, config, last_seen_at, events_total, events_failed)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	err := r.conn.Exec(ctx, q,
		hb.ConnectorID, tenantID, hb.Source, hb.SourceType, "",
		"active", "", time.Now().UTC(), uint64(0), uint64(0))
	if err != nil {
		return fmt.Errorf("record heartbeat for %s: %w", hb.ConnectorID, err)
	}
	return nil
}

// SourceHealth is one source and how long it has been quiet.
type SourceHealth struct {
	Source       string    `json:"source"`
	ConnectorID  string    `json:"connector_id"`
	Events       uint64    `json:"events"`
	LastEventAt  time.Time `json:"last_event_at"`
	SilentFor    string    `json:"silent_for"`
	SilentSecond int64     `json:"silent_seconds"`
	Status       string    `json:"status"`
}

// Statuses a source can be in, by how long it has been quiet.
const (
	StatusLive   = "live"   // heard from within the window
	StatusLate   = "late"   // quiet longer than expected, not yet alarming
	StatusSilent = "silent" // quiet long enough to be a blind spot
)

// Sources lists every source that has ever sent an event for a tenant, with
// how long each has been quiet.
//
// Derived from the events rather than from a status column somebody has to
// remember to update: a source is alive because it spoke, not because a row
// says so. The connectors table records what a connector claims about itself;
// this records what it did.
func (r *HealthRepository) Sources(ctx context.Context, tenantID string, late, silent time.Duration) ([]SourceHealth, error) {
	const q = `
		SELECT source,
		       any(connector_id)                        AS connector_id,
		       count()                                  AS events,
		       max(timestamp)                           AS last_event_at,
		       dateDiff('second', max(timestamp), now()) AS silent_seconds
		FROM crp_audit.cyber_events
		WHERE tenant_id = ?
		GROUP BY source
		ORDER BY last_event_at DESC`

	rows, err := r.conn.Query(ctx, q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("read source health: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read-only

	var out []SourceHealth
	for rows.Next() {
		var s SourceHealth
		var quiet int64
		if err := rows.Scan(&s.Source, &s.ConnectorID, &s.Events, &s.LastEventAt, &quiet); err != nil {
			return nil, fmt.Errorf("scan source health: %w", err)
		}
		s.SilentSecond = quiet
		s.SilentFor = (time.Duration(quiet) * time.Second).Round(time.Second).String()
		s.Status = classifySilence(time.Duration(quiet)*time.Second, late, silent)
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read source health: %w", err)
	}
	return out, nil
}

// classifySilence turns a duration into the word an operator acts on.
func classifySilence(quiet, late, silent time.Duration) string {
	switch {
	case quiet >= silent:
		return StatusSilent
	case quiet >= late:
		return StatusLate
	default:
		return StatusLive
	}
}
