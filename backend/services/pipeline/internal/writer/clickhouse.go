package writer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/cyberradar/platform/internal/pkg/event"
	"github.com/rs/zerolog"
)

const (
	defaultBatchSize    = 1000
	defaultFlushTimeout = 5 * time.Second
)

// ClickHouseWriter batches normalized events and writes them to cyber_events.
//
// Two goroutines reach it: the consumer loop, which calls Write for every
// event, and the periodic flush loop, which calls Flush on a ticker. mu guards
// the buffer between them. Without it the two race on the same slice, and the
// loss is silent — an append and a truncation that interleave drop events that
// the consumer has already committed as handled.
type ClickHouseWriter struct {
	conn      clickhouse.Conn
	logger    zerolog.Logger
	batchSize int

	mu      sync.Mutex
	buf     []*event.NormalizedEvent
	flushAt time.Time
}

// NewClickHouseWriter creates a ClickHouseWriter.
func NewClickHouseWriter(conn clickhouse.Conn, logger zerolog.Logger, batchSize int) *ClickHouseWriter {
	if batchSize <= 0 {
		batchSize = defaultBatchSize
	}
	return &ClickHouseWriter{
		conn:      conn,
		logger:    logger,
		batchSize: batchSize,
		buf:       make([]*event.NormalizedEvent, 0, batchSize),
		flushAt:   time.Now().Add(defaultFlushTimeout),
	}
}

// Write adds an event to the buffer. Flushes automatically when full or timed out.
func (w *ClickHouseWriter) Write(ctx context.Context, e *event.NormalizedEvent) error {
	w.mu.Lock()
	w.buf = append(w.buf, e)
	due := len(w.buf) >= w.batchSize || time.Now().After(w.flushAt)
	w.mu.Unlock()

	if due {
		return w.Flush(ctx)
	}
	return nil
}

// Flush writes all buffered events to ClickHouse in a single batch INSERT.
//
// The buffer is taken under the lock and the insert runs without it, so a slow
// ClickHouse holds up the events it is already carrying and not the ones still
// arriving.
func (w *ClickHouseWriter) Flush(ctx context.Context) error {
	w.mu.Lock()
	batched := w.buf
	w.buf = make([]*event.NormalizedEvent, 0, w.batchSize)
	w.flushAt = time.Now().Add(defaultFlushTimeout)
	w.mu.Unlock()

	if len(batched) == 0 {
		return nil
	}

	batch, err := w.conn.PrepareBatch(ctx,
		`INSERT INTO crp_audit.cyber_events (
			event_id, tenant_id, timestamp, ingested_at,
			source, source_type, connector_id,
			user_id, user_name, user_email, user_department, user_risk_score,
			asset_id, asset_hostname, asset_type, asset_criticality,
			ip_source, ip_destination, port_source, port_dest, geo_country, geo_asn,
			action, category, severity, outcome,
			threat_score, mitre_tactic, mitre_technique, ioc_matched,
			risk_score,
			business_service, cbs_impact, swift_impact,
			raw_event, schema_version
		)`)
	if err != nil {
		return fmt.Errorf("clickhouse prepare batch: %w", err)
	}

	for _, e := range batched {
		var (
			userID         = nullStr(e.UserID)
			userName       = nullStr(e.UserName)
			userEmail      = nullStr(e.UserEmail)
			userDept       = nullStr(e.UserDepartment)
			userRisk       = nullF32(e.UserRiskScore)
			assetID        = nullStr(e.AssetID)
			assetHostname  = nullStr(e.AssetHostname)
			assetType      = nullStr(e.AssetType)
			assetCrit      = nullF32(e.AssetCriticality)
			ipSrc          = nullStr(e.IPSource)
			ipDst          = nullStr(e.IPDestination)
			portSrc        = nullU16(e.PortSource)
			portDst        = nullU16(e.PortDest)
			geoCountry     = nullStr(e.GeoCountry)
			geoASN         = nullStr(e.GeoASN)
			mitreTactic    = nullStr(e.MitreTactic)
			mitreTechnique = nullStr(e.MitreTechnique)
			bizService     = nullStr(e.BusinessService)
			ioc            = e.IOCMatched
		)
		if ioc == nil {
			ioc = []string{}
		}

		if err := batch.Append(
			e.EventID,
			e.TenantID,
			e.Timestamp,
			e.IngestedAt,
			e.Source,
			e.SourceType,
			e.ConnectorID,
			userID, userName, userEmail, userDept, userRisk,
			assetID, assetHostname, assetType, assetCrit,
			ipSrc, ipDst, portSrc, portDst, geoCountry, geoASN,
			e.Action,
			string(e.Category),
			string(e.Severity),
			string(e.Outcome),
			e.ThreatScore,
			mitreTactic, mitreTechnique,
			ioc,
			e.RiskScore,
			bizService, e.CBSImpact, e.SWIFTImpact,
			e.RawEvent,
			e.SchemaVersion,
		); err != nil {
			w.logger.Error().Err(err).
				Str("event_id", e.EventID.String()).
				Msg("clickhouse_append_failed")
		}
	}

	if err := batch.Send(); err != nil {
		w.logger.Error().Err(err).
			Int("batch_size", len(batched)).
			Msg("clickhouse_batch_send_failed")
		return fmt.Errorf("clickhouse batch send: %w", err)
	}

	w.logger.Info().
		Int("written", len(batched)).
		Msg("clickhouse_batch_written")

	return nil
}

// ─── Null helpers ─────────────────────────────────────────────────────────────

func nullStr(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func nullF32(p *float32) any {
	if p == nil {
		return nil
	}
	return *p
}

func nullU16(p *uint16) any {
	if p == nil {
		return nil
	}
	return *p
}
