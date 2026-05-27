package service

import (
	"context"
	"encoding/json"

	"github.com/cyberradar/platform/internal/pkg/event"
	pkgkafka "github.com/cyberradar/platform/internal/pkg/kafka"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// DiscoveryWorker consumes enriched events from D1 pipeline and auto-discovers assets.
type DiscoveryWorker struct {
	assetSvc *AssetService
	consumer *pkgkafka.Consumer
	logger   zerolog.Logger
}

// NewDiscoveryWorker creates a DiscoveryWorker.
func NewDiscoveryWorker(assetSvc *AssetService, consumer *pkgkafka.Consumer, logger zerolog.Logger) *DiscoveryWorker {
	return &DiscoveryWorker{assetSvc: assetSvc, consumer: consumer, logger: logger}
}

// Run starts the Kafka consumer loop. Blocks until ctx is cancelled.
func (w *DiscoveryWorker) Run(ctx context.Context) error {
	w.logger.Info().Msg("discovery_worker_started")
	return w.consumer.Run(ctx, w.handle)
}

// handle processes one enriched event and updates asset inventory accordingly.
func (w *DiscoveryWorker) handle(ctx context.Context, msg pkgkafka.Message) error {
	var e event.NormalizedEvent
	if err := json.Unmarshal(msg.Value, &e); err != nil {
		// Skip unparseable events silently
		return nil
	}

	tenantID, err := uuid.Parse(e.TenantID)
	if err != nil {
		return nil
	}

	// ── Touch last_seen_at for known IPs ─────────────────────────────────────
	if e.IPSource != nil && *e.IPSource != "" {
		w.assetSvc.TouchLastSeen(ctx, tenantID, *e.IPSource)

		// Add to discovery queue if not yet in inventory
		hostname := ""
		if e.AssetHostname != nil {
			hostname = *e.AssetHostname
		}
		connector := e.ConnectorID
		w.assetSvc.UpsertDiscoveryCandidate(ctx, tenantID, *e.IPSource, hostname, e.SourceType, connector)
	}

	if e.IPDestination != nil && *e.IPDestination != "" {
		w.assetSvc.TouchLastSeen(ctx, tenantID, *e.IPDestination)
	}

	return nil
}
