// Package kpi lets a domain service publish the numbers the platform dashboard
// is built from.
//
// The dashboard does not compute anything: PlatformOverview reads the latest
// snapshot each domain reported and assembles them. Nothing published them, so
// every domain read back as absent and the whole overview — the security
// score, every metric card — answered zero. An empty dashboard on a platform
// holding real alerts is worse than no dashboard: it reads as "nothing is
// happening".
//
// A service publishes with one call in main:
//
//	kpi.Start(ctx, kpi.Config{
//		Brokers:  brokers,
//		Domain:   "siem",
//		Tenants:  kpi.TenantsFromPostgres(pool),
//		Source:   siemSvc.KPISamples,
//	}, logger)
//
// and implements Source: given a tenant, return its current numbers. The
// metric keys a domain must report are the ones the dashboard reads for it —
// see MetricKeys below, which is the contract between the two sides.
package kpi

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	kafkago "github.com/segmentio/kafka-go"
)

// Topic is the one the dashboard's ingestor consumes.
const Topic = "crp.events.kpi"

// DefaultInterval matches the "every minute" the dashboard schema documents.
const DefaultInterval = time.Minute

// MetricKeys records what each domain owes the overview. It is here rather
// than in the dashboard so a service can be checked against it without
// importing the dashboard, and so a reader of either side can see the contract.
var MetricKeys = map[string][]string{
	"siem":       {"open_alerts", "critical_alerts", "risk_score"},
	"ueba":       {"active_anomalies", "high_risk_entities", "risk_score"},
	"ti":         {"active_iocs", "ioc_hits_today", "risk_score"},
	"vuln":       {"critical_vulns", "sla_breached", "risk_score"},
	"attackpath": {"total_paths", "choke_points", "risk_score"},
	"soar":       {"open_incidents", "sla_breached"},
	"kg":         {"total_entities"},
}

// Sample is one metric reading for one tenant.
type Sample struct {
	MetricKey string
	Value     float64
	Labels    map[string]string
}

// Source returns a tenant's current numbers. A service implements this over
// whatever it already computes for its own /stats endpoint.
type Source func(ctx context.Context, tenantID uuid.UUID) ([]Sample, error)

// Tenants lists the tenants to sample.
type Tenants func(ctx context.Context) ([]uuid.UUID, error)

// Publisher sends samples onward. Kafka in production; a fake in tests.
type Publisher interface {
	Publish(ctx context.Context, tenantID uuid.UUID, domain string, samples []Sample) error
	Close() error
}

// message is the payload the dashboard's consumer unmarshals. Its shape is
// fixed by that consumer, so it is spelled out here rather than reused from a
// model the producer would otherwise have to import.
type message struct {
	TenantID    string            `json:"tenant_id"`
	Domain      string            `json:"domain"`
	MetricKey   string            `json:"metric_key"`
	MetricValue float64           `json:"metric_value"`
	Labels      map[string]string `json:"labels"`
}

// ─── Kafka publisher ──────────────────────────────────────────────────────────

type kafkaPublisher struct {
	w *kafkago.Writer
}

// NewKafkaPublisher writes to Topic on the given brokers.
func NewKafkaPublisher(brokers []string) Publisher {
	return &kafkaPublisher{
		w: &kafkago.Writer{
			Addr:         kafkago.TCP(brokers...),
			Topic:        Topic,
			Balancer:     &kafkago.Hash{}, // same tenant → same partition, so its readings stay ordered
			BatchTimeout: 200 * time.Millisecond,
			RequiredAcks: kafkago.RequireOne,
		},
	}
}

func (p *kafkaPublisher) Publish(ctx context.Context, tenantID uuid.UUID, domain string, samples []Sample) error {
	if len(samples) == 0 {
		return nil
	}
	msgs := make([]kafkago.Message, 0, len(samples))
	for _, s := range samples {
		body, err := json.Marshal(message{
			TenantID:    tenantID.String(),
			Domain:      domain,
			MetricKey:   s.MetricKey,
			MetricValue: s.Value,
			Labels:      s.Labels,
		})
		if err != nil {
			return fmt.Errorf("marshal %s: %w", s.MetricKey, err)
		}
		msgs = append(msgs, kafkago.Message{Key: []byte(tenantID.String()), Value: body})
	}
	return p.w.WriteMessages(ctx, msgs...)
}

func (p *kafkaPublisher) Close() error { return p.w.Close() }

// ─── Tenant enumeration ───────────────────────────────────────────────────────

// TenantsFromPostgres lists the active tenants from the shared identity schema,
// which every domain service is already connected to.
func TenantsFromPostgres(pool *pgxpool.Pool) Tenants {
	return func(ctx context.Context) ([]uuid.UUID, error) {
		rows, err := pool.Query(ctx, `SELECT id FROM tenants WHERE status = 'active' ORDER BY id`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var ids []uuid.UUID
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return nil, err
			}
			ids = append(ids, id)
		}
		return ids, rows.Err()
	}
}

// ─── Sampler ──────────────────────────────────────────────────────────────────

// Config describes one domain's reporting.
type Config struct {
	Brokers  []string
	Domain   string
	Interval time.Duration
	Tenants  Tenants
	Source   Source
	// Publisher overrides the Kafka one. Tests set it; services do not.
	Publisher Publisher
}

// Sampler reads a domain's numbers on a tick and publishes them.
type Sampler struct {
	cfg    Config
	pub    Publisher
	logger zerolog.Logger
}

// New builds a Sampler. It returns an error only for a configuration that
// cannot work at all, so a service fails at startup rather than reporting
// nothing for weeks.
func New(cfg Config, logger zerolog.Logger) (*Sampler, error) {
	if cfg.Domain == "" {
		return nil, fmt.Errorf("kpi: domain is required")
	}
	if cfg.Source == nil {
		return nil, fmt.Errorf("kpi: source is required for domain %s", cfg.Domain)
	}
	if cfg.Tenants == nil {
		return nil, fmt.Errorf("kpi: tenant lister is required for domain %s", cfg.Domain)
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	pub := cfg.Publisher
	if pub == nil {
		if len(cfg.Brokers) == 0 {
			return nil, fmt.Errorf("kpi: brokers are required for domain %s", cfg.Domain)
		}
		pub = NewKafkaPublisher(cfg.Brokers)
	}
	return &Sampler{cfg: cfg, pub: pub, logger: logger.With().Str("kpi_domain", cfg.Domain).Logger()}, nil
}

// SampleOnce reads and publishes every active tenant's numbers, and reports how
// many tenants it published for.
//
// One tenant's failure does not stop the others: a domain that cannot compute
// for tenant A must still report tenant B, or one bad tenant blanks the
// dashboard for everyone.
func (s *Sampler) SampleOnce(ctx context.Context) (int, error) {
	tenants, err := s.cfg.Tenants(ctx)
	if err != nil {
		return 0, fmt.Errorf("list tenants: %w", err)
	}
	published := 0
	for _, tenantID := range tenants {
		samples, err := s.cfg.Source(ctx, tenantID)
		if err != nil {
			s.logger.Warn().Err(err).Str("tenant_id", tenantID.String()).Msg("kpi_source_error")
			continue
		}
		if err := s.pub.Publish(ctx, tenantID, s.cfg.Domain, samples); err != nil {
			s.logger.Warn().Err(err).Str("tenant_id", tenantID.String()).Msg("kpi_publish_error")
			continue
		}
		published++
	}
	return published, nil
}

// Run samples on the configured interval until ctx is done. It samples once
// immediately, so a restarted service does not leave the dashboard stale for a
// whole interval.
func (s *Sampler) Run(ctx context.Context) {
	defer func() {
		if err := s.pub.Close(); err != nil {
			s.logger.Warn().Err(err).Msg("kpi_publisher_close_error")
		}
	}()

	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()

	for {
		if n, err := s.SampleOnce(ctx); err != nil {
			s.logger.Warn().Err(err).Msg("kpi_sample_error")
		} else {
			s.logger.Debug().Int("tenants", n).Msg("kpi_published")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Start builds a Sampler and runs it in the background.
//
// A service that cannot report its KPIs is still a working service, so a
// configuration error is logged rather than fatal — but it is logged at error
// level, because the consequence is a dashboard that reads zero for this
// domain and says nothing about why.
func Start(ctx context.Context, cfg Config, logger zerolog.Logger) {
	s, err := New(cfg, logger)
	if err != nil {
		logger.Error().Err(err).Msg("kpi_sampler_not_started")
		return
	}
	go s.Run(ctx)
}
