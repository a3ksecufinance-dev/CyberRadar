package kpi

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

type capture struct {
	tenantID uuid.UUID
	domain   string
	samples  []Sample
}

type fakePublisher struct {
	calls  []capture
	failOn map[uuid.UUID]bool
	closed bool
}

func (f *fakePublisher) Publish(_ context.Context, tenantID uuid.UUID, domain string, samples []Sample) error {
	if f.failOn[tenantID] {
		return errors.New("broker unavailable")
	}
	f.calls = append(f.calls, capture{tenantID, domain, samples})
	return nil
}

func (f *fakePublisher) Close() error { f.closed = true; return nil }

func tenants(ids ...uuid.UUID) Tenants {
	return func(context.Context) ([]uuid.UUID, error) { return ids, nil }
}

func TestSamplesEveryTenant(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	pub := &fakePublisher{}
	s, err := New(Config{
		Domain:    "siem",
		Tenants:   tenants(a, b),
		Publisher: pub,
		Source: func(_ context.Context, id uuid.UUID) ([]Sample, error) {
			return []Sample{{MetricKey: "open_alerts", Value: 3}}, nil
		},
	}, zerolog.Nop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	n, err := s.SampleOnce(context.Background())
	if err != nil {
		t.Fatalf("SampleOnce: %v", err)
	}
	if n != 2 || len(pub.calls) != 2 {
		t.Fatalf("published for %d tenants (%d calls), want 2", n, len(pub.calls))
	}
	if pub.calls[0].domain != "siem" {
		t.Errorf("domain = %q, want siem", pub.calls[0].domain)
	}
}

// One tenant failing must not silence the others: a dashboard blanked for
// every tenant because one of them errored is the failure mode this whole
// package exists to remove.
func TestOneTenantFailureDoesNotStopTheRest(t *testing.T) {
	bad, good := uuid.New(), uuid.New()

	t.Run("source error", func(t *testing.T) {
		pub := &fakePublisher{}
		s, _ := New(Config{
			Domain: "ti", Tenants: tenants(bad, good), Publisher: pub,
			Source: func(_ context.Context, id uuid.UUID) ([]Sample, error) {
				if id == bad {
					return nil, errors.New("clickhouse timeout")
				}
				return []Sample{{MetricKey: "active_iocs", Value: 7}}, nil
			},
		}, zerolog.Nop())

		n, err := s.SampleOnce(context.Background())
		if err != nil {
			t.Fatalf("SampleOnce returned an error for one bad tenant: %v", err)
		}
		if n != 1 || len(pub.calls) != 1 || pub.calls[0].tenantID != good {
			t.Errorf("published %d, want only the healthy tenant", n)
		}
	})

	t.Run("publish error", func(t *testing.T) {
		pub := &fakePublisher{failOn: map[uuid.UUID]bool{bad: true}}
		s, _ := New(Config{
			Domain: "ti", Tenants: tenants(bad, good), Publisher: pub,
			Source: func(context.Context, uuid.UUID) ([]Sample, error) {
				return []Sample{{MetricKey: "active_iocs", Value: 7}}, nil
			},
		}, zerolog.Nop())

		n, _ := s.SampleOnce(context.Background())
		if n != 1 {
			t.Errorf("published for %d tenants, want 1", n)
		}
	})
}

func TestConfigurationErrorsAreRefusedUpFront(t *testing.T) {
	src := func(context.Context, uuid.UUID) ([]Sample, error) { return nil, nil }
	cases := map[string]Config{
		"no domain":  {Tenants: tenants(), Source: src, Publisher: &fakePublisher{}},
		"no source":  {Domain: "siem", Tenants: tenants(), Publisher: &fakePublisher{}},
		"no tenants": {Domain: "siem", Source: src, Publisher: &fakePublisher{}},
		"no brokers": {Domain: "siem", Source: src, Tenants: tenants()},
	}
	for name, cfg := range cases {
		if _, err := New(cfg, zerolog.Nop()); err == nil {
			t.Errorf("%s: accepted a configuration that cannot publish", name)
		}
	}
}

func TestIntervalDefaults(t *testing.T) {
	s, err := New(Config{
		Domain: "kg", Tenants: tenants(), Publisher: &fakePublisher{},
		Source: func(context.Context, uuid.UUID) ([]Sample, error) { return nil, nil },
	}, zerolog.Nop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.cfg.Interval != DefaultInterval {
		t.Errorf("interval = %v, want %v", s.cfg.Interval, DefaultInterval)
	}
}

// Run must publish before its first tick, or a restart leaves the dashboard
// stale for a whole interval.
func TestRunPublishesImmediately(t *testing.T) {
	pub := &fakePublisher{}
	s, _ := New(Config{
		Domain: "vuln", Interval: time.Hour, Tenants: tenants(uuid.New()), Publisher: pub,
		Source: func(context.Context, uuid.UUID) ([]Sample, error) {
			return []Sample{{MetricKey: "critical_vulns", Value: 1}}, nil
		},
	}, zerolog.Nop())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	deadline := time.After(2 * time.Second)
	for len(pub.calls) == 0 {
		select {
		case <-deadline:
			cancel()
			t.Fatal("Run did not publish before its first tick")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	cancel()
	<-done
	if !pub.closed {
		t.Error("Run did not close the publisher on shutdown")
	}
}

// The wire format is fixed by the dashboard's consumer; this asserts the
// producer speaks it.
func TestMessageShapeMatchesTheConsumer(t *testing.T) {
	id := uuid.New()
	body, err := json.Marshal(message{
		TenantID: id.String(), Domain: "siem", MetricKey: "open_alerts",
		MetricValue: 42, Labels: map[string]string{"severity": "CRITICAL"},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Transcribed from services/dashboard/cmd/server/main.go.
	var consumer struct {
		TenantID    string            `json:"tenant_id"`
		Domain      string            `json:"domain"`
		MetricKey   string            `json:"metric_key"`
		MetricValue float64           `json:"metric_value"`
		Labels      map[string]string `json:"labels"`
	}
	if err := json.Unmarshal(body, &consumer); err != nil {
		t.Fatalf("the consumer cannot read what the producer writes: %v", err)
	}
	if consumer.TenantID != id.String() || consumer.Domain != "siem" ||
		consumer.MetricKey != "open_alerts" || consumer.MetricValue != 42 ||
		consumer.Labels["severity"] != "CRITICAL" {
		t.Errorf("decoded as %+v", consumer)
	}
}

// Every domain the overview reads must be covered, or that part of the
// dashboard silently stays at zero.
func TestMetricKeysCoverEveryDomainTheOverviewReads(t *testing.T) {
	// Transcribed from DashboardService.PlatformOverview.
	needed := map[string][]string{
		"siem":       {"open_alerts", "critical_alerts", "risk_score"},
		"ueba":       {"active_anomalies", "high_risk_entities", "risk_score"},
		"ti":         {"active_iocs", "ioc_hits_today", "risk_score"},
		"vuln":       {"critical_vulns", "sla_breached", "risk_score"},
		"attackpath": {"total_paths", "choke_points", "risk_score"},
		"soar":       {"open_incidents", "sla_breached"},
		"kg":         {"total_entities"},
	}
	for domain, keys := range needed {
		declared := MetricKeys[domain]
		for _, want := range keys {
			found := false
			for _, got := range declared {
				if got == want {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s does not declare %q, which the overview reads", domain, want)
			}
		}
	}
}
