package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/cyberradar/platform/internal/pkg/event"
	"github.com/segmentio/kafka-go"
)

// ─── The non-functional requirements, made verifiable ────────────────────────
//
// The execution plan lists four of them under L2 and says they are to become
// verifiable, which is a different job from being met: a requirement nobody
// can measure is not a requirement, it is a hope. What follows measures the
// ones this platform can answer today and says plainly what the others would
// need, rather than producing a number for each line.

// pipelineLatencyBudget is the NFR: an event must be enriched and available
// within this long of the collector accepting it.
const pipelineLatencyBudget = 3 * time.Second

// enrichmentBudget is US-CTI-ENR-002.
const enrichmentBudget = 500 * time.Millisecond

// recoveryBudget is the NFR for catching up after an interruption.
const recoveryBudget = 15 * time.Minute

func (b *bench) reportNFR(ctx context.Context, events, rate int) error {
	members, err := b.pipelineInstances(ctx)
	if err != nil {
		return fmt.Errorf("lecture du groupe de consommateurs: %w", err)
	}
	fmt.Printf("   instances du pipeline   %d\n", members)
	if members != 1 {
		// Said here rather than discovered afterwards. A second instance left
		// running shares the partitions and halves what a per-instance figure
		// attributes to the first — which is how a ×2,4 improvement once
		// read as ×1,06 and was nearly published as "no effect".
		fmt.Printf("   ⚠ les chiffres par instance ci-dessous sont faux : %d instances se partagent les partitions\n", members)
	}
	fmt.Println()

	if events == 0 {
		return nil
	}

	lat, err := b.pipelineLatency(ctx, events, rate)
	if err != nil {
		return err
	}
	if lat.n() == 0 {
		fmt.Printf("   latence du pipeline     aucun événement retrouvé sur le sujet enrichi\n")
		return nil
	}

	p50, p95 := lat.quantile(0.50), lat.quantile(0.95)
	fmt.Printf("   latence du pipeline     p50 %s · p95 %s   sur %d événements à %d ev/s   %s\n",
		ms(p50), ms(p95), lat.n(), rate, verdictAgainst(p95, pipelineLatencyBudget))
	fmt.Printf("     du moment où le collecteur accepte l'événement à celui où il est\n")
	fmt.Printf("     lisible sur le sujet enrichi — collecteur, Kafka, pipeline compris.\n")
	fmt.Printf("     Envoyés espacés, pour mesurer la traversée et non la file d'attente\n\n")

	// The enrichment step is not instrumented separately, so this is the only
	// honest thing to say about US-CTI-ENR-002: the whole chain bounds it from
	// above. Reported as a bound, and labelled as one.
	fmt.Printf("   enrichissement          < %s   %s\n", ms(p95), verdictAgainst(p95, enrichmentBudget))
	fmt.Printf("     borne supérieure, pas une mesure : l'enrichissement n'écrit pas\n")
	fmt.Printf("     d'horodatage, donc ce qui le borne est la chaîne entière ci-dessus.\n")
	fmt.Printf("     Un chiffre exact demanderait un champ enriched_at et sa migration,\n")
	fmt.Printf("     ce qui ne se justifie que si la borne cesse de suffire.\n\n")
	return nil
}

// reportRecovery states what backlog the platform can absorb inside the
// recovery budget, from a drain rate measured now.
//
// Stated as a capacity rather than timed as an outage: stopping a service and
// restarting it is an operator's procedure, not a benchmark's, and the figure
// that an operator actually needs is "how far behind can I fall and still be
// back inside a quarter of an hour".
func (b *bench) reportRecovery(ctx context.Context, backlog int) error {
	rate, err := b.drainRate(ctx, backlog)
	if err != nil {
		return err
	}
	if rate <= 0 {
		fmt.Printf("   reprise                 le retard ne diminue pas — rien à conclure\n")
		return nil
	}
	absorbable := int64(rate * recoveryBudget.Seconds())
	fmt.Printf("   reprise                 %.0f ev/s drainés → %d événements rattrapés en %s\n",
		rate, absorbable, recoveryBudget)
	fmt.Printf("     une interruption est donc tenue dans le budget tant que le retard\n")
	fmt.Printf("     accumulé reste sous ce nombre, à ce nombre d'instances\n\n")
	return nil
}

// pipelineLatency sends events through the collector and reads them back off
// the enriched topic, timing the trip.
//
// It reads from the end offsets taken before sending, so only this run's
// events are timed; and it times against each event's own ingested_at, set by
// the collector, so a slow send does not inflate the figure.
func (b *bench) pipelineLatency(ctx context.Context, events, rate int) (*sample, error) {
	parts, err := b.partitionsOf(ctx, event.TopicEnriched)
	if err != nil {
		return nil, fmt.Errorf("partitions du sujet enrichi: %w", err)
	}
	starts, err := b.endsPerPartition(ctx, event.TopicEnriched, parts)
	if err != nil {
		return nil, fmt.Errorf("offsets de départ: %w", err)
	}

	// Every partition is read at once. Read one after another and the first
	// one's wait eats the whole budget while the rest stay untouched: a six
	// way partitioned topic then yields a sixth of the events and a figure
	// taken on that sixth. This measurement reported 34 of 200 exactly that
	// way before the reads were made concurrent.
	out := &sample{}
	var mu sync.Mutex
	budget := time.Duration(events)*time.Second/time.Duration(rate) + 60*time.Second
	readCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	var wg sync.WaitGroup
	for _, p := range parts {
		wg.Add(1)
		go func(partition int, from int64) {
			defer wg.Done()
			b.readSince(readCtx, event.TopicEnriched, partition, from, &mu, out)
		}(p, starts[p])
	}

	// Stop every reader as soon as the whole batch is accounted for, rather
	// than holding the budget open for events that have all arrived.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-readCtx.Done():
				return
			case <-time.After(200 * time.Millisecond):
				mu.Lock()
				n := out.n()
				mu.Unlock()
				if n >= events {
					cancel()
					return
				}
			}
		}
	}()
	// Sent one at a time, spaced, and only once the readers are listening.
	//
	// Sent as one burst instead, every event after the first waits behind the
	// ones in front of it: two hundred events at 3,4 ms each is a queue
	// seven tenths of a second deep, and the figure that comes out is how
	// long a burst takes to drain, not how long an event takes to cross the
	// platform. The first run of this measurement read 784 ms that way.
	// Spacing them below the rate one instance sustains keeps the queue
	// empty, so what is left is the chain itself.
	interval := time.Second / time.Duration(rate)
	for i := 0; i < events; i++ {
		if _, _, failed, err := b.sendBatch(ctx, 1); err != nil {
			cancel()
			return nil, fmt.Errorf("envoi: %w", err)
		} else if failed > 0 {
			cancel()
			return nil, fmt.Errorf("événement refusé par le collecteur")
		}
		select {
		case <-ctx.Done():
			cancel()
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}

	wg.Wait()
	cancel()
	<-done
	return out, nil
}

// readSince reads one partition from an offset and times this run's events.
// It returns when the context ends — the caller cancels once the batch is in.
func (b *bench) readSince(ctx context.Context, topic string, partition int, from int64, mu *sync.Mutex, out *sample) {
	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:   b.brokers,
		Topic:     topic,
		Partition: partition,
		MinBytes:  1,
		MaxBytes:  10 << 20,
	})
	defer r.Close()
	if err := r.SetOffset(from); err != nil {
		return
	}

	for {
		m, err := r.ReadMessage(ctx)
		if err != nil {
			return
		}
		var e event.NormalizedEvent
		if err := json.Unmarshal(m.Value, &e); err != nil {
			continue
		}
		if e.Source != benchSource || e.IngestedAt.IsZero() {
			continue
		}
		mu.Lock()
		out.add(time.Since(e.IngestedAt))
		mu.Unlock()
	}
}

// endsPerPartition is the last offset of each partition, kept per partition
// rather than summed: a reader is positioned on one partition at a time.
func (b *bench) endsPerPartition(ctx context.Context, topic string, parts []int) (map[int]int64, error) {
	ends := make(map[int]int64, len(parts))
	for _, p := range parts {
		conn, err := kafka.DialLeader(ctx, "tcp", b.brokers[0], topic, p)
		if err != nil {
			return nil, err
		}
		last, err := conn.ReadLastOffset()
		conn.Close()
		if err != nil {
			return nil, err
		}
		ends[p] = last
	}
	return ends, nil
}

// pipelineInstances counts the live members of the pipeline's consumer group.
//
// The bench reports this because not knowing it invalidates every per-instance
// figure it prints, and because nothing else on the machine says it plainly.
func (b *bench) pipelineInstances(ctx context.Context) (int, error) {
	c := &kafka.Client{Addr: kafka.TCP(b.brokers[0])}
	res, err := c.DescribeGroups(ctx, &kafka.DescribeGroupsRequest{GroupIDs: []string{pipelineGroup}})
	if err != nil {
		return 0, err
	}
	for _, g := range res.Groups {
		if g.GroupID == pipelineGroup {
			return len(g.Members), nil
		}
	}
	return 0, nil
}

// drainRate fills the normalized topic and returns the median rate at which
// the slower stage works it off.
func (b *bench) drainRate(ctx context.Context, backlog int) (float64, error) {
	if backlog > 0 {
		if _, err := b.fillNormalized(ctx, backlog); err != nil {
			return 0, err
		}
	}
	prev, err := b.engineLag(ctx)
	if err != nil {
		return 0, err
	}
	if prev <= engineIdleLag {
		return 0, nil
	}
	rates := make([]float64, 0, 30)
	for i := 0; i < 30; i++ {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(time.Second):
		}
		now, err := b.engineLag(ctx)
		if err != nil {
			return 0, err
		}
		rates = append(rates, float64(prev-now))
		prev = now
		if now <= engineIdleLag {
			break
		}
	}
	return median(rates), nil
}

func verdictAgainst(got, budget time.Duration) string {
	if got <= budget {
		return fmt.Sprintf("\033[32m✓\033[0m tenu (budget %s)", budget)
	}
	return fmt.Sprintf("\033[31m✗\033[0m dépassé (budget %s)", budget)
}
