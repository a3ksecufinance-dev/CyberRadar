package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/url"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cyberradar/platform/internal/pkg/event"
	"github.com/segmentio/kafka-go"
)

// ─── 1. Ingestion throughput ─────────────────────────────────────────────────

// The plan asks for "events per second before the dead-letter queue fills".
// Taken literally that is the rate at which the platform starts losing events,
// which is a number nobody should operate at. What an operator needs is the
// rate the platform *sustains*: every event accepted, none dead-lettered, and
// the pipeline keeping up rather than falling behind a queue it will never
// drain.
//
// So the measurement is a ladder. Each rung offers a fixed rate for a fixed
// window and then asks three questions of the platform itself, not of the
// client's own counters:
//
//   - did the collector accept every event (published == received, failed 0);
//   - did the dead-letter topic grow;
//   - did the normalized topic advance by what was sent, once given time to
//     settle — a collector that answers 200 and publishes nowhere would pass
//     the first two questions.
//
// The reported figure is the highest rung that answered yes three times.

type rung struct {
	Offered   int // events per second asked for
	Achieved  float64
	Accepted  int
	Published int
	Failed    int
	DLQGrowth int64
	Written   int64 // how far the normalized topic advanced — the collector's work
	Drained   int64 // how far the pipeline committed — the platform's work
	Sent      int
	OK        bool
	Note      string
}

const ingestBatch = 500 // the endpoint accepts up to 1000; half leaves headroom

func (b *bench) throughput(ctx context.Context) ([]rung, error) {
	var out []rung
	for _, offered := range b.ladder {
		r, err := b.oneRung(ctx, offered)
		if err != nil {
			return out, err
		}
		out = append(out, r)
		fmt.Printf("   %6d ev/s offerts → %8.0f ev/s atteints  %s\n", r.Offered, r.Achieved, r.verdict())
		if !r.OK {
			// Past the first rung it cannot hold, the rungs above only
			// measure how much worse it gets.
			break
		}
	}
	return out, nil
}

func (r rung) verdict() string {
	if r.OK {
		return "✓ tenu"
	}
	if r.Note != "" {
		return "✗ " + r.Note
	}
	return "✗"
}

func (b *bench) oneRung(ctx context.Context, offered int) (rung, error) {
	r := rung{Offered: offered}

	before, err := b.topicEnds(ctx)
	if err != nil {
		return r, err
	}
	readBefore, err := b.consumed(ctx)
	if err != nil {
		return r, err
	}

	batches := (offered * int(b.window.Seconds())) / ingestBatch
	if batches < 1 {
		batches = 1
	}
	r.Sent = batches * ingestBatch

	// The offered rate is paced, not hammered: a client that sends as fast as
	// it can measures the client, and what is wanted is the platform's
	// behaviour at a rate an operator would configure.
	interval := b.window / time.Duration(batches)

	var accepted, published, failed int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, b.concurrency)
	start := time.Now()

	for i := 0; i < batches; i++ {
		select {
		case <-ctx.Done():
			return r, ctx.Err()
		case <-time.After(time.Until(start.Add(time.Duration(i) * interval))):
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			got, pub, fail, err := b.sendBatch(ctx, ingestBatch)
			if err != nil {
				atomic.AddInt64(&failed, int64(ingestBatch))
				return
			}
			atomic.AddInt64(&accepted, int64(got))
			atomic.AddInt64(&published, int64(pub))
			atomic.AddInt64(&failed, int64(fail))
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	r.Accepted, r.Published, r.Failed = int(accepted), int(published), int(failed)
	r.Achieved = float64(r.Accepted) / elapsed.Seconds()

	// Let the pipeline drain before asking whether it kept up.
	select {
	case <-ctx.Done():
		return r, ctx.Err()
	case <-time.After(b.settle):
	}

	after, err := b.topicEnds(ctx)
	if err != nil {
		return r, err
	}
	readAfter, err := b.consumed(ctx)
	if err != nil {
		return r, err
	}
	r.DLQGrowth = after[event.TopicDLQ] - before[event.TopicDLQ]
	r.Written = after[event.TopicNormalized] - before[event.TopicNormalized]
	r.Drained = readAfter - readBefore

	classify(&r, b.settle)
	return r, nil
}

// classify decides whether a rung held, and says why when it did not.
//
// Four questions, asked of the platform rather than of the sender's own
// counters, in the order that makes the answer useful: a collector that
// refused events, one that accepted them and published nowhere, a
// dead-letter queue that grew, and a pipeline that fell behind. Only the last
// of these is a rate the platform could reach with more time; the other three
// mean events were lost.
func classify(r *rung, settle time.Duration) bool {
	switch {
	case r.Failed > 0:
		r.Note = fmt.Sprintf("%d événements refusés", r.Failed)
	case r.Published < r.Sent:
		r.Note = fmt.Sprintf("%d sur %d publiés", r.Published, r.Sent)
	case r.DLQGrowth > 0:
		r.Note = fmt.Sprintf("%d en file de rebut", r.DLQGrowth)
	case r.Drained < int64(r.Sent):
		r.Note = fmt.Sprintf("le pipeline n'a consommé que %d sur %d en %s", r.Drained, r.Sent, settle)
	default:
		r.OK = true
	}
	return r.OK
}

func (b *bench) sendBatch(ctx context.Context, n int) (received, published, failed int, err error) {
	now := time.Now().UTC()
	events := make([]string, 0, n)
	for i := 0; i < n; i++ {
		events = append(events, b.syntheticEvent(now))
	}
	var res struct {
		Received  int      `json:"received"`
		Published int      `json:"published"`
		Failed    int      `json:"failed"`
		Errors    []string `json:"errors"`
	}
	err = b.connector.post(ctx, "collector", "/api/v1/events/ingest", map[string]any{
		"connector_id": benchConnectorID,
		"source":       "crp-bench",
		"source_type":  "application",
		"format":       "json",
		"events":       events,
	}, &res)
	if err != nil {
		return 0, 0, 0, err
	}
	return res.Received, res.Published, res.Failed, nil
}

// syntheticEvent is an ordinary authentication line — the shape the normaliser
// and the enrichment actually walk. A payload chosen to be cheap would measure
// the parser rather than the platform.
func (b *bench) syntheticEvent(now time.Time) string {
	raw, _ := json.Marshal(map[string]any{
		"timestamp":  now.Format(time.RFC3339Nano),
		"action":     "user_login",
		"category":   "authentication",
		"severity":   "LOW",
		"outcome":    "success",
		"user_name":  fmt.Sprintf("bench%05d", rand.Intn(20000)),
		"hostname":   fmt.Sprintf("bench-host-%03d", rand.Intn(200)),
		"asset_type": "workstation",
		"src_ip":     fmt.Sprintf("10.90.%d.%d", rand.Intn(256), rand.Intn(256)),
		"dst_ip":     "10.20.1.11",
		"dst_port":   443,
		"risk_score": 1.0,
	})
	return string(raw)
}

// consumed is how far the enrichment pipeline has actually read, taken from
// its committed offset rather than from the end of the topic.
//
// The difference is the whole verdict. The collector writes to the normalized
// topic, so that topic's end offset advances the moment the collector accepts
// a batch — measuring it proves only that the collector answered. The first
// ladder this bench ran did exactly that and called five thousand seven
// hundred events a second "sustained", while the pipeline fell half a million
// events behind and detection stopped working for a quarter of an hour.
func (b *bench) consumed(ctx context.Context) (int64, error) {
	return b.committedAcross(ctx, pipelineGroup, event.TopicNormalized)
}

// partitionsOf lists a topic's partition numbers.
//
// Every offset this bench reads has to be summed over them. Reading partition
// zero alone was right while every topic had one partition and silently wrong
// the moment they had six: the first ladder run after partitioning reported
// that the pipeline had consumed 667 of 4000 events, which is 4000/6 — a
// perfect measurement of one sixth of the work, and a regression that never
// happened.
func (b *bench) partitionsOf(ctx context.Context, topic string) ([]int, error) {
	conn, err := kafka.DialContext(ctx, "tcp", b.brokers[0])
	if err != nil {
		return nil, fmt.Errorf("reach the broker: %w", err)
	}
	parts, err := conn.ReadPartitions(topic)
	cerr := conn.Close()
	if err != nil {
		return nil, fmt.Errorf("read the partitions of %s: %w", topic, err)
	}
	if cerr != nil {
		return nil, fmt.Errorf("close the broker connection: %w", cerr)
	}
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		out = append(out, p.ID)
	}
	sort.Ints(out)
	return out, nil
}

// endAcross is how much has been written to a topic, over every partition.
func (b *bench) endAcross(ctx context.Context, topic string) (int64, error) {
	ids, err := b.partitionsOf(ctx, topic)
	if err != nil {
		// A topic nothing has written to yet does not exist, and that is an
		// offset of zero rather than a failure — the dead-letter topic is in
		// that state on a healthy platform.
		return 0, nil
	}
	var total int64
	for _, id := range ids {
		conn, err := kafka.DialLeader(ctx, "tcp", b.brokers[0], topic, id)
		if err != nil {
			continue
		}
		last, err := conn.ReadLastOffset()
		cerr := conn.Close()
		if err != nil {
			return 0, fmt.Errorf("read the end of %s[%d]: %w", topic, id, err)
		}
		if cerr != nil {
			return 0, fmt.Errorf("close the connection to %s[%d]: %w", topic, id, cerr)
		}
		total += last
	}
	return total, nil
}

// committedAcross is how far a group has read a topic, over every partition.
func (b *bench) committedAcross(ctx context.Context, group, topic string) (int64, error) {
	ids, err := b.partitionsOf(ctx, topic)
	if err != nil {
		return 0, nil
	}
	client := &kafka.Client{Addr: kafka.TCP(b.brokers[0])}
	res, err := client.OffsetFetch(ctx, &kafka.OffsetFetchRequest{
		GroupID: group,
		Topics:  map[string][]int{topic: ids},
	})
	if err != nil {
		return 0, fmt.Errorf("ask what %s has committed on %s: %w", group, topic, err)
	}
	var total int64
	for _, parts := range res.Topics {
		for _, pt := range parts {
			if pt.CommittedOffset > 0 {
				total += pt.CommittedOffset
			}
		}
	}
	return total, nil
}

const pipelineGroup = "crp-pipeline"

// topicEnds reads how much has been written to the topics the verdict rests
// on, from the broker rather than from anything the platform reports about
// itself, and over every partition.
func (b *bench) topicEnds(ctx context.Context) (map[string]int64, error) {
	out := map[string]int64{}
	for _, topic := range []string{event.TopicNormalized, event.TopicDLQ} {
		end, err := b.endAcross(ctx, topic)
		if err != nil {
			return nil, err
		}
		out[topic] = end
	}
	return out, nil
}

// ─── 2. API latency ──────────────────────────────────────────────────────────

// Measured at the client, which is where a user is. The server's own
// histogram is read afterwards as a cross-check: if the two disagree by much,
// the difference is the hop, and saying so is more useful than picking one.

// warm runs a short unmeasured pass. Without it the first measurement of a
// session reads five times worse than the second, and the figure depends on
// whether the operator happened to run the command twice: connections are not
// yet pooled, the Go runtime has not grown its heap, and PostgreSQL has
// nothing in its cache. None of that is what the question is about.
func (b *bench) warm(ctx context.Context, path string) {
	quiet := b.concurrency
	if quiet > 4 {
		b.concurrency = 4
	}
	_, _ = b.latency(ctx, path, 60) //nolint:errcheck // a failed warm-up shows up in the measurement
	b.concurrency = quiet
}

func (b *bench) latency(ctx context.Context, path string, requests int) (*sample, error) {
	s := &sample{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var failures int64
	sem := make(chan struct{}, b.concurrency)

	for i := 0; i < requests; i++ {
		select {
		case <-ctx.Done():
			return s, ctx.Err()
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			start := time.Now()
			var discard json.RawMessage
			err := b.admin.get(ctx, "asset", path, url.Values{"limit": {"50"}}, &discard)
			took := time.Since(start)
			if err != nil {
				atomic.AddInt64(&failures, 1)
				return
			}
			mu.Lock()
			s.add(took)
			mu.Unlock()
		}()
	}
	wg.Wait()
	if failures > 0 {
		return s, fmt.Errorf("%d requêtes sur %d ont échoué", failures, requests)
	}
	return s, nil
}

// ─── 3. Detection time ───────────────────────────────────────────────────────

// From the moment the event is handed to the collector to the moment the alert
// exists, read back through the API — the whole chain, not a segment of it:
// collector, Kafka, pipeline, enrichment, rule engine, and the write the
// interface reads.
//
// Each round uses a value nothing else carries, so the alert found is the
// alert this round caused. Counting alerts instead would attribute someone
// else's to this measurement.

// engineLag is how far the rule engine is behind the enriched topic.
//
// It exists because a detection figure taken while the engine has a backlog
// measures the backlog. The first full run of this bench did exactly that:
// the throughput ladder left a hundred and sixty thousand events on the
// topic, every detection round then timed out at ninety seconds, and the
// report would have said the engine raised no alert — when it was simply
// still reading, minutes behind, and the alerts arrived later.
func (b *bench) engineLag(ctx context.Context) (int64, error) {
	// Both stages, and the larger of the two. Watching only the rule engine
	// reported a backlog of zero while the pipeline was half a million events
	// behind: the engine had read everything it had been given, because the
	// stage in front of it had given it nothing.
	pipelineLag, err := b.stageLag(ctx, pipelineGroup, event.TopicNormalized)
	if err != nil {
		return 0, err
	}
	engineLag, err := b.stageLag(ctx, "crp-siem-rule-engine", event.TopicEnriched)
	if err != nil {
		return 0, err
	}
	if pipelineLag > engineLag {
		return pipelineLag, nil
	}
	return engineLag, nil
}

func (b *bench) stageLag(ctx context.Context, group, topic string) (int64, error) {
	end, err := b.endAcross(ctx, topic)
	if err != nil {
		return 0, err
	}
	committed, err := b.committedAcross(ctx, group, topic)
	if err != nil {
		return 0, err
	}
	lag := end - committed
	if lag < 0 {
		lag = 0
	}
	return lag, nil
}

// awaitIdleEngine refuses to measure detection while the engine is behind,
// and says how far behind rather than timing out round after round.
func (b *bench) awaitIdleEngine(ctx context.Context) error {
	deadline := time.Now().Add(b.drainDeadline)
	var last int64
	for {
		lag, err := b.engineLag(ctx)
		if err != nil {
			return err
		}
		if lag <= engineIdleLag {
			return nil
		}
		if last == 0 {
			fmt.Printf("   le moteur de règles a %d événements de retard — j'attends qu'il rattrape\n", lag)
		}
		last = lag
		if time.Now().After(deadline) {
			return fmt.Errorf("le moteur de règles est encore à %d événements de retard après %s ; "+
				"une mesure de détection prise maintenant mesurerait cet arriéré, pas la détection",
				lag, b.drainDeadline)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// engineIdleLag is the backlog below which the engine counts as caught up. Not
// zero: the topic receives the platform's own traffic, so a handful of events
// in flight is the normal resting state rather than a queue.
const engineIdleLag = 50

func (b *bench) detection(ctx context.Context, rounds int) (*sample, error) {
	if err := b.awaitIdleEngine(ctx); err != nil {
		return nil, err
	}
	s := &sample{}
	for i := 0; i < rounds; i++ {
		select {
		case <-ctx.Done():
			return s, ctx.Err()
		default:
		}
		took, err := b.oneDetection(ctx, i)
		if err != nil {
			return s, err
		}
		if took > 0 {
			s.add(took)
		}
		fmt.Printf("   tour %2d/%d  %s\n", i+1, rounds, ms(took))
	}
	return s, nil
}

func (b *bench) oneDetection(ctx context.Context, round int) (time.Duration, error) {
	// A source address of its own per round.
	//
	// The engine keys an alert on the event's entity, and entityFrom prefers
	// the user, then the asset, then the source address — the normaliser does
	// not fill a user id from a bare user name, so these events are keyed on
	// their address. Deduplication then works on (rule, entity, tenant) for
	// dedup_window_s, 300 seconds by default: reusing one address made the
	// first round fire and every later one wait for a suppressed alert.
	//
	// The address is also what the brute-force rule groups by, so a fresh one
	// per round gives each round its own threshold counter as well.
	source := b.detectSource(round)
	now := time.Now().UTC()

	events := make([]string, 0, 32)
	for i := 0; i < 32; i++ {
		raw, _ := json.Marshal(map[string]any{
			"timestamp":  now.Add(time.Duration(-i) * time.Second).Format(time.RFC3339Nano),
			"action":     "user_login",
			"category":   "authentication",
			"severity":   "MEDIUM",
			"outcome":    "failure",
			"user_name":  fmt.Sprintf("bench-detect-%d", round),
			"hostname":   "web-ebank-01",
			"asset_type": "server",
			"src_ip":     source,
			"dst_ip":     "10.20.1.11",
			"dst_port":   443,
			"risk_score": 5.0,
		})
		events = append(events, string(raw))
	}

	// The window the alert is looked for in opens a little before the send,
	// so a clock that differs by a few hundred milliseconds between this
	// process and the engine cannot hide the alert this round caused.
	since := time.Now().UTC().Add(-5 * time.Second)
	start := time.Now()

	var res struct {
		Published int `json:"published"`
		Failed    int `json:"failed"`
	}
	if err := b.connector.post(ctx, "collector", "/api/v1/events/ingest", map[string]any{
		"connector_id": benchConnectorID,
		"source":       "crp-bench",
		"source_type":  "application",
		"format":       "json",
		"events":       events,
	}, &res); err != nil {
		return 0, fmt.Errorf("tour %d: %w", round, err)
	}
	if res.Failed > 0 {
		return 0, fmt.Errorf("tour %d: %d événements refusés", round, res.Failed)
	}

	deadline := time.Now().Add(b.detectDeadline)
	for time.Now().Before(deadline) {
		found, err := b.alertFor(ctx, source, since)
		if err != nil {
			return 0, err
		}
		if found {
			return time.Since(start), nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
	return 0, fmt.Errorf("tour %d: aucune alerte portant %s en %s — le moteur n'en a pas levé",
		round, source, b.detectDeadline)
}

// alertFor asks the API the question the interface asks: what alerts exist
// since this moment. The entity is matched exactly rather than by searching
// the row for a string — an earlier version passed a "search" parameter the
// endpoint does not have, so it was dropped on the floor and the match was an
// accident.
// detectSource is a source address unique to this round of this run.
//
// Deriving it from the round alone made two runs inside the dedup window
// collide: the second run's first round reused the first run's address, the
// engine recognised the alert as a duplicate and suppressed it, and the bench
// reported that no alert had been raised — blaming the platform for its own
// repetition. The run's start time salts the address so that a measurement
// taken a minute after another still measures something.
func (b *bench) detectSource(round int) string {
	n := b.runSalt + round
	return fmt.Sprintf("10.91.%d.%d", (n/250)%250+1, n%250+1)
}

func (b *bench) alertFor(ctx context.Context, entity string, since time.Time) (bool, error) {
	var raw json.RawMessage
	err := b.admin.get(ctx, "siem", "/api/v1/siem/alerts", url.Values{
		"limit":       {"50"},
		"entity_type": {"ip"},
		"from":        {since.Format(time.RFC3339)},
	}, &raw)
	if err != nil {
		return false, err
	}
	rows, err := decodeRows(raw)
	if err != nil {
		return false, err
	}
	for _, row := range rows {
		if value, ok := row["entity_value"].(string); ok && value == entity {
			return true, nil
		}
	}
	return false, nil
}

// reportLag watches the backlog and reports how fast it shrinks.
//
// A ladder measures what the platform accepts; this measures what it
// processes, which is the smaller and more useful of the two. With no sender
// competing for the machine, the rate a backlog drains at is the pipeline's
// own throughput.
func (b *bench) reportLag(ctx context.Context) error {
	first, err := b.engineLag(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("   retard initial   %d événements\n", first)
	if first <= engineIdleLag {
		fmt.Printf("   le pipeline est à jour ; rien à drainer\n")
		return nil
	}

	const observe = 60 * time.Second
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(observe):
	}

	second, err := b.engineLag(ctx)
	if err != nil {
		return err
	}
	drained := first - second
	fmt.Printf("   retard après %s  %d événements\n", observe, second)
	if drained <= 0 {
		fmt.Printf("   le retard ne diminue pas — le pipeline n'avance plus, ou reçoit autant qu'il traite\n")
		return nil
	}
	rate := float64(drained) / observe.Seconds()
	fmt.Printf("   drainage         %.0f ev/s  (%d événements en %s)\n", rate, drained, observe)
	if second > 0 {
		fmt.Printf("   à ce rythme       %s pour rattraper\n",
			time.Duration(float64(second)/rate*float64(time.Second)).Round(time.Second))
	}
	return nil
}
