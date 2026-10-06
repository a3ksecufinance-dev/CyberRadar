package cache

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cyberradar/platform/internal/pkg/observe"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

// A Window counts occurrences inside a sliding time window, shared by every
// replica of a service.
//
// It replaces the per-process maps that SIEM and UEBA used to count with. Those
// were correct for exactly one replica: with two, an attacker making four
// authentication failures against each of them stayed under a five-failure
// threshold that a single counter would have tripped, and every count was lost
// on restart. Detection thresholds are a security control, so they cannot be
// process-local.
//
// Redis sorted sets hold one member per occurrence, scored by timestamp:
// expiring the window is a range delete by score, and counting is ZCARD.
const (
	// localSweepInterval bounds how often the fallback map is compacted. The
	// maps this replaces never dropped a key, so an entity seen once kept its
	// slice forever.
	localSweepInterval = time.Minute

	// maxLocalKeys forces a sweep before the fallback map can grow without
	// bound during a long Redis outage.
	maxLocalKeys = 100_000

	// expirySlack keeps a key alive a little past its window so a burst that
	// straddles the boundary is not undercounted by the key expiring first.
	expirySlack = 10 * time.Second

	// degradedLogInterval throttles the Redis-unavailable message. The failure
	// is per event, and a busy ingestion path would otherwise turn one Redis
	// outage into a logging outage. The metric carries the exact rate; the log
	// only has to carry the reason.
	degradedLogInterval = 30 * time.Second
)

// Source says where a count came from. A count served FromMemory is local to
// one replica and therefore lower than the truth whenever more than one replica
// is running: it is a degraded reading, not a normal one.
type Source string

const (
	SourceRedis  Source = "redis"
	SourceMemory Source = "memory"
)

var (
	windowFallbacks = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "crp_sliding_window_fallback_total",
		Help: "Sliding-window counts served from process memory instead of Redis, so covering one replica only.",
	}, []string{"window"})

	windowLocalKeys = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "crp_sliding_window_local_keys",
		Help: "Keys held in the in-process fallback of a sliding window.",
	}, []string{"window"})
)

func init() { observe.MustRegister(windowFallbacks, windowLocalKeys) }

// bucket is one key's worth of the in-process fallback.
type bucket struct {
	times   []time.Time
	expires time.Time
}

// Window is a named sliding-window counter. It is safe for concurrent use.
type Window struct {
	rdb    *redis.Client
	name   string
	logger zerolog.Logger

	mu        sync.Mutex
	local     map[string]bucket
	lastSweep time.Time

	// lastDegradedLog is a Unix nanosecond timestamp, read and written without
	// mu so that a Redis error never serialises the counting path.
	lastDegradedLog atomic.Int64
}

// NewWindow returns a counter named after what it counts; the name prefixes
// every Redis key and labels the metrics.
//
// A nil client is allowed and yields a counter that only ever counts in
// process. That configuration is announced at warning level rather than
// accepted quietly, because it silently weakens every threshold built on it.
func NewWindow(c *Client, name string, logger zerolog.Logger) *Window {
	w := &Window{
		name:      name,
		logger:    logger,
		local:     make(map[string]bucket),
		lastSweep: time.Now().UTC(),
	}

	// Create both series up front so a healthy window reports zero rather than
	// nothing: an alert on an absent series never fires.
	windowFallbacks.WithLabelValues(name)
	windowLocalKeys.WithLabelValues(name).Set(0)

	if c != nil {
		w.rdb = c.rdb
	} else {
		logger.Warn().
			Str("window", name).
			Msg("sliding_window_without_redis_thresholds_are_per_replica")
	}
	return w
}

// Count records one occurrence of key at the current time and returns how many
// occurrences fall inside window, the new one included.
//
// It never fails. A Redis error degrades the count to this process rather than
// returning an error the caller might treat as "no events": a detection engine
// that stops counting when its cache blinks is a detection engine that misses
// the attack. The returned Source says which happened, and every count that did
// not go through Redis is added to crp_sliding_window_fallback_total.
func (w *Window) Count(ctx context.Context, key string, window time.Duration) (int, Source) {
	now := time.Now().UTC()

	if w.rdb != nil {
		n, err := w.countShared(ctx, now, key, window)
		if err == nil {
			return n, SourceRedis
		}
		w.logDegraded(now, err)
	}

	// Counted for the outage above and for a window built without Redis at all:
	// both leave thresholds per-replica, and one alert should catch either.
	windowFallbacks.WithLabelValues(w.name).Inc()
	return w.countLocal(now, key, window), SourceMemory
}

// logDegraded reports a Redis failure at most once per degradedLogInterval.
func (w *Window) logDegraded(now time.Time, cause error) {
	last := w.lastDegradedLog.Load()
	if now.UnixNano()-last < int64(degradedLogInterval) {
		return
	}
	if !w.lastDegradedLog.CompareAndSwap(last, now.UnixNano()) {
		return // another goroutine is logging this one
	}
	w.logger.Error().Err(cause).
		Str("window", w.name).
		Dur("throttled_for", degradedLogInterval).
		Msg("sliding_window_redis_unavailable_counting_in_process")
}

// countShared runs the expire/add/count/renew sequence as one transaction, so
// two replicas counting the same entity cannot interleave into a lost update.
func (w *Window) countShared(ctx context.Context, now time.Time, key string, window time.Duration) (int, error) {
	k := w.name + ":" + key

	// Milliseconds, not nanoseconds: sorted-set scores are float64, which stops
	// representing consecutive integers above 2^53 — a nanosecond epoch passed
	// that in 1970 + 104 days, so nanosecond scores would round and two events
	// could land on the same instant. Milliseconds have headroom until 2^53 ms,
	// year 287396. Uniqueness comes from the member, not the score.
	cutoff := strconv.FormatInt(now.Add(-window).UnixMilli(), 10)

	pipe := w.rdb.TxPipeline()
	pipe.ZRemRangeByScore(ctx, k, "-inf", cutoff)
	pipe.ZAdd(ctx, k, redis.Z{Score: float64(now.UnixMilli()), Member: uuid.NewString()})
	card := pipe.ZCard(ctx, k)
	pipe.PExpire(ctx, k, window+expirySlack)

	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}
	return int(card.Val()), nil
}

// countLocal is the fallback. It matches countShared's semantics — an
// occurrence exactly on the cutoff has left the window — so a threshold does
// not shift when Redis goes away.
func (w *Window) countLocal(now time.Time, key string, window time.Duration) int {
	w.mu.Lock()
	defer w.mu.Unlock()

	if now.Sub(w.lastSweep) >= localSweepInterval || len(w.local) > maxLocalKeys {
		w.sweepLocked(now)
	}

	cutoff := now.Add(-window)
	b := w.local[key]
	fresh := b.times[:0]
	for _, ts := range b.times {
		if ts.After(cutoff) {
			fresh = append(fresh, ts)
		}
	}
	fresh = append(fresh, now)
	w.local[key] = bucket{times: fresh, expires: now.Add(window)}

	windowLocalKeys.WithLabelValues(w.name).Set(float64(len(w.local)))
	return len(fresh)
}

// sweepLocked drops keys whose whole window has elapsed. Callers hold w.mu.
func (w *Window) sweepLocked(now time.Time) {
	for k, b := range w.local {
		if !b.expires.After(now) {
			delete(w.local, k)
		}
	}
	w.lastSweep = now
	windowLocalKeys.WithLabelValues(w.name).Set(float64(len(w.local)))
}
