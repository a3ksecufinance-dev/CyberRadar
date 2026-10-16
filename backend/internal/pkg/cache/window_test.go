package cache

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cyberradar/platform/internal/pkg/observe"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

// ─── Fallback (no Redis) ──────────────────────────────────────────────────────

func localWindow(t *testing.T) *Window {
	t.Helper()
	return NewWindow(nil, "test_"+t.Name(), zerolog.Nop())
}

func TestLocalCountRisesWithEachOccurrence(t *testing.T) {
	w := localWindow(t)
	for want := 1; want <= 5; want++ {
		if got, src := w.Count(context.Background(), "k", time.Minute); got != want {
			t.Errorf("occurrence %d: count = %d (%s), want %d", want, got, src, want)
		}
	}
}

func TestLocalCountIsReportedAsDegraded(t *testing.T) {
	// A caller must be able to tell a shared count from a per-replica one,
	// because the second is an undercount whenever replicas > 1.
	if _, src := localWindow(t).Count(context.Background(), "k", time.Minute); src != SourceMemory {
		t.Errorf("source = %s, want %s", src, SourceMemory)
	}
}

func TestLocalKeysAreIndependent(t *testing.T) {
	w := localWindow(t)
	w.Count(context.Background(), "a", time.Minute)
	w.Count(context.Background(), "a", time.Minute)
	if got, _ := w.Count(context.Background(), "b", time.Minute); got != 1 {
		t.Errorf("count for an untouched key = %d, want 1", got)
	}
}

func TestLocalOccurrencesLeaveTheWindow(t *testing.T) {
	w := localWindow(t)
	const window = 40 * time.Millisecond

	w.Count(context.Background(), "k", window)
	w.Count(context.Background(), "k", window)
	time.Sleep(2 * window)

	if got, _ := w.Count(context.Background(), "k", window); got != 1 {
		t.Errorf("count after the window elapsed = %d, want 1 — old occurrences are not expiring", got)
	}
}

func TestLocalSweepDropsKeysNobodyTouchesAgain(t *testing.T) {
	// The maps this replaced never deleted a key: one event from an entity
	// pinned its slice for the life of the process.
	w := localWindow(t)
	for i := 0; i < 50; i++ {
		w.Count(context.Background(), fmt.Sprintf("entity-%d", i), time.Millisecond)
	}
	if len(w.local) != 50 {
		t.Fatalf("local keys = %d, want 50", len(w.local))
	}

	w.mu.Lock()
	w.sweepLocked(time.Now().UTC().Add(time.Hour))
	remaining := len(w.local)
	w.mu.Unlock()

	if remaining != 0 {
		t.Errorf("%d keys survived a sweep past their window, want 0", remaining)
	}
}

func TestLocalCountIsSafeUnderConcurrency(t *testing.T) {
	w := localWindow(t)
	const goroutines, each = 8, 50

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				w.Count(context.Background(), "shared", time.Minute)
			}
		}()
	}
	wg.Wait()

	if got, _ := w.Count(context.Background(), "shared", time.Minute); got != goroutines*each+1 {
		t.Errorf("count = %d, want %d", got, goroutines*each+1)
	}
}

// ─── Redis-backed ─────────────────────────────────────────────────────────────

// testRedis connects to the Redis these tests need.
//
// Skipping when none is reachable keeps the suite usable on a laptop, but a
// skip is indistinguishable from a pass in CI output — so setting
// REDIS_TEST_URL turns the skip into a failure. CI sets it, which is what
// stops the shared-counter path from passing by never running.
func testRedis(t *testing.T) *Client {
	t.Helper()

	url, required := os.LookupEnv("REDIS_TEST_URL")
	if !required {
		url = "redis://localhost:6379/9"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, err := NewFromURL(ctx, url, zerolog.Nop())
	if err != nil || c == nil {
		t.Fatalf("REDIS_TEST_URL %q will not parse: %v", url, err)
	}
	t.Cleanup(func() { _ = c.Close() })

	if err := c.Ping(ctx); err != nil {
		if required {
			t.Fatalf("REDIS_TEST_URL is set to %s but nothing answers there: %v", url, err)
		}
		t.Skipf("no Redis at %s (set REDIS_TEST_URL to require one): %v", url, err)
	}
	return c
}

// redisWindow returns a Redis-backed window named for this test.
func redisWindow(t *testing.T, name string) *Window {
	t.Helper()

	c := testRedis(t)

	w := NewWindow(c, name, zerolog.Nop())
	t.Cleanup(func() {
		_ = c.Del(context.Background(), w.name+":k", w.name+":a", w.name+":b")
	})
	return w
}

func TestRedisCountRisesWithEachOccurrence(t *testing.T) {
	w := redisWindow(t, fmt.Sprintf("test_rise_%d", time.Now().UnixNano()))

	for want := 1; want <= 5; want++ {
		got, src := w.Count(context.Background(), "k", time.Minute)
		if src != SourceRedis {
			t.Fatalf("source = %s, want %s — the Redis path was not exercised", src, SourceRedis)
		}
		if got != want {
			t.Errorf("occurrence %d: count = %d, want %d", want, got, want)
		}
	}
}

func TestRedisCountIsSharedBetweenReplicas(t *testing.T) {
	// The reason this package exists: two processes counting the same entity
	// must reach the threshold together, not each on its own.
	name := fmt.Sprintf("test_shared_%d", time.Now().UnixNano())
	replicaA := redisWindow(t, name)
	replicaB := redisWindow(t, name)

	replicaA.Count(context.Background(), "k", time.Minute)
	replicaA.Count(context.Background(), "k", time.Minute)

	got, src := replicaB.Count(context.Background(), "k", time.Minute)
	if src != SourceRedis {
		t.Fatalf("source = %s, want %s", src, SourceRedis)
	}
	if got != 3 {
		t.Errorf("second replica counted %d, want 3 — the counter is not shared", got)
	}
}

func TestRedisOccurrencesLeaveTheWindow(t *testing.T) {
	w := redisWindow(t, fmt.Sprintf("test_expiry_%d", time.Now().UnixNano()))
	const window = 300 * time.Millisecond

	w.Count(context.Background(), "k", window)
	w.Count(context.Background(), "k", window)
	time.Sleep(2 * window)

	if got, _ := w.Count(context.Background(), "k", window); got != 1 {
		t.Errorf("count after the window elapsed = %d, want 1", got)
	}
}

func TestRedisCountsOccurrencesWithinTheSameMillisecond(t *testing.T) {
	// Scores are timestamps, so two events in one millisecond collide on score.
	// Uniqueness has to come from the member, or a burst counts as one event —
	// precisely the burst a threshold rule is looking for.
	w := redisWindow(t, fmt.Sprintf("test_burst_%d", time.Now().UnixNano()))

	var last int
	for i := 0; i < 20; i++ {
		last, _ = w.Count(context.Background(), "k", time.Minute)
	}
	if last != 20 {
		t.Errorf("20 occurrences counted as %d — same-millisecond events are collapsing", last)
	}
}

func TestRedisKeysCarryAnExpiry(t *testing.T) {
	// Without a TTL every entity ever seen stays in Redis for good.
	w := redisWindow(t, fmt.Sprintf("test_ttl_%d", time.Now().UnixNano()))
	w.Count(context.Background(), "k", time.Minute)

	ttl, err := w.rdb.TTL(context.Background(), w.name+":k").Result()
	if err != nil {
		t.Fatalf("ttl: %v", err)
	}
	if ttl <= 0 {
		t.Errorf("ttl = %v, want a positive expiry", ttl)
	}
}

func TestCountFallsBackWhenRedisIsUnreachable(t *testing.T) {
	// A detection engine must keep counting when its cache blinks. Returning
	// zero — or an error a caller reads as "no events" — would turn a cache
	// outage into a detection blind spot.
	dead := &Client{rdb: redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1", // nothing listens on port 1
		DialTimeout: 200 * time.Millisecond,
		MaxRetries:  -1,
	})}
	t.Cleanup(func() { _ = dead.Close() })

	w := NewWindow(dead, "test_fallback", zerolog.Nop())

	for want := 1; want <= 3; want++ {
		got, src := w.Count(context.Background(), "k", time.Minute)
		if src != SourceMemory {
			t.Fatalf("source = %s, want %s", src, SourceMemory)
		}
		if got != want {
			t.Errorf("occurrence %d: count = %d, want %d — counting stopped when Redis went away", want, got, want)
		}
	}
}

func TestWindowMetricsReachTheScrapedRegistry(t *testing.T) {
	// The platform serves its own registry, not the default one. A metric
	// registered the usual promauto way would exist and be scraped by nobody,
	// which is the failure this asserts against.
	w := NewWindow(nil, "test_metrics", zerolog.Nop())
	w.Count(context.Background(), "k", time.Minute)

	rec := httptest.NewRecorder()
	observe.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	for _, metric := range []string{
		`crp_sliding_window_fallback_total{window="test_metrics"}`,
		`crp_sliding_window_local_keys{window="test_metrics"}`,
	} {
		if !strings.Contains(body, metric) {
			t.Errorf("%s is missing from /metrics — the counter degrades invisibly", metric)
		}
	}
}
