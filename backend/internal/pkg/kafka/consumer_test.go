package kafka

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func testConsumer(maxAttempts int, backoff time.Duration) *Consumer {
	return &Consumer{
		cfg:    ConsumerConfig{MaxAttempts: maxAttempts, RetryBackoff: backoff},
		logger: zerolog.Nop(),
	}
}

func TestNewConsumerRequiresADLQ(t *testing.T) {
	// Without a DLQ there is no safe behaviour left: the handler error either
	// loops or drops the message. Refusing to build is the point.
	_, err := NewConsumer(ConsumerConfig{
		Brokers: []string{"localhost:9092"}, Topic: "crp.events.enriched", GroupID: "g",
	}, zerolog.Nop())
	if err == nil {
		t.Error("a consumer with no DLQ topic was accepted")
	}
}

func TestNewConsumerRejectsADLQEqualToTheSourceTopic(t *testing.T) {
	// Parking a failure back onto the topic it came from is an infinite loop.
	_, err := NewConsumer(ConsumerConfig{
		Brokers: []string{"localhost:9092"},
		Topic:   "crp.events.enriched", DLQTopic: "crp.events.enriched", GroupID: "g",
	}, zerolog.Nop())
	if err == nil {
		t.Error("a DLQ topic equal to the source topic was accepted")
	}
}

func TestHandleStopsAtTheFirstSuccess(t *testing.T) {
	calls := 0
	err := testConsumer(3, time.Millisecond).handle(context.Background(),
		func(context.Context, Message) error { calls++; return nil }, Message{})

	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if calls != 1 {
		t.Errorf("handler called %d times, want 1", calls)
	}
}

func TestHandleRetriesUntilItSucceeds(t *testing.T) {
	calls := 0
	err := testConsumer(3, time.Millisecond).handle(context.Background(),
		func(context.Context, Message) error {
			calls++
			if calls < 3 {
				return errors.New("transient")
			}
			return nil
		}, Message{})

	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if calls != 3 {
		t.Errorf("handler called %d times, want 3", calls)
	}
}

func TestHandleGivesUpAfterMaxAttempts(t *testing.T) {
	calls := 0
	wantErr := errors.New("permanent")

	err := testConsumer(4, time.Millisecond).handle(context.Background(),
		func(context.Context, Message) error { calls++; return wantErr }, Message{})

	if !errors.Is(err, wantErr) {
		t.Errorf("handle returned %v, want the handler's own error", err)
	}
	if calls != 4 {
		t.Errorf("handler called %d times, want 4", calls)
	}
}

func TestBackoffDoubles(t *testing.T) {
	const base = 20 * time.Millisecond
	start := time.Now()

	_ = testConsumer(3, base).handle(context.Background(),
		func(context.Context, Message) error { return errors.New("x") }, Message{})

	// Three attempts means two pauses: base + 2*base.
	if elapsed := time.Since(start); elapsed < 3*base {
		t.Errorf("elapsed %v, want at least %v — the backoff is not doubling", elapsed, 3*base)
	}
}

func TestHandleStopsPromptlyWhenTheContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	start := time.Now()

	err := testConsumer(5, time.Hour).handle(ctx, func(context.Context, Message) error {
		calls++
		cancel() // shutdown arrives while the first attempt is running
		return errors.New("x")
	}, Message{})

	// A shutdown must not wait out an hour-long backoff.
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("handle took %v to notice cancellation", elapsed)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("handle returned %v, want context.Canceled", err)
	}
	if calls != 1 {
		t.Errorf("handler called %d times after cancellation, want 1", calls)
	}
}

func TestTenantOfExtractsTheTenant(t *testing.T) {
	if got := tenantOf([]byte(`{"tenant_id":"t-1","other":2}`)); got != "t-1" {
		t.Errorf("tenantOf = %q, want t-1", got)
	}
}

func TestTenantOfToleratesUnparseablePayloads(t *testing.T) {
	// A payload that will not parse is exactly the kind that reaches the DLQ,
	// so this must never panic or block the parking of the message.
	for _, payload := range []string{"", "not json", "[]", "null", `{"tenant_id":42}`} {
		if got := tenantOf([]byte(payload)); got != "" {
			t.Errorf("tenantOf(%q) = %q, want empty", payload, got)
		}
	}
}
