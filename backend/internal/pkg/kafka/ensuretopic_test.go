package kafka

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
)

// brokersOrSkip is the broker this test counts on, or none.
func brokersOrSkip(t *testing.T) []string {
	t.Helper()
	v := os.Getenv("CRP_TEST_KAFKA_BROKERS")
	if v == "" {
		t.Skip("no CRP_TEST_KAFKA_BROKERS")
	}
	return strings.Split(v, ",")
}

// A consumer built before anything has produced must still read what comes.
//
// What this does and does not establish, stated plainly because the difference
// matters. It asserts the contract: build the consumer on a topic that does
// not exist, start reading, produce afterwards, get the message.
//
// It does **not** reproduce the failure that motivated EnsureTopic. On a cold
// broker the platform lost its whole detection chain — the collector published
// 48 events, the pipeline worker committed none of them, `crp.events.enriched`
// stayed at zero, and the rule engine waited correctly on an empty topic while
// both journals looked healthy, because neither logs a line per event. Removing
// EnsureTopic and running this test leaves it green, so whatever distinguishes
// the platform from these twenty lines is not captured here; the mechanism is
// not fully understood, and saying so is worth more than a comment claiming a
// guard that does not exist.
//
// The guard that does reproduce it is the e2e-chain job against a broker with
// no topics, where the before/after is unambiguous: deterministic failure at
// 2m31s without this call, 4.3s with it. That is the regression test.
//
// EnsureTopic is kept on its own merits either way: a hardened cluster has
// auto-creation disabled, which turns a start-up race into a permanent
// failure.
func TestAConsumerBuiltBeforeAnythingProducedStillReads(t *testing.T) {
	brokers := brokersOrSkip(t)
	topic := fmt.Sprintf("crp.test.cold.%d", time.Now().UnixNano())

	c, err := NewConsumer(ConsumerConfig{
		Brokers:     brokers,
		Topic:       topic,
		GroupID:     topic + ".group",
		StartOffset: FromTheBeginning,
		DLQTopic:    topic + ".dlq",
	}, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewConsumer on a topic nobody has produced to: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	// The order is the whole test. In the platform the reader is already
	// fetching when the topic appears — the worker starts with the services and
	// the first event arrives minutes later — so Run goes first here too.
	// Publishing before Run lets the reader find a settled topic, which is not
	// the situation that lost the events.
	runCtx, stop := context.WithTimeout(context.Background(), 90*time.Second)
	defer stop()
	got := make(chan string, 1)
	go func() {
		_ = c.Run(runCtx, func(_ context.Context, msg Message) error {
			select {
			case got <- string(msg.Value):
			default:
			}
			return nil
		})
	}()
	time.Sleep(2 * time.Second) // let it join and block on a fetch

	// Only now does anything exist to read.
	p := NewProducer(ProducerConfig{Brokers: brokers, Topic: topic}, zerolog.Nop())
	t.Cleanup(func() { _ = p.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// The producer is retried until it lands, and its first refusal is not the
	// failure under test: a writer also meets a topic that is being created,
	// and it has AllowAutoTopicCreation to deal with it. Letting that error end
	// the test would make it fail before reaching the assertion it exists for —
	// which is what happened the first time this was written, and a test that
	// fails for a neighbouring reason is a test that will pass for one too.
	var published error
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		published = p.Publish(ctx, "k", map[string]string{"tenant_id": "t", "hello": "world"})
		if published == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if published != nil {
		t.Fatalf("publish never landed: %v", published)
	}

	select {
	case body := <-got:
		if !strings.Contains(body, "world") {
			t.Errorf("read %q, which is not what was published", body)
		}
	case <-runCtx.Done():
		t.Fatal("the consumer read nothing: it was built before the topic existed, which is the " +
			"state every consumer is in on a cold installation")
	}
}

// EnsureTopic is called on a topic that already exists far more often than not,
// so saying so must be success rather than an error worth logging.
func TestEnsuringATopicTwiceIsNotAnError(t *testing.T) {
	brokers := brokersOrSkip(t)
	topic := fmt.Sprintf("crp.test.twice.%d", time.Now().UnixNano())

	for i := 1; i <= 2; i++ {
		if err := EnsureTopic(brokers, topic, 60*time.Second, zerolog.Nop()); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}

	// And it really is there, with a leader.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := kafka.DialLeader(ctx, "tcp", brokers[0], topic, 0)
	if err != nil {
		t.Fatalf("the topic EnsureTopic reported ready has no leader: %v", err)
	}
	_ = conn.Close()
}

// A broker that is not there must be an error, not a sixty-second stall that
// ends in one: a service with the wrong address should say so at start-up.
func TestEnsuringATopicOnAnAbsentBrokerFailsAtOnce(t *testing.T) {
	start := time.Now()
	err := EnsureTopic([]string{"127.0.0.1:9"}, "crp.test.nowhere", 60*time.Second, zerolog.Nop())
	if err == nil {
		t.Fatal("no error for a broker that is not listening")
	}
	if took := time.Since(start); took > 20*time.Second {
		t.Errorf("took %s to report an unreachable broker", took)
	}
}
