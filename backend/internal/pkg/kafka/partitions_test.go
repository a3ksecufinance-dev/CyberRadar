package kafka

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/cyberradar/platform/internal/pkg/testinfra"
	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
)

// The partition count is a ceiling, not a tuning knob.
//
// A Kafka partition is read by exactly one consumer of a group. A topic with
// one partition therefore cannot be shared, however many instances of a
// service are deployed: nine of ten sit idle. The platform shipped that way
// until measuring it found out (docs/22-mesures.md), so the number is pinned
// here rather than left to whoever edits the file next.
func TestPartitionsDefaultsAboveOne(t *testing.T) {
	t.Setenv("KAFKA_PARTITIONS", "")
	if got := Partitions(); got < 2 {
		t.Fatalf("the default is %d — one partition caps the pipeline at a single consumer", got)
	}
	if DefaultPartitions < 2 {
		t.Fatalf("DefaultPartitions is %d", DefaultPartitions)
	}
}

func TestPartitionsReadsTheEnvironmentAndRefusesNonsense(t *testing.T) {
	for _, c := range []struct {
		set  string
		want int
	}{
		{"12", 12},
		{"1", 1}, // a deliberate single partition is allowed; it is the silent default that was wrong
		{"", DefaultPartitions},
		{"nonsense", DefaultPartitions},
		{"0", DefaultPartitions},
		{"-3", DefaultPartitions},
	} {
		t.Setenv("KAFKA_PARTITIONS", c.set)
		if got := Partitions(); got != c.want {
			t.Errorf("KAFKA_PARTITIONS=%q → %d, attendu %d", c.set, got, c.want)
		}
	}
}

// A topic created before this setting existed has to be raised, not left.
//
// CreateTopics does nothing to a topic that already exists, so without the
// raise a platform that had ever run once would have kept one partition for
// ever — and the only symptom would have been throughput that refused to
// improve however many instances were added. That is the failure this test
// exists for.
func TestAnExistingTopicIsRaisedToTheWantedPartitionCount(t *testing.T) {
	f := testinfra.Kafka(t)
	logger := zerolog.New(os.Stderr).Level(zerolog.WarnLevel)

	topic := f.NewTopic("raise")

	// Born with one, the way every topic on this platform was.
	conn, err := kafka.Dial("tcp", f.Brokers[0])
	if err != nil {
		t.Fatalf("reach the broker: %v", err)
	}
	narrow := topic + ".narrow"
	if err := conn.CreateTopics(kafka.TopicConfig{
		Topic: narrow, NumPartitions: 1, ReplicationFactor: 1,
	}); err != nil {
		t.Fatalf("create %s with one partition: %v", narrow, err)
	}
	_ = conn.Close()

	if n := partitionCount(t, f.Brokers[0], narrow); n != 1 {
		t.Fatalf("the topic starts with %d partitions, not 1 — the test is not testing what it says", n)
	}

	t.Setenv("KAFKA_PARTITIONS", "4")
	if err := EnsureTopic(f.Brokers, narrow, 30*time.Second, logger); err != nil {
		t.Fatalf("EnsureTopic: %v", err)
	}

	if n := partitionCount(t, f.Brokers[0], narrow); n != 4 {
		t.Errorf("after EnsureTopic the topic has %d partitions, want 4 — an existing topic was left as it was", n)
	}
}

// Kafka cannot reduce a partition count, and asking it to must not make
// EnsureTopic fail: a deployment that lowers the setting keeps the topics it
// has rather than refusing to start.
func TestAWiderTopicIsNotNarrowedAndDoesNotFail(t *testing.T) {
	f := testinfra.Kafka(t)
	logger := zerolog.New(os.Stderr).Level(zerolog.WarnLevel)

	t.Setenv("KAFKA_PARTITIONS", "4")
	wide := f.NewTopic("wide")
	if err := EnsureTopic(f.Brokers, wide, 30*time.Second, logger); err != nil {
		t.Fatalf("EnsureTopic at 4: %v", err)
	}
	before := partitionCount(t, f.Brokers[0], wide)

	t.Setenv("KAFKA_PARTITIONS", "2")
	if err := EnsureTopic(f.Brokers, wide, 30*time.Second, logger); err != nil {
		t.Fatalf("EnsureTopic at 2 refused to run: %v", err)
	}
	if after := partitionCount(t, f.Brokers[0], wide); after != before {
		t.Errorf("the topic went from %d to %d partitions — Kafka cannot narrow one, "+
			"so this means something else changed it", before, after)
	}
}

func partitionCount(t *testing.T, broker, topic string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := kafka.DialContext(ctx, "tcp", broker)
	if err != nil {
		t.Fatalf("reach the broker: %v", err)
	}
	defer conn.Close() //nolint:errcheck // read-only
	parts, err := conn.ReadPartitions(topic)
	if err != nil {
		t.Fatalf("read the partitions of %s: %v", topic, err)
	}
	return len(parts)
}
