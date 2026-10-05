package testinfra

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/segmentio/kafka-go"
)

// Kafka hands the test a broker list and a topic of its own.
//
// The topic is created before the call returns and deleted when the test ends,
// so two tests never read each other's messages even on a shared broker. The
// platform's own topics (crp.events.raw and the rest) are never touched: a test
// that wrote to one would be writing into whatever a developer has running.
//
// The returned prefix is unique per test; a test that needs several topics
// derives them from it with Topic.
type KafkaFixture struct {
	Brokers []string
	// Topic is a topic created for this test, already empty.
	Topic string

	prefix string
	t      *testing.T
}

// Kafka starts or finds a broker and gives the test a topic of its own.
func Kafka(t *testing.T) *KafkaFixture {
	t.Helper()

	brokers, err := sharedKafka()
	if err != nil {
		unavailable(t, "kafka", "Kafka", EnvKafka, err)
		return nil // unreachable
	}

	prefix := "crp.test." + randSuffix()
	f := &KafkaFixture{Brokers: brokers, prefix: prefix, t: t}
	f.Topic = f.NewTopic("main")
	return f
}

// NewTopic creates another topic for this test and schedules its removal.
func (f *KafkaFixture) NewTopic(name string) string {
	f.t.Helper()
	full := f.prefix + "." + name

	conn, controller, err := controllerConn(f.Brokers)
	if err != nil {
		f.t.Fatalf("reach the Kafka controller: %v", err)
	}
	defer conn.Close()
	_ = controller

	err = conn.CreateTopics(kafka.TopicConfig{
		Topic:             full,
		NumPartitions:     1,
		ReplicationFactor: 1,
	})
	if err != nil {
		f.t.Fatalf("create topic %s: %v", full, err)
	}

	f.t.Cleanup(func() {
		c, _, err := controllerConn(f.Brokers)
		if err != nil {
			f.t.Logf("testinfra: could not delete topic %s: %v", full, err)
			return
		}
		defer c.Close()
		if err := c.DeleteTopics(full); err != nil {
			f.t.Logf("testinfra: could not delete topic %s: %v", full, err)
		}
	})
	return full
}

// controllerConn opens a connection to the broker that owns topic
// administration.
//
// Creating a topic against a non-controller broker fails with NOT_CONTROLLER,
// which on a single-broker development cluster happens to work and on a
// three-broker production-shaped one does not. Asking for the controller makes
// the test behave the same on both.
func controllerConn(brokers []string) (*kafka.Conn, kafka.Broker, error) {
	var zero kafka.Broker
	conn, err := kafka.DialContext(context.Background(), "tcp", brokers[0])
	if err != nil {
		return nil, zero, err
	}
	controller, err := conn.Controller()
	if err != nil {
		conn.Close()
		return nil, zero, err
	}
	if fmt.Sprintf("%s:%d", controller.Host, controller.Port) == brokers[0] {
		return conn, controller, nil
	}
	conn.Close()

	c, err := kafka.DialContext(context.Background(), "tcp",
		fmt.Sprintf("%s:%d", controller.Host, controller.Port))
	if err != nil {
		return nil, zero, err
	}
	return c, controller, nil
}

var (
	kOnce    sync.Once
	kBrokers []string
	kErr     error
)

func sharedKafka() ([]string, error) {
	kOnce.Do(func() {
		list := os.Getenv(EnvKafka)
		if list == "" {
			var endpoint string
			endpoint, kErr = startKafkaContainer()
			if kErr != nil {
				return
			}
			list = endpoint
		}

		brokers := strings.Split(list, ",")
		for i := range brokers {
			brokers[i] = strings.TrimSpace(brokers[i])
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := kafka.DialContext(ctx, "tcp", brokers[0])
		if err != nil {
			kErr = fmt.Errorf("dial %s: %w", brokers[0], err)
			return
		}
		defer conn.Close()
		if _, err := conn.Brokers(); err != nil {
			kErr = fmt.Errorf("read cluster metadata from %s: %w", brokers[0], err)
			return
		}
		kBrokers = brokers
	})
	return kBrokers, kErr
}
