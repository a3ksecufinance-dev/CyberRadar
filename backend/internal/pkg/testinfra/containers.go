package testinfra

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/segmentio/kafka-go"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// The container backend: used when nothing is already running and a Docker
// daemon is reachable.
//
// Generic containers rather than the per-technology testcontainers modules.
// Each module is its own Go module with its own dependency tree, and four of
// them would land in the go.mod of every service that writes one repository
// test. The images and wait strategies here are the few lines those modules
// would have contributed.
//
// The image tags match deployments/docker-compose.yml. A test that passed
// against a different major version than the platform deploys would be worth
// less than no test.

const (
	postgresImage   = "pgvector/pgvector:pg16"
	clickhouseImage = "clickhouse/clickhouse-server:24.3-alpine"
	kafkaImage      = "confluentinc/cp-kafka:7.6.0"

	containerUser = "crp_test"
	containerPass = "crp_test"
	containerDB   = "postgres"

	startupTimeout = 3 * time.Minute
)

// started keeps every container this process launched, so the cleanup below
// can stop them all.
var (
	startedMu  sync.Mutex
	startedAll []testcontainers.Container
)

func remember(c testcontainers.Container) {
	startedMu.Lock()
	defer startedMu.Unlock()
	startedAll = append(startedAll, c)
}

// StopContainers terminates everything this process started.
//
// testcontainers' own reaper removes containers when the test process dies, so
// this is belt and braces for the case where the reaper is disabled — which is
// the usual configuration on a CI runner that already isolates the job.
func StopContainers() {
	startedMu.Lock()
	defer startedMu.Unlock()
	for _, c := range startedAll {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_ = c.Terminate(ctx)
		cancel()
	}
	startedAll = nil
}

func startPostgresContainer() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        postgresImage,
			ExposedPorts: []string{"5432/tcp"},
			Env: map[string]string{
				"POSTGRES_USER":     containerUser,
				"POSTGRES_PASSWORD": containerPass,
				"POSTGRES_DB":       containerDB,
			},
			// Twice: PostgreSQL's entrypoint starts the server once to run the
			// initialisation scripts and stops it again. Waiting for the first
			// line connects to a server that is about to go away.
			WaitingFor: wait.ForAll(
				wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
				wait.ForListeningPort("5432/tcp"),
			).WithDeadline(startupTimeout),
		},
		Started: true,
	})
	if err != nil {
		return "", fmt.Errorf("start %s: %w", postgresImage, err)
	}
	remember(c)

	endpoint, err := hostPort(ctx, c, "5432")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable",
		containerUser, containerPass, endpoint, containerDB), nil
}

func startClickHouseContainer() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        clickhouseImage,
			ExposedPorts: []string{"9000/tcp"},
			Env: map[string]string{
				// Leave the default user usable without a password.
				//
				// With neither CLICKHOUSE_USER nor CLICKHOUSE_PASSWORD set, the
				// image's entrypoint disables network access for 'default', and
				// every connection from outside the container is refused with
				// "Authentication failed" — while a health check run inside it,
				// over localhost, still passes. Passing an empty password is not
				// the same as skipping the setup, so this is the variable that
				// does it.
				"CLICKHOUSE_SKIP_USER_SETUP": "1",
			},
			// The port, and only the port.
			//
			// Waiting for a log line does not work here: this image logs to
			// /var/log/clickhouse-server/ rather than to standard output, so
			// "Ready for connections" never appears on the stream
			// testcontainers reads, and every start failed after the strategy's
			// own sixty-second timeout — whatever deadline the set carried.
			// The caller pings the server afterwards, which is the real check.
			WaitingFor: wait.ForListeningPort("9000/tcp").
				WithStartupTimeout(startupTimeout),
		},
		Started: true,
	})
	if err != nil {
		return "", fmt.Errorf("start %s: %w", clickhouseImage, err)
	}
	remember(c)

	endpoint, err := hostPort(ctx, c, "9000")
	if err != nil {
		return "", err
	}
	// The colon is not optional: the driver reads user:pass and refuses a DSN
	// carrying a user with no separator.
	return fmt.Sprintf("clickhouse://default:@%s/default", endpoint), nil
}

func startKafkaContainer() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: kafkaImage,
			// A fixed host port, not a mapped one.
			//
			// A Kafka client connects once to bootstrap and is then redirected
			// to whatever the broker advertises. The broker has to advertise an
			// address the client can reach, and it is configured before the
			// container starts — so it cannot know a randomly mapped port. With
			// one, the first connection succeeded and the second was reset by
			// the broker on a port nothing listened to.
			//
			// Binding 9092 to 9092 makes the advertised address true. It costs
			// the ability to run two brokers at once on one machine, which no
			// test does: the broker is shared per process and the topics are
			// what isolate tests from each other.
			ExposedPorts: []string{"9092:9092/tcp"},
			// The same image and the same KRaft settings as the CI service
			// and deployments/docker-compose.yml.
			//
			// confluent-local was here before, and it runs a readiness check of
			// its own that expects the listener layout it configures itself —
			// an explicit one makes that check fail and the container exits.
			// cp-kafka takes the configuration it is given, and this is the
			// configuration a developer already runs.
			Env: map[string]string{
				"KAFKA_NODE_ID":                                  "1",
				"KAFKA_PROCESS_ROLES":                            "broker,controller",
				"KAFKA_LISTENERS":                                "PLAINTEXT://0.0.0.0:9092,CONTROLLER://0.0.0.0:9093",
				"KAFKA_ADVERTISED_LISTENERS":                     "PLAINTEXT://localhost:9092",
				"KAFKA_CONTROLLER_LISTENER_NAMES":                "CONTROLLER",
				"KAFKA_LISTENER_SECURITY_PROTOCOL_MAP":           "PLAINTEXT:PLAINTEXT,CONTROLLER:PLAINTEXT",
				"KAFKA_CONTROLLER_QUORUM_VOTERS":                 "1@localhost:9093",
				"KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR":         "1",
				"KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR": "1",
				"KAFKA_TRANSACTION_STATE_LOG_MIN_ISR":            "1",
				"KAFKA_AUTO_CREATE_TOPICS_ENABLE":                "true",
				// 16 bytes in base64, which is what KRaft decodes. A readable
				// label is refused outright.
				"CLUSTER_ID": "abJmc64xRMOGJdyAgr4muQ",
			},
			WaitingFor: wait.ForListeningPort("9092/tcp").WithStartupTimeout(startupTimeout),
		},
		Started: true,
	})
	if err != nil {
		return "", fmt.Errorf("start %s: %w", kafkaImage, err)
	}
	remember(c)
	addr, err := hostPort(ctx, c, "9092")
	if err != nil {
		return "", err
	}
	// The port is open well before the broker will answer.
	//
	// PostgreSQL above waits for a log line as well as its port, because its
	// entrypoint starts it once for initdb and once for real. A KRaft broker
	// has the same gap for a different reason: it binds 9092 while the
	// controller quorum is still electing a leader, so a client that connects
	// in that window gets LEADER_NOT_AVAILABLE or an empty metadata response
	// — and kafka-go reports the second as an ordinary empty topic list
	// rather than an error, which is the quiet kind of failure this package
	// exists to keep out of the suite.
	//
	// Metadata is the first thing every caller needs, so asking for it is
	// both the readiness check and a rehearsal of the first real call.
	if err := awaitBroker(ctx, addr); err != nil {
		return "", err
	}
	return addr, nil
}

// awaitBroker blocks until the broker answers a metadata request.
//
// kafka-go directly rather than internal/pkg/kafka: that package's tests are
// in-package and use this one, so importing it here would close an import
// cycle the moment somebody writes the obvious test.
func awaitBroker(ctx context.Context, addr string) error {
	deadline := time.Now().Add(startupTimeout)
	var last error
	for time.Now().Before(deadline) {
		conn, err := kafka.DialContext(ctx, "tcp", addr)
		if err != nil {
			last = err
		} else {
			_, err = conn.ReadPartitions()
			cerr := conn.Close()
			if err == nil {
				return nil
			}
			last = err
			if cerr != nil {
				last = fmt.Errorf("%w (and closing: %v)", err, cerr)
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for the broker at %s: %w", addr, ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
	return fmt.Errorf("the broker at %s did not answer a metadata request within %s: %w",
		addr, startupTimeout, last)
}

func hostPort(ctx context.Context, c testcontainers.Container, port string) (string, error) {
	host, err := c.Host(ctx)
	if err != nil {
		return "", fmt.Errorf("container host: %w", err)
	}
	mapped, err := c.MappedPort(ctx, nat.Port(port+"/tcp"))
	if err != nil {
		return "", fmt.Errorf("container port %s: %w", port, err)
	}
	return fmt.Sprintf("%s:%s", host, mapped.Port()), nil
}
