package testinfra

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/docker/go-connections/nat"
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
	kafkaImage      = "confluentinc/confluent-local:7.6.0"

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
				"CLICKHOUSE_USER":                      "default",
				"CLICKHOUSE_PASSWORD":                  "",
				"CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT": "1",
			},
			WaitingFor: wait.ForAll(
				wait.ForLog("Ready for connections"),
				wait.ForListeningPort("9000/tcp"),
			).WithDeadline(startupTimeout),
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
			Image:        kafkaImage,
			ExposedPorts: []string{"9092/tcp"},
			Env: map[string]string{
				"KAFKA_LISTENERS":                        "PLAINTEXT://0.0.0.0:9092,BROKER://0.0.0.0:9093,CONTROLLER://0.0.0.0:9094",
				"KAFKA_ADVERTISED_LISTENERS":             "PLAINTEXT://localhost:9092,BROKER://localhost:9093",
				"KAFKA_LISTENER_SECURITY_PROTOCOL_MAP":   "PLAINTEXT:PLAINTEXT,BROKER:PLAINTEXT,CONTROLLER:PLAINTEXT",
				"KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR": "1",
				"KAFKA_AUTO_CREATE_TOPICS_ENABLE":        "true",
			},
			WaitingFor: wait.ForListeningPort("9092/tcp").WithStartupTimeout(startupTimeout),
		},
		Started: true,
	})
	if err != nil {
		return "", fmt.Errorf("start %s: %w", kafkaImage, err)
	}
	remember(c)
	return hostPort(ctx, c, "9092")
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
