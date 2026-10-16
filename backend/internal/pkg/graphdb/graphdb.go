// Package graphdb opens connections to Neo4j.
//
// It exists so the driver settings live in one place. Two services mirror a
// graph into Neo4j, and the defaults matter: the driver retries a failed
// transaction for thirty seconds, which is fine for a background job and very
// much not fine on the request path, where a mirror write sits. That was
// measured rather than assumed — an unreachable Neo4j made every graph write
// take half a minute — and a second copy of these settings would be free to
// drift back to it.
package graphdb

import (
	"context"
	"fmt"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// Config is what a deployment supplies to reach Neo4j.
type Config struct {
	URI      string // bolt://host:7687 or neo4j://host:7687
	Username string
	Password string
	Database string // "neo4j" when empty
}

// DatabaseOrDefault is the database this config names.
func (c Config) DatabaseOrDefault() string {
	if c.Database == "" {
		return "neo4j"
	}
	return c.Database
}

// FromEnv reads the standard variables. An empty URI means no Neo4j is
// configured, which is not an error: a deployment without one keeps its graph
// in PostgreSQL alone.
func FromEnv(getenv func(string) string) (Config, bool) {
	uri := getenv("NEO4J_URI")
	if uri == "" {
		return Config{}, false
	}
	return Config{
		URI:      uri,
		Username: getenv("NEO4J_USERNAME"),
		Password: getenv("NEO4J_PASSWORD"),
		Database: getenv("NEO4J_DATABASE"),
	}, true
}

// Open connects and verifies the connection.
//
// It fails rather than degrading: a mirror that is configured but unreachable
// drifts from its source of truth silently, and a traversal reading a drifted
// graph answers with relationships that do not exist — or misses the ones that
// do.
func Open(ctx context.Context, cfg Config) (neo4j.DriverWithContext, error) {
	auth := neo4j.NoAuth()
	if cfg.Username != "" {
		auth = neo4j.BasicAuth(cfg.Username, cfg.Password, "")
	}
	driver, err := neo4j.NewDriverWithContext(cfg.URI, auth, func(c *neo4j.Config) {
		c.MaxTransactionRetryTime = 5 * time.Second
		c.SocketConnectTimeout = 3 * time.Second
		c.ConnectionAcquisitionTimeout = 5 * time.Second
	})
	if err != nil {
		return nil, fmt.Errorf("neo4j driver: %w", err)
	}
	if err := driver.VerifyConnectivity(ctx); err != nil {
		_ = driver.Close(ctx)
		return nil, fmt.Errorf("neo4j at %s: %w", cfg.URI, err)
	}
	return driver, nil
}

// Query runs one statement against a database and collects its records.
func Query(ctx context.Context, driver neo4j.DriverWithContext, database, cypher string,
	params map[string]any) (*neo4j.EagerResult, error) {
	return neo4j.ExecuteQuery(ctx, driver, cypher, params,
		neo4j.EagerResultTransformer, neo4j.ExecuteQueryWithDatabase(database))
}
