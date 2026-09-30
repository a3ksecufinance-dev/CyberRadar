// Command demoseed fills a fresh install with a coherent demonstration estate:
// a mid-sized bank, its assets, what is wrong with them, who is attacking it,
// and what the regulator asks about it.
//
// It exists because an empty platform cannot be evaluated. Every page reads
// zero, every chart is blank, and nothing tells a reviewer whether the product
// works or merely starts. This writes a dataset through the platform's own
// REST API, under a real identity with real permissions, so what appears on
// screen went through the same validation, authorization and tenant scoping as
// anything a customer would enter.
//
//	demoseed                      seed the default tenant
//	demoseed -tenant bnf -v       say what is being created, one line each
//	demoseed -summary             create nothing, just report what is there
//
// Running it twice is safe: every step looks for what it is about to create
// and leaves an existing object alone.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cyberradar/platform/internal/pkg/db"
	"github.com/cyberradar/platform/internal/pkg/devtoken"
	"github.com/google/uuid"
)

// services maps a name to the default local address. The ports are the ones
// deployments/docker-compose.yml and scripts/dev-local.sh both use; override
// any of them with the matching *_SERVICE_URL environment variable.
var services = map[string]struct {
	port int
	env  string
}{
	"identity":   {8002, "IDENTITY_SERVICE_URL"},
	"collector":  {8005, "COLLECTOR_SERVICE_URL"},
	"asset":      {8006, "ASSET_SERVICE_URL"},
	"siem":       {8008, "SIEM_SERVICE_URL"},
	"ueba":       {8009, "UEBA_SERVICE_URL"},
	"ti":         {8010, "TI_SERVICE_URL"},
	"vuln":       {8011, "VULN_SERVICE_URL"},
	"attackpath": {8012, "ATTACKPATH_SERVICE_URL"},
	"kg":         {8013, "KG_SERVICE_URL"},
	"soar":       {8014, "SOAR_SERVICE_URL"},
	"compliance": {8018, "COMPLIANCE_SERVICE_URL"},
	"ir":         {8026, "IR_SERVICE_URL"},
}

func main() {
	var (
		email    = flag.String("as", "admin@cyberradar.io", "identity to act as; it must exist on the platform")
		keyPath  = flag.String("key", envOr("JWT_PRIVATE_KEY_PATH", "deployments/jwt/private.pem"), "RSA private key used to mint the access token")
		dsn      = flag.String("db", envOr("DATABASE_URL", "postgres://crp_user:crp_password_dev@localhost:5432/crp_foundation?sslmode=disable"), "PostgreSQL DSN, used only to resolve the identity and its permissions")
		verbose  = flag.Bool("v", false, "print every object as it is created")
		summary  = flag.Bool("summary", false, "create nothing; report what the tenant already holds")
		waitEng  = flag.Duration("settle", 8*time.Second, "how long to let the event pipeline run before counting alerts")
		credFile = flag.String("connector-credential", envOr("CRP_DEMO_CONNECTOR_CREDENTIAL", filepath.Join(envOr("CRP_STATE_DIR", ".dev-local"), "demo-connector.json")), "where the demonstration connector keeps its client secret")
		showTok  = flag.Bool("token", false, "print an access token for this identity and exit, for curl and for scripts")
	)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	token, collectorRole, err := bootstrap(ctx, *dsn, *keyPath, *email, *showTok)
	if err != nil {
		fatal(err)
	}

	if *showTok {
		fmt.Println(token)
		return
	}

	c := newClient(token, baseURLs())

	if *summary {
		reportCounts(ctx, c)
		return
	}

	s := &seeder{c: c, verbose: *verbose, settle: *waitEng, collectorRole: collectorRole, credentialPath: *credFile}
	if err := s.run(ctx); err != nil {
		fatal(err)
	}
	reportCounts(ctx, c)
}

// bootstrap signs an access token for a real identity, with the permissions
// that identity's roles actually grant, and finds the role a collector agent
// is meant to hold.
//
// The alternative — inventing a token that claims every permission — would
// seed data no user of the platform could have created, and would hide an
// authorization mistake instead of hitting it. If a role is missing a
// permission the dataset needs, this fails with a 403 and names it, which is
// the answer one wants.
//
// PostgreSQL is read for two things only: who the acting identity is, and
// which role grants events:ingest. Neither has an endpoint, and neither is
// data this tool creates.
func bootstrap(ctx context.Context, dsn, keyPath, email string, quiet bool) (string, uuid.UUID, error) {
	pool, err := db.NewPostgresPool(ctx, db.DefaultPostgresConfig(dsn))
	if err != nil {
		return "", uuid.Nil, fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	defer pool.Close()

	token, grant, err := devtoken.Mint(ctx, pool, keyPath, email)
	if err != nil {
		return "", uuid.Nil, err
	}

	var collectorRole uuid.UUID
	err = pool.QueryRow(ctx, `
		SELECT r.id
		FROM roles r
		JOIN role_permissions rp ON rp.role_id = r.id
		JOIN permissions p       ON p.id = rp.permission_id
		WHERE p.resource = 'events' AND p.action = 'ingest' AND r.name = 'collector_agent'
		LIMIT 1`).Scan(&collectorRole)
	if err != nil {
		// Not fatal: only the event step needs it, and it says so itself.
		collectorRole = uuid.Nil
	}

	if !quiet {
		fmt.Printf("acting as %s (%s) — %d permissions\n",
			grant.Email, strings.Join(grant.Roles, ", "), len(grant.Permissions))
	}
	return token, collectorRole, nil
}

func baseURLs() map[string]string {
	out := make(map[string]string, len(services))
	for name, s := range services {
		if v := os.Getenv(s.env); v != "" {
			out[name] = v
			continue
		}
		out[name] = fmt.Sprintf("http://localhost:%d", s.port)
	}
	return out
}

// reportCounts asks each list endpoint for its total. These are the same
// numbers the interface shows, read the same way, so a discrepancy between
// this output and the screen is a real one.
func reportCounts(ctx context.Context, c *client) {
	type probe struct {
		label   string
		service string
		path    string
	}
	probes := []probe{
		{"assets", "asset", "/api/v1/assets?limit=500"},
		{"vulnerabilities", "vuln", "/api/v1/vuln/vulnerabilities?limit=500"},
		{"findings", "vuln", "/api/v1/vuln/findings?limit=500"},
		{"IOCs", "ti", "/api/v1/ti/iocs?limit=500"},
		{"threat actors", "ti", "/api/v1/ti/actors?limit=500"},
		{"SIEM rules", "siem", "/api/v1/siem/rules?limit=500"},
		{"SIEM alerts", "siem", "/api/v1/siem/alerts?limit=500"},
		{"SOAR incidents", "soar", "/api/v1/soar/incidents?limit=500"},
		{"attack scenarios", "attackpath", "/api/v1/attack/scenarios"},
		{"graph entities", "kg", "/api/v1/kg/entities?limit=500"},
		{"compliance controls", "compliance", "/api/v1/compliance/controls?limit=500"},
		{"risks", "compliance", "/api/v1/compliance/risks?limit=500"},
	}

	fmt.Printf("\nWhat the tenant now holds\n")
	for _, p := range probes {
		n, err := c.count(ctx, p.service, p.path)
		if err != nil {
			fmt.Printf("  %-22s  unavailable (%v)\n", p.label, err)
			continue
		}
		fmt.Printf("  %-22s  %d\n", p.label, n)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "demoseed: %v\n", err)
	os.Exit(1)
}
