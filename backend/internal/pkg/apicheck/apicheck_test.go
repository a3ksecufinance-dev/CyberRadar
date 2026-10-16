package apicheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyberradar/platform/internal/pkg/devtoken"
)

// backendRoot is where the module tree starts; the interface sits beside it.
const backendRoot = "../../.."

// deployedServices reads the local runner's own table: key → port. It is the
// same table deploycheck holds compose to, so a service cannot be deployed
// under one name here and another there.
func deployedServices(t *testing.T) map[string]string {
	t.Helper()
	ports, err := Ports(backendRoot)
	if err != nil {
		t.Fatalf("read the deployment's port table: %v", err)
	}
	return ports
}

// A service with no probe is a service whose reads nobody has ever run — which
// is exactly where a nullable column scanned into a string survives. This
// fails when a service is added without one, rather than leaving the gap to be
// noticed by a customer.
func TestEveryServiceHasAReadProbe(t *testing.T) {
	probes, err := All(backendRoot)
	if err != nil {
		t.Fatalf("collect probes: %v", err)
	}

	covered := map[string]int{}
	for _, p := range probes {
		covered[p.Service]++
	}

	var missing []string
	for service := range deployedServices(t) {
		if covered[service] > 0 {
			continue
		}
		if reason, ok := NoReadRoutes[service]; ok {
			t.Logf("%s has no read probe — %s", service, reason)
			continue
		}
		missing = append(missing, service)
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("no read probe for %s\n"+
			"add one to BackendRoutes, or name it in NoReadRoutes with the reason",
			strings.Join(missing, ", "))
	}
}

// Every probe must name a service the platform actually deploys, or it is
// testing an address nothing listens on.
func TestEveryProbeNamesADeployedService(t *testing.T) {
	probes, err := All(backendRoot)
	if err != nil {
		t.Fatalf("collect probes: %v", err)
	}
	deployed := deployedServices(t)

	for _, p := range probes {
		if _, ok := deployed[p.Service]; !ok {
			t.Errorf("%s %s names service %q, which is not deployed (from %s)",
				http.MethodGet, p.Path, p.Service, p.Origin)
		}
	}
}

// ─── Against a running platform ───────────────────────────────────────────────

// result is one probe's outcome.
type result struct {
	probe  Probe
	status int
	body   string
	err    error
}

// TestEveryReadRouteAnswers reads every probe against a running platform.
//
// A 500 is the failure this exists for: it is the shape a nullable column
// scanned into a Go string takes, and it is invisible until someone opens the
// page. Two were found that way, in the incident response and OT services, out
// of six services anyone had run.
//
// One limitation, worth knowing before trusting a pass: a read of an empty
// table cannot hit a NULL, so this only covers the services the demonstration
// estate populates plus whatever else has rows. Running scripts/dev-local.sh
// demo first is what makes the pass mean something.
//
// Skipping when no platform is reachable keeps the suite usable on a laptop,
// but a skip reads like a pass in CI output, so setting APICHECK_DSN turns the
// skip into a failure.
func TestEveryReadRouteAnswers(t *testing.T) {
	dsn, required := os.LookupEnv("APICHECK_DSN")
	if !required {
		dsn = "postgres://crp_user:crp_password_dev@localhost:5432/crp_foundation?sslmode=disable"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err == nil {
		err = pool.Ping(ctx)
	}
	if err != nil {
		if required {
			t.Fatalf("APICHECK_DSN is set to %s but it is not reachable: %v", dsn, err)
		}
		t.Skipf("no database at %s (set APICHECK_DSN to require one): %v", dsn, err)
	}
	defer pool.Close()

	keyPath := os.Getenv("JWT_PRIVATE_KEY_PATH")
	if keyPath == "" {
		keyPath = filepath.Join(backendRoot, "deployments", "jwt", "private.pem")
	}
	email := os.Getenv("APICHECK_AS")
	if email == "" {
		email = "admin@cyberradar.io"
	}

	token, grant, err := devtoken.Mint(ctx, pool, keyPath, email)
	if err != nil {
		if required {
			t.Fatalf("mint a token: %v", err)
		}
		t.Skipf("cannot mint a token (set APICHECK_DSN to require this test): %v", err)
	}
	t.Logf("reading as %s with %d permissions", grant.Email, len(grant.Permissions))

	probes, err := All(backendRoot)
	if err != nil {
		t.Fatalf("collect probes: %v", err)
	}
	ports := deployedServices(t)

	client := &http.Client{Timeout: 20 * time.Second}
	var (
		broken   []result
		refused  []result
		answered int
		down     = map[string]bool{}
	)

	for _, p := range probes {
		port := ports[p.Service]
		query := "limit=5"
		if extra := RequiredParams(p.Path); extra != "" {
			query += "&" + extra
		}
		url := fmt.Sprintf("http://localhost:%s%s?%s", port, p.Path, query)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("build a request for %s: %v", url, err)
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := client.Do(req)
		if err != nil {
			// A service that is not listening is not a defect in its reads.
			// Report it once and carry on; the whole platform being down is
			// what the skip above is for.
			if !down[p.Service] {
				down[p.Service] = true
				t.Logf("%-16s not listening on :%s — its probes were not run", p.Service, port)
			}
			continue
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close() //nolint:errcheck // read-only

		r := result{probe: p, status: resp.StatusCode, body: summarise(raw)}
		switch {
		case resp.StatusCode >= 500:
			broken = append(broken, r)
		case resp.StatusCode >= 400:
			refused = append(refused, r)
		default:
			answered++
		}
	}

	// 4xx is information, not failure: a route may legitimately refuse this
	// identity, or expect a parameter this probe does not send. Printing them
	// keeps a real 404 — a path that moved — from hiding in a silent pass.
	for _, r := range refused {
		t.Logf("%d  %-16s %s  %s", r.status, r.probe.Service, r.probe.Path, r.body)
	}

	if len(broken) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "%d read routes answered 5xx:\n", len(broken))
		for _, r := range broken {
			fmt.Fprintf(&b, "  %d  %-16s %s  %s\n", r.status, r.probe.Service, r.probe.Path, r.body)
		}
		b.WriteString("\nA 500 on a read is usually a nullable column scanned into a Go string.\n" +
			"The service's own log names it, now that a 500 always logs.")
		t.Fatal(b.String())
	}

	if answered == 0 {
		t.Fatal("no route answered: is the platform running?")
	}
	t.Logf("%d read routes answered, %d refused, %d services not listening",
		answered, len(refused), len(down))
}

// summarise pulls the error code out of the envelope, or gives the first line
// of whatever came back instead.
func summarise(raw []byte) string {
	var env struct {
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &env) == nil && env.Error != nil {
		return env.Error.Code + ": " + env.Error.Message
	}
	line := strings.TrimSpace(string(raw))
	if i := strings.IndexByte(line, '\n'); i > 0 {
		line = line[:i]
	}
	if len(line) > 120 {
		line = line[:120] + "…"
	}
	return line
}
