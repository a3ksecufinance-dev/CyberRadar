package e2echain

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyberradar/platform/internal/pkg/apicheck"
	"github.com/cyberradar/platform/internal/pkg/devtoken"
)

// backendRoot is where the module tree starts.
const backendRoot = "../../.."

// The budgets. They are generous on purpose: this runs on a CI runner sharing
// a core with PostgreSQL, ClickHouse and Kafka, and a flaky chain is worse
// than a slow one. They are still budgets — a step that stops happening fails
// here rather than becoming a slow page nobody times.
const (
	budgetIngest = 20 * time.Second
	// Long enough to cross one refresh of the engine's rule cache, which is
	// 60 seconds: a rule authored a moment ago is not yet one the engine
	// holds, and the chain writes its own rule on purpose.
	budgetAlert    = 150 * time.Second
	budgetCase     = 15 * time.Second
	budgetPlaybook = 60 * time.Second
	budgetBlock    = 60 * time.Second
	budgetAudit    = 30 * time.Second
)

// fatal fails the test and, in CI, leaves the reason as a run annotation.
//
// The chain's whole value is naming which handover broke. A failure buried in
// a job log that cannot be read is a failure nobody acts on, so every exit
// from this test goes through here.
func fatal(t *testing.T, format string, args ...any) {
	t.Helper()
	Annotate(format, args...)
	t.Fatalf(format, args...)
}

// TestTheChainFromEventToContainment is the whole product in one test.
//
// Skipping when no platform is reachable keeps the suite usable on a laptop,
// but a skip reads like a pass in CI output, so setting E2ECHAIN_DSN turns the
// skip into a failure.
func TestTheChainFromEventToContainment(t *testing.T) {
	dsn, required := os.LookupEnv("E2ECHAIN_DSN")
	if !required {
		dsn = "postgres://crp_user:crp_password_dev@localhost:5432/crp_foundation?sslmode=disable"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err == nil {
		err = pool.Ping(ctx)
	}
	if err != nil {
		if required {
			fatal(t, "E2ECHAIN_DSN is set to %s but it is not reachable: %v", dsn, err)
		}
		t.Skipf("no database at %s (set E2ECHAIN_DSN to require one): %v", dsn, err)
	}
	defer pool.Close()

	ports, err := apicheck.Ports(backendRoot)
	if err != nil {
		fatal(t, "read the deployment's port table: %v", err)
	}

	keyPath := os.Getenv("JWT_PRIVATE_KEY_PATH")
	if keyPath == "" {
		keyPath = filepath.Join(backendRoot, "deployments", "jwt", "private.pem")
	}
	email := os.Getenv("E2ECHAIN_AS")
	if email == "" {
		email = "admin@cyberradar.io"
	}

	token, grant, err := devtoken.Mint(ctx, pool, keyPath, email)
	if err != nil {
		if required {
			fatal(t, "mint a token: %v", err)
		}
		t.Skipf("cannot mint a token (set E2ECHAIN_DSN to require this test): %v", err)
	}
	analyst := NewClient(token, ports)

	// A database and a token are not a platform. Infrastructure up and
	// services down is the normal state of a developer's machine between two
	// `dev-local.sh up` runs, and failing there would teach everyone to stop
	// running `make test`. In CI the variable is set, so the same situation is
	// a failure.
	if err := analyst.Do(ctx, "GET", "siem", "/health", nil, nil); err != nil {
		if required {
			fatal(t, "the platform is not answering: %v", err)
		}
		t.Skipf("the platform is not running (set E2ECHAIN_DSN to require it): %v", err)
	}
	t.Logf("acting as %s with %d permissions", grant.Email, len(grant.Permissions))

	// A fresh address per run. Two runs against the same installation must not
	// collide on the deduplication window, and a chain that matched a policy
	// left by a previous run would pass without doing anything.
	attacker := fmt.Sprintf("203.0.113.%d", 1+rand.Intn(200)) //nolint:gosec // not a secret
	stamp := time.Now().UTC().Format("150405.000")
	// The collector validates connector_id as a uuid4, which is right: it
	// names a registered connector, not a label.
	connectorID := uuid.NewString()
	tl := &Timeline{}

	// ─── The rule ────────────────────────────────────────────────────────────
	//
	// The chain writes its own rule rather than relying on one the estate
	// happens to carry: a chain that depends on seeded content fails for the
	// wrong reason the day the content changes.
	var rule struct {
		ID uuid.UUID `json:"id"`
	}
	if err := tl.Measure("1. a detection rule is authored", 0, func() error {
		return analyst.Do(ctx, "POST", "siem", "/api/v1/siem/rules", map[string]any{
			"name":        "e2e-chain " + stamp + " — brute force from one address",
			"description": "Written by the end-to-end chain. Five failed authentications from one address inside five minutes.",
			"category":    "authentication",
			"severity":    "CRITICAL",
			"conditions": map[string]any{
				"field_matches": []any{
					// "IAM", not "authentication": the collector normalises the
					// raw category into the platform's own taxonomy
					// (internal/pkg/event.Category), and a rule matches the
					// normalised value. Writing the raw one here cost a run of
					// this chain to notice, which is the kind of thing it is
					// for.
					map[string]any{"field": "category", "op": "eq", "value": "IAM"},
					map[string]any{"field": "outcome", "op": "eq", "value": "failure"},
				},
				"threshold": map[string]any{
					"count": 5, "window_seconds": 300, "group_by": []string{"ip_source"},
				},
			},
			// The columns are VARCHAR(10): these are identifiers, not names.
			"mitre_tactic":    "TA0006",
			"mitre_technique": "T1110",
			"dedup_window_s":  60,
		}, &rule)
	}); err != nil {
		fatal(t, "author the rule: %v%s", err, tl)
	}
	if rule.ID == uuid.Nil {
		fatal(t, "the rule was created without an id%s", tl)
	}

	// ─── The event ───────────────────────────────────────────────────────────
	//
	// Ingestion is a machine's endpoint, and rightly so: it needs a service
	// account holding events:ingest, not an analyst's token. The chain
	// onboards one the way a deployed agent is onboarded, through the identity
	// service, because that path is part of what it is testing.
	var agent *Client
	if err := tl.Measure("2. a connector is onboarded", 0, func() error {
		agent, err = onboardConnector(ctx, pool, analyst, stamp)
		return err
	}); err != nil {
		fatal(t, "onboard a connector: %v%s", err, tl)
	}

	burst := func() error {
		var ingested struct {
			Received  int      `json:"received"`
			Published int      `json:"published"`
			Failed    int      `json:"failed"`
			Errors    []string `json:"errors"`
		}
		now := time.Now().UTC()
		// The collector takes raw lines, not objects: one string per event, in
		// the format the request declares. It is the shape a connector sends.
		events := make([]string, 0, 6)
		for i := 0; i < 6; i++ {
			line, err := json.Marshal(map[string]any{
				"timestamp":  now.Add(time.Duration(-i) * time.Second).Format(time.RFC3339),
				"action":     "user_login",
				"category":   "authentication",
				"severity":   "HIGH",
				"outcome":    "failure",
				"user_name":  "e2e-chain",
				"hostname":   "e2e-chain.exemple.fr",
				"asset_type": "server",
				"src_ip":     attacker,
				"dst_ip":     "10.20.1.12",
				"dst_port":   443,
				"risk_score": 7.0,
			})
			if err != nil {
				return err
			}
			events = append(events, string(line))
		}
		if err := agent.Do(ctx, "POST", "collector", "/api/v1/events/ingest", map[string]any{
			"connector_id": connectorID,
			"source":       "e2e-chain",
			"source_type":  "application",
			"format":       "json",
			"events":       events,
		}, &ingested); err != nil {
			return err
		}
		if ingested.Published != 6 {
			return fmt.Errorf("%d of %d events were published (%v)",
				ingested.Published, ingested.Received, ingested.Errors)
		}
		return nil
	}

	if err := tl.Measure("3. the attack begins: six failed logins", budgetIngest, burst); err != nil {
		fatal(t, "ingest the events: %v%s", err, tl)
	}

	// ─── The alert ───────────────────────────────────────────────────────────
	//
	// Asynchronous: the engine consumes from Kafka. This is the step that
	// measures detection time, and the only one whose budget is a product
	// claim rather than an implementation detail.
	var alert struct {
		AlertID  uuid.UUID `json:"alert_id"`
		RuleName string    `json:"rule_name"`
		IPSource string    `json:"ip_source"`
		Severity string    `json:"severity"`
		Title    string    `json:"title"`
	}
	// The attack does not stop while nobody is looking.
	//
	// The engine refreshes its rule cache every sixty seconds, so a rule
	// authored a moment ago does not match the events that arrive next — and
	// those events are consumed and gone. Repeating the burst is what an
	// attacker does anyway, and it makes the number below mean "time from the
	// first attempt to the alert", which is the figure this product quotes,
	// rule-cache latency included rather than excluded.
	lastBurst := time.Now()
	if err := tl.Measure("4. the rule engine raises an alert", budgetAlert, func() error {
		return Until(ctx, budgetAlert, 2*time.Second, func() (bool, error) {
			if time.Since(lastBurst) > 20*time.Second {
				lastBurst = time.Now()
				if err := burst(); err != nil {
					return false, err
				}
			}
			var page []struct {
				AlertID  uuid.UUID `json:"alert_id"`
				RuleName string    `json:"rule_name"`
				IPSource string    `json:"ip_source"`
				Severity string    `json:"severity"`
				Title    string    `json:"title"`
			}
			if err := analyst.Do(ctx, "GET", "siem",
				"/api/v1/siem/alerts?limit=50&rule_id="+rule.ID.String(), nil, &page); err != nil {
				return false, err
			}
			for _, a := range page {
				if a.IPSource == attacker {
					alert.AlertID, alert.RuleName = a.AlertID, a.RuleName
					alert.IPSource, alert.Severity, alert.Title = a.IPSource, a.Severity, a.Title
					return true, nil
				}
			}
			return false, nil
		})
	}); err != nil {
		fatal(t, "the alert never appeared for %s: %v%s", attacker, err, tl)
	}
	if alert.Severity != "CRITICAL" {
		t.Errorf("the alert is %q, want the rule's CRITICAL", alert.Severity)
	}

	// ─── The case ────────────────────────────────────────────────────────────
	var investigation struct {
		ID       uuid.UUID `json:"id"`
		CaseKey  string    `json:"case_key"`
		Severity string    `json:"severity"`
	}
	if err := tl.Measure("5. an analyst promotes it to a case", budgetCase, func() error {
		return analyst.Do(ctx, "POST", "siem",
			"/api/v1/siem/alerts/"+alert.AlertID.String()+"/case", map[string]any{
				"title":       "e2e-chain " + stamp + " — brute force from " + attacker,
				"description": "Opened by the end-to-end chain from the alert the engine raised.",
				"severity":    "CRITICAL",
				"priority":    1,
				"alert_ids":   []string{alert.AlertID.String()},
			}, &investigation)
	}); err != nil {
		fatal(t, "promote the alert: %v%s", err, tl)
	}
	if investigation.ID == uuid.Nil {
		fatal(t, "the case was created without an id%s", tl)
	}

	// ─── The playbook ────────────────────────────────────────────────────────
	//
	// One step, block_ip, which is the action with an effect outside the SOAR
	// — and therefore the one whose failure is invisible from inside it.
	var playbook struct {
		ID uuid.UUID `json:"id"`
	}
	if err := tl.Measure("6. a containment playbook is written", 0, func() error {
		return analyst.Do(ctx, "POST", "soar", "/api/v1/soar/playbooks", map[string]any{
			"name":         "e2e-chain " + stamp + " — contain an address",
			"description":  "Written by the end-to-end chain.",
			"trigger_type": "manual",
			"is_active":    true,
			"steps": []any{map[string]any{
				"name":        "block the source address",
				"action_type": "block_ip",
				"on_failure":  "abort",
				"timeout_sec": 30,
			}},
		}, &playbook)
	}); err != nil {
		fatal(t, "write the playbook: %v%s", err, tl)
	}

	// Started, then followed through the listing.
	//
	// POST /playbooks/{id}/run answers {"status":"running","playbook_id":…} and
	// not the identifier of the execution it started, so the only way to
	// follow an asynchronous job is to list the executions of that playbook and
	// take the newest. Every client has to do this; it is written down here
	// rather than smoothed over, because the fix is an API change and belongs
	// with the people who own that contract.
	var execution struct {
		ID     uuid.UUID `json:"id"`
		Status string    `json:"status"`
	}
	if err := tl.Measure("7. the playbook runs to completion", budgetPlaybook, func() error {
		if err := analyst.Do(ctx, "POST", "soar",
			"/api/v1/soar/playbooks/"+playbook.ID.String()+"/run", map[string]any{
				"trigger_event": map[string]any{
					"ip_source": attacker,
					"alert_id":  alert.AlertID.String(),
					"case_id":   investigation.ID.String(),
				},
			}, nil); err != nil {
			return err
		}
		if err := Until(ctx, budgetPlaybook, time.Second, func() (bool, error) {
			var page []struct {
				ID uuid.UUID `json:"id"`
			}
			if err := analyst.Do(ctx, "GET", "soar",
				"/api/v1/soar/executions?limit=20&playbook_id="+playbook.ID.String(),
				nil, &page); err != nil {
				return false, err
			}
			if len(page) == 0 {
				return false, nil
			}
			execution.ID = page[0].ID
			return true, nil
		}); err != nil {
			return fmt.Errorf("the execution never appeared: %w", err)
		}

		// The executor runs the steps in its own goroutine, so the answer
		// above says "accepted", not "done".
		return Until(ctx, budgetPlaybook, 2*time.Second, func() (bool, error) {
			var got struct {
				Status string `json:"status"`
				Error  string `json:"error_message"`
				Steps  []struct {
					Name   string `json:"step_name"`
					Status string `json:"status"`
					Error  string `json:"error_message"`
				} `json:"steps"`
			}
			if err := analyst.Do(ctx, "GET", "soar",
				"/api/v1/soar/executions/"+execution.ID.String(), nil, &got); err != nil {
				return false, err
			}
			switch got.Status {
			case "completed", "success", "succeeded":
				return true, nil
			case "failed", "error", "aborted":
				detail := got.Error
				for _, s := range got.Steps {
					if s.Error != "" {
						detail += fmt.Sprintf(" [%s: %s]", s.Name, s.Error)
					}
				}
				return false, fmt.Errorf("the execution %s: %s", got.Status, detail)
			}
			return false, nil
		})
	}); err != nil {
		fatal(t, "run the playbook: %v%s", err, tl)
	}

	// ─── The containment ─────────────────────────────────────────────────────
	//
	// The assertion this whole file exists for: the effect is outside the
	// service that caused it. netsec's POST /policies answered 500 on every
	// call until its RETURNING clause stopped reading a nullable column into a
	// Go string, and nothing in the SOAR's own tests could see that.
	var policy struct {
		ID       uuid.UUID `json:"id"`
		Name     string    `json:"name"`
		Action   string    `json:"action"`
		SrcCIDR  string    `json:"src_cidr"`
		Priority int       `json:"priority"`
		IsActive bool      `json:"is_active"`
	}
	if err := tl.Measure("8. the address is blocked at the network", budgetBlock, func() error {
		return Until(ctx, budgetBlock, 2*time.Second, func() (bool, error) {
			var page []struct {
				ID       uuid.UUID `json:"id"`
				Name     string    `json:"name"`
				Action   string    `json:"action"`
				SrcCIDR  string    `json:"src_cidr"`
				Priority int       `json:"priority"`
				IsActive bool      `json:"is_active"`
			}
			if err := analyst.Do(ctx, "GET", "netsec",
				"/api/v1/netsec/policies?limit=200", nil, &page); err != nil {
				return false, err
			}
			for _, p := range page {
				if p.Name == "soar-block-"+attacker {
					policy.ID, policy.Name, policy.Action = p.ID, p.Name, p.Action
					policy.SrcCIDR, policy.Priority, policy.IsActive = p.SrcCIDR, p.Priority, p.IsActive
					return true, nil
				}
			}
			return false, nil
		})
	}); err != nil {
		fatal(t, "no deny policy for %s: %v%s", attacker, err, tl)
	}
	if policy.Action != "deny" {
		t.Errorf("the containment policy says %q, not deny", policy.Action)
	}
	if !policy.IsActive {
		t.Error("the containment policy is not active, so it contains nothing")
	}
	if policy.Priority != 1 {
		t.Errorf("the containment policy has priority %d; above a standing allow is the point", policy.Priority)
	}

	// ─── The trail ───────────────────────────────────────────────────────────
	//
	// Who blocked the address. The answer must be the playbook's own service
	// account, not the analyst who pressed run: an automated action attributed
	// to a person is a trail that cannot be reconstructed, and a regulator
	// reads this table.
	var entry struct {
		ActorType  string
		ActorEmail string
		ActorID    string
		Action     string
	}
	if err := tl.Measure("9. the audit trail names the playbook", budgetAudit, func() error {
		return Until(ctx, budgetAudit, 2*time.Second, func() (bool, error) {
			var page []struct {
				ActorType    string `json:"actor_type"`
				ActorEmail   string `json:"actor_email"`
				ActorID      string `json:"actor_id"`
				Action       string `json:"action"`
				ResourceType string `json:"resource_type"`
				ResourceID   string `json:"resource_id"`
			}
			if err := analyst.Do(ctx, "GET", "audit",
				"/api/v1/audit/events?limit=200&resource_id="+policy.ID.String(), nil, &page); err != nil {
				return false, err
			}
			for _, e := range page {
				if e.ResourceID != policy.ID.String() {
					continue
				}
				entry.ActorType, entry.ActorEmail = e.ActorType, e.ActorEmail
				entry.ActorID, entry.Action = e.ActorID, e.Action
				return true, nil
			}
			return false, nil
		})
	}); err != nil {
		t.Errorf("no audit entry for the policy the playbook created: %v", err)
	} else {
		if entry.ActorType != "service" {
			t.Errorf("the audit entry attributes the block to a %q, want the playbook's service account", entry.ActorType)
		}
		if entry.ActorEmail == grant.Email {
			t.Errorf("the audit entry attributes the block to %s, the analyst who pressed run", entry.ActorEmail)
		}
	}

	t.Logf("contained %s in %s%s", attacker, round(tl.Total()), tl)
}

// onboardConnector gives the chain what a deployed agent has: a service
// account holding events:ingest, and a token minted from its credential.
func onboardConnector(ctx context.Context, pool *pgxpool.Pool, admin *Client, stamp string) (*Client, error) {
	var role uuid.UUID
	err := pool.QueryRow(ctx, `
		SELECT r.id
		FROM roles r
		JOIN role_permissions rp ON rp.role_id = r.id
		JOIN permissions p       ON p.id = rp.permission_id
		WHERE p.resource = 'events' AND p.action = 'ingest' AND r.name = 'collector_agent'
		LIMIT 1`).Scan(&role)
	if err != nil {
		return nil, fmt.Errorf("no collector_agent role grants events:ingest: %w", err)
	}

	var created struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := admin.Do(ctx, "POST", "identity", "/api/v1/service-accounts", map[string]any{
		"client_id":       "e2e-chain-" + stamp,
		"description":     "Connector of the end-to-end chain.",
		"scope":           "tenant",
		"role_ids":        []uuid.UUID{role},
		"expires_in_days": 1,
	}, &created); err != nil {
		return nil, fmt.Errorf("create the service account: %w", err)
	}
	if created.ClientSecret == "" {
		return nil, fmt.Errorf("%s was created without a secret", created.ClientID)
	}

	var granted struct {
		AccessToken string `json:"access_token"`
	}
	if err := admin.Do(ctx, "POST", "identity", "/api/v1/auth/service-token", map[string]any{
		"client_id":     created.ClientID,
		"client_secret": created.ClientSecret,
	}, &granted); err != nil {
		return nil, fmt.Errorf("exchange the credential for a token: %w", err)
	}
	if granted.AccessToken == "" {
		return nil, fmt.Errorf("the exchange returned no token")
	}
	return admin.As(granted.AccessToken), nil
}
