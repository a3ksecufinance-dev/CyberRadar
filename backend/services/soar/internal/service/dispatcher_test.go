package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cyberradar/platform/internal/pkg/svcauth"
	"github.com/cyberradar/platform/services/soar/internal/model"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

var testTenant = uuid.MustParse("3f2504e0-4f89-11d3-9a0c-0305e82c3301")

// seen records what a target service actually received.
type seen struct {
	method string
	path   string
	query  string
	auth   string
	body   map[string]any
}

// target stands in for a platform service. reply is the JSON it answers with;
// status is the code it answers.
func target(t *testing.T, status int, reply string, log *[]seen) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/service-token" {
			w.Header().Set("Content-Type", "application/json")
			//nolint:errcheck // test stub
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"access_token": "svc-token", "expires_at": time.Now().Add(time.Hour),
			}})
			return
		}

		var body map[string]any
		//nolint:errcheck // an empty body is legitimate for GET and DELETE
		json.NewDecoder(r.Body).Decode(&body)
		*log = append(*log, seen{
			method: r.Method, path: r.URL.Path, query: r.URL.RawQuery,
			auth: r.Header.Get("Authorization"), body: body,
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		//nolint:errcheck // test stub
		w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// dispatcher points every service at one stub, so a test asserts the path the
// action chose rather than which stub it happened to hit.
func dispatcher(t *testing.T, url string) *HTTPDispatcher {
	t.Helper()
	tokens, err := svcauth.NewPool(svcauth.Config{
		IdentityURL: url, ClientID: "soar", ClientSecret: "s3cret",
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	return NewHTTPDispatcher(Endpoints{
		Netsec: url, Identity: url, Asset: url, ThreatIntel: url, Vuln: url,
		Notification: url, SIEM: url, IR: url, AttackPath: url,
	}, tokens, zerolog.Nop())
}

func step(action string, params map[string]any) model.PlaybookStep {
	return model.PlaybookStep{
		ID: uuid.New(), Name: "test step", ActionType: action, ActionParams: params,
	}
}

func do(t *testing.T, d *HTTPDispatcher, s model.PlaybookStep, ev map[string]any) (map[string]any, error) {
	t.Helper()
	return d.Do(context.Background(), testTenant, s, ev)
}

// ─── The change that matters: failures are failures ───────────────────────────

func TestAFailingServiceFailsTheStep(t *testing.T) {
	// Every action used to return a fixed success map without contacting
	// anything, so on_failure: abort could never fire and an execution record
	// showed containment that had not occurred.
	var log []seen
	srv := target(t, http.StatusInternalServerError, `{"error":{"message":"firewall unreachable"}}`, &log)

	out, err := do(t, dispatcher(t, srv.URL), step(model.ActionBlockIP, map[string]any{"ip": "203.0.113.5"}), nil)
	if err == nil {
		t.Fatalf("a 500 from netsec produced no error; output: %v", out)
	}
	if !strings.Contains(err.Error(), "netsec") || !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %q, want the service and status named", err)
	}
	if !strings.Contains(err.Error(), "firewall unreachable") {
		t.Errorf("error = %q, want the service's own message carried through", err)
	}
}

func TestAnUnreachableServiceFailsTheStep(t *testing.T) {
	d := dispatcher(t, "http://127.0.0.1:1")
	if _, err := do(t, d, step(model.ActionBlockIP, map[string]any{"ip": "203.0.113.5"}), nil); err == nil {
		t.Error("an unreachable netsec produced no error")
	}
}

func TestAnUnconfiguredServiceFailsLoudly(t *testing.T) {
	// Half-deployed is the dangerous case: the playbook must not report
	// success for a service it was never told how to reach.
	tokens, err := svcauth.NewPool(svcauth.Config{
		IdentityURL: "http://x", ClientID: "soar", ClientSecret: "s",
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	d := NewHTTPDispatcher(Endpoints{}, tokens, zerolog.Nop())

	_, err = do(t, d, step(model.ActionBlockIP, map[string]any{"ip": "203.0.113.5"}), nil)
	if err == nil {
		t.Fatal("an action ran against a service with no URL")
	}
	if !strings.Contains(err.Error(), "netsec") || !strings.Contains(err.Error(), "no URL") {
		t.Errorf("error = %q, want it to name the unconfigured service", err)
	}
}

// ─── Each action calls the right thing ────────────────────────────────────────

func TestBlockIPInstallsADenyPolicy(t *testing.T) {
	var log []seen
	srv := target(t, http.StatusCreated, `{"data":{"id":"p-1"}}`, &log)

	if _, err := do(t, dispatcher(t, srv.URL), step(model.ActionBlockIP, nil),
		map[string]any{"ip_source": "203.0.113.5"}); err != nil {
		t.Fatalf("block_ip: %v", err)
	}

	if len(log) != 1 {
		t.Fatalf("%d calls, want 1", len(log))
	}
	got := log[0]
	if got.method != http.MethodPost || got.path != "/api/v1/netsec/policies" {
		t.Errorf("called %s %s", got.method, got.path)
	}
	if got.body["action"] != "deny" {
		t.Errorf("policy action = %v, want deny", got.body["action"])
	}
	if got.body["src_cidr"] != "203.0.113.5/32" {
		t.Errorf("src_cidr = %v, want a single-host CIDR", got.body["src_cidr"])
	}
	if got.auth != "Bearer svc-token" {
		t.Errorf("Authorization = %q, want the service account's token", got.auth)
	}
}

func TestDisableUserCallsIdentity(t *testing.T) {
	var log []seen
	srv := target(t, http.StatusNoContent, ``, &log)

	if _, err := do(t, dispatcher(t, srv.URL), step(model.ActionDisableUser, nil),
		map[string]any{"user_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8"}); err != nil {
		t.Fatalf("disable_user: %v", err)
	}

	got := log[0]
	if got.method != http.MethodDelete || got.path != "/api/v1/users/6ba7b810-9dad-11d1-80b4-00c04fd430c8" {
		t.Errorf("called %s %s", got.method, got.path)
	}
}

func TestIsolateHostResolvesAnAssetToItsAddress(t *testing.T) {
	// Asset and device vocabularies have no "isolated" state, so isolation is
	// a deny policy on the host's address. The asset has to be resolved first.
	var log []seen
	srv := target(t, http.StatusOK, `{"data":{"ip_addresses":["10.1.2.3"]}}`, &log)

	out, err := do(t, dispatcher(t, srv.URL),
		step(model.ActionIsolateHost, map[string]any{"asset_id": "a-1"}), nil)
	if err != nil {
		t.Fatalf("isolate_host: %v", err)
	}

	if len(log) != 2 {
		t.Fatalf("%d calls, want 2 (asset lookup then policy)", len(log))
	}
	if log[0].method != http.MethodGet || log[0].path != "/api/v1/assets/a-1" {
		t.Errorf("first call was %s %s, want the asset lookup", log[0].method, log[0].path)
	}
	if log[1].path != "/api/v1/netsec/policies" || log[1].body["src_cidr"] != "10.1.2.3/32" {
		t.Errorf("second call = %s body %v", log[1].path, log[1].body)
	}
	if out["isolated_ip"] != "10.1.2.3" {
		t.Errorf("output does not record which address was isolated: %v", out)
	}
}

func TestIsolateHostFailsWhenTheAssetHasNoAddress(t *testing.T) {
	// Better a failed step than a record of a containment that cannot have
	// happened.
	var log []seen
	srv := target(t, http.StatusOK, `{"data":{"ip_addresses":[]}}`, &log)

	if _, err := do(t, dispatcher(t, srv.URL),
		step(model.ActionIsolateHost, map[string]any{"asset_id": "a-1"}), nil); err == nil {
		t.Error("an asset with no address was reported as isolated")
	}
}

func TestAddToBlocklistInfersTheIndicatorType(t *testing.T) {
	var log []seen
	srv := target(t, http.StatusCreated, `{"data":{"id":"i-1"}}`, &log)
	d := dispatcher(t, srv.URL)

	for value, want := range map[string]string{
		"203.0.113.5":                      "ip",
		"evil.example.com":                 "domain",
		"https://evil.example.com/x":       "url",
		"d41d8cd98f00b204e9800998ecf8427e": "hash_md5",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "hash_sha256",
		"CVE-2024-3094": "cve",
	} {
		log = nil
		if _, err := do(t, d, step(model.ActionAddToBlocklist, map[string]any{"ioc_value": value}), nil); err != nil {
			t.Fatalf("add_to_blocklist(%s): %v", value, err)
		}
		if got := log[0].body["ioc_type"]; got != want {
			t.Errorf("ioc_type for %q = %v, want %s", value, got, want)
		}
	}
}

func TestTagEntityKeepsTheTagsTheAssetAlreadyHas(t *testing.T) {
	// The asset update replaces the tag list, so writing only the new tag
	// would silently drop every existing one.
	var log []seen
	srv := target(t, http.StatusOK, `{"data":{"tags":["pci","prod"]}}`, &log)

	if _, err := do(t, dispatcher(t, srv.URL),
		step(model.ActionTagEntity, map[string]any{"asset_id": "a-1", "tag": "compromised"}), nil); err != nil {
		t.Fatalf("tag_entity: %v", err)
	}

	if len(log) != 2 {
		t.Fatalf("%d calls, want 2 (read then write)", len(log))
	}
	tags, _ := log[1].body["tags"].([]any)
	if len(tags) != 3 {
		t.Fatalf("wrote %v, want the existing tags plus the new one", log[1].body["tags"])
	}
}

func TestTagEntityIsIdempotent(t *testing.T) {
	// A playbook re-run on the same alert must not be an error.
	var log []seen
	srv := target(t, http.StatusOK, `{"data":{"tags":["compromised"]}}`, &log)

	out, err := do(t, dispatcher(t, srv.URL),
		step(model.ActionTagEntity, map[string]any{"asset_id": "a-1", "tag": "compromised"}), nil)
	if err != nil {
		t.Fatalf("tag_entity: %v", err)
	}
	if len(log) != 1 {
		t.Errorf("%d calls, want 1 — an already-present tag was written again", len(log))
	}
	if out["already_tagged"] != true {
		t.Errorf("output = %v, want it to say the tag was already there", out)
	}
}

func TestRunSIEMQueryPassesItsFiltersAsQueryParameters(t *testing.T) {
	var log []seen
	srv := target(t, http.StatusOK, `{"data":[]}`, &log)

	if _, err := do(t, dispatcher(t, srv.URL),
		step(model.ActionRunSIEMQuery, map[string]any{"severity": "CRITICAL", "limit": "50"}), nil); err != nil {
		t.Fatalf("run_siem_query: %v", err)
	}

	got := log[0]
	if got.method != http.MethodGet || got.path != "/api/v1/siem/alerts" {
		t.Errorf("called %s %s", got.method, got.path)
	}
	if !strings.Contains(got.query, "severity=CRITICAL") || !strings.Contains(got.query, "limit=50") {
		t.Errorf("query = %q, want the filters", got.query)
	}
}

func TestSendNotificationRefusesWithoutAChannel(t *testing.T) {
	// There is no safe default recipient for an automated security alert.
	var log []seen
	srv := target(t, http.StatusOK, `{}`, &log)

	if _, err := do(t, dispatcher(t, srv.URL),
		step(model.ActionSendNotification, map[string]any{"message": "contained"}), nil); err == nil {
		t.Error("a notification was sent with no channel")
	}
	if len(log) != 0 {
		t.Error("a request was made despite the missing channel")
	}
}

func TestCreateIncidentCallsIR(t *testing.T) {
	var log []seen
	srv := target(t, http.StatusCreated, `{"data":{"id":"inc-1"}}`, &log)

	if _, err := do(t, dispatcher(t, srv.URL),
		step(model.ActionCreateIncident, map[string]any{"title": "Credential stuffing"}), nil); err != nil {
		t.Fatalf("create_incident: %v", err)
	}

	got := log[0]
	if got.method != http.MethodPost || got.path != "/api/v1/incidents" {
		t.Errorf("called %s %s", got.method, got.path)
	}
	if got.body["source"] != "soar" {
		t.Errorf("source = %v, want soar so the incident says where it came from", got.body["source"])
	}
}

func TestMarkCompromisedCallsAttackPath(t *testing.T) {
	var log []seen
	srv := target(t, http.StatusNoContent, ``, &log)

	if _, err := do(t, dispatcher(t, srv.URL),
		step(model.ActionMarkCompromised, map[string]any{"node_id": "n-1"}), nil); err != nil {
		t.Fatalf("mark_compromised: %v", err)
	}

	got := log[0]
	if got.method != http.MethodPut || got.path != "/api/v1/attack/nodes/n-1/compromise" {
		t.Errorf("called %s %s", got.method, got.path)
	}
	if got.body["compromised"] != true {
		t.Errorf("body = %v", got.body)
	}
}

// ─── Missing parameters ───────────────────────────────────────────────────────

func TestActionsRefuseWithoutTheirRequiredParameter(t *testing.T) {
	var log []seen
	srv := target(t, http.StatusOK, `{}`, &log)
	d := dispatcher(t, srv.URL)

	for _, action := range []string{
		model.ActionBlockIP, model.ActionDisableUser, model.ActionIsolateHost,
		model.ActionEnrichIOC, model.ActionAddToBlocklist, model.ActionCreateTicket,
		model.ActionCloseTicket, model.ActionMarkCompromised, model.ActionCreateIncident,
		model.ActionRunSIEMQuery, model.ActionTagEntity, model.ActionUnblockIP,
	} {
		t.Run(action, func(t *testing.T) {
			log = nil
			if _, err := do(t, d, step(action, nil), nil); err == nil {
				t.Error("ran with no parameters at all")
			}
			if len(log) != 0 {
				t.Error("a request was made despite the missing parameter")
			}
		})
	}
}

func TestAnUnknownActionIsAnError(t *testing.T) {
	var log []seen
	srv := target(t, http.StatusOK, `{}`, &log)
	if _, err := do(t, dispatcher(t, srv.URL), step("launch_missiles", nil), nil); err == nil {
		t.Error("an unknown action type was accepted")
	}
}

// ─── The record of what happened ──────────────────────────────────────────────

func TestOutputRecordsWhatWasActuallyCalled(t *testing.T) {
	// The execution record is what an analyst reads afterwards. It has to say
	// which service was called and what it answered, not a fixed label.
	var log []seen
	srv := target(t, http.StatusCreated, `{"data":{"id":"p-1"}}`, &log)

	out, err := do(t, dispatcher(t, srv.URL),
		step(model.ActionBlockIP, map[string]any{"ip": "203.0.113.5"}), nil)
	if err != nil {
		t.Fatalf("block_ip: %v", err)
	}

	if out["service"] != "netsec" || out["status"] != http.StatusCreated {
		t.Errorf("output = %v, want the service and status it really got", out)
	}
	if dig(out, "response", "data", "id") != "p-1" {
		t.Errorf("output does not carry the service's own answer: %v", out)
	}
}

func TestStepTimeoutBoundsTheCall(t *testing.T) {
	// A step that hangs holds up every step behind it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/service-token" {
			//nolint:errcheck // test stub
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"access_token": "svc-token", "expires_at": time.Now().Add(time.Hour),
			}})
			return
		}
		time.Sleep(3 * time.Second)
	}))
	defer srv.Close()

	s := step(model.ActionBlockIP, map[string]any{"ip": "203.0.113.5"})
	s.TimeoutSec = 1

	start := time.Now()
	_, err := do(t, dispatcher(t, srv.URL), s, nil)
	if err == nil {
		t.Fatal("a hanging service produced no error")
	}
	if elapsed := time.Since(start); elapsed > 2500*time.Millisecond {
		t.Errorf("took %v, want the step's 1s timeout to bound it", elapsed)
	}
}
