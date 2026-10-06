package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	"github.com/google/uuid"
)

// recorder stands in for a platform service and keeps what was asked of it.
type recorder struct {
	server *httptest.Server
	method string
	path   string
	body   string
	status int
	reply  string
}

func newRecorder(t *testing.T) *recorder {
	t.Helper()
	r := &recorder{status: http.StatusOK, reply: `{"data":[]}`}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		raw, _ := io.ReadAll(req.Body)
		r.method, r.path, r.body = req.Method, req.URL.Path, string(raw)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(r.status)
		//nolint:errcheck // test server
		io.WriteString(w, r.reply)
	}))
	t.Cleanup(r.server.Close)
	return r
}

func callerContext() context.Context {
	return authctx.With(context.Background(), authctx.Identity{
		TenantID: uuid.New(),
		UserID:   uuid.New(),
		Token:    "caller-token",
	})
}

// Every tool must reach a route the platform actually mounts. Three of them
// did not — they asked for /api/v1/alerts, /api/v1/findings and
// /api/v1/iocs/lookup, and each got a 404 page the model then read as "no
// results". A wrong prefix is invisible in production: the answer comes back
// fluent, confident, and about nothing.
func TestEachToolCallsAMountedRoute(t *testing.T) {
	cases := []struct {
		tool    string
		service string
		input   map[string]any
		method  string
		path    string
	}{
		{"query_alerts", "siem", map[string]any{"limit": 5}, http.MethodGet, "/api/v1/siem/alerts"},
		{"lookup_ioc", "ti", map[string]any{"value": "198.51.100.23"}, http.MethodPost, "/api/v1/ti/iocs/lookup"},
		{"get_incident", "soar", map[string]any{"limit": 5}, http.MethodGet, "/api/v1/soar/incidents"},
		{"query_anomalies", "ueba", map[string]any{"limit": 5}, http.MethodGet, "/api/v1/ueba/anomalies"},
		{"query_vulnerabilities", "vuln", map[string]any{"limit": 5}, http.MethodGet, "/api/v1/vuln/findings"},
		{"analyze_attack_path", "attackpath", map[string]any{"limit": 5}, http.MethodGet, "/api/v1/attack/paths"},
		{"search_entities", "kg", map[string]any{"limit": 5}, http.MethodGet, "/api/v1/kg/entities"},
		{"get_asset", "asset", map[string]any{"hostname": "db-core-01"}, http.MethodGet, "/api/v1/assets"},
		{"query_platform_stats", "dashboard", map[string]any{}, http.MethodGet, "/api/v1/dashboard/overview"},
	}

	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			rec := newRecorder(t)
			d := NewToolDispatcher(map[string]string{tc.service: rec.server.URL})

			if _, err := d.Dispatch(callerContext(), tc.tool, tc.input); err != nil {
				t.Fatalf("Dispatch: %v", err)
			}
			if rec.method != tc.method {
				t.Errorf("method = %s, want %s", rec.method, tc.method)
			}
			if rec.path != tc.path {
				t.Errorf("path = %s, want %s", rec.path, tc.path)
			}
		})
	}
}

// The caller's own token goes with every call. Without it the Copilot would
// read with whatever authority the service itself holds, which is more than
// the person asking has.
func TestToolsCarryTheCallersToken(t *testing.T) {
	var seen string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		seen = req.Header.Get("Authorization")
		//nolint:errcheck // test server
		io.WriteString(w, `{"data":[]}`)
	}))
	defer server.Close()

	d := NewToolDispatcher(map[string]string{"siem": server.URL})
	if _, err := d.Dispatch(callerContext(), "query_alerts", map[string]any{}); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if seen != "Bearer caller-token" {
		t.Errorf("Authorization = %q, want the caller's token", seen)
	}
}

// Without a caller there is no authority to borrow, so the call must not go
// out at all.
func TestToolsRefuseToCallWithoutACaller(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		t.Error("a service was called with no caller in context")
	}))
	defer server.Close()

	d := NewToolDispatcher(map[string]string{"siem": server.URL})
	if _, err := d.Dispatch(context.Background(), "query_alerts", map[string]any{}); err == nil {
		t.Fatal("the call was made without a caller token")
	}
}

// A refusal must reach the model as a refusal. Reported as data it becomes
// "there are no alerts" — an answer that is wrong and sounds certain.
func TestARefusalIsNotReportedAsAnEmptyResult(t *testing.T) {
	rec := newRecorder(t)
	rec.status = http.StatusNotFound
	rec.reply = "404 page not found\n"

	d := NewToolDispatcher(map[string]string{"siem": rec.server.URL})
	out, err := d.Dispatch(callerContext(), "query_alerts", map[string]any{})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if out["error"] != true {
		t.Fatalf("result = %#v, want it marked as an error", out)
	}
	if out["status_code"] != http.StatusNotFound {
		t.Errorf("status_code = %v, want 404", out["status_code"])
	}
}

// The lookup endpoint requires a type; the tool declares it optional. The
// value says what it is, so deriving it beats a round trip that is rejected.
func TestIOCTypeIsInferredFromTheValue(t *testing.T) {
	for value, want := range map[string]string{
		"198.51.100.23":          "ip",
		"2001:db8::1":            "ip",
		"evil.example":           "domain",
		"https://evil.example/x": "url",
		"someone@evil.example":   "email",
		"CVE-2024-3400":          "cve",
		"9f2b6c1d5a4e3f8b7c0d9e2a1b4c6d8e0f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c": "hash_sha256",
		"1a3c5e7092b4d6f8001a3c5e7092b4d6":                                 "hash_md5",
		"1a3c5e7092b4d6f8001a3c5e7092b4d6f8001a3c":                         "hash_sha1",
	} {
		if got := inferIOCType(value); got != want {
			t.Errorf("inferIOCType(%q) = %q, want %q", value, got, want)
		}
	}
}

// The inferred type has to be one the endpoint accepts, or the lookup is
// rejected at validation with the type this code chose.
func TestTheInferredTypeIsSentInTheBody(t *testing.T) {
	rec := newRecorder(t)
	rec.reply = `{"data":{"matched":false}}`

	d := NewToolDispatcher(map[string]string{"ti": rec.server.URL})
	if _, err := d.Dispatch(callerContext(), "lookup_ioc", map[string]any{"value": "CVE-2024-3400"}); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}

	var sent map[string]string
	if err := json.Unmarshal([]byte(rec.body), &sent); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, rec.body)
	}
	if sent["type"] != "cve" || sent["value"] != "CVE-2024-3400" {
		t.Errorf("body = %v, want the value and the inferred type", sent)
	}
}
