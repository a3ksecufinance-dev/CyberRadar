// Package apicheck exercises every service's read paths against a running
// platform.
//
// It exists because of a class of defect that no build and no unit test sees: a
// column that may be NULL scanned into a Go string. The read compiles, passes
// review, and answers 500 the first time the column is empty — so the page is
// blank, the log says "an internal error occurred", and nothing says which
// column. Two were found, in the incident response and OT services, by running
// six services and clicking through them. Twenty-four services were never
// exercised at all.
//
// Reading every list endpoint of every service against a populated estate
// finds the whole class in one pass, and keeps finding it: a service added
// without a probe fails the coverage test, and a probe that starts answering
// 500 fails the smoke test.
package apicheck

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Probe is one read to make.
type Probe struct {
	// Service is the key used by the deployment tables — the same name
	// scripts/dev-local.sh and docker-compose use, minus the "-service" suffix.
	Service string
	Path    string
	// Origin says where the probe came from, so a failure points at what is
	// broken: the interface's own contract, or a path only this package knows.
	Origin string
}

// FrontendRoutes reads the interface's own route table.
//
// Parsed rather than copied: the table in frontend/src/lib/api.ts is what the
// interface actually calls, so a route it gains is covered here without anyone
// remembering to add it, and a route it renames cannot leave a stale probe
// passing against an endpoint nobody uses.
func FrontendRoutes(backendRoot string) ([]Probe, error) {
	path := filepath.Join(backendRoot, "..", "frontend", "src", "lib", "api.ts")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the interface's route table: %w", err)
	}

	body, err := routesObject(string(raw))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	var probes []Probe
	service := ""
	for _, line := range strings.Split(body, "\n") {
		if m := serviceLine.FindStringSubmatch(line); m != nil {
			service = m[1]
			continue
		}
		if m := pathLine.FindStringSubmatch(line); m != nil && service != "" {
			probes = append(probes, Probe{Service: service, Path: m[1], Origin: "frontend ROUTES"})
		}
	}
	if len(probes) == 0 {
		return nil, fmt.Errorf("%s: the route table parsed to nothing", path)
	}
	return probes, nil
}

var (
	serviceLine = regexp.MustCompile(`^\s{2}([a-zA-Z]+):\s*\{`)
	pathLine    = regexp.MustCompile(`^\s+[a-zA-Z]+:\s*'(/api/v1/[^']+)'`)
)

// routesObject returns the body of the ROUTES object literal, brace-matched so
// that a nested object cannot end it early.
func routesObject(src string) (string, error) {
	const marker = "export const ROUTES"
	i := strings.Index(src, marker)
	if i < 0 {
		return "", fmt.Errorf("no %q", marker)
	}
	open := strings.Index(src[i:], "{")
	if open < 0 {
		return "", fmt.Errorf("%s has no object literal", marker)
	}
	open += i

	depth := 0
	for j := open; j < len(src); j++ {
		switch src[j] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[open : j+1], nil
			}
		}
	}
	return "", fmt.Errorf("%s: unbalanced braces", marker)
}

// BackendRoutes are the read paths of the services the interface does not call.
//
// Fourteen services have no page yet. Some are reached by the Copilot's tools,
// some by nothing at all — and those are precisely the ones whose reads have
// never been run, which is where the defect this package hunts survives. They
// are listed by hand because there is no client to parse; the coverage test
// below is what stops the list going stale.
var BackendRoutes = []Probe{
	{"tenant", "/api/v1/tenants", "apicheck"},
	{"siem", "/api/v1/siem/rule-library", "apicheck"},
	{"siem", "/api/v1/siem/rule-library/coverage", "apicheck"},
	{"tenant", "/api/v1/risk-profiles/presets", "apicheck"},
	{"tenant", "/api/v1/risk-profiles/active", "apicheck"},
	{"tenant", "/api/v1/risk-profiles/history", "apicheck"},
	{"tenant", "/api/v1/remediation-policies/presets", "apicheck"},
	{"tenant", "/api/v1/remediation-policies/active", "apicheck"},
	{"tenant", "/api/v1/remediation-policies/history", "apicheck"},
	{"audit", "/api/v1/audit/events", "apicheck"},
	{"notification", "/api/v1/notifications/rules", "apicheck"},
	{"pam", "/api/v1/pam/accounts", "apicheck"},
	{"pam", "/api/v1/pam/requests", "apicheck"},
	{"pam", "/api/v1/pam/sessions", "apicheck"},
	{"pam", "/api/v1/pam/identities/high-risk", "apicheck"},
	{"ueba", "/api/v1/ueba/profiles", "apicheck"},
	{"ueba", "/api/v1/ueba/anomalies", "apicheck"},
	{"ueba", "/api/v1/ueba/anomalies/stats", "apicheck"},
	{"ueba", "/api/v1/ueba/peer-groups", "apicheck"},
	{"soar", "/api/v1/soar/incidents", "apicheck"},
	{"soar", "/api/v1/soar/playbooks", "apicheck"},
	{"soar", "/api/v1/soar/executions", "apicheck"},
	{"soar", "/api/v1/soar/stats", "apicheck"},
	{"knowledgegraph", "/api/v1/kg/entities", "apicheck"},
	{"knowledgegraph", "/api/v1/kg/subgraph", "apicheck"},
	{"knowledgegraph", "/api/v1/kg/stats", "apicheck"},
	{"easm", "/api/v1/easm/assets", "apicheck"},
	{"easm", "/api/v1/easm/exposures", "apicheck"},
	{"easm", "/api/v1/easm/leaks", "apicheck"},
	{"easm", "/api/v1/easm/brand-alerts", "apicheck"},
	{"easm", "/api/v1/easm/scans", "apicheck"},
	{"easm", "/api/v1/easm/risk-score", "apicheck"},
	{"easm", "/api/v1/easm/stats", "apicheck"},
	{"fraud", "/api/v1/fraud/rules", "apicheck"},
	{"fraud", "/api/v1/fraud/transactions", "apicheck"},
	{"fraud", "/api/v1/fraud/cases", "apicheck"},
	{"fraud", "/api/v1/fraud/watchlist", "apicheck"},
	{"fraud", "/api/v1/fraud/stats", "apicheck"},
	{"dlp", "/api/v1/dlp/labels", "apicheck"},
	{"dlp", "/api/v1/dlp/assets", "apicheck"},
	{"dlp", "/api/v1/dlp/policies", "apicheck"},
	{"dlp", "/api/v1/dlp/violations", "apicheck"},
	{"dlp", "/api/v1/dlp/scans", "apicheck"},
	{"dlp", "/api/v1/dlp/stats", "apicheck"},
	{"netsec", "/api/v1/netsec/zones", "apicheck"},
	{"netsec", "/api/v1/netsec/policies", "apicheck"},
	{"netsec", "/api/v1/netsec/flows", "apicheck"},
	{"netsec", "/api/v1/netsec/anomalies", "apicheck"},
	{"netsec", "/api/v1/netsec/devices", "apicheck"},
	{"netsec", "/api/v1/netsec/topology", "apicheck"},
	{"netsec", "/api/v1/netsec/stats", "apicheck"},
	{"iga", "/api/v1/iga/roles", "apicheck"},
	{"iga", "/api/v1/iga/assignments", "apicheck"},
	{"iga", "/api/v1/iga/campaigns", "apicheck"},
	{"iga", "/api/v1/iga/reviews", "apicheck"},
	{"iga", "/api/v1/iga/sod/policies", "apicheck"},
	{"iga", "/api/v1/iga/sod/violations", "apicheck"},
	{"iga", "/api/v1/iga/stats", "apicheck"},
	{"cspm", "/api/v1/cspm/accounts", "apicheck"},
	{"cspm", "/api/v1/cspm/rules", "apicheck"},
	{"cspm", "/api/v1/cspm/resources", "apicheck"},
	{"cspm", "/api/v1/cspm/findings", "apicheck"},
	{"cspm", "/api/v1/cspm/scans", "apicheck"},
	{"cspm", "/api/v1/cspm/stats", "apicheck"},
}

// NoReadRoutes are the services that expose nothing to read, and why.
//
// The coverage test needs them named: a service with no probe is either one of
// these or an oversight, and there is no way to tell the two apart from a
// count.
var NoReadRoutes = map[string]string{
	// Ingestion and liveness only, both for machines. There is nothing for a
	// person to read here, which is the design — see the collector's routes.
	"collector": "write-only: events:ingest and heartbeat, both service-account",
}

// requiredParams are the query parameters a route refuses to answer without.
//
// Five routes were being logged as "refused" and so never exercised at all —
// which defeats the point: an unexercised read is exactly where the defect
// this package hunts survives. The values need not match anything; an empty
// result runs the same scan code as a full one.
//
// The identifiers are fixed rather than random so a failure is reproducible.
var requiredParams = map[string]string{
	"/api/v1/cspm/scans":                  "account_id=00000000-0000-4000-8000-000000000001",
	"/api/v1/dashboard/kpi/snapshot":      "domain=siem",
	"/api/v1/dashboard/kpi/timeseries":    "domain=siem&metric_key=open_alerts",
	"/api/v1/dashboard/kpi/risk-timeline": "entity_type=asset&entity_id=00000000-0000-4000-8000-000000000002",
	"/api/v1/kg/subgraph":                 "ids=00000000-0000-4000-8000-000000000003",
}

// RequiredParams is the query string a route refuses to answer without, or
// empty for the routes that need none.
func RequiredParams(path string) string { return requiredParams[path] }

// All returns every probe, sorted so a failure list reads the same way twice.
// backendRoot is the backend directory; the interface sits beside it.
func All(backendRoot string) ([]Probe, error) {
	fromFrontend, err := FrontendRoutes(backendRoot)
	if err != nil {
		return nil, err
	}
	probes := append(fromFrontend, BackendRoutes...)
	sort.Slice(probes, func(i, j int) bool {
		if probes[i].Service != probes[j].Service {
			return probes[i].Service < probes[j].Service
		}
		return probes[i].Path < probes[j].Path
	})
	return probes, nil
}
