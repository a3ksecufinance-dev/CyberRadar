package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"
)

// seeder holds the identifiers each step hands to the next. The estate is a
// graph, not a list: a finding needs an asset and a vulnerability, an attack
// edge needs two nodes, a compliance assessment needs a control. Creating them
// in order and remembering the identifiers is the whole of the bookkeeping.
type seeder struct {
	c       *client
	verbose bool
	settle  time.Duration

	assets   map[string]uuid.UUID // asset name  → id
	vulns    map[string]uuid.UUID // CVE id      → id
	iocs     map[string]uuid.UUID // IOC value   → id
	nodes    map[string]uuid.UUID // node label  → id
	entities map[string]uuid.UUID // entity name → id
	controls map[string]uuid.UUID // control id  → id

	// collectorRole is the role a machine must hold to write events. Empty
	// when the platform has none, which the event step reports rather than
	// working around.
	collectorRole uuid.UUID

	// credentialPath is where the demonstration connector keeps its secret,
	// which is shown once and cannot be read back from the platform.
	credentialPath string

	written int
	reused  int
}

// naturalKeys names the field that identifies an object to a person, per
// create path. It is what makes a second run a no-op: each step lists what is
// there, and creates only the keys that are missing.
//
// The alternative — deleting the tenant's data first — would make the tool
// dangerous to run against anything but an empty install, which is exactly
// the install where one is most tempted to run it.
var naturalKeys = map[string]string{
	"/api/v1/assets":                "name",
	"/api/v1/vuln/vulnerabilities":  "cve_id",
	"/api/v1/ti/iocs":               "value",
	"/api/v1/ti/actors":             "name",
	"/api/v1/ti/feeds":              "name",
	"/api/v1/siem/rules":            "name",
	"/api/v1/soar/incidents":        "title",
	"/api/v1/attack/scenarios":      "name",
	"/api/v1/compliance/frameworks": "code",
	"/api/v1/compliance/controls":   "control_id",
	"/api/v1/compliance/risks":      "title",
	"/api/v1/kg/entities":           "name",
}

func (s *seeder) note(format string, args ...any) {
	if s.verbose {
		fmt.Printf("  %s\n", fmt.Sprintf(format, args...))
	}
}

// index reads a list endpoint and maps each object's natural key to its id.
func (s *seeder) index(ctx context.Context, service, path string) (map[string]uuid.UUID, error) {
	key, ok := naturalKeys[path]
	if !ok {
		return nil, fmt.Errorf("no natural key declared for %s", path)
	}

	var data json.RawMessage
	if err := s.c.get(ctx, service, path, url.Values{"limit": {"500"}}, &data); err != nil {
		return nil, fmt.Errorf("list %s: %w", path, err)
	}
	rows, err := decodeRows(data)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", path, err)
	}

	out := make(map[string]uuid.UUID, len(rows))
	for _, row := range rows {
		name, _ := row[key].(string)
		id, err := uuid.Parse(fmt.Sprint(row["id"]))
		if name == "" || err != nil {
			continue
		}
		out[name] = id
	}
	return out, nil
}

// ensure creates an object unless the index already holds its key, and returns
// the identifier either way.
func (s *seeder) ensure(ctx context.Context, idx map[string]uuid.UUID, key, service, path string, body any) (uuid.UUID, error) {
	if id, ok := idx[key]; ok {
		s.reused++
		s.note("· %s", key)
		return id, nil
	}

	var created struct {
		ID uuid.UUID `json:"id"`
	}
	err := s.c.post(ctx, service, path, body, &created)
	if err != nil {
		// A unique constraint means something created it between the listing
		// and now — or that the natural key here is not the one the service
		// enforces. Re-reading answers both cases without inventing a second
		// copy.
		if isConflict(err) {
			if refreshed, ferr := s.index(ctx, service, path); ferr == nil {
				if id, ok := refreshed[key]; ok {
					idx[key] = id
					s.reused++
					return id, nil
				}
			}
		}
		return uuid.Nil, fmt.Errorf("create %q: %w", key, err)
	}
	if created.ID == uuid.Nil {
		return uuid.Nil, fmt.Errorf("create %q: the service answered without an id", key)
	}

	idx[key] = created.ID
	s.written++
	s.note("+ %s", key)
	return created.ID, nil
}

// upsert posts to an endpoint that decides for itself whether the row is new.
// The attack graph and the knowledge graph both work this way — their keys are
// declared in the schema, so re-posting is the update.
func (s *seeder) upsert(ctx context.Context, service, path string, body any) (uuid.UUID, error) {
	var created struct {
		ID uuid.UUID `json:"id"`
	}
	if err := s.c.post(ctx, service, path, body, &created); err != nil {
		return uuid.Nil, err
	}
	s.written++
	return created.ID, nil
}

// softFail reports a step that could not run, without stopping the rest.
//
// A demonstration estate is worth more partially filled than not at all: one
// service being down should cost its own section, not the other eleven.
func (s *seeder) softFail(section string, err error) {
	fmt.Printf("  \033[33m!\033[0m %s: %v\n", section, err)
}

func step(name string) {
	fmt.Printf("\n\033[1m── %s\033[0m\n", name)
}

// decodeRows reads a list response whether the service answers with a bare
// array or wraps it in an object beside its own total.
//
// Both shapes are in use across the thirty services. Insisting on one here
// would mean either editing every handler to seed a demonstration — the tail
// wagging the dog — or a seeder that works on some pages and not others.
func decodeRows(data json.RawMessage) ([]map[string]any, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var rows []map[string]any
	if err := json.Unmarshal(data, &rows); err == nil {
		return rows, nil
	}

	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("response is neither a list nor an object: %w", err)
	}
	for _, v := range wrapper {
		var inner []map[string]any
		if err := json.Unmarshal(v, &inner); err == nil {
			return inner, nil
		}
	}
	// An object with no array inside is an empty page, not a failure.
	return nil, nil
}
