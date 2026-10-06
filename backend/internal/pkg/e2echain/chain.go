// Package e2echain drives one attack, end to end, across the services that are
// supposed to answer it: an event is ingested, the rule engine raises an alert,
// an analyst promotes it to a case, a playbook runs, the address is blocked at
// the network, and the audit trail records who did the blocking.
//
// Every one of those steps has a unit test. None of them had a test that the
// *next* step happens, and that is where this platform's defects live: the
// SOAR's block_ip action posts to netsec's policy endpoint, which answered 500
// on every call for as long as it existed, because a RETURNING clause read a
// nullable column into a Go string. Six services were in that state. A chain
// that runs is the only thing that notices.
//
// It is also the only honest place to measure "time to containment", which is
// a number this product's own documentation quotes. Each step is timed and the
// table is printed, so the figure is a measurement rather than a hope.
package e2echain

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to one platform, as one identity.
type Client struct {
	HTTP  *http.Client
	Token string
	Ports map[string]string
}

// NewClient returns a client for the given identity.
func NewClient(token string, ports map[string]string) *Client {
	return &Client{
		HTTP:  &http.Client{Timeout: 30 * time.Second},
		Token: token,
		Ports: ports,
	}
}

// As returns the same client under another identity, for the steps a machine
// makes rather than a person.
func (c *Client) As(token string) *Client {
	return &Client{HTTP: c.HTTP, Token: token, Ports: c.Ports}
}

// Do makes one call and decodes the envelope's data into out.
//
// The platform answers {"data": …} on success and {"error": {...}} on failure;
// a caller that only checks the status code reads a zero-valued struct when a
// route is refused, which is how a chain comes to report a step that never
// happened.
func (c *Client) Do(ctx context.Context, method, service, path string, body, out any) error {
	port, ok := c.Ports[service]
	if !ok {
		return fmt.Errorf("%s is not a deployed service", service)
	}

	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode the body for %s %s: %w", method, path, err)
		}
		payload = bytes.NewReader(encoded)
	}

	url := "http://localhost:" + port + path
	req, err := http.NewRequestWithContext(ctx, method, url, payload)
	if err != nil {
		return fmt.Errorf("build %s %s: %w", method, url, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, url, err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("%s %s: read the answer: %w", method, url, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %s: %s", method, url, resp.Status, summarise(raw))
	}
	if out == nil {
		return nil
	}

	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err == nil && len(env.Data) > 0 {
		return json.Unmarshal(env.Data, out)
	}
	// Not every route wraps its answer; the collector's ingest does not.
	return json.Unmarshal(raw, out)
}

// summarise keeps an error body short enough to read in a failure message.
func summarise(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	return s
}

// Step is one leg of the chain, and what it cost.
type Step struct {
	Name     string
	Took     time.Duration
	Deadline time.Duration
}

// Timeline collects the steps in order so the whole run can be printed as one
// table — the thing an operator reads when asked how long containment takes.
type Timeline struct {
	Steps []Step
}

// Measure runs fn, records how long it took, and returns its error unchanged.
func (tl *Timeline) Measure(name string, deadline time.Duration, fn func() error) error {
	start := time.Now()
	err := fn()
	tl.Steps = append(tl.Steps, Step{Name: name, Took: time.Since(start), Deadline: deadline})
	return err
}

// Total is the wall time of every step measured.
func (tl *Timeline) Total() time.Duration {
	var total time.Duration
	for _, s := range tl.Steps {
		total += s.Took
	}
	return total
}

// String renders the table.
func (tl *Timeline) String() string {
	var b strings.Builder
	b.WriteString("\n  step                                     took     budget\n")
	for _, s := range tl.Steps {
		over := ""
		if s.Deadline > 0 && s.Took > s.Deadline {
			over = "  ← over budget"
		}
		fmt.Fprintf(&b, "  %-38s %7s   %7s%s\n",
			s.Name, round(s.Took), round(s.Deadline), over)
	}
	fmt.Fprintf(&b, "  %-38s %7s\n", "total", round(tl.Total()))
	return b.String()
}

func round(d time.Duration) string {
	if d == 0 {
		return "—"
	}
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(100 * time.Millisecond).String()
}

// Until polls fn until it reports true, or the deadline passes.
//
// Three of the six steps are asynchronous — the rule engine consumes from
// Kafka, the playbook executor runs steps in its own goroutine — so the chain
// cannot assert immediately after a write. Polling with a deadline is what
// turns "eventually" into a number: the step either happens inside its budget
// or the chain fails naming the budget it missed.
func Until(ctx context.Context, deadline, every time.Duration, fn func() (bool, error)) error {
	limit := time.Now().Add(deadline)
	var last error
	for {
		ok, err := fn()
		if ok {
			return nil
		}
		if err != nil {
			last = err
		}
		if time.Now().After(limit) {
			if last != nil {
				return fmt.Errorf("not within %s: %w", deadline, last)
			}
			return fmt.Errorf("not within %s", deadline)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(every):
		}
	}
}
