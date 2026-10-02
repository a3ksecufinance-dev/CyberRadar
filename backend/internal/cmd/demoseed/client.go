package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// client talks to the platform the way the web interface does: one bearer
// token, the /api/v1 prefix, and the standard envelope on the way back.
//
// It deliberately goes through HTTP rather than writing rows directly. A
// dataset inserted behind the services proves nothing — it would skip
// validation, authorization, tenant scoping, the KPI snapshots the dashboard
// reads and the graph the attack path analysis walks. Going through the API
// means the demonstration data is data the product itself could have produced.
type client struct {
	http  *http.Client
	token string
	base  map[string]string // service name → http://host:port
}

func newClient(token string, base map[string]string) *client {
	return &client{
		http:  &http.Client{Timeout: 60 * time.Second},
		token: token,
		base:  base,
	}
}

// envelope mirrors internal/pkg/response.Envelope.
type envelope struct {
	Data json.RawMessage `json:"data"`
	Meta *struct {
		Total int64 `json:"total"`
	} `json:"meta"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// apiError carries the status so a caller can tell "already there" (409) from
// a payload the service refused (422).
type apiError struct {
	Status  int
	Method  string
	Path    string
	Code    string
	Message string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("%s %s → %d %s: %s", e.Method, e.Path, e.Status, e.Code, e.Message)
}

func isNotFound(err error) bool {
	var ae *apiError
	if !asAPIError(err, &ae) {
		return false
	}
	return ae.Status == http.StatusNotFound
}

func isConflict(err error) bool {
	var ae *apiError
	if !asAPIError(err, &ae) {
		return false
	}
	return ae.Status == http.StatusConflict
}

func asAPIError(err error, target **apiError) bool {
	if ae, ok := err.(*apiError); ok {
		*target = ae
		return true
	}
	return false
}

func (c *client) do(ctx context.Context, method, service, path string, body, out any) error {
	base, ok := c.base[service]
	if !ok {
		return fmt.Errorf("no base URL for service %q", service)
	}

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal %s %s: %w", method, path, err)
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read %s %s: %w", method, path, err)
	}

	// 204 carries no body by design, and a delete answers with one.
	if len(bytes.TrimSpace(raw)) == 0 {
		if resp.StatusCode >= 300 {
			return &apiError{Status: resp.StatusCode, Method: method, Path: path,
				Code: "EMPTY", Message: "the service answered with no body"}
		}
		return nil
	}

	var env envelope
	// A service that answers with something other than the envelope (a proxy
	// error page, say) must not be reported as an empty success.
	if uerr := json.Unmarshal(raw, &env); uerr != nil {
		if resp.StatusCode >= 300 {
			return &apiError{Status: resp.StatusCode, Method: method, Path: path,
				Code: "NON_JSON", Message: truncate(string(raw), 200)}
		}
		return fmt.Errorf("%s %s: response is not the API envelope: %s", method, path, truncate(string(raw), 200))
	}

	if resp.StatusCode >= 300 {
		ae := &apiError{Status: resp.StatusCode, Method: method, Path: path}
		if env.Error != nil {
			ae.Code, ae.Message = env.Error.Code, env.Error.Message
		} else {
			ae.Message = truncate(string(raw), 200)
		}
		return ae
	}

	if out != nil && len(env.Data) > 0 {
		if err := json.Unmarshal(env.Data, out); err != nil {
			return fmt.Errorf("decode %s %s data: %w", method, path, err)
		}
	}
	return nil
}

func (c *client) post(ctx context.Context, service, path string, body, out any) error {
	return c.do(ctx, http.MethodPost, service, path, body, out)
}

func (c *client) put(ctx context.Context, service, path string, body, out any) error {
	return c.do(ctx, http.MethodPut, service, path, body, out)
}

func (c *client) get(ctx context.Context, service, path string, query url.Values, out any) error {
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	return c.do(ctx, http.MethodGet, service, path, nil, out)
}

// count reads a list endpoint only for its meta.total, which is how the
// summary at the end reports what the interface will show.
func (c *client) count(ctx context.Context, service, path string) (int64, error) {
	base, ok := c.base[service]
	if !ok {
		return 0, fmt.Errorf("no base URL for service %q", service)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+path, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close() //nolint:errcheck // read-only
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return 0, fmt.Errorf("GET %s → %d", path, resp.StatusCode)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return 0, err
	}
	if env.Meta != nil {
		return env.Meta.Total, nil
	}
	// Without meta the total may still be inside the payload, beside the
	// list. Reading it matters: counting the rows of a page would report the
	// page size, which is a plausible-looking wrong number.
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(env.Data, &wrapper); err == nil {
		if rawTotal, ok := wrapper["total"]; ok {
			var total int64
			if err := json.Unmarshal(rawTotal, &total); err == nil {
				return total, nil
			}
		}
	}

	rows, err := decodeRows(env.Data)
	if err != nil {
		return 0, err
	}
	return int64(len(rows)), nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
