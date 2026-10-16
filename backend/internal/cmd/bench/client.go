package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// The bench talks to the platform the way the interface and a connector do —
// one bearer token, the /api/v1 prefix, the standard envelope. Measuring
// anything through a back door would measure a path no customer takes.

var services = map[string]struct {
	port int
	env  string
}{
	"identity":  {8002, "IDENTITY_SERVICE_URL"},
	"collector": {8005, "COLLECTOR_SERVICE_URL"},
	"asset":     {8006, "ASSET_SERVICE_URL"},
	"siem":      {8008, "SIEM_SERVICE_URL"},
	"ir":        {8026, "IR_SERVICE_URL"},
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

type client struct {
	http  *http.Client
	token string
	base  map[string]string
}

func newClient(token string, base map[string]string) *client {
	return &client{
		// Connections are pooled deliberately: a bench that opened a socket
		// per request would measure the handshake, and the figure would get
		// better the day somebody turned keep-alive on.
		http: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        256,
				MaxIdleConnsPerHost: 256,
				MaxConnsPerHost:     256,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		token: token,
		base:  base,
	}
}

type envelope struct {
	Data  json.RawMessage `json:"data"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
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
			return err
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
	var env envelope
	if uerr := json.Unmarshal(raw, &env); uerr != nil {
		return fmt.Errorf("%s %s → %d: %s", method, path, resp.StatusCode, truncate(string(raw), 200))
	}
	if resp.StatusCode >= 300 {
		if env.Error != nil {
			return fmt.Errorf("%s %s → %d %s: %s", method, path, resp.StatusCode, env.Error.Code, env.Error.Message)
		}
		return fmt.Errorf("%s %s → %d", method, path, resp.StatusCode)
	}
	if out != nil && len(env.Data) > 0 {
		if err := json.Unmarshal(env.Data, out); err != nil {
			return fmt.Errorf("decode %s %s: %w", method, path, err)
		}
	}
	return nil
}

func (c *client) post(ctx context.Context, service, path string, body, out any) error {
	return c.do(ctx, http.MethodPost, service, path, body, out)
}

func (c *client) get(ctx context.Context, service, path string, query url.Values, out any) error {
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	return c.do(ctx, http.MethodGet, service, path, nil, out)
}

// connectorClient exchanges the credential demo-seed stored for a token that
// carries events:ingest. The bench does not onboard one of its own: a tool
// that creates service accounts every time it runs leaves a list of them
// behind, and the credential on disk is the same connector a demonstration
// uses.
func connectorClient(ctx context.Context, admin *client, path string) (*client, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // an operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("read the connector credential at %s: %w", path, err)
	}
	var cred struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal(raw, &cred); err != nil {
		return nil, fmt.Errorf("%s is not a credential: %w", path, err)
	}
	if cred.ClientID == "" || cred.ClientSecret == "" {
		return nil, fmt.Errorf("%s holds no credential", path)
	}
	var granted struct {
		AccessToken string `json:"access_token"`
	}
	if err := admin.post(ctx, "identity", "/api/v1/auth/service-token", map[string]any{
		"client_id":     cred.ClientID,
		"client_secret": cred.ClientSecret,
	}, &granted); err != nil {
		return nil, fmt.Errorf("exchange the %s credential: %w", cred.ClientID, err)
	}
	if granted.AccessToken == "" {
		return nil, fmt.Errorf("the identity service granted no token for %s", cred.ClientID)
	}
	return newClient(granted.AccessToken, admin.base), nil
}

// decodeRows reads a list response whether the service answers with a bare
// array or wraps it beside its own total. Both shapes are in use.
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
	return nil, nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
