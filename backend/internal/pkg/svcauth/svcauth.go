// Package svcauth lets a CRP service authenticate as itself.
//
// A service that calls another on a user's behalf should forward that user's
// token and stay inside their scope, as the copilot does. This package is for
// the other case: work with no user behind it — a playbook the SOAR runs from
// an alert, a scheduled job, an audit entry a service writes about its own
// activity. Before it existed those calls had no credential at all, so the
// endpoints they needed had to be left open to any valid token.
package svcauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// refreshMargin renews a token before it expires, so a call never fails
// because the token died between the check and the request reaching the
// server.
const refreshMargin = 60 * time.Second

// Config describes how a service authenticates.
type Config struct {
	// IdentityURL is the base URL of the identity service, e.g.
	// http://identity-service:8002.
	IdentityURL string

	ClientID     string
	ClientSecret string

	// TenantID is required for a platform-scoped account and must be left
	// empty for a tenant-scoped one. A TokenSource holds a token for one
	// tenant; a platform service acting for several needs one source per
	// tenant, which keeps a token from ever being reused across customers.
	TenantID string

	// HTTPClient is optional; a sensible default is used when nil.
	HTTPClient *http.Client
}

// TokenSource hands out a valid service token, fetching a new one when the
// current one is close to expiry. It is safe for concurrent use.
type TokenSource struct {
	cfg    Config
	client *http.Client

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// New builds a TokenSource. It does not contact identity: a service must be
// able to start while identity is still coming up.
func New(cfg Config) (*TokenSource, error) {
	if cfg.IdentityURL == "" {
		return nil, fmt.Errorf("svcauth: IdentityURL is required")
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("svcauth: ClientID and ClientSecret are required")
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &TokenSource{cfg: cfg, client: client}, nil
}

// Token returns a valid access token, fetching one if needed.
func (s *TokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.token != "" && time.Now().Add(refreshMargin).Before(s.expiresAt) {
		return s.token, nil
	}

	token, expiresAt, err := s.fetch(ctx)
	if err != nil {
		return "", err
	}
	s.token, s.expiresAt = token, expiresAt
	return token, nil
}

// Authorize sets the Authorization header on req.
func (s *TokenSource) Authorize(ctx context.Context, req *http.Request) error {
	token, err := s.Token(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

type tokenResponse struct {
	Data struct {
		AccessToken string    `json:"access_token"`
		ExpiresAt   time.Time `json:"expires_at"`
	} `json:"data"`

	// Some deployments front identity with a gateway that unwraps the
	// envelope, so the flat form is accepted too.
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (s *TokenSource) fetch(ctx context.Context) (string, time.Time, error) {
	body, err := json.Marshal(map[string]string{
		"client_id":     s.cfg.ClientID,
		"client_secret": s.cfg.ClientSecret,
		"tenant_id":     s.cfg.TenantID,
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("svcauth: marshal request: %w", err)
	}

	url := s.cfg.IdentityURL + "/api/v1/auth/service-token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("svcauth: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("svcauth: call identity: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// The body may carry the reason but also echoes nothing secret; the
		// credential is never in the response.
		return "", time.Time{}, fmt.Errorf("svcauth: identity answered %s", resp.Status)
	}

	var parsed tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", time.Time{}, fmt.Errorf("svcauth: decode response: %w", err)
	}

	token, expiresAt := parsed.Data.AccessToken, parsed.Data.ExpiresAt
	if token == "" {
		token, expiresAt = parsed.AccessToken, parsed.ExpiresAt
	}
	if token == "" {
		return "", time.Time{}, fmt.Errorf("svcauth: identity returned no access token")
	}
	if expiresAt.IsZero() {
		// Never treat an unknown expiry as unlimited.
		expiresAt = time.Now().Add(5 * time.Minute)
	}
	return token, expiresAt, nil
}
