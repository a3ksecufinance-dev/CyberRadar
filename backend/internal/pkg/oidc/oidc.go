// Package oidc verifies access tokens issued by an external identity provider.
//
// The web interface signs users in against Keycloak and sends Keycloak's access
// token to the services. The services used to verify only tokens signed by
// identity-service, so every call from a browser was refused with 401 — the
// interface could sign a user in and then read nothing. Two issuers, no bridge.
//
// What this package settles is only *who the caller is*. Keycloak's realm roles
// are not the platform's: the realm ships dpo, risk_manager, platform_admin and
// the platform has tenant_admin, threat_hunter, super_admin. Mapping one
// vocabulary onto the other would mean maintaining both and keeping them in
// step. So authentication comes from the provider and authorisation stays with
// the platform's own matrix — see internal/pkg/rbac.
//
// No new dependency: the keys are read from the provider's JWKS and rebuilt as
// RSA public keys here, and the signature is checked by the golang-jwt already
// in use elsewhere.
package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Claims is what a verified provider token tells us about the caller.
//
// Deliberately little: a subject, an email, and the roles the provider happens
// to carry — recorded for the audit trail, never consulted for a permission.
type Claims struct {
	Subject   string
	Email     string
	Username  string
	Roles     []string
	Issuer    string
	ExpiresAt time.Time
}

// Config points at the provider.
type Config struct {
	// Issuer is the exact `iss` the tokens carry, e.g.
	// http://localhost:8080/realms/cyberradar. Empty means no external provider
	// is configured and nothing here runs.
	Issuer string
	// Audience, when set, must appear in the token's `aud` or match `azp`. A
	// token minted for another client of the same realm is then refused.
	Audience string
	// HTTPClient is used to fetch the discovery document and the keys.
	HTTPClient *http.Client
	// Clock skew allowed when checking expiry.
	Leeway time.Duration
}

// Verifier checks tokens against one provider's keys.
type Verifier struct {
	cfg     Config
	jwksURI string
	client  *http.Client

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

// minRefreshInterval bounds how often an unknown key id makes us re-fetch.
// Without it, a token with a made-up kid is a request to the provider — one per
// request, from thirty services.
const minRefreshInterval = 30 * time.Second

// New builds a Verifier and reads the provider's discovery document once, so a
// misconfigured issuer is a startup failure rather than a 401 per request.
func New(ctx context.Context, cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("oidc: issuer is required")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	if cfg.Leeway == 0 {
		cfg.Leeway = 30 * time.Second
	}
	cfg.Issuer = strings.TrimSuffix(cfg.Issuer, "/")

	v := &Verifier{cfg: cfg, client: cfg.HTTPClient, keys: map[string]*rsa.PublicKey{}}
	if err := v.discover(ctx); err != nil {
		return nil, err
	}
	if err := v.refresh(ctx); err != nil {
		return nil, err
	}
	return v, nil
}

// Issuer is the provider this verifier trusts.
func (v *Verifier) Issuer() string { return v.cfg.Issuer }

func (v *Verifier) discover(ctx context.Context) error {
	url := v.cfg.Issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("oidc discovery: %w", err)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("oidc discovery %s: %w", url, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc discovery %s: %s", url, resp.Status)
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("oidc discovery %s: %w", url, err)
	}
	// The document has to agree with the address it was fetched from, or a
	// token minted by whoever answered that address would be trusted.
	if strings.TrimSuffix(doc.Issuer, "/") != v.cfg.Issuer {
		return fmt.Errorf("oidc discovery: %s declares issuer %q", url, doc.Issuer)
	}
	if doc.JWKSURI == "" {
		return fmt.Errorf("oidc discovery %s: no jwks_uri", url)
	}
	v.jwksURI = doc.JWKSURI
	return nil
}

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (v *Verifier) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURI, nil)
	if err != nil {
		return fmt.Errorf("oidc jwks: %w", err)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("oidc jwks %s: %w", v.jwksURI, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc jwks %s: %s", v.jwksURI, resp.Status)
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("oidc jwks %s: %w", v.jwksURI, err)
	}

	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		// Signing keys only, and only RSA: an encryption key in the set is not
		// a key a signature may be checked against.
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		if k.Alg != "" && !strings.HasPrefix(k.Alg, "RS") {
			continue
		}
		pub, err := rsaKeyFromJWK(k)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return fmt.Errorf("oidc jwks %s: no usable RSA signing key", v.jwksURI)
	}

	v.mu.Lock()
	v.keys, v.fetchedAt = keys, time.Now()
	v.mu.Unlock()
	return nil
}

func rsaKeyFromJWK(k jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("exponent: %w", err)
	}
	if len(eBytes) == 0 || len(eBytes) > 8 {
		return nil, fmt.Errorf("exponent is %d bytes", len(eBytes))
	}
	padded := make([]byte, 8)
	copy(padded[8-len(eBytes):], eBytes)
	e := binary.BigEndian.Uint64(padded)
	if e == 0 || e > 1<<31 {
		return nil, fmt.Errorf("exponent out of range")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e)}, nil
}

// key returns the signing key for a key id, re-fetching once if it is unknown
// — which is what happens after the provider rotates its keys.
func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	k, ok := v.keys[kid]
	age := time.Since(v.fetchedAt)
	v.mu.RUnlock()
	if ok {
		return k, nil
	}
	if age < minRefreshInterval {
		return nil, fmt.Errorf("unknown key id %q", kid)
	}
	if err := v.refresh(ctx); err != nil {
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown key id %q", kid)
}
