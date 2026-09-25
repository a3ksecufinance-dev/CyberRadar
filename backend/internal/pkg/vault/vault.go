// Package vault reads secrets from HashiCorp Vault, falling back to the
// environment.
//
// Vault was already deployed and three services carried VAULT_ADDR, but no Go
// code ever connected to it: every secret — database passwords, the JWT signing
// key — came from an environment variable. Environment variables are readable
// from `docker inspect`, from the process table and from a crash dump, which is
// the exposure Vault exists to remove.
//
// The fallback is deliberate. A platform that refuses to start without Vault
// cannot be run by a developer on a laptop, so Resolve prefers Vault when it is
// configured and uses the environment when it is not — and says which it used,
// so an operator can tell whether production is really reading from Vault.
package vault

import (
	"context"
	"fmt"
	"os"

	vaultapi "github.com/hashicorp/vault/api"
)

// DefaultMount is the KV v2 mount a dev-mode Vault exposes.
const DefaultMount = "secret"

// Client reads secrets from a KV v2 mount.
type Client struct {
	kv *vaultapi.KVv2
}

// New builds a client for addr using token, reading from the given KV v2 mount.
func New(addr, token, mount string) (*Client, error) {
	if addr == "" {
		return nil, fmt.Errorf("vault address is empty")
	}
	if mount == "" {
		mount = DefaultMount
	}

	cfg := vaultapi.DefaultConfig()
	cfg.Address = addr
	api, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("vault client: %w", err)
	}
	api.SetToken(token)

	return &Client{kv: api.KVv2(mount)}, nil
}

// NewFromEnv builds a client from VAULT_ADDR, VAULT_TOKEN and VAULT_KV_MOUNT.
// It returns (nil, nil) when VAULT_ADDR is unset: Vault is optional, and an
// absent address means "not configured" rather than "misconfigured".
func NewFromEnv() (*Client, error) {
	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		return nil, nil
	}
	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("VAULT_ADDR is set but VAULT_TOKEN is empty")
	}
	return New(addr, token, os.Getenv("VAULT_KV_MOUNT"))
}

// Secret reads one field of the secret stored at path.
func (c *Client) Secret(ctx context.Context, path, field string) (string, error) {
	s, err := c.kv.Get(ctx, path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	if s == nil || s.Data == nil {
		return "", fmt.Errorf("read %s: no data", path)
	}

	raw, ok := s.Data[field]
	if !ok {
		return "", fmt.Errorf("read %s: no field %q", path, field)
	}
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("read %s: field %q is %T, want string", path, field, raw)
	}
	return value, nil
}

// Origin says where a resolved value came from, so a service can log it and an
// operator can confirm production reads from Vault rather than the environment.
type Origin string

const (
	FromVault       Origin = "vault"
	FromEnvironment Origin = "env"
)

// Resolver reads secrets from Vault when one is configured, and from the
// environment otherwise. A nil client is valid and means environment-only.
type Resolver struct {
	client *Client
	prefix string
}

// NewResolver builds a Resolver. prefix is prepended to every secret path, so a
// service reads "crp/identity/db" as NewResolver(c, "crp/identity").Get(ctx, "db", ...).
func NewResolver(client *Client, prefix string) *Resolver {
	return &Resolver{client: client, prefix: prefix}
}

// Enabled reports whether a Vault client is configured.
func (r *Resolver) Enabled() bool { return r != nil && r.client != nil }

// Get returns the secret at path/field, falling back to the environment
// variable envVar. It reports where the value came from.
//
// A Vault read that fails is reported rather than silently falling through: a
// service quietly running on an environment fallback when it was meant to use
// Vault is exactly the misconfiguration this package should surface.
func (r *Resolver) Get(ctx context.Context, path, field, envVar string) (string, Origin, error) {
	if r.Enabled() {
		value, err := r.client.Secret(ctx, r.join(path), field)
		if err == nil {
			return value, FromVault, nil
		}
		if fallback := os.Getenv(envVar); fallback != "" {
			return fallback, FromEnvironment, err
		}
		return "", FromVault, err
	}

	value := os.Getenv(envVar)
	if value == "" {
		return "", FromEnvironment, fmt.Errorf("%s is not set and Vault is not configured", envVar)
	}
	return value, FromEnvironment, nil
}

func (r *Resolver) join(path string) string {
	if r.prefix == "" {
		return path
	}
	return r.prefix + "/" + path
}
