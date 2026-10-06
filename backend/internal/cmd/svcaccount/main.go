// Command svcaccount creates the service account a service needs in order to
// call the others, and keeps its secret in a file.
//
// It exists because of a hole this platform shipped with: the SOAR acts under
// its own identity, by design and as documented — a playbook that blocks an
// address must not do it as the analyst who pressed run, both because the
// analyst may not hold netsec:write and because the audit trail would then
// name the wrong actor. The design was right, the configuration was there, and
// nothing anywhere created the account. Every installation started the SOAR
// with SOAR_CLIENT_SECRET=change-me-create-the-account-first, so every action
// that reached another service answered 401 and every containment step failed.
// The end-to-end chain found it on its first full run.
//
//	svcaccount -client-id soar-executor -role soar_executor -out .dev-local/soar-executor.json
//
// Run again, it reuses the file when the credential still works, because the
// client id carries a unique index that a revoked account still occupies:
// "revoke and recreate under the same name" is not something an operator can
// do either, and a tool that silently issued a second credential would leave
// an operator with a list of them and no idea which is live.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyberradar/platform/internal/pkg/devtoken"
)

type credential struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func main() {
	var (
		clientID = flag.String("client-id", "", "the account's client id, e.g. soar-executor")
		roleName = flag.String("role", "", "the role to grant it, by name, e.g. soar_executor")
		out      = flag.String("out", "", "where to keep the credential")
		identity = flag.String("identity", envOr("IDENTITY_URL", "http://localhost:8002"), "the identity service")
		dsn      = flag.String("dsn", envOr("DATABASE_URL", "postgres://crp_user:crp_password_dev@localhost:5432/crp_foundation?sslmode=disable"), "PostgreSQL, to resolve the role and mint a token")
		keyPath  = flag.String("key", envOr("JWT_PRIVATE_KEY_PATH", "deployments/jwt/private.pem"), "the signing key")
		as       = flag.String("as", envOr("CRP_ADMIN_EMAIL", "admin@cyberradar.io"), "the identity to act as")
		days     = flag.Int("expires-in-days", 365, "how long the credential is valid")
		quiet    = flag.Bool("quiet", false, "print the export lines and nothing else")
	)
	flag.Parse()

	if *clientID == "" || *roleName == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "-client-id, -role and -out are all required")
		flag.Usage()
		os.Exit(2)
	}

	if err := run(*clientID, *roleName, *out, *identity, *dsn, *keyPath, *as, *days, *quiet); err != nil {
		fmt.Fprintf(os.Stderr, "svcaccount: %v\n", err)
		os.Exit(1)
	}
}

func run(clientID, roleName, out, identity, dsn, keyPath, as string, days int, quiet bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", dsn, err)
	}
	defer pool.Close()

	// Any tenant will do for the check below: a platform-scoped account has
	// to name the tenant it acts for, and the question here is only whether
	// the secret still authenticates.
	var anyTenant string
	_ = pool.QueryRow(ctx,
		`SELECT id::text FROM tenants WHERE deleted_at IS NULL ORDER BY created_at LIMIT 1`).Scan(&anyTenant)

	// An existing credential that still works is the answer.
	if cred, err := read(out); err == nil {
		if _, err := exchange(ctx, identity, cred, anyTenant); err == nil {
			emit(cred, quiet, "reused "+out)
			return nil
		}
		// It no longer works — revoked, or from a database since reset. Fall
		// through and create one, under a name the unique index allows.
	}

	token, _, err := devtoken.Mint(ctx, pool, keyPath, as)
	if err != nil {
		return fmt.Errorf("mint a token as %s: %w", as, err)
	}

	var roleID uuid.UUID
	if err := pool.QueryRow(ctx,
		`SELECT id FROM roles WHERE name = $1 LIMIT 1`, roleName).Scan(&roleID); err != nil {
		return fmt.Errorf("no role named %s: %w", roleName, err)
	}

	cred, err := create(ctx, identity, token, clientID, roleID, days)
	if err != nil {
		return err
	}
	if err := write(out, cred); err != nil {
		return err
	}
	emit(cred, quiet, "created "+cred.ClientID)
	return nil
}

// create asks the identity service for the account. A client id already taken
// is reported as such rather than retried under a mangled name: an operator
// who sees two accounts for one service cannot tell which is live.
func create(ctx context.Context, identity, token, clientID string, roleID uuid.UUID, days int) (credential, error) {
	body, _ := json.Marshal(map[string]any{
		"client_id":       clientID,
		"description":     "Created by internal/cmd/svcaccount.",
		"scope":           "platform",
		"role_ids":        []uuid.UUID{roleID},
		"expires_in_days": days,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		identity+"/api/v1/service-accounts", bytes.NewReader(body))
	if err != nil {
		return credential{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return credential{}, fmt.Errorf("reach the identity service at %s: %w", identity, err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return credential{}, fmt.Errorf("create %s: %s: %s", clientID, resp.Status, trim(raw))
	}

	var env struct {
		Data credential `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return credential{}, fmt.Errorf("decode the answer: %w", err)
	}
	if env.Data.ClientSecret == "" {
		return credential{}, fmt.Errorf("%s was created without a secret", clientID)
	}
	return env.Data, nil
}

// exchange proves a credential still works, which is the only way to know:
// the secret is hashed, so it cannot be compared against the stored one.
func exchange(ctx context.Context, identity string, cred credential, tenantID string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"client_id":     cred.ClientID,
		"client_secret": cred.ClientSecret,
		"tenant_id":     tenantID,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		identity+"/api/v1/auth/service-token", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck // read-only
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("%s: %s", resp.Status, trim(raw))
	}
	var env struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(raw, &env)
	if env.Data.AccessToken != "" {
		return env.Data.AccessToken, nil
	}
	if env.AccessToken == "" {
		return "", fmt.Errorf("the exchange returned no token")
	}
	return env.AccessToken, nil
}

func read(path string) (credential, error) {
	var cred credential
	raw, err := os.ReadFile(path)
	if err != nil {
		return cred, err
	}
	if err := json.Unmarshal(raw, &cred); err != nil {
		return cred, err
	}
	if cred.ClientID == "" || cred.ClientSecret == "" {
		return cred, fmt.Errorf("%s holds no credential", path)
	}
	return cred, nil
}

func write(path string, cred credential) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cred, "", "  ")
	if err != nil {
		return err
	}
	// 0600: it is a live credential for acting on other services.
	return os.WriteFile(path, raw, 0o600)
}

// emit prints the two export lines a caller can evaluate, and the note on
// standard error so that evaluating the output stays safe.
func emit(cred credential, quiet bool, note string) {
	if !quiet {
		fmt.Fprintf(os.Stderr, "svcaccount: %s\n", note)
	}
	fmt.Printf("CLIENT_ID=%s\nCLIENT_SECRET=%s\n", cred.ClientID, cred.ClientSecret)
}

func trim(raw []byte) string {
	s := string(raw)
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	return s
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
