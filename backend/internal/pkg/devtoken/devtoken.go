// Package devtoken mints an access token for a real identity, for the tools
// that run beside a platform rather than inside it: the demonstration seeder,
// the read-path smoke check, a developer with curl.
//
// It exists so there is one implementation. Two tools each signing their own
// token is where the claims drift apart, and a tool that hands itself
// permissions no role grants seeds data no user of the platform could have
// created — hiding an authorization mistake instead of hitting it.
//
// The prerequisite is the signing key, which only the identity service and
// whoever runs the machine hold. Nothing here weakens that: a tool without the
// key gets nothing.
package devtoken

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyberradar/platform/internal/pkg/jwt"
	"github.com/cyberradar/platform/internal/pkg/rbac"
)

// DefaultTTL is short on purpose: these tokens are for a command that runs and
// exits, not for something left in a file.
const DefaultTTL = time.Hour

// Mint signs an access token for the identity behind email, carrying the
// permissions that identity's roles actually grant.
//
// It returns the grant as well as the token so a caller can say who it is
// acting as — and so a 403 later is read as "this role lacks that permission"
// rather than as a broken tool.
func Mint(ctx context.Context, pool *pgxpool.Pool, keyPath, email string) (string, *rbac.Grant, error) {
	grant, err := rbac.NewResolver(pool).ByEmail(ctx, email)
	if err != nil {
		return "", nil, fmt.Errorf("resolve %s: %w (has the identity seed been run?)", email, err)
	}

	signer, err := jwt.NewSignerFromFile(keyPath, DefaultTTL, DefaultTTL)
	if err != nil {
		return "", nil, fmt.Errorf("load %s: %w", keyPath, err)
	}

	pair, err := signer.GenerateTokenPair(jwt.Subject{
		TenantID:    grant.TenantID.String(),
		UserID:      grant.IdentityID.String(),
		Email:       grant.Email,
		Roles:       grant.Roles,
		Permissions: grant.Permissions,
		IsAdmin:     grant.IsAdmin,
	})
	if err != nil {
		return "", nil, fmt.Errorf("mint token: %w", err)
	}
	return pair.AccessToken, grant, nil
}
