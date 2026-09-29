package authmw

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/cyberradar/platform/internal/pkg/oidc"
	"github.com/cyberradar/platform/internal/pkg/rbac"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// ProviderFromEnv wires up the external identity provider a deployment has
// configured, so each service does it the same way in two lines:
//
//	providerOpt, err := authmw.ProviderFromEnv(ctx, pool, logger)
//	if err != nil {
//		logger.Fatal().Err(err).Msg("identity provider")
//	}
//	...
//	r.Use(authmw.RequireJWT(jwtVerifier, logger, providerOpt))
//
// OIDC_ISSUER empty means no provider, and the service accepts only the
// platform's own tokens — which is right for a deployment whose interface is
// behind the same issuer, and for service-to-service traffic.
//
// A configured provider that cannot be reached is an error rather than a
// warning. Starting without it would leave every call from a browser answered
// 401, with nothing in any log saying the provider was the reason: exactly the
// failure this whole seam was added to fix.
func ProviderFromEnv(ctx context.Context, pool *pgxpool.Pool, logger zerolog.Logger) (Option, error) {
	issuer := strings.TrimSpace(os.Getenv("OIDC_ISSUER"))
	if issuer == "" {
		return func(*Options) {}, nil
	}
	if pool == nil {
		return nil, fmt.Errorf("OIDC_ISSUER is set but this service has no database pool to resolve grants against")
	}

	verifier, err := oidc.New(ctx, oidc.Config{
		Issuer:   issuer,
		Audience: strings.TrimSpace(os.Getenv("OIDC_AUDIENCE")),
	})
	if err != nil {
		return nil, err
	}
	logger.Info().
		Str("issuer", verifier.Issuer()).
		Str("audience", os.Getenv("OIDC_AUDIENCE")).
		Msg("identity provider accepted for user tokens")

	return WithProvider(verifier, rbac.NewResolver(pool)), nil
}
