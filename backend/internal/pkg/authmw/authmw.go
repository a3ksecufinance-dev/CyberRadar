// Package authmw holds the HTTP authentication middleware shared by every CRP
// service.
//
// It exists as one implementation rather than a copy per service because the
// copies drifted: only one of the thirty verified the token's signing algorithm,
// and each repeated the claims struct it parsed into.
package authmw

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	"github.com/cyberradar/platform/internal/pkg/jwt"
	"github.com/cyberradar/platform/internal/pkg/oidc"
	"github.com/cyberradar/platform/internal/pkg/rbac"
	"github.com/rs/zerolog"
)

func unauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	//nolint:errcheck // nothing actionable if the client already hung up
	fmt.Fprintf(w, `{"error":{"code":"UNAUTHORIZED","message":%q}}`, message)
}

// ProviderVerifier checks a token issued by an external identity provider.
// internal/pkg/oidc implements it; a test can supply its own.
type ProviderVerifier interface {
	Validate(ctx context.Context, raw string) (*oidc.Claims, error)
}

// GrantResolver says what an authenticated person may do on this platform.
// internal/pkg/rbac implements it.
type GrantResolver interface {
	ByEmail(ctx context.Context, email string) (*rbac.Grant, error)
}

// Options add an external identity provider to the platform's own tokens.
//
// The web interface signs users in against Keycloak and sends Keycloak's token
// to the services, which until now verified only tokens signed by
// identity-service: every call from a browser was refused, so the interface
// could sign someone in and then read nothing.
//
// A provider token is trusted for who the caller is and nothing more. The
// tenant, the roles and the permissions come from this platform's own tables —
// the provider's realm roles are a different vocabulary, and authorisation
// stays where it can be audited.
type Options struct {
	Provider ProviderVerifier
	Grants   GrantResolver
}

// Option configures RequireJWT.
type Option func(*Options)

// WithProvider accepts tokens from an external identity provider, resolving
// what the caller may do through the platform's own RBAC tables. Both are
// required: a provider without a resolver would authenticate people and give
// them nothing, which is indistinguishable from being broken.
func WithProvider(v ProviderVerifier, grants GrantResolver) Option {
	return func(o *Options) {
		if v != nil && grants != nil {
			o.Provider, o.Grants = v, grants
		}
	}
}

// RequireJWT authenticates the bearer token on every request it wraps and puts
// the caller's identity in the request context for handlers to read through
// authctx. Requests without a valid token never reach the handler.
//
// The platform's own token is tried first: it carries everything needed and
// costs nothing to check, and it is what services use to call each other. A
// token that is not one of ours is then offered to the identity provider, when
// one is configured.
func RequireJWT(verifier *jwt.Verifier, logger zerolog.Logger, opts ...Option) func(http.Handler) http.Handler {
	var o Options
	for _, opt := range opts {
		opt(&o)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := bearerToken(r)
			if !ok {
				unauthorized(w, "Missing Authorization header")
				return
			}

			claims, err := verifier.Validate(raw)
			if err != nil {
				if o.Provider == nil {
					logger.Warn().Err(err).Str("path", r.URL.Path).Msg("jwt_invalid")
					unauthorized(w, "Invalid or expired token")
					return
				}
				identity, perr := identityFromProvider(r, raw, o, logger)
				if perr != nil {
					writeProviderError(w, perr)
					return
				}
				next.ServeHTTP(w, r.WithContext(authctx.With(r.Context(), identity)))
				return
			}

			identity, err := authctx.Parse(claims.TenantID, claims.UserID, claims.Email, claims.Roles, claims.IsAdmin)
			if err != nil {
				logger.Warn().Err(err).Str("path", r.URL.Path).Msg("jwt_claims_invalid")
				unauthorized(w, "Invalid token claims")
				return
			}
			identity.Token = raw
			identity.Permissions = claims.Perms
			identity.ServiceID = claims.ServiceID

			next.ServeHTTP(w, r.WithContext(authctx.With(r.Context(), identity)))
		})
	}
}

// forbidden answers a caller who proved who they are and has no account here.
// Not 401: repeating the sign-in would change nothing, and an interface that
// retries authentication on this is an interface that loops.
func forbidden(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	//nolint:errcheck // nothing actionable if the client already hung up
	fmt.Fprintf(w, `{"error":{"code":"NO_PLATFORM_IDENTITY","message":%q}}`, message)
}

// providerError distinguishes "this token is not valid" from "this person has
// no account here", which need different answers and different status codes.
type providerError struct {
	status int
	msg    string
}

func (e providerError) Error() string { return e.msg }

func writeProviderError(w http.ResponseWriter, err error) {
	var pe providerError
	if errors.As(err, &pe) && pe.status == http.StatusForbidden {
		forbidden(w, pe.msg)
		return
	}
	unauthorized(w, "Invalid or expired token")
}

func identityFromProvider(r *http.Request, raw string, o Options, logger zerolog.Logger) (authctx.Identity, error) {
	ctx := r.Context()
	claims, err := o.Provider.Validate(ctx, raw)
	if err != nil {
		logger.Warn().Err(err).Str("path", r.URL.Path).Msg("provider_token_invalid")
		return authctx.Identity{}, providerError{status: http.StatusUnauthorized, msg: "Invalid or expired token"}
	}

	grant, err := o.Grants.ByEmail(ctx, claims.Email)
	if err != nil {
		if errors.Is(err, rbac.ErrNoIdentity) {
			// Worth a log line at info: someone the directory knows tried to
			// use the platform, and an operator has to decide whether they
			// should have an identity here.
			logger.Info().Str("email", claims.Email).Str("path", r.URL.Path).Msg("provider_user_has_no_identity")
			return authctx.Identity{}, providerError{
				status: http.StatusForbidden,
				msg:    "Authenticated, but this account has no identity on this platform",
			}
		}
		logger.Error().Err(err).Str("email", claims.Email).Msg("grant_resolve_failed")
		return authctx.Identity{}, providerError{status: http.StatusUnauthorized, msg: "Invalid or expired token"}
	}

	identity, err := authctx.Parse(
		grant.TenantID.String(), grant.IdentityID.String(), grant.Email, grant.Roles, grant.IsAdmin)
	if err != nil {
		logger.Error().Err(err).Str("email", claims.Email).Msg("grant_identity_invalid")
		return authctx.Identity{}, providerError{status: http.StatusUnauthorized, msg: "Invalid or expired token"}
	}
	identity.Token = raw
	identity.Permissions = grant.Permissions
	return identity, nil
}

// RequirePermission rejects a request whose caller does not hold perm, named
// "resource:action". It must be mounted after RequireJWT, which is what puts
// the caller in the context.
//
// Before this existed no service compared the caller's roles against anything,
// so any authenticated user could reach every route of every service.
func RequirePermission(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !authctx.HasPermission(r.Context(), perm) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				//nolint:errcheck // nothing actionable if the client already hung up
				fmt.Fprintf(w, `{"error":{"code":"FORBIDDEN","message":%q}}`,
					"permission required: "+perm)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireServiceAccount rejects any request that is not made by a service
// account. Mount it after RequireJWT, alongside the permission the route
// needs.
//
// A permission alone is not enough for a machine-only route: permissions are
// granted to roles, and a role granted to a person one day by mistake would
// silently open the route. Requiring the token to name a service account makes
// that mistake impossible to make by grant alone.
func RequireServiceAccount() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !authctx.IsService(r.Context()) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				//nolint:errcheck // nothing actionable if the client already hung up
				fmt.Fprint(w, `{"error":{"code":"FORBIDDEN","message":"this endpoint is for service accounts"}}`)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermissionByMethod applies read/write/delete on resource according to
// the request method, for route groups that share one resource.
func RequirePermissionByMethod(resource string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			RequirePermission(resource+":"+actionFor(r.Method))(next).ServeHTTP(w, r)
		})
	}
}

func actionFor(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return "read"
	case http.MethodDelete:
		return "delete"
	default:
		return "write"
	}
}

func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	return token, token != ""
}
