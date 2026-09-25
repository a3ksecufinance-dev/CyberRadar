// Package authmw holds the HTTP authentication middleware shared by every CRP
// service.
//
// It exists as one implementation rather than a copy per service because the
// copies drifted: only one of the thirty verified the token's signing algorithm,
// and each repeated the claims struct it parsed into.
package authmw

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	"github.com/cyberradar/platform/internal/pkg/jwt"
	"github.com/rs/zerolog"
)

func unauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	//nolint:errcheck // nothing actionable if the client already hung up
	fmt.Fprintf(w, `{"error":{"code":"UNAUTHORIZED","message":%q}}`, message)
}

// RequireJWT authenticates the bearer token on every request it wraps and puts
// the caller's identity in the request context for handlers to read through
// authctx. Requests without a valid token never reach the handler.
func RequireJWT(verifier *jwt.Verifier, logger zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := bearerToken(r)
			if !ok {
				unauthorized(w, "Missing Authorization header")
				return
			}

			claims, err := verifier.Validate(raw)
			if err != nil {
				logger.Warn().Err(err).Str("path", r.URL.Path).Msg("jwt_invalid")
				unauthorized(w, "Invalid or expired token")
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
