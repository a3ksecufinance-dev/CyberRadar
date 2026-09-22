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

			next.ServeHTTP(w, r.WithContext(authctx.With(r.Context(), identity)))
		})
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
