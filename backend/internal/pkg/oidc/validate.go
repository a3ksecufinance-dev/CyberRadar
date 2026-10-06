package oidc

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// providerClaims is the subset of a Keycloak access token this platform reads.
type providerClaims struct {
	jwt.RegisteredClaims
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	AuthorizedParty   string `json:"azp"`
	RealmAccess       struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
}

// Validate checks a token's signature, issuer, audience and expiry, and
// returns who it says the caller is.
//
// The signing method is pinned to RSA. Accepting whatever the token's own
// header asks for is the algorithm-confusion bug: a token with alg "none", or
// one signed with HMAC using the public key as the secret, would otherwise
// verify. The same mistake was found in this platform's own verifier and is
// not repeated here.
func (v *Verifier) Validate(ctx context.Context, raw string) (*Claims, error) {
	var claims providerClaims
	token, err := jwt.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %q", t.Method.Alg())
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("token has no key id")
		}
		return v.key(ctx, kid)
	},
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}),
		jwt.WithIssuer(v.cfg.Issuer),
		jwt.WithLeeway(v.cfg.Leeway),
	)
	if err != nil {
		return nil, fmt.Errorf("oidc: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("oidc: token is not valid")
	}

	// A realm usually has several clients. Without this check a token minted
	// for any of them — including one with far weaker sign-in requirements —
	// would open the platform.
	if v.cfg.Audience != "" && !audienceMatches(claims, v.cfg.Audience) {
		return nil, fmt.Errorf("oidc: token is not for %q", v.cfg.Audience)
	}

	out := &Claims{
		Subject:  claims.Subject,
		Email:    strings.TrimSpace(claims.Email),
		Username: claims.PreferredUsername,
		Roles:    claims.RealmAccess.Roles,
		Issuer:   v.cfg.Issuer,
	}
	if claims.ExpiresAt != nil {
		out.ExpiresAt = claims.ExpiresAt.Time
	} else {
		// A token with no expiry is a token that never stops working.
		return nil, fmt.Errorf("oidc: token has no expiry")
	}
	if out.Subject == "" {
		return nil, fmt.Errorf("oidc: token has no subject")
	}
	return out, nil
}

// audienceMatches accepts the client named in `aud` or in `azp`. Keycloak puts
// the client in `azp` and only lists it in `aud` when an audience mapper says
// to, so checking `aud` alone would refuse every token the realm ships with.
func audienceMatches(claims providerClaims, want string) bool {
	if claims.AuthorizedParty == want {
		return true
	}
	for _, a := range claims.Audience {
		if a == want {
			return true
		}
	}
	return false
}

// Expiry is when the token stops being accepted, for a caller that wants to
// cache something for no longer than that.
func (c Claims) Expiry() time.Time { return c.ExpiresAt }
