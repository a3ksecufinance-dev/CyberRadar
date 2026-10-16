// Package jwt issues and verifies the platform's access tokens.
//
// Tokens are RS256. The identity service holds the private key and is the only
// component that can mint one; every other service verifies with the public key
// alone. A service compromised at runtime therefore cannot forge a token for any
// other service, which the previously shared HMAC secret did allow.
package jwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Issuer identifies tokens minted by this platform.
const Issuer = "cyberradar-platform"

// Claims are the JWT payload fields used throughout CRP.
// All tokens carry tenant_id — this is the cornerstone of tenant isolation.
type Claims struct {
	TenantID string   `json:"tid"`
	UserID   string   `json:"uid"`
	Email    string   `json:"email"`
	Roles    []string `json:"roles"`
	// Perms are the caller's effective permissions, resolved from their roles
	// when the token was minted. Carrying them makes authorization a local
	// check in every service; the cost is that a permission change only takes
	// effect on the next token, so access token lifetime bounds revocation.
	Perms   []string `json:"perms,omitempty"`
	IsAdmin bool     `json:"is_admin"`

	// ServiceID names the service account behind a machine-to-machine call,
	// and is empty for a person's token. A route meant only for machines can
	// then refuse a human's token outright rather than hope no role grants
	// the permission by accident.
	ServiceID string `json:"svc,omitempty"`

	gojwt.RegisteredClaims
}

// Subject describes who a token is being minted for.
type Subject struct {
	TenantID    string
	UserID      string
	Email       string
	Roles       []string
	Permissions []string
	IsAdmin     bool

	// ServiceID is set only for a service account, and names it.
	ServiceID string
}

// TokenPair holds an access token and a refresh token.
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
}

// ─── Verifier ─────────────────────────────────────────────────────────────────

// Verifier validates tokens minted by the identity service.
type Verifier struct {
	key *rsa.PublicKey
}

// NewVerifier builds a Verifier from a PEM-encoded RSA public key.
func NewVerifier(publicKeyPEM []byte) (*Verifier, error) {
	key, err := gojwt.ParseRSAPublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse rsa public key: %w", err)
	}
	return &Verifier{key: key}, nil
}

// NewVerifierFromFile builds a Verifier from a PEM file on disk.
func NewVerifierFromFile(path string) (*Verifier, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key %s: %w", path, err)
	}
	return NewVerifier(pem)
}

// Validate parses and validates an access token, returning its claims.
func (v *Verifier) Validate(tokenStr string) (*Claims, error) {
	return validate(tokenStr, v.key)
}

func validate(tokenStr string, key *rsa.PublicKey) (*Claims, error) {
	token, err := gojwt.ParseWithClaims(tokenStr, &Claims{}, func(t *gojwt.Token) (any, error) {
		// Pinning the family here is what stops an attacker downgrading the
		// token to HMAC and signing it with the public key, which is not secret.
		if _, ok := t.Method.(*gojwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return key, nil
	}, gojwt.WithIssuer(Issuer))
	if err != nil {
		if errors.Is(err, gojwt.ErrTokenExpired) {
			return nil, fmt.Errorf("token expired")
		}
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Enforce mandatory tenant isolation field.
	if strings.TrimSpace(claims.TenantID) == "" {
		return nil, fmt.Errorf("token missing tenant_id")
	}

	return claims, nil
}

// ─── Signer ───────────────────────────────────────────────────────────────────

// Signer mints tokens. Only the identity service should hold one.
type Signer struct {
	key                *rsa.PrivateKey
	accessTokenExpiry  time.Duration
	refreshTokenExpiry time.Duration
}

// NewSigner builds a Signer from a PEM-encoded RSA private key.
func NewSigner(privateKeyPEM []byte, accessExpiry, refreshExpiry time.Duration) (*Signer, error) {
	key, err := gojwt.ParseRSAPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse rsa private key: %w", err)
	}
	if key.N.BitLen() < 2048 {
		return nil, fmt.Errorf("rsa key is %d bits, minimum 2048", key.N.BitLen())
	}
	return &Signer{key: key, accessTokenExpiry: accessExpiry, refreshTokenExpiry: refreshExpiry}, nil
}

// NewSignerFromFile builds a Signer from a PEM file on disk.
func NewSignerFromFile(path string, accessExpiry, refreshExpiry time.Duration) (*Signer, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key %s: %w", path, err)
	}
	return NewSigner(pem, accessExpiry, refreshExpiry)
}

// GenerateTokenPair issues an access + refresh token pair.
func (s *Signer) GenerateTokenPair(sub Subject) (*TokenPair, error) {
	now := time.Now()
	expiresAt := now.Add(s.accessTokenExpiry)

	accessClaims := &Claims{
		TenantID:  sub.TenantID,
		UserID:    sub.UserID,
		Email:     sub.Email,
		Roles:     sub.Roles,
		Perms:     sub.Permissions,
		IsAdmin:   sub.IsAdmin,
		ServiceID: sub.ServiceID,
		RegisteredClaims: gojwt.RegisteredClaims{
			Subject:   sub.UserID,
			IssuedAt:  gojwt.NewNumericDate(now),
			ExpiresAt: gojwt.NewNumericDate(expiresAt),
			ID:        uuid.NewString(),
			Issuer:    Issuer,
		},
	}

	accessToken, err := gojwt.NewWithClaims(gojwt.SigningMethodRS256, accessClaims).SignedString(s.key)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	refreshClaims := &gojwt.RegisteredClaims{
		Subject:   sub.UserID,
		IssuedAt:  gojwt.NewNumericDate(now),
		ExpiresAt: gojwt.NewNumericDate(now.Add(s.refreshTokenExpiry)),
		ID:        uuid.NewString(),
		Issuer:    Issuer,
	}

	refreshToken, err := gojwt.NewWithClaims(gojwt.SigningMethodRS256, refreshClaims).SignedString(s.key)
	if err != nil {
		return nil, fmt.Errorf("sign refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		TokenType:    "Bearer",
	}, nil
}

// GenerateServiceToken mints an access token for a service account.
//
// There is no refresh token: a machine holds a credential and can ask for a
// new token whenever it needs one, so a refresh token would only be a second,
// longer-lived secret to protect. ttl is usually shorter than a person's
// session for the same reason — re-authenticating costs a machine nothing.
//
// It refuses a Subject with no ServiceID. A service token that does not say
// which service it belongs to cannot be revoked, attributed in an audit trail,
// or distinguished from a person's by the middleware.
func (s *Signer) GenerateServiceToken(sub Subject, ttl time.Duration) (*TokenPair, error) {
	if strings.TrimSpace(sub.ServiceID) == "" {
		return nil, fmt.Errorf("service token requires a ServiceID")
	}
	if ttl <= 0 {
		ttl = s.accessTokenExpiry
	}

	now := time.Now()
	expiresAt := now.Add(ttl)

	claims := &Claims{
		TenantID:  sub.TenantID,
		UserID:    sub.UserID,
		Email:     sub.Email,
		Roles:     sub.Roles,
		Perms:     sub.Permissions,
		IsAdmin:   sub.IsAdmin,
		ServiceID: sub.ServiceID,
		RegisteredClaims: gojwt.RegisteredClaims{
			Subject:   sub.UserID,
			IssuedAt:  gojwt.NewNumericDate(now),
			ExpiresAt: gojwt.NewNumericDate(expiresAt),
			ID:        uuid.NewString(),
			Issuer:    Issuer,
		},
	}

	token, err := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims).SignedString(s.key)
	if err != nil {
		return nil, fmt.Errorf("sign service token: %w", err)
	}

	return &TokenPair{AccessToken: token, ExpiresAt: expiresAt, TokenType: "Bearer"}, nil
}

// Validate parses an access token the Signer itself minted.
func (s *Signer) Validate(tokenStr string) (*Claims, error) {
	return validate(tokenStr, &s.key.PublicKey)
}

// ValidateRefreshToken validates a refresh token and returns its subject (userID).
func (s *Signer) ValidateRefreshToken(tokenStr string) (string, error) {
	token, err := gojwt.ParseWithClaims(tokenStr, &gojwt.RegisteredClaims{}, func(t *gojwt.Token) (any, error) {
		if _, ok := t.Method.(*gojwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return &s.key.PublicKey, nil
	}, gojwt.WithIssuer(Issuer))
	if err != nil {
		return "", fmt.Errorf("invalid refresh token: %w", err)
	}

	claims, ok := token.Claims.(*gojwt.RegisteredClaims)
	if !ok || !token.Valid {
		return "", fmt.Errorf("invalid refresh token claims")
	}

	return claims.Subject, nil
}
