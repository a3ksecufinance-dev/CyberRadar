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
	IsAdmin  bool     `json:"is_admin"`
	gojwt.RegisteredClaims
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
func (s *Signer) GenerateTokenPair(tenantID, userID, email string, roles []string, isAdmin bool) (*TokenPair, error) {
	now := time.Now()
	expiresAt := now.Add(s.accessTokenExpiry)

	accessClaims := &Claims{
		TenantID: tenantID,
		UserID:   userID,
		Email:    email,
		Roles:    roles,
		IsAdmin:  isAdmin,
		RegisteredClaims: gojwt.RegisteredClaims{
			Subject:   userID,
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
		Subject:   userID,
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
