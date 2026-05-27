package jwt

import (
	"errors"
	"fmt"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

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

// Service handles JWT generation and validation.
type Service struct {
	secret              []byte
	accessTokenExpiry   time.Duration
	refreshTokenExpiry  time.Duration
}

// New creates a JWT service.
func New(secret string, accessExpiry, refreshExpiry time.Duration) *Service {
	return &Service{
		secret:             []byte(secret),
		accessTokenExpiry:  accessExpiry,
		refreshTokenExpiry: refreshExpiry,
	}
}

// GenerateTokenPair issues an access + refresh token pair.
func (s *Service) GenerateTokenPair(tenantID, userID, email string, roles []string, isAdmin bool) (*TokenPair, error) {
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
			Issuer:    "cyberradar-platform",
		},
	}

	accessToken, err := gojwt.NewWithClaims(gojwt.SigningMethodHS256, accessClaims).SignedString(s.secret)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	refreshClaims := &gojwt.RegisteredClaims{
		Subject:   userID,
		IssuedAt:  gojwt.NewNumericDate(now),
		ExpiresAt: gojwt.NewNumericDate(now.Add(s.refreshTokenExpiry)),
		ID:        uuid.NewString(),
		Issuer:    "cyberradar-platform",
	}

	refreshToken, err := gojwt.NewWithClaims(gojwt.SigningMethodHS256, refreshClaims).SignedString(s.secret)
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

// Validate parses and validates an access token, returning its claims.
func (s *Service) Validate(tokenStr string) (*Claims, error) {
	token, err := gojwt.ParseWithClaims(tokenStr, &Claims{}, func(t *gojwt.Token) (any, error) {
		if _, ok := t.Method.(*gojwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.secret, nil
	})
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
	if claims.TenantID == "" {
		return nil, fmt.Errorf("token missing tenant_id")
	}

	return claims, nil
}

// ValidateRefreshToken validates a refresh token and returns its subject (userID).
func (s *Service) ValidateRefreshToken(tokenStr string) (string, error) {
	token, err := gojwt.ParseWithClaims(tokenStr, &gojwt.RegisteredClaims{}, func(t *gojwt.Token) (any, error) {
		return s.secret, nil
	})
	if err != nil {
		return "", fmt.Errorf("invalid refresh token: %w", err)
	}

	claims, ok := token.Claims.(*gojwt.RegisteredClaims)
	if !ok || !token.Valid {
		return "", fmt.Errorf("invalid refresh token claims")
	}

	return claims.Subject, nil
}
