package service

import (
	"fmt"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWTService manages JWT generation and validation for the identity service.
type JWTService struct {
	secret             []byte
	accessTokenExpiry  time.Duration
	refreshTokenExpiry time.Duration
}

// Claims are the platform-standard JWT claims.
type Claims struct {
	TenantID string   `json:"tid"`
	UserID   string   `json:"uid"`
	Email    string   `json:"email"`
	Roles    []string `json:"roles"`
	IsAdmin  bool     `json:"is_admin"`
	gojwt.RegisteredClaims
}

// TokenPair holds an access + refresh token.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// NewJWTService creates a JWTService.
func NewJWTService(secret string, accessExpiry, refreshExpiry time.Duration) *JWTService {
	return &JWTService{
		secret:             []byte(secret),
		accessTokenExpiry:  accessExpiry,
		refreshTokenExpiry: refreshExpiry,
	}
}

// GenerateTokenPair issues an access + refresh token pair.
func (s *JWTService) GenerateTokenPair(tenantID, userID, email string, roles []string, isAdmin bool) (*TokenPair, error) {
	now := time.Now()
	expiresAt := now.Add(s.accessTokenExpiry)

	access := gojwt.NewWithClaims(gojwt.SigningMethodHS256, &Claims{
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
	})
	accessToken, err := access.SignedString(s.secret)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	refresh := gojwt.NewWithClaims(gojwt.SigningMethodHS256, &gojwt.RegisteredClaims{
		Subject:   userID,
		IssuedAt:  gojwt.NewNumericDate(now),
		ExpiresAt: gojwt.NewNumericDate(now.Add(s.refreshTokenExpiry)),
		ID:        uuid.NewString(),
		Issuer:    "cyberradar-platform",
	})
	refreshToken, err := refresh.SignedString(s.secret)
	if err != nil {
		return nil, fmt.Errorf("sign refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}

// ValidateRefreshToken parses a refresh token and returns its subject (userID).
func (s *JWTService) ValidateRefreshToken(tokenStr string) (string, error) {
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
