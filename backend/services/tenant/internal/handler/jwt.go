package handler

import (
	"fmt"
	"strings"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// jwtClaims mirrors the platform-standard JWT claims structure.
type jwtClaims struct {
	TenantID string   `json:"tid"`
	UserID   string   `json:"uid"`
	Email    string   `json:"email"`
	Roles    []string `json:"roles"`
	IsAdmin  bool     `json:"is_admin"`
	gojwt.RegisteredClaims
}

// validateJWT parses and validates a JWT string, returning its claims.
func validateJWT(tokenStr, secret string) (*jwtClaims, error) {
	token, err := gojwt.ParseWithClaims(tokenStr, &jwtClaims{}, func(t *gojwt.Token) (any, error) {
		if _, ok := t.Method.(*gojwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*jwtClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	if strings.TrimSpace(claims.TenantID) == "" {
		return nil, fmt.Errorf("token missing tenant_id")
	}
	return claims, nil
}
