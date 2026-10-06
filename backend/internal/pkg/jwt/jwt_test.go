package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

const (
	testTenant = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	testUser   = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
)

// newKeyPair returns PEM-encoded RSA keys for tests.
func newKeyPair(t *testing.T) (privPEM, pubPEM []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	return privPEM, pubPEM
}

func newPair(t *testing.T) (*Signer, *Verifier, []byte) {
	t.Helper()
	privPEM, pubPEM := newKeyPair(t)
	signer, err := NewSigner(privPEM, 15*time.Minute, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	verifier, err := NewVerifier(pubPEM)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return signer, verifier, pubPEM
}

func TestRoundTrip(t *testing.T) {
	signer, verifier, _ := newPair(t)

	tokens, err := signer.GenerateTokenPair(Subject{
		TenantID: testTenant, UserID: testUser, Email: "a@b.c",
		Roles: []string{"analyst"}, Permissions: []string{"alerts:read"}, IsAdmin: true,
	})
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}

	claims, err := verifier.Validate(tokens.AccessToken)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.TenantID != testTenant {
		t.Errorf("TenantID = %q, want %q", claims.TenantID, testTenant)
	}
	if claims.UserID != testUser {
		t.Errorf("UserID = %q, want %q", claims.UserID, testUser)
	}
	if !claims.IsAdmin {
		t.Error("IsAdmin = false, want true")
	}

	subject, err := signer.ValidateRefreshToken(tokens.RefreshToken)
	if err != nil {
		t.Fatalf("ValidateRefreshToken: %v", err)
	}
	if subject != testUser {
		t.Errorf("refresh subject = %q, want %q", subject, testUser)
	}
}

// TestRejectsHMACForgedWithPublicKey covers the algorithm-confusion attack that
// moving to RS256 is meant to close: the public key is not secret, so a verifier
// that accepted HMAC would accept a token any holder of it could mint.
func TestRejectsHMACForgedWithPublicKey(t *testing.T) {
	_, verifier, pubPEM := newPair(t)

	forged := gojwt.NewWithClaims(gojwt.SigningMethodHS256, &Claims{
		TenantID: testTenant,
		UserID:   testUser,
		IsAdmin:  true,
		RegisteredClaims: gojwt.RegisteredClaims{
			Subject:   testUser,
			IssuedAt:  gojwt.NewNumericDate(time.Now()),
			ExpiresAt: gojwt.NewNumericDate(time.Now().Add(time.Hour)),
			Issuer:    Issuer,
		},
	})
	tokenStr, err := forged.SignedString(pubPEM)
	if err != nil {
		t.Fatalf("sign forged token: %v", err)
	}

	if _, err := verifier.Validate(tokenStr); err == nil {
		t.Fatal("Validate accepted an HMAC token signed with the public key")
	}
}

func TestRejectsTokenFromAnotherKey(t *testing.T) {
	signer, _, _ := newPair(t)
	_, otherVerifier, _ := newPair(t)

	tokens, err := signer.GenerateTokenPair(Subject{TenantID: testTenant, UserID: testUser, Email: "a@b.c"})
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}

	if _, err := otherVerifier.Validate(tokens.AccessToken); err == nil {
		t.Fatal("Validate accepted a token signed by a different key")
	}
}

func TestRejectsExpiredToken(t *testing.T) {
	privPEM, pubPEM := newKeyPair(t)
	signer, err := NewSigner(privPEM, -time.Minute, time.Hour) // already expired
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	verifier, err := NewVerifier(pubPEM)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	tokens, err := signer.GenerateTokenPair(Subject{TenantID: testTenant, UserID: testUser, Email: "a@b.c"})
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}

	if _, err := verifier.Validate(tokens.AccessToken); err == nil {
		t.Fatal("Validate accepted an expired token")
	}
}

func TestRejectsForeignIssuer(t *testing.T) {
	privPEM, pubPEM := newKeyPair(t)
	key, err := gojwt.ParseRSAPrivateKeyFromPEM(privPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	verifier, err := NewVerifier(pubPEM)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	tokenStr, err := gojwt.NewWithClaims(gojwt.SigningMethodRS256, &Claims{
		TenantID: testTenant,
		UserID:   testUser,
		RegisteredClaims: gojwt.RegisteredClaims{
			ExpiresAt: gojwt.NewNumericDate(time.Now().Add(time.Hour)),
			Issuer:    "somebody-else",
		},
	}).SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := verifier.Validate(tokenStr); err == nil {
		t.Fatal("Validate accepted a token from a foreign issuer")
	}
}

func TestRejectsTokenWithoutTenant(t *testing.T) {
	privPEM, pubPEM := newKeyPair(t)
	key, err := gojwt.ParseRSAPrivateKeyFromPEM(privPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	verifier, err := NewVerifier(pubPEM)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	tokenStr, err := gojwt.NewWithClaims(gojwt.SigningMethodRS256, &Claims{
		UserID: testUser,
		RegisteredClaims: gojwt.RegisteredClaims{
			ExpiresAt: gojwt.NewNumericDate(time.Now().Add(time.Hour)),
			Issuer:    Issuer,
		},
	}).SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := verifier.Validate(tokenStr); err == nil {
		t.Fatal("Validate accepted a token carrying no tenant")
	}
}

func TestSignerRejectsUndersizedKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	if _, err := NewSigner(privPEM, time.Minute, time.Hour); err == nil {
		t.Fatal("NewSigner accepted a 1024-bit key")
	}
}

func TestVerifierRejectsMalformedPEM(t *testing.T) {
	if _, err := NewVerifier([]byte("not a pem")); err == nil {
		t.Fatal("NewVerifier accepted malformed PEM")
	}
}

// ─── Service tokens ───────────────────────────────────────────────────────────

func TestServiceTokenCarriesItsServiceID(t *testing.T) {
	signer, verifier, _ := newPair(t)

	tokens, err := signer.GenerateServiceToken(Subject{
		TenantID: testTenant, UserID: testUser, ServiceID: "collector-agent-01",
		Permissions: []string{"events:ingest"},
	}, time.Minute)
	if err != nil {
		t.Fatalf("GenerateServiceToken: %v", err)
	}

	claims, err := verifier.Validate(tokens.AccessToken)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.ServiceID != "collector-agent-01" {
		t.Errorf("ServiceID = %q, want collector-agent-01", claims.ServiceID)
	}
	if claims.TenantID != testTenant {
		t.Errorf("TenantID = %q, want %s", claims.TenantID, testTenant)
	}
}

func TestServiceTokenRequiresAServiceID(t *testing.T) {
	// A token that does not say which service it belongs to cannot be revoked,
	// attributed, or told apart from a person's.
	signer, _, _ := newPair(t)
	if _, err := signer.GenerateServiceToken(Subject{
		TenantID: testTenant, UserID: testUser,
	}, time.Minute); err == nil {
		t.Error("a service token with no ServiceID was minted")
	}
}

func TestServiceTokenHasNoRefreshToken(t *testing.T) {
	// A machine holds a credential and can re-authenticate at will, so a
	// refresh token would only be a second long-lived secret to protect.
	signer, _, _ := newPair(t)
	tokens, err := signer.GenerateServiceToken(Subject{
		TenantID: testTenant, UserID: testUser, ServiceID: "soar",
	}, time.Minute)
	if err != nil {
		t.Fatalf("GenerateServiceToken: %v", err)
	}
	if tokens.RefreshToken != "" {
		t.Error("a service token came with a refresh token")
	}
}

func TestServiceTokenHonoursItsTTL(t *testing.T) {
	signer, _, _ := newPair(t)
	const ttl = 90 * time.Second

	tokens, err := signer.GenerateServiceToken(Subject{
		TenantID: testTenant, UserID: testUser, ServiceID: "soar",
	}, ttl)
	if err != nil {
		t.Fatalf("GenerateServiceToken: %v", err)
	}

	// The signer's own access expiry is 15 minutes; the argument must win.
	if d := time.Until(tokens.ExpiresAt); d > 2*time.Minute {
		t.Errorf("expires in %v, want about %v — the ttl argument was ignored", d, ttl)
	}
}

func TestAUserTokenNamesNoService(t *testing.T) {
	// RequireServiceAccount relies on this: a person's token must never look
	// like a machine's.
	signer, verifier, _ := newPair(t)
	tokens, err := signer.GenerateTokenPair(Subject{
		TenantID: testTenant, UserID: testUser, Email: "a@b.c",
	})
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}

	claims, err := verifier.Validate(tokens.AccessToken)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.ServiceID != "" {
		t.Errorf("a user token carries ServiceID %q", claims.ServiceID)
	}
}
