package authmw

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cyberradar/platform/internal/pkg/authctx"
	"github.com/cyberradar/platform/internal/pkg/jwt"
	"github.com/rs/zerolog"
)

const (
	testTenant = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	testUser   = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
)

func newSignerVerifier(t *testing.T) (*jwt.Signer, *jwt.Verifier) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	signer, err := jwt.NewSigner(privPEM, 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	verifier, err := jwt.NewVerifier(pubPEM)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return signer, verifier
}

// serve runs one request through the middleware, reporting whether the handler
// was reached and what identity it saw.
func serve(t *testing.T, verifier *jwt.Verifier, authHeader string) (status int, reached bool, seen authctx.Identity) {
	t.Helper()
	handler := RequireJWT(verifier, zerolog.Nop())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		seen, _ = authctx.From(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/things", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code, reached, seen
}

func TestValidTokenReachesHandler(t *testing.T) {
	signer, verifier := newSignerVerifier(t)
	tokens, err := signer.GenerateTokenPair(testTenant, testUser, "a@b.c", []string{"analyst"}, true)
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}

	status, reached, seen := serve(t, verifier, "Bearer "+tokens.AccessToken)
	if !reached {
		t.Fatalf("handler not reached, status %d", status)
	}
	if got := seen.TenantID.String(); got != testTenant {
		t.Errorf("TenantID = %s, want %s", got, testTenant)
	}
	if !seen.IsSuperAdmin {
		t.Error("IsSuperAdmin = false, want true")
	}
	if seen.Token != tokens.AccessToken {
		t.Error("raw token not carried on the identity; downstream calls cannot forward it")
	}
}

func TestRejectsMissingAndMalformedHeaders(t *testing.T) {
	_, verifier := newSignerVerifier(t)

	for name, header := range map[string]string{
		"absent":        "",
		"no scheme":     "abcdef",
		"wrong scheme":  "Basic abcdef",
		"empty bearer":  "Bearer ",
		"garbage token": "Bearer not.a.jwt",
	} {
		t.Run(name, func(t *testing.T) {
			status, reached, _ := serve(t, verifier, header)
			if reached {
				t.Error("handler reached without a valid token")
			}
			if status != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", status)
			}
		})
	}
}

func TestRejectsTokenFromAnotherIssuerKey(t *testing.T) {
	otherSigner, _ := newSignerVerifier(t)
	_, verifier := newSignerVerifier(t)

	tokens, err := otherSigner.GenerateTokenPair(testTenant, testUser, "a@b.c", nil, false)
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}

	status, reached, _ := serve(t, verifier, "Bearer "+tokens.AccessToken)
	if reached {
		t.Error("handler reached with a token signed by an unknown key")
	}
	if status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", status)
	}
}

func TestSchemeIsCaseInsensitive(t *testing.T) {
	signer, verifier := newSignerVerifier(t)
	tokens, err := signer.GenerateTokenPair(testTenant, testUser, "a@b.c", nil, false)
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}

	if _, reached, _ := serve(t, verifier, "bearer "+tokens.AccessToken); !reached {
		t.Error("lowercase bearer scheme rejected")
	}
}

func TestUnauthorizedBodyIsValidJSON(t *testing.T) {
	_, verifier := newSignerVerifier(t)
	handler := RequireJWT(verifier, zerolog.Nop())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/things", nil))

	body, _ := io.ReadAll(rec.Body)
	want := `{"error":{"code":"UNAUTHORIZED","message":"Missing Authorization header"}}`
	if string(body) != want {
		t.Errorf("body = %s, want %s", body, want)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}
