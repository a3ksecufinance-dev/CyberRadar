package handler

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cyberradar/platform/internal/pkg/authmw"
	pkgjwt "github.com/cyberradar/platform/internal/pkg/jwt"
	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"
)

const (
	testTenant = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	testUser   = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
)

func keys(t *testing.T) (*pkgjwt.Signer, *pkgjwt.Verifier) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	priv := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	signer, err := pkgjwt.NewSigner(priv, 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	verifier, err := pkgjwt.NewVerifier(pub)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return signer, verifier
}

// router mounts the real routes exactly as cmd/server does. The handler's
// service is nil on purpose: every case below is rejected by the middleware,
// so reaching the service at all would be the bug.
func router(verifier *pkgjwt.Verifier) http.Handler {
	r := chi.NewRouter()
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(authmw.RequireJWT(verifier, zerolog.Nop()))
		NewAuditHandler(nil).RegisterRoutes(r)
	})
	return r
}

func post(t *testing.T, h http.Handler, path, token string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestWritingToTheAuditTrailIsClosedToPeople(t *testing.T) {
	// Appending to an audit trail from a browser session is never legitimate:
	// the trail is evidence, and a person who can write to it can launder
	// their own actions. Even a super admin holding audit:write is refused.
	signer, verifier := keys(t)
	tokens, err := signer.GenerateTokenPair(pkgjwt.Subject{
		TenantID: testTenant, UserID: testUser, Email: "ciso@bank.example",
		Permissions: []string{"audit:write", "audit:read", "audit:export"},
		IsAdmin:     true,
	})
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}

	status, body := post(t, router(verifier), "/api/v1/audit/events", tokens.AccessToken)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (body: %s)", status, http.StatusForbidden, body)
	}
	if !strings.Contains(body, "service accounts") {
		t.Errorf("body = %s, want the service-account refusal", body)
	}
}

func TestWritingToTheAuditTrailNeedsAuditWrite(t *testing.T) {
	// Being a machine is not authorization. A collector agent holds a service
	// token and must still not reach the audit write API.
	signer, verifier := keys(t)
	tokens, err := signer.GenerateServiceToken(pkgjwt.Subject{
		TenantID: testTenant, UserID: testUser, ServiceID: "collector-agent-01",
		Permissions: []string{"events:ingest"},
	}, time.Minute)
	if err != nil {
		t.Fatalf("GenerateServiceToken: %v", err)
	}

	status, body := post(t, router(verifier), "/api/v1/audit/events", tokens.AccessToken)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (body: %s)", status, http.StatusForbidden, body)
	}
	if !strings.Contains(body, "audit:write") {
		t.Errorf("body = %s, want the missing permission named", body)
	}
}

func TestWritingToTheAuditTrailNeedsAToken(t *testing.T) {
	_, verifier := keys(t)
	if status, body := post(t, router(verifier), "/api/v1/audit/events", ""); status != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d (body: %s)", status, http.StatusUnauthorized, body)
	}
}

func TestReadingTheAuditTrailStaysOpenToPeople(t *testing.T) {
	// The machine-only gate must not have been applied to the whole group:
	// an auditor reading the trail is the ordinary case.
	signer, verifier := keys(t)
	tokens, err := signer.GenerateTokenPair(pkgjwt.Subject{
		TenantID: testTenant, UserID: testUser, Email: "auditor@bank.example",
		Permissions: []string{"audit:read"},
	})
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/events", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec := httptest.NewRecorder()

	// The nil service panics once the handler is reached, which is precisely
	// the signal that authorization let the request through.
	defer func() {
		if recover() == nil && rec.Code == http.StatusForbidden {
			var body map[string]any
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			t.Errorf("an auditor holding audit:read was refused: %v", body)
		}
	}()
	router(verifier).ServeHTTP(rec, req)
}
