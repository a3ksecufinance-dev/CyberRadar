package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// provider is a stand-in identity provider: a discovery document, a key set,
// and the ability to mint tokens with it.
type provider struct {
	*httptest.Server
	key *rsa.PrivateKey
	kid string
}

func newProvider(t *testing.T) *provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p := &provider{key: key, kid: "test-key-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   p.URL,
			"jwks_uri": p.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		e := big.NewInt(int64(key.PublicKey.E)).Bytes()
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kid": p.kid, "kty": "RSA", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(e),
		}}})
	})
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

type tokenOpts struct {
	issuer   string
	audience string
	azp      string
	email    string
	subject  string
	expires  time.Time
	noExpiry bool
	method   jwt.SigningMethod
	key      any
	kid      string
}

func (p *provider) mint(t *testing.T, o tokenOpts) string {
	t.Helper()
	claims := jwt.MapClaims{"iss": orDefault(o.issuer, p.URL)}
	if o.subject != "" {
		claims["sub"] = o.subject
	}
	if o.email != "" {
		claims["email"] = o.email
	}
	if o.azp != "" {
		claims["azp"] = o.azp
	}
	if o.audience != "" {
		claims["aud"] = o.audience
	}
	if !o.noExpiry {
		exp := o.expires
		if exp.IsZero() {
			exp = time.Now().Add(time.Hour)
		}
		claims["exp"] = exp.Unix()
	}
	claims["realm_access"] = map[string]any{"roles": []string{"ciso"}}

	method := o.method
	if method == nil {
		method = jwt.SigningMethodRS256
	}
	key := o.key
	if key == nil {
		key = p.key
	}
	tok := jwt.NewWithClaims(method, claims)
	tok.Header["kid"] = orDefault(o.kid, p.kid)
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func verifier(t *testing.T, p *provider, audience string) *Verifier {
	t.Helper()
	v, err := New(context.Background(), Config{Issuer: p.URL, Audience: audience})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

func TestAValidTokenIsAccepted(t *testing.T) {
	p := newProvider(t)
	v := verifier(t, p, "cyberradar-frontend")

	claims, err := v.Validate(context.Background(), p.mint(t, tokenOpts{
		subject: "0c1a…", email: "CISO@Bank.example", azp: "cyberradar-frontend",
	}))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Email != "CISO@Bank.example" || claims.Subject != "0c1a…" {
		t.Errorf("claims = %+v", claims)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "ciso" {
		t.Errorf("roles = %v", claims.Roles)
	}
}

// Accepting whatever algorithm the token's own header names is the
// algorithm-confusion bug: a token signed with HMAC using the public key as
// the secret would verify. This platform's own verifier had that defect once.
func TestAlgorithmConfusionIsRefused(t *testing.T) {
	p := newProvider(t)
	v := verifier(t, p, "")

	hmacToken := p.mint(t, tokenOpts{
		subject: "s", email: "a@b.c",
		method: jwt.SigningMethodHS256, key: []byte("public-key-as-secret"),
	})
	if _, err := v.Validate(context.Background(), hmacToken); err == nil {
		t.Error("an HMAC-signed token was accepted")
	}

	noneToken := p.mint(t, tokenOpts{
		subject: "s", email: "a@b.c",
		method: jwt.SigningMethodNone, key: jwt.UnsafeAllowNoneSignatureType,
	})
	if _, err := v.Validate(context.Background(), noneToken); err == nil {
		t.Error("an unsigned token was accepted")
	}
}

// A token signed by someone else, or naming another issuer, is not this
// provider's token.
func TestAForeignTokenIsRefused(t *testing.T) {
	p, other := newProvider(t), newProvider(t)
	v := verifier(t, p, "")

	foreign := other.mint(t, tokenOpts{issuer: p.URL, subject: "s", email: "a@b.c"})
	if _, err := v.Validate(context.Background(), foreign); err == nil {
		t.Error("a token signed by another key was accepted")
	}

	wrongIssuer := p.mint(t, tokenOpts{issuer: "https://elsewhere.example", subject: "s", email: "a@b.c"})
	if _, err := v.Validate(context.Background(), wrongIssuer); err == nil {
		t.Error("a token naming another issuer was accepted")
	}
}

// A realm usually has several clients. A token minted for one of the others —
// possibly with far weaker sign-in requirements — must not open the platform.
func TestATokenForAnotherClientIsRefused(t *testing.T) {
	p := newProvider(t)
	v := verifier(t, p, "cyberradar-frontend")

	if _, err := v.Validate(context.Background(), p.mint(t, tokenOpts{
		subject: "s", email: "a@b.c", azp: "some-other-client",
	})); err == nil {
		t.Error("a token for another client was accepted")
	}

	// Keycloak names the client in azp and only lists it in aud when a mapper
	// says to, so both have to be accepted.
	if _, err := v.Validate(context.Background(), p.mint(t, tokenOpts{
		subject: "s", email: "a@b.c", audience: "cyberradar-frontend",
	})); err != nil {
		t.Errorf("a token naming the client in aud was refused: %v", err)
	}
}

func TestExpiryIsEnforced(t *testing.T) {
	p := newProvider(t)
	v := verifier(t, p, "")

	expired := p.mint(t, tokenOpts{subject: "s", email: "a@b.c", expires: time.Now().Add(-2 * time.Hour)})
	if _, err := v.Validate(context.Background(), expired); err == nil {
		t.Error("an expired token was accepted")
	}

	// A token with no expiry is a token that never stops working.
	forever := p.mint(t, tokenOpts{subject: "s", email: "a@b.c", noExpiry: true})
	if _, err := v.Validate(context.Background(), forever); err == nil {
		t.Error("a token with no expiry was accepted")
	}
}

// The discovery document has to agree with the address it came from, or a
// token minted by whoever answers that address would be trusted.
func TestDiscoveryMustAgreeWithItsOwnAddress(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   "https://keycloak.bank.example/realms/real",
			"jwks_uri": "https://keycloak.bank.example/jwks",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	if _, err := New(context.Background(), Config{Issuer: srv.URL}); err == nil {
		t.Error("a discovery document declaring another issuer was accepted")
	}
}

// An unknown key id is what a rotation looks like. The set is re-fetched once,
// and not on every request: a token with a made-up kid would otherwise be one
// call to the provider per request, from thirty services.
func TestAnUnknownKeyIdDoesNotStampedeTheProvider(t *testing.T) {
	p := newProvider(t)
	v := verifier(t, p, "")

	bad := p.mint(t, tokenOpts{subject: "s", email: "a@b.c", kid: "not-a-key"})
	for i := 0; i < 3; i++ {
		if _, err := v.Validate(context.Background(), bad); err == nil {
			t.Fatal("a token with an unknown key id was accepted")
		}
	}
}

func TestIssuerIsRequired(t *testing.T) {
	if _, err := New(context.Background(), Config{}); err == nil {
		t.Error("a verifier was built with no issuer")
	}
}
