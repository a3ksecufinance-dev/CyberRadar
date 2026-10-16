package clientip

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The point of this package is that the answer cannot be dictated by the
// request, so that is what the test asserts: a caller who writes an address
// into a header does not get it back.

func serve(t *testing.T, r *http.Request) string {
	t.Helper()
	var got string
	h := Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		got = Of(req)
	}))
	h.ServeHTTP(httptest.NewRecorder(), r)
	return got
}

func request(t *testing.T, peer string, headers map[string]string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.RemoteAddr = peer
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// One ingress inside the cluster, and the real client beyond it.
func TestTheAddressBeyondOurOwnProxyIsTheClient(t *testing.T) {
	t.Setenv(EnvTrustedProxies, "")
	got := serve(t, request(t, "10.0.0.7:4321", map[string]string{
		"X-Forwarded-For": "203.0.113.9, 10.0.0.7",
	}))
	if got != "203.0.113.9" {
		t.Errorf("client is %q, want the address our ingress observed", got)
	}
}

// Two hops of our own: the walk keeps going right to left until it leaves our
// ranges.
func TestTheWalkCrossesEveryProxyOfOurs(t *testing.T) {
	t.Setenv(EnvTrustedProxies, "")
	got := serve(t, request(t, "10.0.0.7:4321", map[string]string{
		"X-Forwarded-For": "203.0.113.9, 172.16.4.4, 10.0.0.7",
	}))
	if got != "203.0.113.9" {
		t.Errorf("client is %q", got)
	}
}

// What the advisory is about: a header written by the caller, with no proxy in
// front at all. RealIP returned 203.0.113.1 here — the caller's own choice.
func TestAForgedHeaderDoesNotChooseTheAnswer(t *testing.T) {
	t.Setenv(EnvTrustedProxies, "")
	for _, h := range []map[string]string{
		{"X-Forwarded-For": "203.0.113.1"},
		{"X-Real-IP": "203.0.113.1"},
		{"True-Client-IP": "203.0.113.1"},
		{"X-Forwarded-For": "203.0.113.1, 198.51.100.2"},
	} {
		got := serve(t, request(t, "198.51.100.77:5555", h))
		if got == "203.0.113.1" {
			t.Errorf("%v: the caller chose the answer", h)
		}
	}
}

// No proxy, no headers: the peer address is the client, which is what it means.
func TestWithNoProxyThePeerIsTheClient(t *testing.T) {
	t.Setenv(EnvTrustedProxies, "")
	got := serve(t, request(t, "198.51.100.77:5555", nil))
	if got != "198.51.100.77" {
		t.Errorf("client is %q, want the peer", got)
	}
}

// A chain that arrives from a peer we do not operate is ignored entirely.
//
// Nothing appended it on our behalf, so no entry in it is evidence — including
// the rightmost one, which chi's walk returns on the ground that the hop
// closest to us put it there. With no proxy in front, the hop closest to us is
// the caller.
func TestAChainFromAnUntrustedPeerIsIgnored(t *testing.T) {
	t.Setenv(EnvTrustedProxies, "")
	got := serve(t, request(t, "198.51.100.77:5555", map[string]string{
		"X-Forwarded-For": "203.0.113.1, 198.51.100.2",
	}))
	if got != "198.51.100.77" {
		t.Errorf("client is %q, want the peer — the only fact available", got)
	}
}

// The deployment's own ranges, when they are not the private ones.
func TestTheConfiguredRangesAreTheOnesTrusted(t *testing.T) {
	t.Setenv(EnvTrustedProxies, "198.51.100.0/24")
	got := serve(t, request(t, "198.51.100.5:443", map[string]string{
		"X-Forwarded-For": "203.0.113.9, 198.51.100.5",
	}))
	if got != "203.0.113.9" {
		t.Errorf("client is %q with the balancer's range configured", got)
	}

	// And a private address is no longer trusted once the list is explicit.
	got = serve(t, request(t, "10.0.0.7:4321", map[string]string{
		"X-Forwarded-For": "203.0.113.9, 10.0.0.7",
	}))
	if got != "10.0.0.7" {
		t.Errorf("client is %q, want the walk to stop at an untrusted hop", got)
	}
}

// A malformed variable does not take the service down, and does not widen what
// is trusted either.
func TestAMalformedConfigurationFallsBackRatherThanPanics(t *testing.T) {
	for _, raw := range []string{"pas-un-cidr", "10.0.0.0/8, pas-un-cidr", "   ", ","} {
		t.Setenv(EnvTrustedProxies, raw)
		got := TrustedProxies()
		if len(got) == 0 {
			t.Errorf("%q: no prefix at all", raw)
		}
		for _, p := range got {
			if p == "pas-un-cidr" {
				t.Errorf("%q: the malformed entry was kept", raw)
			}
		}
	}

	t.Setenv(EnvTrustedProxies, "pas-un-cidr")
	if got := serve(t, request(t, "10.0.0.7:4321", map[string]string{
		"X-Forwarded-For": "203.0.113.9, 10.0.0.7",
	})); got != "203.0.113.9" {
		t.Errorf("client is %q, want the defaults to have applied", got)
	}
}

// The peer address is left alone. RealIP overwrote it, so the one field that
// said who actually connected was gone.
func TestThePeerAddressIsNotOverwritten(t *testing.T) {
	t.Setenv(EnvTrustedProxies, "")
	r := request(t, "10.0.0.7:4321", map[string]string{
		"X-Forwarded-For": "203.0.113.9, 10.0.0.7",
	})
	var peer string
	h := Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		peer = req.RemoteAddr
	}))
	h.ServeHTTP(httptest.NewRecorder(), r)
	if peer != "10.0.0.7:4321" {
		t.Errorf("remote_addr is %q after the middleware", peer)
	}
}
