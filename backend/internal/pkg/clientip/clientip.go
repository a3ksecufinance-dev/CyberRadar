// Package clientip answers one question — which address did this request come
// from — in a way that cannot be dictated by the request itself.
//
// chi's middleware.RealIP used to do this, and every service in this platform
// used it. It is deprecated since chi v5.3.0 and carries two advisories
// (GO-2026-5775, GO-2026-5777), for a reason worth stating plainly: it
// overwrote r.RemoteAddr with the leftmost X-Forwarded-For value, or with
// True-Client-IP or X-Real-IP, whether or not anything in the deployment
// actually sets those headers. A caller sending
//
//	X-Forwarded-For: 203.0.113.1
//
// therefore chose what the audit trail recorded. On a security platform that is
// not a hardening nicety: the source address is evidence.
//
// What replaces it is chi's ClientIPFromXFF, which walks the forwarded chain
// from the right and stops at the first address that is not one of our own
// proxies. The addresses to the left of that one are whatever the client wrote;
// the one it returns is the one our outermost proxy observed and appended
// itself, which nobody downstream can forge.
package clientip

import (
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// EnvTrustedProxies names the CIDR prefixes of the reverse proxies in front of
// this service, comma-separated. It is the one piece of deployment knowledge
// this package cannot infer.
const EnvTrustedProxies = "CRP_TRUSTED_PROXY_CIDRS"

// defaultTrustedProxies are the ranges a platform deployed behind its own
// ingress sits behind: loopback, the three private IPv4 blocks, IPv6 loopback
// and unique-local.
//
// It is a default, not an assumption to leave in place. Deployed with a public
// load balancer whose address is outside these ranges, the walk stops at the
// balancer and records *its* address — wrong, but wrong in the safe direction:
// the value cannot be chosen by the caller. Set EnvTrustedProxies to the real
// ranges and the answer becomes right.
var defaultTrustedProxies = []string{
	"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"::1/128", "fc00::/7",
}

// Middleware records the client address for the rest of the chain to read with
// Of. Unlike RealIP it never touches r.RemoteAddr, so the peer address stays
// available and truthful.
//
// The forwarded chain is read only when the peer is one of our own proxies.
// That condition is not decoration: ClientIPFromXFF walks the header and
// returns its rightmost entry when that entry is not trusted, on the ground
// that the rightmost entry was appended by the hop closest to us. With no
// proxy in front there is no such hop, so a request arriving straight from the
// internet with a one-entry X-Forwarded-For would hand the caller the answer
// again — the very thing RealIP was faulted for. A connection from an address
// we do not operate has no forwarded chain worth reading, and its own address
// is the only fact available.
func Middleware() func(http.Handler) http.Handler {
	trusted := TrustedProxies()
	prefixes := make([]netip.Prefix, 0, len(trusted))
	for _, p := range trusted {
		if pre, err := netip.ParsePrefix(p); err == nil {
			prefixes = append(prefixes, pre)
		}
	}
	walk := chimw.ClientIPFromXFF(trusted...)

	return func(next http.Handler) http.Handler {
		walker := walk(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if peerIsTrusted(r.RemoteAddr, prefixes) {
				walker.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func peerIsTrusted(remoteAddr string, prefixes []netip.Prefix) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap().WithZone("")
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// TrustedProxies returns the configured prefixes, or the defaults above. An
// entry that is not a valid prefix is dropped rather than carried into
// ClientIPFromXFF, which panics on one — a malformed environment variable
// should not take a service down at start-up, and the fail-closed behaviour of
// the walk already covers the case where the remaining list is too narrow.
func TrustedProxies() []string {
	raw := os.Getenv(EnvTrustedProxies)
	if strings.TrimSpace(raw) == "" {
		return defaultTrustedProxies
	}
	var out []string
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(p); err != nil {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return defaultTrustedProxies
	}
	return out
}

// Of returns the client address for this request: the one Middleware worked
// out, or the peer address when the walk found nothing to trust — which is
// what the peer address means when no proxy is involved at all.
func Of(r *http.Request) string {
	if ip := chimw.GetClientIP(r.Context()); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
