// Package corsmw lets a browser on another origin call a service.
//
// The web interface runs on one origin and each service on its own port, so
// every call the interface makes is cross-origin. Without these headers a
// browser refuses them all: the interface renders its shell, every panel
// reports "Failed to fetch", and nothing in any service log says why, because
// the browser never sent the request. It was found by running the interface
// against the platform for the first time — curl had never needed them.
//
// The preflight has to be answered before authentication. A browser sends
// OPTIONS without credentials, so an OPTIONS that reaches the JWT middleware
// is answered 401, and the browser reports the real request as blocked.
package corsmw

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Config says which origins may call, and with what.
type Config struct {
	// AllowedOrigins is an exact list. Empty means no CORS headers at all,
	// which is right for a deployment where the interface and the services are
	// behind one origin — a gateway, an ingress — and nothing needs to cross.
	//
	// There is deliberately no wildcard: these services answer to a bearer
	// token, and "*" cannot be combined with credentials. A platform that
	// holds a bank's alerts should not be callable from any page a user
	// happens to have open.
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
	MaxAge         time.Duration
}

// DefaultConfig allows the methods and headers this platform's services use.
func DefaultConfig(origins []string) Config {
	return Config{
		AllowedOrigins: origins,
		AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Authorization", "Content-Type", "X-Tenant-ID", "X-Request-ID"},
		MaxAge:         10 * time.Minute,
	}
}

// OriginsFromEnv reads a comma-separated list, e.g.
// CORS_ALLOWED_ORIGINS=http://localhost:3000,https://radar.bank.example
func OriginsFromEnv(raw string) []string {
	var out []string
	for _, o := range strings.Split(raw, ",") {
		// Whitespace first, then the trailing slash: the other order leaves
		// the slash on " http://localhost:3000/ ", whose last character is a
		// space, and the origin then never matches what a browser sends.
		if o = strings.TrimSuffix(strings.TrimSpace(o), "/"); o != "" {
			out = append(out, o)
		}
	}
	return out
}

// Middleware answers preflights and marks allowed responses.
//
// With no origins configured it returns the handler untouched, so a deployment
// that does not need CORS carries none of it.
func Middleware(cfg Config) func(http.Handler) http.Handler {
	if len(cfg.AllowedOrigins) == 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	allowed := make(map[string]bool, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		allowed[strings.TrimSuffix(o, "/")] = true
	}
	methods := strings.Join(cfg.AllowedMethods, ", ")
	headers := strings.Join(cfg.AllowedHeaders, ", ")
	maxAge := strconv.Itoa(int(cfg.MaxAge.Seconds()))

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Vary on Origin whatever happens: a cache that served one origin's
			// response to another would hand a bank's data to a page that is
			// not allowed to ask for it.
			w.Header().Add("Vary", "Origin")

			if origin == "" || !allowed[strings.TrimSuffix(origin, "/")] {
				// Not a cross-origin call, or not one we allow. A disallowed
				// preflight is answered without the headers rather than passed
				// to the handler: the browser will block it either way, and
				// this keeps an unauthenticated OPTIONS off the auth path.
				if r.Method == http.MethodOptions && origin != "" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")

			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", methods)
				w.Header().Set("Access-Control-Allow-Headers", headers)
				w.Header().Set("Access-Control-Max-Age", maxAge)
				w.Header().Add("Vary", "Access-Control-Request-Method")
				w.Header().Add("Vary", "Access-Control-Request-Headers")
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
