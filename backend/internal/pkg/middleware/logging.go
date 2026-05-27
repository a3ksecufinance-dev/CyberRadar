package middleware

import (
	"net/http"
	"time"

	"github.com/rs/zerolog"
)

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func wrapResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{ResponseWriter: w, status: http.StatusOK}
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.wroteHeader {
		rw.status = code
		rw.ResponseWriter.WriteHeader(code)
		rw.wroteHeader = true
	}
}

// Logging returns structured request logging middleware using zerolog.
func Logging(logger zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			wrapped := wrapResponseWriter(w)

			next.ServeHTTP(wrapped, r)

			duration := time.Since(start)

			event := logger.Info()
			if wrapped.status >= 500 {
				event = logger.Error()
			} else if wrapped.status >= 400 {
				event = logger.Warn()
			}

			event.
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Int("status", wrapped.status).
				Dur("duration_ms", duration).
				Str("remote_addr", r.RemoteAddr).
				Str("user_agent", r.UserAgent()).
				Str("request_id", r.Header.Get("X-Request-ID")).
				Msg("http_request")
		})
	}
}
