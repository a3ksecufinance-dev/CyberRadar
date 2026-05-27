package middleware

import (
	"net/http"
	"runtime/debug"

	"github.com/rs/zerolog"
)

// Recovery catches panics, logs them, and returns 500.
func Recovery(logger zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error().
						Interface("panic", rec).
						Bytes("stack", debug.Stack()).
						Str("method", r.Method).
						Str("path", r.URL.Path).
						Msg("panic_recovered")

					http.Error(w, `{"error":{"code":"INTERNAL_ERROR","message":"An internal error occurred"}}`,
						http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
