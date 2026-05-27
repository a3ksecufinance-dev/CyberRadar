module github.com/cyberradar/platform/services/identity

go 1.22

require (
	github.com/cyberradar/platform/internal v0.0.0
	github.com/go-chi/chi/v5 v5.1.0
	github.com/go-playground/validator/v10 v10.22.0
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.6.0
	github.com/pquerna/otp v1.4.0
	github.com/redis/go-redis/v9 v9.5.3
	github.com/rs/zerolog v1.33.0
	github.com/spf13/viper v1.19.0
	golang.org/x/crypto v0.24.0
)

replace github.com/cyberradar/platform/internal => ../../internal
