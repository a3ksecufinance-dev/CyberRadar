module github.com/cyberradar/platform/services/mobile

go 1.22

require (
	github.com/cyberradar/platform/internal v0.0.0
	github.com/go-chi/chi/v5 v5.1.0
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.6.0
	github.com/rs/zerolog v1.33.0
	github.com/segmentio/kafka-go v0.4.47
)

replace github.com/cyberradar/platform/internal => ../../internal
