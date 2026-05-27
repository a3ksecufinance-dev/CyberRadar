module github.com/cyberradar/platform/services/audit

go 1.22

require (
	github.com/cyberradar/platform/internal v0.0.0
	github.com/ClickHouse/clickhouse-go/v2 v2.23.2
	github.com/go-chi/chi/v5 v5.1.0
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/google/uuid v1.6.0
	github.com/rs/zerolog v1.33.0
	github.com/spf13/viper v1.19.0
)

replace github.com/cyberradar/platform/internal => ../../internal
