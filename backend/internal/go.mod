module github.com/cyberradar/platform/internal

go 1.22

require (
	github.com/ClickHouse/clickhouse-go/v2 v2.23.2
	github.com/IBM/sarama v1.43.2
	github.com/segmentio/kafka-go v0.4.47
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/google/uuid v1.6.0
	github.com/hashicorp/vault/api v1.14.0
	github.com/jackc/pgx/v5 v5.6.0
	github.com/open-policy-agent/opa v0.64.1
	github.com/prometheus/client_golang v1.19.1
	github.com/redis/go-redis/v9 v9.5.3
	github.com/rs/zerolog v1.33.0
	github.com/spf13/viper v1.19.0
	go.opentelemetry.io/otel v1.27.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.27.0
	go.opentelemetry.io/otel/sdk v1.27.0
	go.opentelemetry.io/otel/trace v1.27.0
	golang.org/x/crypto v0.24.0
)
