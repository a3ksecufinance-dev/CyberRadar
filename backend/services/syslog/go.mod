module github.com/cyberradar/platform/services/syslog

go 1.22

require (
	github.com/cyberradar/platform/internal v0.0.0
	github.com/google/uuid v1.6.0
	github.com/rs/zerolog v1.33.0
	github.com/segmentio/kafka-go v0.4.47
)

replace github.com/cyberradar/platform/internal => ../../internal
