# ─── Build stage ─────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /workspace

# Copy internal shared packages
COPY internal/ internal/

# Copy syslog service
COPY services/syslog/ services/syslog/

# Copy go.work for workspace-aware build
COPY go.work go.work
COPY go.work.sum go.work.sum 2>/dev/null || true

# Download dependencies
WORKDIR /workspace/services/syslog
RUN go mod download

# Build — statically linked binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w -extldflags=-static" \
    -o /syslog-connector ./cmd/server

# ─── Runtime stage ───────────────────────────────────────────────────────────
FROM scratch

COPY --from=builder /syslog-connector /syslog-connector
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Health port
EXPOSE 8031
# UDP syslog (RFC 5426)
EXPOSE 5140/udp
# TCP syslog (RFC 6587)
EXPOSE 5141/tcp
# TLS syslog (RFC 5425)
EXPOSE 6514/tcp

ENTRYPOINT ["/syslog-connector"]
