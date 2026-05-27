# ── Build stage ────────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy workspace and module files first (for better layer caching)
COPY go.work go.work.sum* ./
COPY internal/go.mod internal/go.sum ./internal/
COPY services/tenant/go.mod services/tenant/go.sum ./services/tenant/

# Download dependencies
WORKDIR /app/services/tenant
RUN go mod download

# Copy source
WORKDIR /app
COPY internal/ ./internal/
COPY services/tenant/ ./services/tenant/

# Build binary (statically linked, minimal)
WORKDIR /app/services/tenant
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" \
    -o /bin/tenant-service ./cmd/server/

# ── Runtime stage ───────────────────────────────────────────────────────────────
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /bin/tenant-service /tenant-service

EXPOSE 8001

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/tenant-service", "-healthcheck"] || exit 1

ENTRYPOINT ["/tenant-service"]
