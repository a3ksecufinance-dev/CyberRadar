FROM golang:1.22-alpine AS builder

WORKDIR /workspace

# Copy go.work files
COPY go.work go.work.sum ./

# Copy internal shared module
COPY internal/ internal/

# Copy service source
COPY services/mobile/ services/mobile/

WORKDIR /workspace/services/mobile
RUN go build -ldflags="-s -w" -o /mobile-service ./cmd/server

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM scratch

COPY --from=builder /mobile-service /mobile-service

EXPOSE 8029

ENTRYPOINT ["/mobile-service"]
