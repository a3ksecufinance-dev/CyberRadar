FROM golang:1.22-alpine AS builder

WORKDIR /workspace

# Copy go.work files
COPY go.work go.work.sum ./

# Copy internal shared module
COPY internal/ internal/

# Copy service source
COPY services/dspm/ services/dspm/

WORKDIR /workspace/services/dspm
RUN go build -ldflags="-s -w" -o /dspm-service ./cmd/server

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM scratch

COPY --from=builder /dspm-service /dspm-service

EXPOSE 8030

ENTRYPOINT ["/dspm-service"]
