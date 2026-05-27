FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.work go.work.sum* ./
COPY internal/go.mod internal/go.sum ./internal/
COPY services/audit/go.mod services/audit/go.sum ./services/audit/

WORKDIR /app/services/audit
RUN go mod download

WORKDIR /app
COPY internal/ ./internal/
COPY services/audit/ ./services/audit/

WORKDIR /app/services/audit
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" \
    -o /bin/audit-service ./cmd/server/

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /bin/audit-service /audit-service

EXPOSE 8003

ENTRYPOINT ["/audit-service"]
