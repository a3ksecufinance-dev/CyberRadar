FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.work go.work.sum* ./
COPY internal/go.mod internal/go.sum ./internal/
COPY services/identity/go.mod services/identity/go.sum ./services/identity/

WORKDIR /app/services/identity
RUN go mod download

WORKDIR /app
COPY internal/ ./internal/
COPY services/identity/ ./services/identity/

WORKDIR /app/services/identity
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" \
    -o /bin/identity-service ./cmd/server/

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /bin/identity-service /identity-service

EXPOSE 8002

ENTRYPOINT ["/identity-service"]
