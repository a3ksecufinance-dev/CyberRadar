FROM golang:1.22-alpine AS builder

WORKDIR /workspace

COPY go.work go.work.sum* ./
COPY internal/ internal/
COPY services/vuln/ services/vuln/

WORKDIR /workspace/services/vuln
RUN go build -trimpath -ldflags="-s -w" -o /vuln-service ./cmd/server

FROM scratch
COPY --from=builder /vuln-service /vuln-service
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8011
ENTRYPOINT ["/vuln-service"]
