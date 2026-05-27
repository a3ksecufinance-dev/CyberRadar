FROM golang:1.22-alpine AS builder

WORKDIR /workspace

COPY go.work go.work.sum* ./
COPY internal/ internal/
COPY services/dlp/ services/dlp/

WORKDIR /workspace/services/dlp
RUN go build -trimpath -ldflags="-s -w" -o /dlp-service ./cmd/server

FROM scratch
COPY --from=builder /dlp-service /dlp-service
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8021
ENTRYPOINT ["/dlp-service"]
