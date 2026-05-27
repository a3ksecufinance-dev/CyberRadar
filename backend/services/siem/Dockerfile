FROM golang:1.22-alpine AS builder

WORKDIR /workspace

COPY go.work go.work.sum* ./
COPY internal/ internal/
COPY services/siem/ services/siem/

WORKDIR /workspace/services/siem
RUN go build -trimpath -ldflags="-s -w" -o /siem-service ./cmd/server

FROM scratch
COPY --from=builder /siem-service /siem-service
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8008
ENTRYPOINT ["/siem-service"]
