FROM golang:1.22-alpine AS builder

WORKDIR /workspace

COPY go.work go.work.sum* ./
COPY internal/ internal/
COPY services/dashboard/ services/dashboard/

WORKDIR /workspace/services/dashboard
RUN go build -trimpath -ldflags="-s -w" -o /dashboard-service ./cmd/server

FROM scratch
COPY --from=builder /dashboard-service /dashboard-service
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8015
ENTRYPOINT ["/dashboard-service"]
