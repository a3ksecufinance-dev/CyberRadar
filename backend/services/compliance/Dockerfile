FROM golang:1.22-alpine AS builder

WORKDIR /workspace

COPY go.work go.work.sum* ./
COPY internal/ internal/
COPY services/compliance/ services/compliance/

WORKDIR /workspace/services/compliance
RUN go build -trimpath -ldflags="-s -w" -o /compliance-service ./cmd/server

FROM scratch
COPY --from=builder /compliance-service /compliance-service
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8018
ENTRYPOINT ["/compliance-service"]
