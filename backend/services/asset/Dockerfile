FROM golang:1.22-alpine AS builder

WORKDIR /workspace

COPY go.work go.work.sum* ./
COPY internal/ internal/
COPY services/asset/ services/asset/

WORKDIR /workspace/services/asset
RUN go build -trimpath -ldflags="-s -w" -o /asset-service ./cmd/server

FROM scratch
COPY --from=builder /asset-service /asset-service
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8006
ENTRYPOINT ["/asset-service"]
