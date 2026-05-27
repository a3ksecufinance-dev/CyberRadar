FROM golang:1.22-alpine AS builder

WORKDIR /workspace

COPY go.work go.work.sum* ./
COPY internal/ internal/
COPY services/copilot/ services/copilot/

WORKDIR /workspace/services/copilot
RUN go build -trimpath -ldflags="-s -w" -o /copilot-service ./cmd/server

FROM scratch
COPY --from=builder /copilot-service /copilot-service
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8016
ENTRYPOINT ["/copilot-service"]
