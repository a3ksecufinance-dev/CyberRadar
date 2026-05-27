FROM golang:1.22-alpine AS builder

WORKDIR /workspace

COPY go.work go.work.sum* ./
COPY internal/ internal/
COPY services/fraud/ services/fraud/

WORKDIR /workspace/services/fraud
RUN go build -trimpath -ldflags="-s -w" -o /fraud-service ./cmd/server

FROM scratch
COPY --from=builder /fraud-service /fraud-service
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8020
ENTRYPOINT ["/fraud-service"]
