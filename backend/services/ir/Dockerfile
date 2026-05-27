FROM golang:1.22-alpine AS builder
WORKDIR /app

COPY go.work go.work.sum ./
COPY internal/ internal/
COPY services/ir/ services/ir/

RUN go build -o /ir-service ./services/ir/cmd/server/

FROM scratch
COPY --from=builder /ir-service /ir-service
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8026
ENTRYPOINT ["/ir-service"]
