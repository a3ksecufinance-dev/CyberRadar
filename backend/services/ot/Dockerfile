FROM golang:1.22-alpine AS builder
WORKDIR /app

COPY go.work go.work.sum ./
COPY internal/ internal/
COPY services/ot/ services/ot/

RUN go build -o /ot-service ./services/ot/cmd/server/

FROM scratch
COPY --from=builder /ot-service /ot-service
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8028
ENTRYPOINT ["/ot-service"]
