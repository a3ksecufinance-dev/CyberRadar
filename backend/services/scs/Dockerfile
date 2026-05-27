FROM golang:1.22-alpine AS builder
WORKDIR /app

COPY go.work go.work.sum ./
COPY internal/ internal/
COPY services/scs/ services/scs/

RUN go build -o /scs-service ./services/scs/cmd/server/

FROM scratch
COPY --from=builder /scs-service /scs-service
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8027
ENTRYPOINT ["/scs-service"]
