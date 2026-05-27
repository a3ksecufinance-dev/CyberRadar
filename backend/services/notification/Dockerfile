FROM golang:1.22-alpine AS builder

WORKDIR /workspace

COPY go.work go.work.sum* ./
COPY internal/ internal/
COPY services/notification/ services/notification/

WORKDIR /workspace/services/notification
RUN go build -trimpath -ldflags="-s -w" -o /notification ./cmd/server

FROM scratch
COPY --from=builder /notification /notification
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8004
ENTRYPOINT ["/notification"]
