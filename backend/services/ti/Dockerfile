FROM golang:1.22-alpine AS builder

WORKDIR /workspace

COPY go.work go.work.sum* ./
COPY internal/ internal/
COPY services/ti/ services/ti/

WORKDIR /workspace/services/ti
RUN go build -trimpath -ldflags="-s -w" -o /ti-service ./cmd/server

FROM scratch
COPY --from=builder /ti-service /ti-service
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8010
ENTRYPOINT ["/ti-service"]
