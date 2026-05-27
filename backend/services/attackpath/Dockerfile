FROM golang:1.22-alpine AS builder

WORKDIR /workspace

COPY go.work go.work.sum* ./
COPY internal/ internal/
COPY services/attackpath/ services/attackpath/

WORKDIR /workspace/services/attackpath
RUN go build -trimpath -ldflags="-s -w" -o /attackpath-service ./cmd/server

FROM scratch
COPY --from=builder /attackpath-service /attackpath-service
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8012
ENTRYPOINT ["/attackpath-service"]
