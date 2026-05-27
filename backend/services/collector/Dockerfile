FROM golang:1.22-alpine AS builder

WORKDIR /workspace

COPY go.work go.work.sum* ./
COPY internal/ internal/
COPY services/collector/ services/collector/

WORKDIR /workspace/services/collector
RUN go build -trimpath -ldflags="-s -w" -o /collector ./cmd/server

FROM scratch
COPY --from=builder /collector /collector
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8005
ENTRYPOINT ["/collector"]
