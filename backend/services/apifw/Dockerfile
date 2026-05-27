FROM golang:1.22-alpine AS builder

WORKDIR /workspace

COPY go.work go.work.sum* ./
COPY internal/ internal/
COPY services/apifw/ services/apifw/

WORKDIR /workspace/services/apifw
RUN go build -trimpath -ldflags="-s -w" -o /apifw-service ./cmd/server

FROM scratch
COPY --from=builder /apifw-service /apifw-service
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8017
ENTRYPOINT ["/apifw-service"]
