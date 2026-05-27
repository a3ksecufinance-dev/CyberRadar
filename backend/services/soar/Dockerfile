FROM golang:1.22-alpine AS builder

WORKDIR /workspace

COPY go.work go.work.sum* ./
COPY internal/ internal/
COPY services/soar/ services/soar/

WORKDIR /workspace/services/soar
RUN go build -trimpath -ldflags="-s -w" -o /soar-service ./cmd/server

FROM scratch
COPY --from=builder /soar-service /soar-service
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8014
ENTRYPOINT ["/soar-service"]
