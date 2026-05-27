FROM golang:1.22-alpine AS builder

WORKDIR /workspace

COPY go.work go.work.sum* ./
COPY internal/ internal/
COPY services/easm/ services/easm/

WORKDIR /workspace/services/easm
RUN go build -trimpath -ldflags="-s -w" -o /easm-service ./cmd/server

FROM scratch
COPY --from=builder /easm-service /easm-service
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8019
ENTRYPOINT ["/easm-service"]
