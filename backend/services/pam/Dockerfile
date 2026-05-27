FROM golang:1.22-alpine AS builder

WORKDIR /workspace

COPY go.work go.work.sum* ./
COPY internal/ internal/
COPY services/pam/ services/pam/

WORKDIR /workspace/services/pam
RUN go build -trimpath -ldflags="-s -w" -o /pam-service ./cmd/server

FROM scratch
COPY --from=builder /pam-service /pam-service
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8007
ENTRYPOINT ["/pam-service"]
