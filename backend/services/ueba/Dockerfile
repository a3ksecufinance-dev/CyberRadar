FROM golang:1.22-alpine AS builder

WORKDIR /workspace

COPY go.work go.work.sum* ./
COPY internal/ internal/
COPY services/ueba/ services/ueba/

WORKDIR /workspace/services/ueba
RUN go build -trimpath -ldflags="-s -w" -o /ueba-service ./cmd/server

FROM scratch
COPY --from=builder /ueba-service /ueba-service
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8009
ENTRYPOINT ["/ueba-service"]
